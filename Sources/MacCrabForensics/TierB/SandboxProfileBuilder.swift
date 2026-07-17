// SandboxProfileBuilder — declarative DSL → Apple's Sandbox
// Profile Language (SBPL) text profile.
//
// Plan §3.9. Apple marks `sandbox-exec` unsupported but the
// profile format remains consumable by App Sandbox + XPC
// services (the documented path). This builder produces the
// text profile from a manifest-declared declarative shape so
// the Tier B IPC contract can carry the profile alongside the
// plugin binary.
//
// What this builder emits is SBPL — the same DSL Apple's
// `sandboxd` consumes. The output is a valid `.sb` file. What
// loads it depends on the deployment shape:
//   - App Sandbox + XPC service: the service's Info.plist
//     references the profile via `com.apple.security.*`
//     entitlements + XPC-bridge'd file references.
//   - Direct sandbox_init() — deprecated but functional;
//     research-only fallback if the App Sandbox path is too
//     constraining for the plugin's needs.

import Foundation

/// Declarative shape Tier B plugins declare in their manifest.
/// Each clause maps to a single SBPL allow / deny rule.
public struct SandboxProfileSpec: Sendable {

    /// Default rule. `false` = "deny default" (recommended).
    /// `true` = "allow default" (permissive; only useful for
    /// transition periods).
    public let allowAllByDefault: Bool

    /// File-system read allowances. Each entry is a subpath
    /// (recursive) the plugin can read.
    public let fileReadSubpaths: [String]

    /// File-system write allowances. Smaller list — Tier B
    /// plugins usually only write into their vault prefix.
    public let fileWriteSubpaths: [String]

    /// Network endpoints the plugin may connect to. Each entry
    /// is a `host:port` (use `*` for wildcard). Empty list ==
    /// no network.
    public let networkConnectAllowlist: [String]

    /// IPC mach service names the plugin may connect to. Used
    /// for XPC services + other system services.
    public let machServiceConnects: [String]

    /// `process-exec` allowances — paths the plugin may spawn.
    /// Operator-declared; common values include
    /// `/usr/bin/codesign`, `/usr/bin/otool` for analyzers.
    public let processExecPaths: [String]

    /// `process-fork` — when true, allows the plugin to call
    /// fork() / posix_spawn(). Required when processExecPaths
    /// is non-empty.
    public let allowProcessFork: Bool

    public init(
        allowAllByDefault: Bool = false,
        fileReadSubpaths: [String] = [],
        fileWriteSubpaths: [String] = [],
        networkConnectAllowlist: [String] = [],
        machServiceConnects: [String] = [],
        processExecPaths: [String] = [],
        allowProcessFork: Bool = false
    ) {
        self.allowAllByDefault = allowAllByDefault
        self.fileReadSubpaths = fileReadSubpaths
        self.fileWriteSubpaths = fileWriteSubpaths
        self.networkConnectAllowlist = networkConnectAllowlist
        self.machServiceConnects = machServiceConnects
        self.processExecPaths = processExecPaths
        self.allowProcessFork = allowProcessFork
    }
}

public enum SandboxProfileBuilder {

    /// Compile a SandboxProfileSpec into SBPL text.
    ///
    /// Two emission strategies:
    ///
    /// **strict (allowAllByDefault == false)**: `allow default`
    /// baseline (Swift runtime survives) + explicit blocks of
    /// sensitive areas (user home, /etc, network) + explicit
    /// allows that come BEFORE the blocks so they win under
    /// SBPL's first-match semantics. This is the model that
    /// actually launches a Swift binary under sandbox-exec —
    /// pure `deny default` fails execvp() before our profile
    /// even gets evaluated. The strictness comes from the
    /// targeted deny list, not from inverting the baseline.
    ///
    /// **permissive (allowAllByDefault == true)**: pure
    /// `allow default` for transition / instrumentation. No
    /// blocks added. Useful for tracing what a plugin actually
    /// touches before locking it down.
    public static func compile(_ spec: SandboxProfileSpec) -> String {
        var lines: [String] = []
        lines.append("(version 1)")
        lines.append("")
        lines.append("(allow default)")
        lines.append("")

        if !spec.allowAllByDefault {
            // SBPL is *last-match-wins*. Emit the targeted
            // denies first, then the operator's manifest-declared
            // allowlist so the operator's choices override the
            // baseline denies.
            //
            // Denies are kept narrow: a broad
            // `(deny file-read* (subpath "/Users"))` would block
            // the binary itself + dyld-loaded frameworks +
            // execvp. The strategy is to enumerate the
            // *narrowly* sensitive places — login keychains,
            // /etc, /var/db, mail/messages stores, .ssh — and
            // lean on the manifest allowlist for the plugin's
            // home subtree.
            lines.append(";; Targeted denies for sensitive areas (emitted first;")
            lines.append(";; manifest-declared allows below win under last-match).")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/Library/Keychains\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/Library/Application Support/com.apple.TCC\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/Library/Messages\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/Library/Mail\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/Library/Safari\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/.ssh\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/.aws\"))")
            lines.append("(deny file-read* (subpath \"\(NSHomeDirectory())/.config\"))")
            lines.append("(deny file-read* (subpath \"/private/etc\"))")
            lines.append("(deny file-read* (subpath \"/private/var/db\"))")
            lines.append("(deny file-read* (subpath \"/Library/Keychains\"))")
            lines.append("(deny file-read* (subpath \"/var/db\"))")
            if spec.networkConnectAllowlist.isEmpty {
                lines.append("(deny network*)")
            }
            lines.append("")

            // Manifest-declared allows last so they override the
            // denies above on overlapping subpaths.
            if !spec.fileReadSubpaths.isEmpty {
                lines.append(";; Manifest-declared file-read allowlist.")
                for path in spec.fileReadSubpaths {
                    lines.append("(allow file-read* (subpath \(quoted(path))))")
                }
                lines.append("")
            }
            if !spec.fileWriteSubpaths.isEmpty {
                lines.append(";; Manifest-declared file-write allowlist.")
                for path in spec.fileWriteSubpaths {
                    lines.append("(allow file-write* (subpath \(quoted(path))))")
                }
                lines.append("")
            }
            if !spec.networkConnectAllowlist.isEmpty {
                lines.append(";; Manifest-declared network allowlist.")
                for endpoint in spec.networkConnectAllowlist {
                    lines.append("(allow network-outbound (remote ip \(quoted(endpoint))))")
                }
                lines.append("")
            }
            if !spec.processExecPaths.isEmpty {
                lines.append(";; Manifest-declared process-exec allowlist.")
                for path in spec.processExecPaths {
                    lines.append("(allow process-exec (literal \(quoted(path))))")
                }
                lines.append("")
            }
            for service in spec.machServiceConnects {
                lines.append("(allow mach-lookup (global-name \(quoted(service))))")
            }
            if !spec.machServiceConnects.isEmpty { lines.append("") }
        }

        return lines.joined(separator: "\n") + "\n"
    }

    /// Compile a genuine DENY-DEFAULT ("Model B") profile for UNTRUSTED
    /// third-party plugins.
    ///
    /// `compile` above is allow-default + targeted denies — which is NOT
    /// containment for untrusted code (anything not explicitly denied is
    /// allowed; a new sensitive path is a silent leak). This emits
    /// `(deny default)` and allows ONLY a minimal runtime base plus the
    /// manifest-declared capabilities. fork / exec / network and ALL files
    /// outside the base+allowlist are DENIED unless the manifest declares them.
    ///
    /// APPLICATION MODEL (validated on-device, Stream-0 spike): a deny-default
    /// profile applied at exec time aborts the binary (sandbox-exec custom
    /// deny-default → SIGABRT / execvp denied). So this profile is applied by
    /// the signed `maccrab-tierb-sandbox-host` trampoline via `sandbox_init`
    /// AFTER process startup (dyld/exec already done). In that form the spike
    /// proved containment holds: an allow-listed read succeeds, a non-listed
    /// read returns EPERM.
    ///
    /// Named base set of system Mach services a sandbox_init'd process is likely to
    /// need to start (notifications, directory/identity, launch services, trust).
    /// Replaces the former unscoped `(allow mach-lookup)` — a contained plugin can
    /// now reach ONLY this base + its manifest-declared `machServiceConnects`, not
    /// arbitrary `com.apple.*` services (audit #4: broad mach-lookup is a classic
    /// macOS sandbox-escape surface). DEVICE-TUNE: if a Swift plugin SIGABRTs at
    /// startup needing another service, ADD it here and re-run the corpus — never
    /// restore the global allow. Deliberately excludes exfil-adjacent services
    /// (pasteboard, screen capture, etc.).
    static let runtimeBaseMachServices: [String] = [
        "com.apple.system.notification_center",
        "com.apple.system.opendirectoryd.libinfo",
        "com.apple.system.opendirectoryd.membership",
        "com.apple.CoreServices.coreservicesd",
        "com.apple.coreservices.launchservicesd",
        "com.apple.lsd.mapdb",
        "com.apple.logd",
        "com.apple.diagnosticd",
        "com.apple.trustd",
        "com.apple.trustd.agent",
        "com.apple.SecurityServer",
        "com.apple.cfprefsd.daemon",
    ]

    /// User crown-jewels whose METADATA (existence/size/mtime) a contained plugin
    /// must not learn via `stat()`, even though their CONTENT is brokered. Denied
    /// AFTER the global `file-read-metadata` allow (last-match-wins). User-sensitive
    /// paths ONLY — never system runtime dirs dyld must stat at startup. (audit #4)
    static func metadataDenyCrownJewels(home: String) -> [String] {
        [home + "/Library/Keychains",
         home + "/Library/Application Support/com.apple.TCC",
         home + "/Library/Messages",
         home + "/Library/Mail",
         home + "/Library/Safari",
         home + "/.ssh",
         home + "/.aws",
         home + "/.config",
         // v1.21.4 audit #10 follow-up: mirror the credential stores now
         // content-brokered by TCCProtectedPaths so a contained plugin can't
         // learn their existence/size/mtime via stat() either.
         home + "/.docker",
         home + "/.gnupg",
         home + "/.kube",
         home + "/.azure",
         home + "/.netrc",
         "/Library/Keychains",
         "/Library/Application Support/com.apple.TCC"]
    }

    /// DEVICE-TUNE (corpus work, Stream 0-1): the runtime base below (the named
    /// `runtimeBaseMachServices` + the file-read base) must be proven to START a
    /// full Swift plugin against the adversarial corpus AS A CLIENT TEST on a
    /// physical macOS host. If a plugin SIGABRTs at startup needing another system
    /// service, ADD it to `runtimeBaseMachServices` and re-run the corpus — do NOT
    /// restore a global `(allow mach-lookup)`. This lane is reached live via
    /// TierBCollectorExecutor; first-party / sideload execution is trust-gated
    /// (FirstPartyTrustRoot / signed-catalog / TOFU), not gated on this profile
    /// being final.
    public static func compileDenyDefault(_ spec: SandboxProfileSpec) -> String {
        var lines: [String] = []
        lines.append("(version 1)")
        lines.append("(deny default)")
        lines.append("")
        lines.append(";; Minimal runtime base — applied POST-STARTUP by the signed trampoline.")
        lines.append("(allow process-info* (target self))")   // self only — no system-wide process enumeration
        lines.append("(allow sysctl-read)")
        lines.append(";; Named runtime Mach services (NOT a global allow — audit #4). DEVICE-TUNE.")
        for svc in runtimeBaseMachServices { lines.append("(allow mach-lookup (global-name \(quoted(svc))))") }
        lines.append("(allow file-read-metadata)")
        lines.append("(allow file-read* (subpath \"/usr/lib\"))")
        lines.append("(allow file-read* (subpath \"/System/Library\"))")
        // The dyld shared cache on macOS 13+ lives under the Cryptexes paths, not
        // /usr/lib — without these, dyld cannot map the cache and the binary
        // SIGABRTs at startup. (Corpus finding, macOS 26.) Read-only.
        lines.append("(allow file-read* (subpath \"/System/Volumes/Preboot/Cryptexes\"))")
        lines.append("(allow file-read* (subpath \"/private/preboot/Cryptexes\"))")
        lines.append("(allow file-read* (subpath \"/System/Cryptexes\"))")
        lines.append("(allow file-read* (subpath \"/System/DriverKit\"))")
        lines.append("(allow file-read* (literal \"/\"))")   // dyld stats the root
        lines.append("(allow file-read* (literal \"/dev/null\") (literal \"/dev/random\") (literal \"/dev/urandom\"))")
        lines.append("")
        // Manifest-declared allowlist. Anything not listed stays denied by the
        // (deny default) baseline — fork/exec/network are denied unless declared.
        if !spec.fileReadSubpaths.isEmpty {
            lines.append(";; Manifest file-read allowlist.")
            for p in spec.fileReadSubpaths { lines.append("(allow file-read* (subpath \(quoted(p))))") }
        }
        if !spec.fileWriteSubpaths.isEmpty {
            lines.append(";; Manifest file-write allowlist.")
            for p in spec.fileWriteSubpaths { lines.append("(allow file-write* (subpath \(quoted(p))))") }
        }
        if !spec.networkConnectAllowlist.isEmpty {
            lines.append(";; Manifest network allowlist (else all egress stays denied).")
            for e in spec.networkConnectAllowlist { lines.append("(allow network-outbound (remote ip \(quoted(e))))") }
        }
        if !spec.processExecPaths.isEmpty {
            lines.append(";; Manifest exec allowlist (else exec stays denied).")
            for p in spec.processExecPaths { lines.append("(allow process-exec (literal \(quoted(p))))") }
        }
        if spec.allowProcessFork {
            lines.append(";; Manifest opted into fork/posix_spawn.")
            lines.append("(allow process-fork)")
        }
        // Manifest mach-service allowlist — ENFORCED (audit #4). The runtime base
        // above is the only OTHER mach-lookup grant; everything else stays denied
        // by the (deny default) baseline. (Was previously decoded + validated but
        // not emitted, while a global allow made the allowlist meaningless.)
        if !spec.machServiceConnects.isEmpty {
            lines.append(";; Manifest mach-service allowlist (else only the runtime base resolves).")
            for s in spec.machServiceConnects { lines.append("(allow mach-lookup (global-name \(quoted(s))))") }
        }
        // Crown-jewel metadata denies LAST so they win under SBPL last-match over
        // both the global file-read-metadata allow and any (allow file-read*) above.
        lines.append("")
        lines.append(";; Deny stat()/metadata on user crown-jewels (last-match-wins).")
        for p in metadataDenyCrownJewels(home: NSHomeDirectory()) {
            lines.append("(deny file-read-metadata (subpath \(quoted(p))))")
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Compile the deny-default ("Model B") profile the signed
    /// `maccrab-tierb-sandbox-host` trampoline applies to ITSELF via
    /// `sandbox_init`, with the one extra grant the trampoline needs that a plain
    /// `compileDenyDefault` cannot have: permission to `execv` the verified plugin
    /// temp.
    ///
    /// WHY: the trampoline applies this profile to itself, then `execv`s the
    /// plugin. Under `(deny default)`, that exec is itself denied unless the
    /// profile allows `process-exec*` + `file-read*` on the exact target. The
    /// target is the host-controlled 0o500 verified-binary temp (NOT an
    /// attacker-named path), so granting exec on that single literal does not
    /// widen the plugin's authority — once the plugin image is running it is still
    /// `(deny default)` for everything outside its manifest allowlist + base.
    ///
    /// `selfExecPath` MUST be the registry's per-resolve verified temp. The SBPL
    /// quoter neutralises any metacharacters; callers still pass a host path.
    public static func compileTrampolineDenyDefault(
        _ spec: SandboxProfileSpec,
        selfExecPath: String
    ) -> String {
        var profile = compileDenyDefault(spec)
        profile += ";; Trampoline self-exec target — the host-controlled verified plugin temp.\n"
        profile += "(allow process-exec* (literal \(quoted(selfExecPath))))\n"
        profile += "(allow file-read* (literal \(quoted(selfExecPath))))\n"
        return profile
    }

    /// Quote a string for SBPL. SBPL uses double-quoted strings.
    /// Backslash + double-quote need escaping. Newlines and other
    /// control chars need to be either stripped or hex-escaped
    /// because they can break out of the literal in some SBPL
    /// parser variants. Defense-in-depth above the manifest-time
    /// validation in PluginInstaller.validateSandboxPath.
    private static func quoted(_ s: String) -> String {
        var result = ""
        result.reserveCapacity(s.count + 2)
        result.append("\"")
        for scalar in s.unicodeScalars {
            let v = scalar.value
            switch v {
            case 0x5C: result.append("\\\\")     // backslash
            case 0x22: result.append("\\\"")     // double quote
            case 0x09: result.append(" ")        // tab → space
            case 0x0A, 0x0D: result.append(" ")  // newline/CR → space (last-line defense)
            case 0x00...0x1F, 0x7F: result.append("?")  // other controls → ?
            case 0x80...0x9F: result.append("?") // C1 controls → ?
            default: result.unicodeScalars.append(scalar)
            }
        }
        result.append("\"")
        return result
    }

    /// Example: profile a hypothetical Tier B plugin that
    /// inventories Library/Safari for read-only metadata. Used
    /// by tests + the research write-up as a worked example.
    public static func exampleSafariReadOnlyProfile() -> SandboxProfileSpec {
        SandboxProfileSpec(
            allowAllByDefault: false,
            fileReadSubpaths: [
                NSHomeDirectory() + "/Library/Safari",
            ],
            fileWriteSubpaths: [],
            networkConnectAllowlist: [],
            machServiceConnects: [],
            processExecPaths: [],
            allowProcessFork: false
        )
    }
}
