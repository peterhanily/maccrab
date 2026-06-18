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
    /// PENDING (corpus work, Stream 0-1): the runtime base below is the spike
    /// base (broad `mach-lookup`, which must be tightened to the specific
    /// services the Swift runtime needs), and the exact base for full Swift
    /// plugins must be proven against the adversarial corpus AS A CLIENT TEST
    /// before this is wired into any execution path. It is intentionally NOT
    /// wired yet — third-party execution stays fail-closed.
    public static func compileDenyDefault(_ spec: SandboxProfileSpec) -> String {
        var lines: [String] = []
        lines.append("(version 1)")
        lines.append("(deny default)")
        lines.append("")
        lines.append(";; Minimal runtime base — applied POST-STARTUP by the signed trampoline.")
        lines.append(";; TODO(corpus): tighten mach-lookup to the specific runtime services.")
        lines.append("(allow process-info*)")
        lines.append("(allow sysctl-read)")
        lines.append("(allow mach-lookup)")
        lines.append("(allow file-read-metadata)")
        lines.append("(allow file-read* (subpath \"/usr/lib\"))")
        lines.append("(allow file-read* (subpath \"/System/Library\"))")
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
        // NOTE: spec.machServiceConnects is decoded + install-validated but NOT
        // yet ENFORCED here — the runtime base above allows broad mach-lookup
        // (needed to launch; see the TODO). The corpus-tightening step replaces
        // that broad allow with a minimal runtime set AND emits per-service
        // (allow mach-lookup (global-name ...)) from spec.machServiceConnects.
        // Recorded + deferred, NOT silently dropped.
        return lines.joined(separator: "\n") + "\n"
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
