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
    public static func compile(_ spec: SandboxProfileSpec) -> String {
        var lines: [String] = []
        lines.append("(version 1)")
        lines.append("")
        lines.append(spec.allowAllByDefault ? "(allow default)" : "(deny default)")
        lines.append("")

        // Apple-standard inherits for any sandboxed process.
        lines.append(";; Apple-standard inherits — process-info, sysctl-read,")
        lines.append(";; mach-issue-extension, IOKit-open for the small reads")
        lines.append(";; that every binary needs. Without these, even basic")
        lines.append(";; Foundation calls fail.")
        lines.append("(allow process-info-pidinfo (target self))")
        lines.append("(allow process-info-pidfdinfo (target self))")
        lines.append("(allow sysctl-read)")
        lines.append("(allow iokit-open (iokit-user-client-class \"IOSurfaceRootUserClient\"))")
        lines.append("(allow file-read-metadata)")
        lines.append("(allow file-read-data (subpath \"/usr/lib\"))")
        lines.append("(allow file-read-data (subpath \"/System/Library\"))")
        lines.append("")

        if spec.allowProcessFork {
            lines.append("(allow process-fork)")
        }

        for path in spec.processExecPaths {
            lines.append("(allow process-exec (literal \(quoted(path))))")
        }
        if !spec.processExecPaths.isEmpty { lines.append("") }

        for path in spec.fileReadSubpaths {
            lines.append("(allow file-read* (subpath \(quoted(path))))")
        }
        if !spec.fileReadSubpaths.isEmpty { lines.append("") }

        for path in spec.fileWriteSubpaths {
            lines.append("(allow file-write* (subpath \(quoted(path))))")
        }
        if !spec.fileWriteSubpaths.isEmpty { lines.append("") }

        if !spec.networkConnectAllowlist.isEmpty {
            for endpoint in spec.networkConnectAllowlist {
                lines.append("(allow network-outbound (remote ip \(quoted(endpoint))))")
            }
            lines.append("")
        }

        for service in spec.machServiceConnects {
            lines.append("(allow mach-lookup (global-name \(quoted(service))))")
        }
        if !spec.machServiceConnects.isEmpty { lines.append("") }

        return lines.joined(separator: "\n") + "\n"
    }

    /// Quote a string for SBPL. SBPL uses double-quoted strings;
    /// embedded quotes need a backslash.
    private static func quoted(_ s: String) -> String {
        let escaped = s.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "\"\(escaped)\""
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
