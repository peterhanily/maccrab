// IntentEvidenceClassifier.swift
// MacCrabAgentKit
//
// v1.12.0 — translates an enriched `Event` into zero or more
// `BayesianIntentEngine.Evidence` values. EventLoop feeds the result
// into `state.bayesianIntent.observe(...)` so the per-tree posterior
// over attacker `Goal` accumulates as the kill chain develops.
//
// Detection-only: only the engine's posterior is updated. EventLoop
// emits an alert when the top non-benign goal exceeds the threshold
// AND we've gathered enough evidence — never on a single signal.

import Foundation
import MacCrabCore

enum IntentEvidenceClassifier {

    /// Stable tree key for the engine. Prefers the root ancestor's
    /// (executable, pid) tuple, falling back to the current process.
    static func treeKey(for event: Event) -> String {
        if let root = event.process.ancestors.last {
            return "\(root.executable)@\(root.pid)"
        }
        return "\(event.process.executable)@\(event.process.pid)"
    }

    /// Map an enriched event to zero or more Evidence values. Returns
    /// an empty array when no signal is present (the common case).
    static func extract(_ event: Event) -> [BayesianIntentEngine.Evidence] {
        // v1.12.0 post-audit (H-Perf1): the prior implementation called
        // `.lowercased()` on event.process.commandLine (2–8KB for npm /
        // cargo / python builds) on EVERY event regardless of category,
        // allocating a fresh String per event. On a 1k-event/s burst
        // that's ~5MB/s of string churn through the autorelease pool.
        // We now early-out by category BEFORE allocating, and call
        // `.lowercased()` only on the small fields each branch actually
        // needs (paths and hostnames are tiny; exe basenames are small).
        // FileContent enrichment is checked first — it's the cheapest
        // path and any event can carry it.
        var out: [BayesianIntentEngine.Evidence] = []

        if event.enrichments["FileContent_Obfuscated"] == "true" {
            out.append(.obfuscatedContent)
        }

        switch event.eventCategory {
        case .file:
            guard let path = event.file?.path else { return out }
            let action = event.eventAction
            // Path lowercase IS needed for substring-match predicates,
            // but a file path is typically 30–80 bytes, not kilobytes.
            // This is the only allocation we keep in the file branch.
            let lower = path.lowercased()

            if action == "open" || action == "read" || action == "OPEN" || action == "READ" {
                if isCredentialPath(lower) {
                    out.append(.credentialRead)
                }
            } else if action == "write" || action == "create" || action == "close" || action == "rename"
                   || action == "WRITE" || action == "CREATE" || action == "CLOSE" || action == "RENAME" {
                if isLaunchAgentPath(lower) {
                    out.append(.launchAgentWrite)
                }
                if isShellRcPath(lower) {
                    out.append(.shellRcWrite)
                }
                if isWorkflowPath(lower) {
                    out.append(.workflowWrite)
                }
                if isPackageConfigPath(lower) {
                    // Only lowercase the executable basename when we
                    // actually need it for the package-config check.
                    let exeName = ((event.process.executable as NSString).lastPathComponent).lowercased()
                    if !isPackageManagerName(exeName) {
                        out.append(.configFileTampered)
                    }
                }
            }

        case .network:
            guard let net = event.network else { return out }
            // Network event-action set is small — case-insensitive
            // compare avoids an allocation.
            if event.eventAction.caseInsensitiveCompare("connect") == .orderedSame {
                if let rawHost = net.destinationHostname, !rawHost.isEmpty {
                    let host = rawHost.lowercased()
                    if isRegistryHost(host) {
                        out.append(.registryEgress)
                    } else if !isPrivateHost(host, ip: net.destinationIp) {
                        out.append(.nonRegistryEgress)
                    }
                }
            }

        case .process:
            // Most process events are not exec — early-out before any
            // commandLine touch.
            guard event.eventAction.caseInsensitiveCompare("exec") == .orderedSame else { return out }
            // Use the basename (small) for the obvious checks; only
            // fall back to a full commandLine lowercase when a check
            // needs it.
            let exeName = ((event.process.executable as NSString).lastPathComponent).lowercased()
            if isRuntimeDropBasename(exeName, fullPath: event.process.executable) {
                out.append(.runtimeDrop)
            }
            // Destructive + VM-detection predicates need the
            // commandLine. Build the lowercase form only when we hit
            // the matching exe basenames so the kilobyte commandLine
            // allocation is paid once per relevant exec, not once per
            // event in the stream.
            if isDestructiveExeName(exeName) {
                let cmd = event.process.commandLine.lowercased()
                if isDestructiveCommandLine(exeName: exeName, cmd: cmd) {
                    out.append(.destructiveCmd)
                }
            }
            if isVMDetectionExeName(exeName) {
                let cmd = event.process.commandLine.lowercased()
                if isVMDetectionCommandLine(exeName: exeName, cmd: cmd) {
                    out.append(.vmDetectionProbe)
                }
            }
            // v1.12.0 RC4 fix (Int-R4-N1): detect credential-read by
            // proxy of process exec commandLine. ESCollector does
            // not subscribe to NOTIFY_OPEN/READ, and NOTIFY_CLOSE
            // fires only on modified writes — so a pure
            // `cat ~/.aws/credentials` (no write) is invisible to
            // the file branch above. Catch the common shell-invoked
            // patterns (cat / less / head / grep / awk / jq /
            // security / openssl / gpg) against a credential-shaped
            // argument. Imperfect (a manual `cp` or fopen() in code
            // is missed) but covers the worm-shape scenario CHANGELOG
            // advertises until full ES OPEN-subscription lands.
            if isReadlikeExeName(exeName) {
                let cmd = event.process.commandLine.lowercased()
                if cmdLineMentionsCredential(cmd) {
                    out.append(.credentialRead)
                }
            }

        default:
            break
        }

        return out
    }

    // MARK: - Path predicates

    private static func isCredentialPath(_ p: String) -> Bool {
        return p.hasSuffix("/.aws/credentials")
            || p.hasSuffix("/.aws/config")
            || p.contains("/.ssh/id_")
            || p.hasSuffix("/.ssh/authorized_keys")
            || p.hasSuffix("/.netrc")
            || p.hasSuffix("/.npmrc")
            || p.hasSuffix("/.pypirc")
            || p.hasSuffix("/.docker/config.json")
            || p.contains("/.kube/config")
            || p.hasSuffix("/.gitconfig")
            || p.contains("/.config/gh/hosts.yml")
            || p.contains("/.cargo/credentials")
    }

    private static func isLaunchAgentPath(_ p: String) -> Bool {
        return p.contains("/library/launchagents/")
            || p.contains("/library/launchdaemons/")
    }

    private static func isShellRcPath(_ p: String) -> Bool {
        return p.hasSuffix("/.zshrc")
            || p.hasSuffix("/.bashrc")
            || p.hasSuffix("/.bash_profile")
            || p.hasSuffix("/.profile")
            || p.hasSuffix("/.zprofile")
            || p.hasSuffix("/.zshenv")
    }

    private static func isWorkflowPath(_ p: String) -> Bool {
        return p.contains("/.github/workflows/") && (p.hasSuffix(".yml") || p.hasSuffix(".yaml"))
    }

    private static func isPackageConfigPath(_ p: String) -> Bool {
        return p.hasSuffix("/.npmrc")
            || p.hasSuffix("/.pypirc")
            || p.hasSuffix("/.yarnrc")
            || p.hasSuffix("/.yarnrc.yml")
    }

    // v1.12.0 RC5 (Perf-R5-N4): hoisted to static let Set to avoid
    // per-call [String] array literal allocation. Set membership is
    // O(1) vs. Array's O(n).
    private static let packageManagerNames: Set<String> = [
        "npm", "yarn", "pnpm", "bun", "pip", "pip3", "uv", "poetry", "pipenv", "cargo",
    ]

    private static func isPackageManagerName(_ name: String) -> Bool {
        return packageManagerNames.contains(name)
    }

    // MARK: - Network predicates

    private static func isRegistryHost(_ host: String) -> Bool {
        return host == "registry.npmjs.org"
            || host == "registry.yarnpkg.com"
            || host == "upload.pypi.org"
            || host == "pypi.org"
            || host == "files.pythonhosted.org"
            || host == "crates.io"
            || host == "static.crates.io"
    }

    private static func isPrivateHost(_ host: String, ip: String) -> Bool {
        if host == "localhost" || host.hasSuffix(".local") || host.hasSuffix(".internal") {
            return true
        }
        // v1.12.0 RC4 fix (Sec-R4-N4): 172.0.0.0/8 covers public
        // Google ranges (172.217.x, 172.253.x). The actual RFC 1918
        // private range is 172.16.0.0/12 — second octet must be
        // 16..31 inclusive. Pre-fix `hasPrefix("172.")` mis-classified
        // every 172.x as private and suppressed nonRegistryEgress
        // evidence for legit-looking public traffic.
        // v1.12.0 RC5 (Sec-R5-N3): include RFC 6598 CGNAT
        // (100.64.0.0/10) and RFC 3927 link-local (169.254/16) for
        // parity with NetworkInfo.isPrivateAddress. CGNAT-routed
        // traffic on tethered mobile networks would otherwise fire
        // nonRegistryEgress evidence falsely.
        if ip.hasPrefix("10.") || ip.hasPrefix("192.168.") || ip.hasPrefix("127.")
            || ip == "::1"
            || ip.hasPrefix("169.254.")
            || isPrivate172(ip)
            || isPrivateCGNAT(ip) {
            return true
        }
        return false
    }

    // MARK: - Process predicates
    //
    // v1.12.0 post-audit (H-Perf1): split into basename-only checks
    // (cheap, no allocation) + full-commandLine checks (kilobyte
    // allocation deferred until we know the basename matches a
    // candidate). Callers in extract() gate the expensive lowercase()
    // on the cheap check.

    private static func isDestructiveExeName(_ name: String) -> Bool {
        return name == "rm" || name == "dscl" || name == "diskutil"
    }

    private static func isDestructiveCommandLine(exeName: String, cmd: String) -> Bool {
        if exeName == "rm" && cmd.contains("-rf") && (cmd.contains(" /") || cmd.contains(" ~") || cmd.contains(" $home")) {
            return true
        }
        if exeName == "dscl" && cmd.contains("-delete") {
            return true
        }
        if exeName == "diskutil" && cmd.contains("erasedisk") {
            return true
        }
        return false
    }

    private static func isVMDetectionExeName(_ name: String) -> Bool {
        return name == "sysctl" || name == "ioreg" || name == "system_profiler"
    }

    private static func isVMDetectionCommandLine(exeName: String, cmd: String) -> Bool {
        if exeName == "sysctl" && (cmd.contains("hw.model") || cmd.contains("machdep.cpu.brand_string")) {
            return true
        }
        if exeName == "ioreg" && cmd.contains("ioplatformexpertdevice") {
            return true
        }
        if exeName == "system_profiler" && cmd.contains("sphardwaredatatype") {
            return true
        }
        return false
    }

    /// Runtime-drop check takes both the basename (already-lowered)
    /// and the original full path so we can do the standard-prefix
    /// check without re-lowering the whole path.
    private static func isRuntimeDropBasename(_ name: String, fullPath: String) -> Bool {
        guard name == "bun" || name == "deno" else { return false }
        let standardPrefixes = [
            "/opt/homebrew/", "/usr/local/", "/usr/bin/", "/.bun/bin/", "/.deno/bin/"
        ]
        return !standardPrefixes.contains { fullPath.contains($0) }
    }

    private static func isRuntimeDropLegacy(exe: String) -> Bool {
        let name = (exe as NSString).lastPathComponent
        guard name == "bun" || name == "deno" else { return false }
        // Suspicious only when the binary lives outside the standard
        // package-manager locations.
        let standardPrefixes = [
            "/opt/homebrew/", "/usr/local/", "/usr/bin/", "/.bun/bin/", "/.deno/bin/"
        ]
        return !standardPrefixes.contains { exe.contains($0) }
    }

    // MARK: - Small helpers

    private static func action(action: String, equals other: String) -> Bool {
        return action.caseInsensitiveCompare(other) == .orderedSame
    }

    /// v1.12.0 RC4 (Int-R4-N1): shell-invokable readers that
    /// commonly target credential files. Matches the basename of
    /// the executing process. v1.12.0 RC5 (Perf-R5-N4): hoisted to
    /// static let Set so the literal isn't rebuilt per call.
    private static let readlikeExeNames: Set<String> = [
        "cat", "less", "more", "head", "tail", "view",
        "grep", "egrep", "rg", "awk", "sed",
        "jq", "yq",
        "security", "openssl", "gpg", "gpg2", "age",
        "base64", "xxd", "od", "strings",
    ]

    private static func isReadlikeExeName(_ name: String) -> Bool {
        return readlikeExeNames.contains(name)
    }

    /// True iff the lowercased commandLine references a path that
    /// matches one of the credential-shape predicates the file branch
    /// uses. Substring match keeps it cheap.
    private static func cmdLineMentionsCredential(_ cmd: String) -> Bool {
        return cmd.contains("/.aws/credentials")
            || cmd.contains("/.aws/config")
            || cmd.contains("/.ssh/id_")
            || cmd.contains("/.ssh/authorized_keys")
            || cmd.contains("/.netrc")
            || cmd.contains("/.npmrc")
            || cmd.contains("/.pypirc")
            || cmd.contains("/.docker/config.json")
            || cmd.contains("/.kube/config")
            || cmd.contains("/.gitconfig")
            || cmd.contains("/.config/gh/hosts.yml")
            || cmd.contains("/.cargo/credentials")
    }

    /// v1.12.0 RC5 (Sec-R5-N3): 100.64.0.0/10 (RFC 6598 CGNAT)
    /// check — first octet 100, second octet in [64, 127].
    private static func isPrivateCGNAT(_ ip: String) -> Bool {
        guard ip.hasPrefix("100.") else { return false }
        let parts = ip.split(separator: ".")
        guard parts.count >= 2, let octet2 = Int(parts[1]) else { return false }
        return octet2 >= 64 && octet2 <= 127
    }

    /// 172.16.0.0/12 (RFC 1918) check — second octet must be in
    /// [16, 31]. Pre-fix the caller used `hasPrefix("172.")` which
    /// also matched 172.217.x.x (Google CDN) and 172.253.x.x (Google
    /// CDN), incorrectly suppressing nonRegistryEgress evidence.
    private static func isPrivate172(_ ip: String) -> Bool {
        guard ip.hasPrefix("172.") else { return false }
        let parts = ip.split(separator: ".")
        guard parts.count >= 2, let octet2 = Int(parts[1]) else { return false }
        return octet2 >= 16 && octet2 <= 31
    }
}
