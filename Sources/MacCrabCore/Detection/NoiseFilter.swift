// NoiseFilter.swift
// MacCrabCore
//
// Shared low-signal match filters. Applied at every rule-evaluation entry
// point (main event loop, FSEvents fallback loop, SIGHUP retroactive
// scan) so noise suppression stays consistent and can't be bypassed by a
// new integration forgetting to call it.
//
// Every fix we've shipped between 1.2.1 and 1.2.3 to cut the alert rate
// on real dev workstations has landed here, so this file is also the
// regression-test surface — see FPRegressionTests.swift.

import Foundation

/// Low-signal match filters applied before alert emission. Stateless —
/// every input is passed in; no singleton, no hidden global state. This
/// makes the filter trivially testable from the FP-regression harness.
public enum NoiseFilter {

    /// Apply all three gates to a batch of rule matches. Mutates in place.
    /// Each gate drops non-`.critical` matches; critical rules (ransomware,
    /// SIP disabled, known-malicious-hash) always fire regardless of gate.
    ///
    /// - Parameters:
    ///   - matches: rule matches to filter; mutated in place.
    ///   - event: the event that produced these matches. Process attribution
    ///     and executable path drive the unknown-process and trusted-browser
    ///     gates.
    ///   - isWarmingUp: `true` during the daemon's first 60 seconds of
    ///     operation, when inventory scans produce a one-shot burst.
    public static func apply(
        _ matches: inout [RuleMatch],
        event: Event,
        isWarmingUp: Bool
    ) {
        // Gate 1: unattributable event. FSEvents fires file events without
        // a process; Sigma rules with `Image|contains` filters designed to
        // exclude trusted system processes fail open in that case. Dropping
        // non-critical matches here means we never alert on activity we
        // cannot triage.
        if event.process.name == "unknown" || event.process.executable.isEmpty {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 2: startup warm-up window. Inventory scans (browser
        // extensions, quarantine baseline, process-tree model hydration)
        // complete in the first 60 s and generate a one-shot burst that
        // isn't live-threat signal. Critical still fires so a ransomware
        // note at T+10s isn't missed.
        if isWarmingUp {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 3: trusted browser / Electron helper. Chromium apps spawn
        // large helper trees that fire individual Sigma rules in isolation
        // (reading their own cookie DB, writing their own cache, opening
        // long-lived HTTPS, spawning child tools for profile migration).
        // A single bundle-prefix short-circuit drops non-critical matches
        // without needing per-rule-per-helper allowlists.
        if isTrustedBrowserHelper(path: event.process.executable) {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 4: MacCrab self-activity. Our install pipeline modifies its
        // own compiled_rules/ directory, its own bundles get signed by its
        // own Developer ID, and the sysext fires TCC + XPC events at
        // sysextd during normal operation. Without this gate, every
        // upgrade fires our own tamper-detection rules against ourselves,
        // every sysext XPC interaction looks like an EDR remote-session
        // start, and user-initiated FDA grants look like "automated TCC
        // manipulation". Drop non-critical matches whose subject is
        // MacCrab itself — critical still fires so a real integrity
        // compromise against our binaries isn't hidden.
        if isMacCrabSelf(event: event) {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 5: interactive admin CLI from a terminal parent. ps, top,
        // defaults, dscl, id, lsof, etc. are what every developer and
        // sysadmin runs constantly. Sigma rules flag them as "recon" at
        // Medium severity because in an attack chain those commands
        // really ARE enumeration — but fired in isolation from Terminal →
        // zsh → ps, they're nobody's evidence of intrusion. Suppress
        // non-critical matches when (a) the event process is a known
        // admin CLI and (b) any ancestor is a desktop terminal emulator.
        // Critical still fires so a genuine post-exploitation pattern
        // (unsigned parent, dropped-to-disk binary) isn't hidden.
        if isInteractiveAdminCommand(event: event) {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 6: auto-updater process tree. GoogleUpdater, Sparkle's
        // Autoupdate, Microsoft AutoUpdate, softwareupdated, brew, etc.
        // legitimately touch multiple MITRE tactics during an update
        // cycle (MDM-state probe, xattr removal, plist write, code-sig
        // check). Drop non-critical matches when the subject OR any
        // ancestor is a known auto-updater — the Sigma per-rule
        // ParentImage filters we've added against GoogleUpdater /
        // Sparkle require the DIRECT parent to match by name, which
        // fails when Chrome → GoogleUpdater.app/Contents/MacOS/
        // GoogleUpdater → launcher → GoogleUpdater → profiles chains
        // shove the updater two ancestors up. This gate walks the
        // full ancestor list so the backstop works regardless of chain
        // depth. Critical still fires so a real compromise inside an
        // updater tree isn't hidden.
        if isAutoUpdaterOrAncestor(event: event) {
            matches.removeAll { $0.severity != .critical }
        }

        // Gate 7: Apple-signed platform binary. The ultimate backstop
        // for the long-running FP thread around `/bin/ps`,
        // `/usr/bin/defaults`, `/usr/bin/csrutil`, `/usr/bin/sw_vers`,
        // `/usr/sbin/system_profiler`, and friends. Per-rule
        // `filter_system_path` and `filter_platform` already attempt
        // to catch these, but field data across v1.6.2-1.6.7 shows
        // the same alerts recurring — either because rules aren't
        // reloaded on the running daemon, or because the ES event's
        // code-sig enrichment hasn't settled by the time the rule
        // engine evaluates. When the subject is unambiguously an
        // Apple-shipped platform binary — flagged by macOS itself via
        // `isPlatformBinary`, OR anchored on a SIP-protected path
        // prefix — drop non-critical matches regardless. Critical
        // rules (ransomware, SIP disable, known-bad hash) still fire.
        if isAppleSystemBinary(event: event) {
            matches.removeAll { $0.severity != .critical }
        }
    }

    /// True when an event's subject is a MacCrab process, a MacCrab file,
    /// or a file inside a MacCrab managed directory. Matches the three
    /// known bundle IDs (app + sysext + legacy daemon) and the two data
    /// dirs (system and user). Public so rule-level allowlists can reuse
    /// the same definition.
    public static func isMacCrabSelf(event: Event) -> Bool {
        let name = event.process.name.lowercased()
        if name == "maccrab" ||
           name == "com.maccrab.agent" ||
           name == "maccrabd" ||
           name == "maccrabctl" ||
           name == "maccrab-mcp" {
            return true
        }
        let path = event.process.executable
        if path.hasPrefix("/Applications/MacCrab.app/") ||
           path.hasPrefix("/Library/SystemExtensions/") && path.contains("com.maccrab.agent") ||
           path.contains("/maccrab.app/") ||  // ad-hoc-signed dev builds
           path.hasSuffix("/maccrabd") ||
           path.hasSuffix("/maccrabctl") ||
           path.hasSuffix("/maccrab-mcp") {
            return true
        }
        // File-event subjects: filesystem paths under MacCrab's managed
        // directories. Tamper-detection rules on compiled_rules/ fire on
        // legitimate cask postflight updates; suppress unless critical.
        if let filePath = event.file?.path,
           filePath.hasPrefix("/Library/Application Support/MacCrab/") ||
           filePath.hasPrefix("\(NSHomeDirectory())/Library/Application Support/MacCrab/") {
            return true
        }
        return false
    }

    /// True when the given executable path is inside a trusted browser or
    /// Electron-helper app bundle. Public so rule-level allowlists can
    /// reuse the same definition.
    public static func isTrustedBrowserHelper(path: String) -> Bool {
        for prefix in trustedBrowserPrefixes where path.hasPrefix(prefix) {
            return true
        }
        return false
    }

    /// True when the event process is one of the admin-CLI basenames (ps,
    /// lsof, defaults, csrutil, …) AND at least one ancestor is a desktop
    /// terminal emulator (Terminal, iTerm, Warp, Alacritty, tmux, …). This
    /// is the "human at a shell prompt" heuristic — by far the biggest
    /// source of discovery-rule noise on developer workstations. Ancestry
    /// walk handles tmux / screen / zsh chains (terminal → tmux → zsh → ps).
    public static func isInteractiveAdminCommand(event: Event) -> Bool {
        let basename = (event.process.executable as NSString).lastPathComponent.lowercased()
        let imageBasename = event.process.name.lowercased()
        guard interactiveAdminBasenames.contains(basename)
            || interactiveAdminBasenames.contains(imageBasename) else {
            return false
        }
        for ancestor in event.process.ancestors {
            if isInteractiveTerminalAncestor(ancestor.executable) {
                return true
            }
        }
        return false
    }

    /// True when the event's subject is an Apple-shipped platform
    /// binary. Union of three signals, any of which is sufficient:
    ///
    /// 1. `event.process.isPlatformBinary` — set by ES when macOS
    ///    recognises the binary as platform-shipped. Most reliable.
    /// 2. `process.codeSignature.signerType == .apple` — kernel
    ///    code-sig enrichment recognised the signer.
    /// 3. Image path under a SIP-protected prefix — `/bin/`,
    ///    `/sbin/`, `/usr/bin/`, `/usr/sbin/`, `/usr/libexec/`,
    ///    `/System/`. Since SIP prevents writing to these paths on a
    ///    healthy system, anything running from them is guaranteed
    ///    Apple-shipped. Anchoring here makes the gate resilient to
    ///    enrichment races where neither isPlatformBinary nor
    ///    signerType arrive before the rule fires.
    ///
    /// Intentionally scoped to the SUBJECT process only; we don't
    /// walk ancestors. A /bin/ps invoked from /tmp/malicious shell
    /// will still be suppressed — but /tmp/malicious itself won't
    /// be, because Gate 7 only fires on Apple subjects. That's the
    /// right split: we trust the platform binary, we don't trust
    /// its caller.
    public static func isAppleSystemBinary(event: Event) -> Bool {
        if event.process.isPlatformBinary { return true }
        if event.process.codeSignature?.signerType == .apple { return true }
        let path = event.process.executable
        if path.hasPrefix("/bin/") || path.hasPrefix("/sbin/") { return true }
        if path.hasPrefix("/usr/bin/") || path.hasPrefix("/usr/sbin/") { return true }
        if path.hasPrefix("/usr/libexec/") { return true }
        if path.hasPrefix("/System/") { return true }
        return false
    }

    /// True when the event's subject process or any ancestor in its
    /// lineage is a known auto-updater. Delegates to
    /// `CampaignDetector.isAutoUpdater` (the narrow variant) — NOT
    /// `isKnownBenignProcess`, which includes Apple system daemon paths
    /// that would sweep in Terminal, Finder, and every
    /// `/System/Applications/Utilities/` tool. Exposed publicly so the
    /// campaign and sequence engines can reuse the same definition.
    public static func isAutoUpdaterOrAncestor(event: Event) -> Bool {
        if CampaignDetector.isAutoUpdater(processPath: event.process.executable) {
            return true
        }
        for ancestor in event.process.ancestors {
            if CampaignDetector.isAutoUpdater(processPath: ancestor.executable) {
                return true
            }
        }
        return false
    }

    /// True when the path is a desktop terminal emulator bundle. Covers
    /// Apple Terminal, third-party terminals, multiplexers (tmux/screen)
    /// that commonly sit between a terminal and an interactive shell.
    ///
    /// v1.4.5: also treat a shell binary (bash, zsh, sh, fish, etc.) as
    /// a terminal-equivalent ancestor. Field data showed Gate 5 failing
    /// to fire on `ps` invoked from `zsh` when the ES ancestor chain
    /// only contained the shell — the user's Terminal window was too
    /// far up the tree. Shells as direct parents of admin CLI tools
    /// are overwhelmingly a human at a prompt; the FN risk (attacker
    /// launches shell → launches ps) is low because the attacker's
    /// shell would itself be a child of a dropper, and Gate 5 only
    /// fires on the admin-CLI basenames list anyway.
    public static func isInteractiveTerminalAncestor(_ path: String) -> Bool {
        for prefix in terminalEmulatorPrefixes where path.hasPrefix(prefix) {
            return true
        }
        let base = (path as NSString).lastPathComponent
        if terminalMultiplexerBasenames.contains(base) { return true }
        if shellAncestorBasenames.contains(base) { return true }
        return false
    }

    /// Shells that, when seen as an ancestor of an admin-CLI basename,
    /// indicate the command was run in an interactive shell session.
    /// Intentionally scoped to basenames (not paths) so we match both
    /// /bin/zsh and /opt/homebrew/bin/zsh.
    public static let shellAncestorBasenames: Set<String> = [
        "bash", "zsh", "sh", "dash", "fish", "ksh", "tcsh", "csh",
    ]

    /// Admin-CLI basenames that commonly fire discovery rules when run
    /// interactively. Intentionally narrow — only well-known system tools
    /// a developer/admin runs at a prompt. Adding anything here with a
    /// more generic name (like "sh" or "python") would hide real signal.
    public static let interactiveAdminBasenames: Set<String> = [
        "ps", "top", "lsof", "netstat", "ifconfig", "ipconfig", "networksetup",
        "scutil", "arp", "route", "tcpdump",
        "defaults", "dscl", "dseditgroup", "id", "dsmemberutil", "groups",
        "who", "w", "whoami",
        "uname", "hostname", "sw_vers", "system_profiler", "ioreg",
        "csrutil", "spctl", "profiles", "kextstat", "launchctl",
        "sysctl", "diskutil", "mount", "df", "mdutil",
        "smbutil", "nettop", "nfsstat", "ndp", "dig", "host", "nslookup",
    ]

    /// Desktop-terminal-emulator bundle prefixes. If an ancestor's
    /// executable path starts with one of these, the descendant process
    /// was launched from a terminal window.
    public static let terminalEmulatorPrefixes: [String] = [
        "/System/Applications/Utilities/Terminal.app/",
        "/Applications/Utilities/Terminal.app/",
        "/Applications/iTerm.app/",
        "/Applications/iTerm2.app/",
        "/Applications/Alacritty.app/",
        "/Applications/Warp.app/",
        "/Applications/WarpPreview.app/",
        "/Applications/kitty.app/",
        "/Applications/WezTerm.app/",
        "/Applications/Hyper.app/",
        "/Applications/Tabby.app/",
        "/Applications/Ghostty.app/",
    ]

    /// Multiplexer/helper basenames that sit between a terminal and a
    /// shell. When we see one of these as an ancestor, keep walking — the
    /// terminal proper is usually one or two levels above.
    public static let terminalMultiplexerBasenames: Set<String> = [
        "tmux", "screen", "byobu", "zellij",
    ]

    /// Known browser / Electron app-bundle prefixes whose helper processes
    /// do a lot of activity individual Sigma rules flag in isolation.
    /// Adding an entry here turns every rule into a non-critical skip for
    /// processes under that bundle — use sparingly and only for widely-
    /// deployed first-party software.
    public static let trustedBrowserPrefixes: [String] = [
        // Browsers
        "/Applications/Google Chrome.app/",
        "/Applications/Google Chrome Canary.app/",
        "/Applications/Chromium.app/",
        "/Applications/Microsoft Edge.app/",
        "/Applications/Microsoft Edge Canary.app/",
        "/Applications/Microsoft Edge Dev.app/",
        "/Applications/Microsoft Edge Beta.app/",
        "/Applications/Brave Browser.app/",
        "/Applications/Brave Browser Nightly.app/",
        "/Applications/Brave Browser Dev.app/",
        "/Applications/Arc.app/",
        "/Applications/Vivaldi.app/",
        "/Applications/Opera.app/",
        "/Applications/Firefox.app/",
        "/Applications/Firefox Nightly.app/",
        "/Applications/Firefox Developer Edition.app/",
        "/Applications/Safari.app/",
        "/Applications/Orion.app/",
        // Electron apps that ship a Chromium helper tree and behave
        // identically to browsers from the detection engine's perspective.
        "/Applications/Slack.app/",
        "/Applications/Discord.app/",
        "/Applications/Microsoft Teams.app/",
        "/Applications/Visual Studio Code.app/",
        "/Applications/Code.app/",
        "/Applications/Cursor.app/",
        "/Applications/Claude.app/",
        "/Applications/ChatGPT Atlas.app/",
        "/Applications/Codex.app/",
        "/Applications/GitHub Desktop.app/",
        "/Applications/Signal.app/",
        "/Applications/Telegram.app/",
        "/Applications/WhatsApp.app/",
    ]
}
