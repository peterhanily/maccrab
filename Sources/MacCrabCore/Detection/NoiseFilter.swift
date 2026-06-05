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
        // Short-circuit: nothing to filter. Saves 7 gate checks on
        // every event whose rule engine produced zero matches — which
        // is the overwhelming majority of events on a healthy system.
        guard !matches.isEmpty else { return }

        // Fast path: the gates drop SUPPRESSIBLE matches and keep must-fire ones.
        // A match is must-fire when it declared `suppressible: false` OR is
        // `.critical` (see RuleMatch.isMustFire). So if every remaining match is
        // must-fire, there is nothing for any gate to drop; skip them (and their
        // ancestor walks) entirely.
        // (v1.18 decoupled the explicit `suppressible` flag from severity so a
        // mis-rated-critical SINGLE-EVENT rule is not a blanket bypass; the
        // `.critical` clause is retained as the must-fire floor for the
        // Sequence/Baseline/behavior streams that do not yet carry the flag, so
        // a completed critical kill chain is never silently suppressed.)
        if matches.allSatisfy({ $0.isMustFire }) { return }

        // Gate ordering rationale (v1.6.9 reorder):
        //
        // Gates are ordered cheapest-first AND by expected hit rate
        // on a healthy macOS system. The cost of each gate roughly:
        //
        //   Gate 7  bool + enum cmp  → O(1)       [60-80% of events hit]
        //   Gate 1  string cmp       → O(1)       [<1% hit]
        //   Gate 2  bool             → O(1)       [first 60s only]
        //   Gate 4  basename + path  → O(1)       [<5% hit]
        //   Gate 3  prefix scan 35   → O(35)      [~20% hit — browsers/Electron]
        //   Gate 5  basename + walk  → O(A)       [~10% hit — terminals]
        //   Gate 6  subject + walk   → O(A)       [<5% hit — updaters]
        //
        // Gate 7 first is the biggest win: most process events on a
        // healthy Mac are Apple platform binaries (launchd spawning
        // mdworker, syspolicyd, etc.). A single bool on process.
        // isPlatformBinary short-circuits the remaining 6 gates for
        // those cases. Pre-v1.6.9 gate order paid the O(A) ancestor
        // walks (Gates 5 + 6) on every event regardless.

        // Gate 7 — Apple platform binary. Hot: the majority of events
        // on a healthy Mac. See `isAppleSystemBinary` for signals.
        if isAppleSystemBinary(event: event) {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 1 — unattributable event. FSEvents fires file events
        // without a process; rules with `Image|contains` filters
        // fail open in that case. Dropping non-critical matches
        // means we never alert on activity we cannot triage.
        if event.process.name == "unknown" || event.process.executable.isEmpty {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 2 — startup warm-up window. Inventory scans complete
        // in the first 60s and produce a one-shot burst that isn't
        // live-threat signal. Critical still fires.
        if isWarmingUp {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 4a — events whose ACTOR is a MacCrab process: (rc.14)
        // forensic plugins running from MacCrabApp reading
        // ~/Library/Messages/chat.db, TCC.db, etc. (operator-initiated
        // scans, not credential-stealer behavior), plus our own sysext
        // XPC events and the daemon writing its own install dirs. Drop
        // ALL severities — the notification storm every time the operator
        // ran a kit was the rc.14 motivation, and genuine self-binary
        // compromise is caught by the SelfDefense subsystem (binary
        // integrity, signed-by-team-id), not by these event rules.
        if isMacCrabProcess(event: event) {
            matches.removeAll()
            return
        }

        // Gate 4b — a NON-MacCrab process touching a file under our
        // managed dirs (compiled_rules/, events.db). Benign churn — e.g.
        // a Homebrew cask postflight rewriting compiled rules — is noise,
        // so drop non-critical. But a CRITICAL match here is exactly the
        // self-tamper signal we must not swallow. (rc.17 fix: pre-this,
        // Gate 4 did a blanket removeAll() and silently dropped that
        // critical on any mixed-severity batch, since the critical-only
        // fast path above never fired.)
        if isMacCrabManagedFile(event: event) {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 3 — trusted browser / Electron helper. Chromium apps
        // spawn large helper trees that fire individual Sigma rules
        // in isolation. Single bundle-prefix short-circuit.
        if isTrustedBrowserHelper(path: event.process.executable) {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 5 — interactive admin CLI from a terminal parent. ps,
        // top, defaults, dscl, etc. fired from Terminal→zsh→ps.
        // Short-circuits on basename check so non-admin-CLI subjects
        // exit before the ancestor walk.
        if isInteractiveAdminCommand(event: event) {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 6 — auto-updater process tree. GoogleUpdater, Sparkle's
        // Autoupdate, Microsoft AutoUpdate, softwareupdated, brew.
        // Full ancestor walk so chains like Chrome → GoogleUpdater →
        // launcher → GoogleUpdater → profiles get caught regardless
        // of nesting depth.
        if isAutoUpdaterOrAncestor(event: event) {
            matches.removeAll { !$0.isMustFire }
            if matches.isEmpty { return }
        }

        // Gate 8 — trusted non-Apple signer (v1.18). The ~370 signer-negating
        // heuristic rules (notarization, LOLBin, masquerade, injection) flood on
        // legitimately-signed third-party dev tools and our own first-party
        // builds. Trust the SIGNED SUBJECT, not its caller (mirrors the Gate 7
        // split): drop suppressible matches when the subject is a NOTARIZED
        // Developer-ID binary or a MacCrab first-party (team 79S425CW99) binary.
        // Must-fire rules (revoked cert, known-bad hash, SIP/AMFI disable) are
        // `suppressible: false` and survive — that is the point of the decoupling.
        //
        // EXCEPTION — credential theft. A notarized Developer-ID binary reading
        // password stores / keychains / browser logins / wallets / private keys
        // is the AMOS / Banshee signed-stealer pattern; Gate 8 must NOT hide it.
        // Credential-theft matches survive here REGARDLESS of `suppressible`.
        // (Gate 7 still suppresses the same read by an APPLE platform binary —
        // securityd, etc. — so first-party credential access is not re-noised.)
        if isTrustedSigner(event: event) {
            matches.removeAll { !$0.isMustFire && !isCredentialTheftMatch($0) }
        }
    }

    /// Credential-theft ATT&CK techniques whose matches survive the Gate-8
    /// trusted-signer suppressor (prefix match catches sub-techniques like
    /// `attack.t1555.001`).
    static let credentialTheftTechniquePrefixes: [String] = [
        "attack.t1555",   // Credentials from Password Stores (keychain, browser logins, wallets)
        "attack.t1003",   // OS Credential Dumping (shadow hashes, securityd memory)
        "attack.t1552",   // Unsecured Credentials (private keys, cloud creds)
        "attack.t1539",   // Steal Web Session Cookie
    ]

    /// True when a match is a credential-theft detection — used to exempt it
    /// from the Gate-8 trusted-signer suppressor (the AMOS/Banshee hole).
    static func isCredentialTheftMatch(_ match: RuleMatch) -> Bool {
        match.mitreTechniques.contains { tech in
            let t = tech.lowercased()
            return credentialTheftTechniquePrefixes.contains { t.hasPrefix($0) }
        }
    }

    /// MacCrab's Apple Developer team identifier (first-party trust).
    public static let macCrabTeamId = "79S425CW99"

    /// True when the event's subject is a NOTARIZED Developer-ID binary or a
    /// MacCrab first-party binary. Subject-only (no ancestor walk) — we trust
    /// the signed binary, not whoever launched it. `isNotarized` warms from the
    /// NotarizationChecker enrichment on the same cadence the notarization rules
    /// fire, so the gate sees it when those heuristics fire.
    public static func isTrustedSigner(event: Event) -> Bool {
        guard let sig = event.process.codeSignature else { return false }
        if sig.teamId == macCrabTeamId { return true }
        if sig.signerType == .devId && sig.isNotarized { return true }
        return false
    }

    /// True when an event's subject is a MacCrab process, a MacCrab file,
    /// or a file inside a MacCrab managed directory. Public so rule-level
    /// allowlists can reuse the same definition. Composed of the two
    /// finer predicates the noise gates use directly — `isMacCrabProcess`
    /// (the ACTOR is us) and `isMacCrabManagedFile` (the FILE is under our
    /// dirs) — which Gate 4 deliberately treats differently (full drop vs
    /// drop-non-critical) so self-tamper criticals still alert.
    public static func isMacCrabSelf(event: Event) -> Bool {
        isMacCrabProcess(event: event) || isMacCrabManagedFile(event: event)
    }

    /// True when the event's ACTOR is one of MacCrab's own processes
    /// (app, sysext, legacy daemon, CLI, MCP server) — by process name or
    /// by executable path, including ad-hoc-signed dev builds.
    public static func isMacCrabProcess(event: Event) -> Bool {
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
        return false
    }

    /// True when the event's FILE subject is inside one of MacCrab's
    /// managed directories (system + user Application Support). Actor-
    /// agnostic by design: a non-MacCrab process writing here is a tamper
    /// candidate, which is why Gate 4b keeps .critical matches instead of
    /// dropping the whole batch.
    public static func isMacCrabManagedFile(event: Event) -> Bool {
        guard let filePath = event.file?.path else { return false }
        return filePath.hasPrefix("/Library/Application Support/MacCrab/") ||
               filePath.hasPrefix("\(NSHomeDirectory())/Library/Application Support/MacCrab/")
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
