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

    // MARK: - v1.19 (S1-T6) self-test noise suppression flag
    //
    // OFF by default (prod). When enabled, Gate 4c additionally drops the
    // self-inflicted noise that `make test` / `make test-*` generate: the
    // test runner reading MacCrab's OWN deployed honeyfiles and tripping the
    // credential/discovery rules that key on those decoy paths. This is dev-
    // harness noise, not threat signal. `honeyfile_accessed` itself is
    // `suppressible: false` (must-fire) and is therefore UNAFFECTED — it
    // bypasses every gate, including this one, so the deception detection it
    // provides is never weakened.
    //
    // Enable via the `MACCRAB_SUPPRESS_SELFTEST_NOISE=1` env var (the daemon
    // bootstrap sets it from `daemon_config.json → suppress_selftest_noise`),
    // or set `selfTestNoiseSuppressionEnabled` directly from a test. Read once
    // from the environment at first access; the explicit setter overrides it.
    nonisolated(unsafe) private static var _selfTestNoiseFlag: Bool? = nil

    /// Whether Gate 4c's self-test honeyfile/runner suppression is active.
    /// Defaults to the `MACCRAB_SUPPRESS_SELFTEST_NOISE` env var (off in prod).
    public static var selfTestNoiseSuppressionEnabled: Bool {
        get {
            if let v = _selfTestNoiseFlag { return v }
            let v = Foundation.ProcessInfo.processInfo
                .environment["MACCRAB_SUPPRESS_SELFTEST_NOISE"] == "1"
            _selfTestNoiseFlag = v
            return v
        }
        set { _selfTestNoiseFlag = newValue }
    }

    /// Swift test-runner process names that drive the self-inflicted honeyfile
    /// noise during `make test`. Scoped narrowly to the toolchain test harness
    /// — NOT the general dev-tool set — so enabling the flag can't hide a real
    /// threat masquerading as an unrelated binary.
    static let selfTestRunnerProcessNames: Set<String> = [
        "swiftpm-testing-helper",
        "xctest",
        "MacCrabPackageTests.xctest",
    ]

    /// True when the event's subject is a MacCrab self-test runner accessing a
    /// deployed honeyfile. Gated behind `selfTestNoiseSuppressionEnabled`. The
    /// honeyfile is identified by the `IsHoneyfile` enrichment (set by
    /// EventEnricher when the path matches a MacCrab-deployed decoy — these live
    /// at realistic credential paths like `~/.aws/credentials.bak`, NOT under
    /// the support dir). Scoping is by the test-runner PROCESS NAME plus the
    /// honeyfile marker: a REAL intruder tripping the decoy has a different
    /// process name and is NOT swept in. Off in prod (the flag default).
    static func isSelfTestHoneyfileAccess(event: Event) -> Bool {
        guard selfTestNoiseSuppressionEnabled else { return false }
        guard selfTestRunnerProcessNames.contains(event.process.name) else { return false }
        return event.enrichments["IsHoneyfile"] == "true"
    }

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

        // v1.19: trust-aware must-fire. The subject is "trusted" when it is an
        // Apple platform binary OR a notarized-DevID / first-party signer. A
        // critical match is must-fire (bypasses every gate) only when the subject
        // is NOT trusted — closing the structural critical-always-bypass that let
        // a trusted-signer critical-rated NOISE match defeat Gates 7/8. Explicit
        // `suppressible: false` rules always survive regardless of trust. Computed
        // once (the gates re-use the same `trustedSubject` value).
        let trustedSubject = isAppleSystemBinary(event: event) || isTrustedSigner(event: event)

        // Fast path: the gates drop SUPPRESSIBLE matches and keep must-fire ones.
        // If every remaining match is must-fire, there is nothing for any gate to
        // drop; skip them (and their ancestor walks) entirely.
        if matches.allSatisfy({ Self.isMustFire($0, trustedSubject: trustedSubject) }) { return }

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
            // EXCEPTION — LOLBin / C2 execution. Shells and interpreters
            // (/bin/bash, /usr/bin/curl, python3, osascript) ARE Apple platform
            // binaries, so a blanket drop here silently kills the entire single-
            // event execution/C2 class that detects a MALICIOUS pattern in the
            // subject's OWN commandline (curl|bash, do-shell-script, reverse
            // shells). Trust the subject's BEHAVIOUR, not its Apple path:
            // execution/C2 matches survive regardless of `suppressible` (mirrors
            // the Gate-8 credential-theft carve-out). Non-execution noise (a
            // discovery/info rule on an Apple binary) is still dropped.
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) && !isExecutionMatch($0) }
            if matches.isEmpty { return }
        }

        // Gate 1 — unattributable event. FSEvents fires file events
        // without a process; rules with `Image|contains` filters
        // fail open in that case. Dropping non-critical matches
        // means we never alert on activity we cannot triage.
        if event.process.name == "unknown" || event.process.executable.isEmpty {
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
            if matches.isEmpty { return }
        }

        // Gate 2 — startup warm-up window. Inventory scans complete
        // in the first 60s and produce a one-shot burst that isn't
        // live-threat signal. Critical still fires.
        if isWarmingUp {
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
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
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
            if matches.isEmpty { return }
        }

        // Gate 4c — self-test honeyfile noise (v1.19, S1-T6). The make-test
        // runner reading MacCrab's OWN deployed honeyfiles trips the credential/
        // discovery rules that key on those decoy paths — dev-harness noise, not
        // signal. Flag-gated (off in prod) so prod detection is untouched.
        // `honeyfile_accessed` is must-fire (`suppressible: false`) and survives
        // this drop, so the deception detection itself is never weakened.
        if isSelfTestHoneyfileAccess(event: event) {
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
            if matches.isEmpty { return }
        }

        // Gate 3 — trusted browser / Electron helper. Chromium apps
        // spawn large helper trees that fire individual Sigma rules
        // in isolation. Single bundle-prefix short-circuit.
        if isTrustedBrowserHelper(path: event.process.executable) {
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
            if matches.isEmpty { return }
        }

        // Gate 5 — interactive admin CLI from a terminal parent. ps,
        // top, defaults, dscl, etc. fired from Terminal→zsh→ps.
        // Short-circuits on basename check so non-admin-CLI subjects
        // exit before the ancestor walk.
        if isInteractiveAdminCommand(event: event) {
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
            if matches.isEmpty { return }
        }

        // Gate 6 — auto-updater process tree. GoogleUpdater, Sparkle's
        // Autoupdate, Microsoft AutoUpdate, softwareupdated, brew.
        // Full ancestor walk so chains like Chrome → GoogleUpdater →
        // launcher → GoogleUpdater → profiles get caught regardless
        // of nesting depth.
        if isAutoUpdaterOrAncestor(event: event) {
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) }
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
            matches.removeAll { !Self.isMustFire($0, trustedSubject: trustedSubject) && !isCredentialTheftMatch($0) }
        }
    }

    /// Trust-aware must-fire test (v1.19). A match survives every gate when it
    /// explicitly declared `suppressible: false`, OR it is `.critical` AND the
    /// subject is NOT trusted (an unmarked critical on an untrusted/unknown
    /// subject is almost always real, so it still bypasses; a critical on a
    /// trusted/Apple subject is almost always mis-rated noise, so it becomes
    /// gate-able — Gates 7/8 then apply with their execution-/credential-theft
    /// carve-outs). Replaces the old `RuleMatch.isMustFire` that hard-bypassed
    /// every critical and structurally defeated the trusted-signer gate.
    static func isMustFire(_ match: RuleMatch, trustedSubject: Bool) -> Bool {
        if !match.suppressible { return true }
        if match.severity == .critical && !trustedSubject { return true }
        return false
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

    /// True when a match must survive a BROAD operator suppression scope: a
    /// CRITICAL execution/C2 or credential-theft detection. A general
    /// `.path`/`.host`/`.rule` allowlist ("trust this process/host") may quiet
    /// ordinary noise but must never silence an active C2 or credential-theft
    /// critical — the operator-foot-gun the v1.20 review flagged. Narrow,
    /// rule-specific entries (`.rulePath` / `.ruleHash`) remain honored for FP
    /// management, mirroring the rule-engine rule that a critical can't be
    /// muted by swiping it away. Consumed by `SuppressionManager.isSuppressed`.
    static func resistsBroadSuppression(_ match: RuleMatch) -> Bool {
        guard match.severity >= .critical else { return false }
        return isExecutionMatch(match) || isCredentialTheftMatch(match)
    }

    /// Execution / C2 ATT&CK techniques whose matches survive the Gate-7
    /// Apple-platform-binary suppressor. These rules fire on a malicious pattern
    /// in the SUBJECT's own commandline (a LOLBin abuse of an Apple-shipped
    /// interpreter), so the subject being `/bin/bash` is exactly what they detect
    /// — trusting the Apple path would defeat them. Prefix match catches
    /// sub-techniques (e.g. `attack.t1059.004` Unix Shell).
    static let executionTechniquePrefixes: [String] = [
        "attack.t1059",   // Command and Scripting Interpreter (shell/python/osascript/jxa)
        "attack.t1105",   // Ingress Tool Transfer (curl|bash download-and-execute)
        "attack.t1095",   // Non-Application Layer Protocol (reverse shell, /dev/tcp)
        "attack.t1071",   // Application Layer Protocol (C2 over http/dns)
        "attack.t1572",   // Protocol Tunneling (ngrok, ssh -R)
    ]

    /// Execution/C2-tagged rules temporarily held back from surviving Gate 7 on
    /// an Apple interpreter because their own filters were too loose (flooded on
    /// benign `npm install` postinstall scripts, every PKG install, or generic
    /// help text). The four original entries — package_manager_downloads_and_
    /// executes, npm_postinstall_downloads_binary, installer_pkg_script_execution,
    /// mcp_server_tool_poisoning — were re-tightened (off-canonical-source +
    /// install-context + structured-marker gating) so they now re-arm safely.
    /// Kept as the mechanism for any future deferral.
    static let gate7NonExemptRuleIds: Set<String> = []

    /// True when a match should SURVIVE the Gate-7 Apple-platform-binary
    /// suppressor: an execution/C2 LOLBin detection (the curl|bash hole) that is
    /// (a) at least `.medium` — a LOW-severity exec indicator is too weak to
    /// override the trust gate (mirrors the must-fire floor), and (b) not on the
    /// FP-prone deferral list above.
    static func isExecutionMatch(_ match: RuleMatch) -> Bool {
        guard match.severity >= .medium else { return false }
        guard !gate7NonExemptRuleIds.contains(match.ruleId) else { return false }
        return match.mitreTechniques.contains { tech in
            let t = tech.lowercased()
            return executionTechniquePrefixes.contains { t.hasPrefix($0) }
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
        // First-party (MacCrab) binaries are self-trusted by team id even when
        // ad-hoc-signed (dev builds) — SelfDefense covers first-party tamper.
        if sig.teamId == macCrabTeamId { return true }
        // v1.19 (S1-T3): a third-party signer only earns trust-to-downgrade-a-
        // critical when it is a NOTARIZED Developer-ID binary that is NOT ad-hoc.
        // `isNotarized` is derived from SecStaticCodeCheckValidity against the
        // "notarized" requirement, which performs CERTIFICATE-REVOCATION checking
        // — so a REVOKED Developer-ID cert (the AMOS/Banshee post-takedown vector)
        // yields isNotarized == false and is NOT trusted here. (And the revoked-
        // cert event itself fires must-fire via developer_cert_revoked.) Bare
        // valid-DevID-without-notarization no longer suffices.
        if sig.signerType == .devId && sig.isNotarized && sig.isAdhocSigned != true {
            return true
        }
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
