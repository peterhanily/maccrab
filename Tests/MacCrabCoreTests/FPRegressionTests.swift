// FPRegressionTests.swift
//
// False-positive regression harness. Every test here encodes a known benign
// activity pattern that has produced alert noise in the field, and asserts
// that the full detection stack (RuleEngine + NoiseFilter) stays silent
// on that pattern.
//
// How to add a new case:
//   1. Observe an FP in the live DB (sqlite query the user ran).
//   2. Build an Event that reproduces the essential shape (file path,
//      process path, network tuple, etc.).
//   3. Add a @Test that calls `runAndAssertSilent(event:)`.
//
// Positive counter-tests in the "Sanity" suite at the bottom confirm that
// the same rules still fire when the benign gate doesn't apply — so a
// future over-broad filter can't silently turn the whole engine off.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Event Builders

/// Build a file event with FSEvents-shaped "no process attribution" — this
/// is the common shape for the non-root daemon fallback, and the shape
/// that triggered 34 alerts overnight in the 1.2.2 → 1.2.3 investigation.
private func fsEventsFileWrite(path: String, action: FileAction = .write) -> Event {
    let unknownProc = ProcessInfo(
        pid: 0, ppid: 0, rpid: 0,
        name: "unknown", executable: "",
        commandLine: "", args: [],
        workingDirectory: "/",
        userId: UInt32(getuid()), userName: NSUserName(),
        groupId: UInt32(getgid()),
        startTime: Date(),
        ancestors: [],
        isPlatformBinary: false
    )
    let file = FileInfo(path: path, action: action)
    return Event(
        eventCategory: .file,
        eventType: action == .delete ? .deletion : .creation,
        eventAction: action.rawValue,
        process: unknownProc,
        file: file,
        enrichments: ["source": "fsevents"]
    )
}

/// Build a process-creation event driven by an executable name (e.g. `ps`,
/// `lsof`) with a specific ancestor chain. Used for Gate 5 (interactive
/// admin CLI) regression tests.
func interactiveAdminExec(
    basename: String,
    ancestors: [ProcessAncestor]
) -> Event {
    let exe = "/usr/bin/\(basename)"
    let proc = ProcessInfo(
        pid: Int32.random(in: 1000...60000),
        ppid: ancestors.first?.pid ?? 1, rpid: 1,
        name: basename, executable: exe,
        commandLine: exe, args: [exe],
        workingDirectory: "/tmp",
        userId: 501, userName: "testuser", groupId: 20,
        startTime: Date(),
        codeSignature: nil,
        ancestors: ancestors,
        architecture: "arm64",
        isPlatformBinary: true
    )
    return Event(
        eventCategory: .process,
        eventType: .start,
        eventAction: "exec",
        process: proc
    )
}

/// Build a file event with full process attribution — the shape ES-mode
/// produces. Drives the positive counter-tests: same file path, but now
/// we know who wrote it, so the rules should fire if the content pattern
/// matches.
private func attributedFileWrite(
    path: String,
    processPath: String,
    processName: String? = nil,
    signer: SignerType? = nil
) -> Event {
    let codeSig: CodeSignatureInfo? = signer.map {
        CodeSignatureInfo(
            signerType: $0,
            teamId: nil, signingId: nil, authorities: [],
            flags: 0, isNotarized: false
        )
    }
    let name = processName ?? (processPath as NSString).lastPathComponent
    let proc = ProcessInfo(
        pid: Int32.random(in: 1000...60000),
        ppid: 1, rpid: 1,
        name: name, executable: processPath,
        commandLine: processPath, args: [processPath],
        workingDirectory: "/tmp",
        userId: 501, userName: "testuser", groupId: 20,
        startTime: Date(),
        codeSignature: codeSig,
        ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
        architecture: "arm64",
        isPlatformBinary: signer == .apple
    )
    return Event(
        eventCategory: .file,
        eventType: .creation,
        eventAction: "write",
        process: proc,
        file: FileInfo(path: path, action: .write)
    )
}

// MARK: - Harness

/// Compile all rules once per test run (cached by the shared lock) and
/// return a ready-to-query engine.
private func loadedEngine() async throws -> RuleEngine {
    ensureRulesCompiled()
    let engine = RuleEngine()
    _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
    return engine
}

/// Run `event` through the full detection stack (rule engine + noise
/// filter) and assert the filter left nothing behind. Accepts `.critical`
/// matches — those bypass the filter by design, and if one fires on
/// benign activity that's a separate issue worth knowing about.
private func runAndAssertSilent(
    event: Event,
    isWarmingUp: Bool = false,
    sourceLocation: SourceLocation = #_sourceLocation
) async throws {
    let engine = try await loadedEngine()
    var matches = await engine.evaluate(event)
    NoiseFilter.apply(&matches, event: event, isWarmingUp: isWarmingUp)
    let nonCritical = matches.filter { $0.severity != .critical }
    #expect(
        nonCritical.isEmpty,
        "Expected zero non-critical matches after noise filter, got: \(nonCritical.map(\.ruleName))",
        sourceLocation: sourceLocation
    )
}

/// Run through the stack and return all surviving matches — for
/// positive tests that need to assert a specific rule fires.
private func runAndCollect(
    event: Event,
    isWarmingUp: Bool = false
) async throws -> [RuleMatch] {
    let engine = try await loadedEngine()
    var matches = await engine.evaluate(event)
    NoiseFilter.apply(&matches, event: event, isWarmingUp: isWarmingUp)
    return matches
}

// MARK: - FSEvents without process attribution

@Suite("FP regression: FSEvents without process attribution")
struct FSEventsNoAttributionTests {

    @Test("Codex sentry session.json write does not fire unicode rule")
    func codexSentrySession() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/Codex/sentry/session.json"
        ))
    }

    @Test("Codex sentry scope_v3.json write does not fire")
    func codexSentryScope() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/Codex/sentry/scope_v3.json"
        ))
    }

    @Test("AddressBook metadata write does not fire contacts-DB rule")
    func addressBookMetadata() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/AddressBook/Metadata/.info"
        ))
    }

    @Test("Firefox prefs-1.js write does not fire bidi-unicode rule")
    func firefoxPrefs() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/Firefox/Profiles/abc.default-release/prefs-1.js"
        ))
    }

    @Test("Firefox AlternateServices.bin write does not fire cookie-DB rule")
    func firefoxAltServices() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/Firefox/Profiles/abc.default-release/AlternateServices.bin"
        ))
    }

    @Test("Firefox storage idb write does not fire")
    func firefoxIdbStorage() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/Firefox/Profiles/abc.default-release/storage/permanent/chrome/idb/2918063365.sqlite-wal"
        ))
    }

    @Test("MacCrab's own threat_intel cache write does not fire")
    func maccrabThreatIntel() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/MacCrab/threat_intel/feed_cache.json"
        ))
    }

    @Test("Firefox session-ping tmp write does not fire")
    func firefoxSessionPing() async throws {
        try await runAndAssertSilent(event: fsEventsFileWrite(
            path: "/Users/any/Library/Application Support/Firefox/Profiles/abc.default-release/datareporting/aborted-session-ping.tmp"
        ))
    }
}

// MARK: - Trusted browser / Electron helpers

@Suite("FP regression: trusted browser and Electron helpers")
struct TrustedBrowserHelperTests {

    @Test("Chrome helper reading its own cookie DB is silent")
    func chromeHelperCookies() async throws {
        let event = attributedFileWrite(
            path: "/Users/any/Library/Application Support/Google/Chrome/Default/Cookies",
            processPath: "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
            processName: "Google Chrome Helper",
            signer: .devId
        )
        try await runAndAssertSilent(event: event)
    }

    @Test("Brave helper reading its own Login Data is silent")
    func braveHelperLoginData() async throws {
        let event = attributedFileWrite(
            path: "/Users/any/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
            processPath: "/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper",
            processName: "Brave Browser Helper",
            signer: .devId
        )
        try await runAndAssertSilent(event: event)
    }

    @Test("VS Code helper writing an unusual source file is silent")
    func vscodeHelperSource() async throws {
        let event = attributedFileWrite(
            path: "/Users/any/project/weird_unicode_strings.js",
            processPath: "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer)",
            processName: "Code Helper (Renderer)",
            signer: .devId
        )
        try await runAndAssertSilent(event: event)
    }

    @Test("Slack helper is treated as trusted")
    func slackHelper() async throws {
        #expect(NoiseFilter.isTrustedBrowserHelper(
            path: "/Applications/Slack.app/Contents/Frameworks/Slack Helper.app/Contents/MacOS/Slack Helper"
        ))
    }

    @Test("Signed third-party app NOT under /Applications is not trusted")
    func unsignedThirdPartyNotTrusted() async throws {
        #expect(!NoiseFilter.isTrustedBrowserHelper(
            path: "/tmp/fake-browser/Chrome Helper"
        ))
        #expect(!NoiseFilter.isTrustedBrowserHelper(
            path: "/Users/attacker/Downloads/Fake Chrome.app/Contents/MacOS/Chrome"
        ))
    }
}

// MARK: - Warm-up window

@Suite("FP regression: startup warm-up window")
struct WarmupWindowTests {

    @Test("Non-critical match is suppressed during warm-up")
    func suppressedDuringWarmup() async throws {
        // Build a match that would fire on trojan-source bidi in a .py
        // written by an unsigned process. Outside warmup this WOULD alert.
        let event = attributedFileWrite(
            path: "/tmp/malicious.py",
            processPath: "/tmp/unsigned-attacker",
            processName: "attacker"
        )
        try await runAndAssertSilent(event: event, isWarmingUp: true)
    }
}

// MARK: - Sanity positive tests
//
// Every noise gate is a risk of over-suppression. These tests guard the
// other direction: if we break a filter in a way that drops legit alerts,
// at least one of these should fail loudly.

@Suite("Sanity: real threats still fire outside the gates")
struct SanityPositiveTests {

    @Test("Unsigned binary is NOT treated as trusted browser helper")
    func unsignedNotTrusted() async throws {
        #expect(!NoiseFilter.isTrustedBrowserHelper(
            path: "/tmp/evil-helper"
        ))
        #expect(!NoiseFilter.isTrustedBrowserHelper(
            path: "/Users/Shared/hidden.app/Contents/MacOS/hidden"
        ))
    }

    @Test("Critical match survives the warm-up gate")
    func criticalSurvivesWarmup() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.critical",
                ruleName: "Test Critical",
                severity: .critical,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = fsEventsFileWrite(path: "/etc/passwd")
        NoiseFilter.apply(&matches, event: event, isWarmingUp: true)
        #expect(matches.count == 1)
    }

    @Test("Critical match survives the unknown-process gate")
    func criticalSurvivesUnknownProc() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.critical",
                ruleName: "Test Critical",
                severity: .critical,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = fsEventsFileWrite(path: "/etc/passwd")
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1)
    }

    @Test("High match IS dropped by unknown-process gate")
    func highDroppedByUnknownProc() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.high",
                ruleName: "Test High",
                severity: .high,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = fsEventsFileWrite(path: "/etc/passwd")
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty)
    }

    @Test("High match IS dropped by trusted-browser gate")
    func highDroppedByTrustedBrowser() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.high",
                ruleName: "Test High",
                severity: .high,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/some/file.js",
            processPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            processName: "Google Chrome"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty)
    }

    @Test("High match with attributed unsigned process is NOT dropped")
    func attributedUnsignedSurvives() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.high",
                ruleName: "Test High",
                severity: .high,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/tmp/payload.sh",
            processPath: "/tmp/dropper",
            processName: "dropper"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "High match on attributed non-trusted process must survive all three gates")
    }
}

// MARK: - MacCrab self-allowlist (v1.3.8)

/// v1.3.7 users saw their own install fire tamper-detection, EDR-remote-
/// session, and TCC-rate-manipulation alerts against MacCrab itself.
/// These tests encode every known self-triggering path so future rule
/// changes can't regress the self-allowlist.
@Suite("FP regression: MacCrab self-allowlist")
struct MacCrabSelfTests {

    @Test("Tamper detection on /Library/Application Support/MacCrab/ is suppressed")
    func tamperOnOwnRulesDir() async throws {
        var matches = [
            RuleMatch(
                ruleId: "maccrab.self-defense.rules-dir-modified",
                ruleName: "MacCrab Tamper Detection: Rules Modified",
                severity: .high,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/Library/Application Support/MacCrab/compiled_rules/execution/shell_spawned_by_browser.json",
            processPath: "/opt/homebrew/bin/brew",
            processName: "brew"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "Homebrew cask postflight updating our own rules must not fire tamper detection")
    }

    @Test("Process-based rule on com.maccrab.agent is suppressed")
    func alertOnOwnSysext() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.some-rule",
                ruleName: "Some Rule",
                severity: .medium,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/tmp/out.log",
            processPath: "/Library/SystemExtensions/ABCD/com.maccrab.agent.systemextension/Contents/MacOS/com.maccrab.agent",
            processName: "com.maccrab.agent"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "Events from our own sysext process must not fire rules on themselves")
    }

    @Test("Process-based rule on MacCrab.app is suppressed")
    func alertOnOwnApp() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.tcc-rate",
                ruleName: "Multiple TCC Permissions Granted Rapidly",
                severity: .medium,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/Library/Application Support/com.apple.TCC/TCC.db",
            processPath: "/Applications/MacCrab.app/Contents/MacOS/MacCrab",
            processName: "MacCrab"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "User granting FDA to MacCrab must not fire TCC-manipulation rules")
    }

    @Test("CRITICAL match on MacCrab self still survives")
    func criticalOnSelfStillFires() async throws {
        // If a real integrity compromise hits our own binaries, we MUST
        // still alert. The self-allowlist is scoped to non-critical only.
        var matches = [
            RuleMatch(
                ruleId: "test.hash-mismatch",
                ruleName: "MacCrab Binary Integrity Mismatch",
                severity: .critical,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/Applications/MacCrab.app/Contents/MacOS/MacCrab",
            processPath: "/Applications/MacCrab.app/Contents/MacOS/MacCrab",
            processName: "MacCrab"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "Critical self-integrity alerts must survive the self-allowlist")
    }

    @Test("Events on non-MacCrab paths still fire normally")
    func unrelatedPathStillFires() async throws {
        var matches = [
            RuleMatch(
                ruleId: "test.some-rule",
                ruleName: "Some Rule",
                severity: .high,
                description: "",
                mitreTechniques: [],
                tags: []
            )
        ]
        let event = attributedFileWrite(
            path: "/tmp/something",
            processPath: "/usr/local/bin/curl",
            processName: "curl"
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "Events on non-MacCrab paths/processes must be unaffected by the self-allowlist")
    }
}

// MARK: - Interactive admin CLI gate (v1.4)

/// Gate 5 suppresses non-critical matches on admin CLI tools whose
/// ancestor chain includes a desktop terminal emulator. These tests lock
/// the behaviour so a future refactor can't accidentally start alerting
/// every time a developer runs `ps` at a Terminal prompt.
@Suite("FP regression: interactive admin CLI gate")
struct InteractiveAdminGateTests {

    private func terminalAncestor(_ path: String = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal") -> ProcessAncestor {
        ProcessAncestor(pid: 800, executable: path, name: (path as NSString).lastPathComponent)
    }

    @Test("ps launched from Terminal via zsh suppresses non-critical matches")
    func psFromTerminalSuppressed() async throws {
        var matches = [
            RuleMatch(ruleId: "d1a2b3c4-0123", ruleName: "Process Listing by Unsigned Process",
                      severity: .low, description: "", mitreTechniques: [], tags: [])
        ]
        let event = interactiveAdminExec(
            basename: "ps",
            ancestors: [
                ProcessAncestor(pid: 900, executable: "/bin/zsh", name: "zsh"),
                terminalAncestor(),
            ]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "ps launched from Terminal should not fire recon alerts")
    }

    @Test("lsof via tmux under iTerm is still treated as interactive")
    func lsofViaTmuxSuppressed() async throws {
        var matches = [
            RuleMatch(ruleId: "d1a2b3c4-0252", ruleName: "lsof network enumeration",
                      severity: .medium, description: "", mitreTechniques: [], tags: [])
        ]
        let event = interactiveAdminExec(
            basename: "lsof",
            ancestors: [
                ProcessAncestor(pid: 950, executable: "/bin/zsh", name: "zsh"),
                ProcessAncestor(pid: 940, executable: "/opt/homebrew/bin/tmux", name: "tmux"),
                terminalAncestor("/Applications/iTerm.app/Contents/MacOS/iTerm2"),
            ]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "lsof reached via tmux multiplexer under iTerm must still be treated as interactive")
    }

    @Test("Critical ps from launchd still fires through Gate 7")
    func psFromLaunchdStillFires() async throws {
        // v1.6.8: Gate 7 now suppresses all non-critical matches on
        // Apple platform binaries (/bin/ps included) regardless of
        // ancestor chain. The "ps spawned from launchd" scenario that
        // this test originally documented is now suppressed at non-
        // critical severity. A critical-severity rule must still fire
        // so a genuine daemon-compromise pattern isn't hidden.
        var matches = [
            RuleMatch(ruleId: "critical.daemon-exec",
                      ruleName: "Rare Daemon-Spawned Recon",
                      severity: .critical, description: "",
                      mitreTechniques: [], tags: [])
        ]
        let event = interactiveAdminExec(
            basename: "ps",
            ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "Critical-severity rules survive Gate 7 even on Apple platform binaries")
    }

    @Test("CRITICAL-severity admin CLI match survives interactive gate")
    func criticalAdminStillFires() async throws {
        var matches = [
            RuleMatch(ruleId: "critical.admin-misuse", ruleName: "Admin Misuse",
                      severity: .critical, description: "", mitreTechniques: [], tags: [])
        ]
        let event = interactiveAdminExec(
            basename: "csrutil",
            ancestors: [
                ProcessAncestor(pid: 900, executable: "/bin/zsh", name: "zsh"),
                terminalAncestor(),
            ]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "Critical-severity rules on admin CLI must still fire even from a terminal")
    }

    @Test("Non-admin-CLI, non-platform-binary processes are unaffected by Gate 5")
    func unrelatedProcessUnaffected() async throws {
        // v1.6.8: updated to use /opt/homebrew/bin/http which is NOT
        // a platform binary and NOT in the Gate 5 admin-CLI basename
        // list. Previously used /usr/bin/curl, but Gate 7 now
        // suppresses platform-binary paths — so the test no longer
        // isolated Gate 5's scope; it also had to dodge Gate 7.
        var matches = [
            RuleMatch(ruleId: "test.unrelated", ruleName: "Some Rule",
                      severity: .medium, description: "", mitreTechniques: [], tags: [])
        ]
        let proc = ProcessInfo(
            pid: 5555, ppid: 900, rpid: 1,
            name: "http", executable: "/opt/homebrew/bin/http",
            commandLine: "/opt/homebrew/bin/http", args: [],
            workingDirectory: "/tmp",
            userId: 501, userName: "testuser", groupId: 20,
            startTime: Date(),
            codeSignature: nil,
            ancestors: [
                ProcessAncestor(pid: 900, executable: "/bin/zsh", name: "zsh"),
                ProcessAncestor(pid: 800, executable: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", name: "Terminal"),
            ],
            architecture: "arm64",
            isPlatformBinary: false
        )
        let event = Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: proc)
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "Gate 5 only applies to admin-CLI basenames; http under Homebrew isn't one")
    }
}

// MARK: - Auto-updater ancestor gate (v1.6.5)

/// Gate 6 regression: the auto-updater ancestor walk. Introduced after
/// v1.6.4 shipped per-rule ParentImage filters for GoogleUpdater/Sparkle
/// that only caught direct parents — a test machine still produced MDM-
/// enrollment medium alerts when the chain was Chrome → GoogleUpdater →
/// launcher → GoogleUpdater → profiles (`profiles`'s immediate parent
/// was the second GoogleUpdater, but its *name* basename was mangled by
/// Sigma's |contains matching). The engine-level gate walks all
/// ancestors and drops non-critical matches regardless of chain depth.
@Suite("FP regression: auto-updater ancestor gate")
struct AutoUpdaterAncestorGateTests {

    private func execUnderAncestors(
        processPath: String,
        ancestors: [ProcessAncestor],
        signerType: SignerType? = .devId
    ) -> Event {
        let codeSig: CodeSignatureInfo? = signerType.map {
            CodeSignatureInfo(
                signerType: $0,
                teamId: "EQHXZ8M8AV", signingId: nil, authorities: [],
                flags: 0, isNotarized: true
            )
        }
        let basename = (processPath as NSString).lastPathComponent
        let proc = ProcessInfo(
            pid: Int32.random(in: 1000...60000),
            ppid: ancestors.first?.pid ?? 1, rpid: 1,
            name: basename, executable: processPath,
            commandLine: "\(processPath) status", args: [processPath, "status"],
            workingDirectory: "/",
            userId: 501, userName: "phanily", groupId: 20,
            startTime: Date(),
            codeSignature: codeSig,
            ancestors: ancestors,
            architecture: "arm64",
            isPlatformBinary: false
        )
        return Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: proc
        )
    }

    @Test("GoogleUpdater as subject process suppresses non-critical matches")
    func googleUpdaterSubjectSuppressed() async throws {
        var matches = [
            RuleMatch(ruleId: "d1a2b3c4-0410", ruleName: "TCC Bypass via Process Injection",
                      severity: .high, description: "", mitreTechniques: [], tags: []),
            RuleMatch(ruleId: "d1a2b3c4-0255", ruleName: "MDM Enrollment Status Check",
                      severity: .medium, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execUnderAncestors(
            processPath: "/Users/phanily/Library/Application Support/Google/GoogleUpdater/148.0.7730.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
            ancestors: [
                ProcessAncestor(pid: 600, executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", name: "Google Chrome"),
            ]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "GoogleUpdater running as the subject process must suppress all non-critical rule matches")
    }

    @Test("profiles under deep GoogleUpdater chain is suppressed")
    func profilesUnderDeepUpdaterChainSuppressed() async throws {
        // Exact chain from user's test system: Chrome → GoogleUpdater →
        // launcher → GoogleUpdater → profiles. Per-rule ParentImage
        // filters only catch the immediate parent; Gate 6 must catch
        // this regardless.
        var matches = [
            RuleMatch(ruleId: "d1a2b3c4-0255", ruleName: "MDM Enrollment Status Check",
                      severity: .medium, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execUnderAncestors(
            processPath: "/usr/bin/profiles",
            ancestors: [
                // Immediate parent — second GoogleUpdater invocation.
                ProcessAncestor(
                    pid: 7003,
                    executable: "/Users/phanily/Library/Application Support/Google/GoogleUpdater/148.0.7730.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
                    name: "GoogleUpdater"
                ),
                ProcessAncestor(
                    pid: 7002,
                    executable: "/Users/phanily/Library/Application Support/Google/GoogleUpdater/148.0.7730.0/GoogleUpdater.app/Contents/Helpers/launcher",
                    name: "launcher"
                ),
                ProcessAncestor(
                    pid: 7001,
                    executable: "/Users/phanily/Library/Application Support/Google/GoogleUpdater/148.0.7730.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
                    name: "GoogleUpdater"
                ),
                ProcessAncestor(pid: 600, executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", name: "Google Chrome"),
            ],
            signerType: .apple  // profiles itself is Apple
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "profiles spawned inside the GoogleUpdater subprocess tree must be suppressed by ancestor walk")
    }

    @Test("Sparkle Autoupdate ancestor suppresses matches on child tools")
    func sparkleAutoupdateAncestorSuppressed() async throws {
        var matches = [
            RuleMatch(ruleId: "d1a2b3c4-0023", ruleName: "Hidden File Created in User Directory",
                      severity: .low, description: "", mitreTechniques: [], tags: []),
            RuleMatch(ruleId: "d1a2b3c4-0255", ruleName: "MDM Enrollment Status Check",
                      severity: .medium, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execUnderAncestors(
            processPath: "/usr/bin/xattr",
            ancestors: [
                ProcessAncestor(
                    pid: 8100,
                    executable: "/Users/phanily/Library/Caches/com.maccrab.app/org.sparkle-project.Sparkle/Installation/AbCd/EfGh/MacCrab.app/Contents/Frameworks/Sparkle.framework/Versions/B/Autoupdate",
                    name: "Autoupdate"
                ),
                ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd"),
            ]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "Sparkle's Autoupdate binary as ancestor must suppress child-process rule matches")
    }

    @Test("Critical matches under GoogleUpdater still fire (counter-test)")
    func criticalUnderUpdaterStillFires() async throws {
        // Counter-test: Gate 6 must not be a universal kill-switch.
        // Ransomware deployed via a compromised updater tree should
        // still alert at critical.
        var matches = [
            RuleMatch(ruleId: "critical.ransomware_note", ruleName: "Ransomware Note Created",
                      severity: .critical, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execUnderAncestors(
            processPath: "/Users/phanily/Library/Application Support/Google/GoogleUpdater/148.0.7730.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
            ancestors: []
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "Critical-severity matches must still fire under auto-updater ancestor gate")
    }

    @Test("Non-updater ancestor chain does NOT trigger gate (counter-test)")
    func unrelatedAncestorNotSuppressed() async throws {
        // Counter-test: proves gate only applies to known auto-updaters.
        // A third-party utility with Chrome as parent must still be
        // capable of triggering rules.
        var matches = [
            RuleMatch(ruleId: "d1a2b3c4-0410", ruleName: "TCC Bypass via Process Injection",
                      severity: .high, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execUnderAncestors(
            processPath: "/tmp/unknown_tool",
            ancestors: [
                ProcessAncestor(pid: 600, executable: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", name: "Google Chrome"),
            ]
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1,
                "An unknown tool spawned from Chrome (not an auto-updater) must not be silenced by Gate 6")
    }

    @Test("isAutoUpdaterOrAncestor exposes direct API for campaign detector reuse")
    func publicHelperContract() async {
        let updaterEvent = execUnderAncestors(
            processPath: "/Users/x/Library/Application Support/Google/GoogleUpdater/148.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
            ancestors: []
        )
        #expect(NoiseFilter.isAutoUpdaterOrAncestor(event: updaterEvent))

        let benignEvent = execUnderAncestors(
            processPath: "/usr/bin/whoami",
            ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")]
        )
        #expect(!NoiseFilter.isAutoUpdaterOrAncestor(event: benignEvent))
    }
}

// MARK: - Apple platform binary gate (v1.6.8)

/// Gate 7 regression: the ultimate FP backstop for `/bin/ps`,
/// `/usr/bin/defaults`, `/usr/bin/csrutil`, `/usr/bin/sw_vers`, and
/// every other Apple-shipped platform binary. Field data across
/// v1.6.2-v1.6.7 showed the same LOW-severity enumeration rules
/// firing on these over and over — filter_system_path was added at
/// the rule level in v1.6.5, but enrichment races and stale-rule-
/// cache scenarios kept letting them through. Gate 7 catches them
/// at the engine level regardless of rule filters.
@Suite("FP regression: Apple platform binary gate")
struct ApplePlatformBinaryGateTests {

    private func execWithSigner(
        path: String,
        signerType: SignerType?,
        isPlatformBinary: Bool
    ) -> Event {
        let codeSig: CodeSignatureInfo? = signerType.map {
            CodeSignatureInfo(
                signerType: $0, teamId: nil, signingId: nil,
                authorities: [], flags: 0, isNotarized: false
            )
        }
        let proc = ProcessInfo(
            pid: 5000, ppid: 4000, rpid: 1,
            name: (path as NSString).lastPathComponent,
            executable: path,
            commandLine: path, args: [path],
            workingDirectory: "/",
            userId: 501, userName: "testuser", groupId: 20,
            startTime: Date(),
            codeSignature: codeSig,
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: isPlatformBinary
        )
        return Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    @Test("/bin/ps with isPlatformBinary=true suppresses non-critical")
    func psPlatformBinarySuppressed() {
        var matches = [
            RuleMatch(ruleId: "rule.ps", ruleName: "Process Listing",
                      severity: .low, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execWithSigner(
            path: "/bin/ps", signerType: nil, isPlatformBinary: true
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty)
    }

    @Test("/usr/bin/defaults anchored only by path still suppressed")
    func defaultsByPathAloneSuppressed() {
        // No platform-binary flag, no code signature — just the path.
        // This is the enrichment-race case we actually saw in the field.
        var matches = [
            RuleMatch(ruleId: "rule.def", ruleName: "Defaults Read Sensitive",
                      severity: .low, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execWithSigner(
            path: "/usr/bin/defaults", signerType: nil, isPlatformBinary: false
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "SIP-protected path must suppress even when enrichment hasn't populated signer info")
    }

    @Test("/usr/bin/csrutil and /usr/bin/sw_vers are suppressed")
    func csrutilAndSwVersSuppressed() {
        for path in ["/usr/bin/csrutil", "/usr/bin/sw_vers", "/usr/sbin/system_profiler"] {
            var matches = [
                RuleMatch(ruleId: "r", ruleName: "R", severity: .low,
                          description: "", mitreTechniques: [], tags: [])
            ]
            let event = execWithSigner(path: path, signerType: nil, isPlatformBinary: false)
            NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
            #expect(matches.isEmpty, "\(path) must be suppressed by Gate 7")
        }
    }

    @Test("Apple-signed /Applications/Keynote.app binary is suppressed")
    func keynoteSuppressed() {
        var matches = [
            RuleMatch(ruleId: "c2.beacon", ruleName: "Regular C2 Beacon Pattern",
                      severity: .medium, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execWithSigner(
            path: "/Applications/Keynote.app/Contents/MacOS/Keynote",
            signerType: .apple, isPlatformBinary: false
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "Apple-signed /Applications/ app must be suppressed by Gate 7")
    }

    @Test("Critical match on /bin/ps STILL fires (counter-test)")
    func criticalSurvives() {
        var matches = [
            RuleMatch(ruleId: "critical.ransomware", ruleName: "Ransomware Note",
                      severity: .critical, description: "", mitreTechniques: [], tags: [])
        ]
        let event = execWithSigner(path: "/bin/ps", signerType: .apple, isPlatformBinary: true)
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1, "Gate 7 must not suppress critical severity")
    }

    @Test("Non-Apple binary at /tmp/evil is NOT suppressed (counter-test)")
    func nonApplePreserved() {
        var matches = [
            RuleMatch(ruleId: "rule.x", ruleName: "X", severity: .medium,
                      description: "", mitreTechniques: [], tags: [])
        ]
        let event = execWithSigner(
            path: "/tmp/evil", signerType: .unsigned, isPlatformBinary: false
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.count == 1, "Gate 7 must not sweep up non-Apple paths")
    }

    @Test("isAppleSystemBinary public API: all three signals work")
    func publicAPIContract() {
        let byPlatformFlag = execWithSigner(path: "/tmp/ps", signerType: nil, isPlatformBinary: true)
        #expect(NoiseFilter.isAppleSystemBinary(event: byPlatformFlag))

        let bySigner = execWithSigner(path: "/tmp/ps", signerType: .apple, isPlatformBinary: false)
        #expect(NoiseFilter.isAppleSystemBinary(event: bySigner))

        let byPath = execWithSigner(path: "/usr/bin/defaults", signerType: nil, isPlatformBinary: false)
        #expect(NoiseFilter.isAppleSystemBinary(event: byPath))

        let notApple = execWithSigner(path: "/tmp/evil", signerType: .unsigned, isPlatformBinary: false)
        #expect(!NoiseFilter.isAppleSystemBinary(event: notApple))
    }

    @Test("v1.6.9: networkserviceproxy sequence match passes through Gate 7 suppression")
    func sequenceMatchOnApplePlatformBinary() {
        // The regression that motivated the v1.6.9 NoiseFilter
        // re-layering: `credential_theft_exfil` is a SEQUENCE rule,
        // and sequence matches used to be appended AFTER
        // `NoiseFilter.apply` — so Gate 7 never got a chance to
        // suppress them. This tests that a sequence-rule-shaped
        // match on `/usr/libexec/networkserviceproxy` now gets
        // dropped by Gate 7 when `apply` runs against all three
        // detection layers.
        var matches = [
            RuleMatch(ruleId: "e1f2a3b4-0009-4000-b000-000000000009",
                      ruleName: "Credential File Access Followed by Network Upload",
                      severity: .high, description: "",
                      mitreTechniques: ["attack.t1555", "attack.t1041"],
                      tags: ["attack.credential_access", "attack.exfiltration"])
        ]
        let event = execWithSigner(
            path: "/usr/libexec/networkserviceproxy",
            signerType: .apple, isPlatformBinary: true
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty,
                "High-severity sequence match on networkserviceproxy must be suppressed by Gate 7")
    }

    @Test("v1.6.9: allSatisfy(.critical) short-circuit preserves criticals")
    func criticalOnlyShortCircuit() {
        var matches = [
            RuleMatch(ruleId: "r1", ruleName: "R1", severity: .critical,
                      description: "", mitreTechniques: [], tags: []),
            RuleMatch(ruleId: "r2", ruleName: "R2", severity: .critical,
                      description: "", mitreTechniques: [], tags: []),
        ]
        // Event would normally trigger several gates, but every
        // match is already critical — apply() short-circuits.
        let event = execWithSigner(
            path: "/Applications/MacCrab.app/Contents/MacOS/MacCrab",
            signerType: .devId, isPlatformBinary: false
        )
        NoiseFilter.apply(&matches, event: event, isWarmingUp: true)
        #expect(matches.count == 2,
                "Critical-only match list must survive with no work")
    }

    @Test("v1.6.9: empty matches list short-circuits cleanly")
    func emptyMatchesShortCircuit() {
        var matches: [RuleMatch] = []
        let event = execWithSigner(path: "/usr/bin/ps", signerType: nil, isPlatformBinary: true)
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        #expect(matches.isEmpty)
    }
}
