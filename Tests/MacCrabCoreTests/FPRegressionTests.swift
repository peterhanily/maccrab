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
