// SequenceEngineFireTests.swift
// v1.18 — end-to-end fire tests for the SequenceEngine. Before this, the
// temporal tier had only a loadRules() count test (SequenceEngineTests);
// evaluate() was never driven with a multi-event sequence, so ordered-step
// completion, the time window, the partial-match LRU cap, and .processSame
// correlation could all silently regress to zero on a refactor. These tests
// drive the REAL engine with synthetic rules whose step predicates we fully
// control, plus a smoke load of the real compiled sequence rules.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SequenceEngine: end-to-end fires (v1.18)")
struct SequenceEngineFireTests {

    private func proc(_ exec: String, pid: Int32) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: 1,
            name: (exec as NSString).lastPathComponent,
            executable: exec, commandLine: exec, args: [exec],
            workingDirectory: "/tmp", userId: 501, userName: "t", groupId: 20,
            startTime: Date(), codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/sbin/launchd", name: "launchd")],
            architecture: "arm64", isPlatformBinary: false)
    }

    private func procEvent(_ exec: String, pid: Int32) -> Event {
        Event(eventCategory: .process, eventType: .start, eventAction: "exec",
              process: proc(exec, pid: pid))
    }

    /// download (`*/curl`) → execute (`/tmp/*`), ordered, .processSame.
    private func dlExecRule(
        id: String = "seq-fire-test",
        window: TimeInterval = 60,
        correlation: CorrelationType = .processSame
    ) -> SequenceRule {
        SequenceRule(
            id: id, title: "Download then Execute (test)", description: "test",
            level: .high, tags: ["attack.execution", "attack.t1059"],
            window: window, correlationType: correlation, ordered: true,
            steps: [
                SequenceStep(id: "download", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)],
                             condition: .allOf, afterStep: nil, processRelation: nil),
                SequenceStep(id: "execute", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .startswith, values: ["/tmp/"], negate: false)],
                             condition: .allOf, afterStep: "download", processRelation: nil),
            ],
            trigger: .allSteps, enabled: true)
    }

    @Test("ordered .processSame sequence fires on the final event")
    func fires() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule())
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 100))
        #expect(final.contains { $0.ruleId == "seq-fire-test" },
                "expected sequence completion, got \(final.map(\.ruleId))")
    }

    @Test(".processSame does not cross-correlate two different PIDs")
    func processSameNegative() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule())
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 200))
        #expect(!final.contains { $0.ruleId == "seq-fire-test" },
                "a different-PID execute must not complete the chain")
    }

    @Test("a step arriving after the window expires does not complete the sequence")
    func windowExpiry() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule(window: 0.1))
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        try await Task.sleep(nanoseconds: 300_000_000)   // 0.3 s > 0.1 s window
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 100))
        #expect(!final.contains { $0.ruleId == "seq-fire-test" },
                "an expired partial must not complete")
    }

    @Test("partial-match cap evicts oldest: an evicted chain cannot complete, a recent one can")
    func capEviction() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 20)
        try await engine.addRule(dlExecRule(window: 600))
        // 30 distinct first-steps → 30 partials, capped to 20 (oldest evicted).
        for pid in Int32(1)...Int32(30) {
            _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: pid))
        }
        let evicted  = await engine.evaluate(procEvent("/tmp/payload", pid: 1))    // oldest → evicted
        let retained = await engine.evaluate(procEvent("/tmp/payload", pid: 30))   // newest → kept
        #expect(!evicted.contains { $0.ruleId == "seq-fire-test" }, "oldest partial should have been evicted")
        #expect(retained.contains { $0.ruleId == "seq-fire-test" }, "recent partial should still complete")
    }

    @Test("BLOCKER-1: a must-fire (suppressible:false) sequence survives NoiseFilter on an Apple platform binary")
    func mustFireSequenceSurvivesNoiseFilter() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        let base = dlExecRule(id: "seq-mustfire")
        // Mirror a kill-chain YAML: critical + suppressible:false.
        try await engine.addRule(SequenceRule(
            id: "seq-mustfire", title: base.title, description: base.description,
            level: .critical, tags: base.tags, window: 60,
            correlationType: .processSame, ordered: true, steps: base.steps,
            trigger: .allSteps, enabled: true, suppressible: false))
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        var matches = await engine.evaluate(procEvent("/tmp/payload", pid: 100))
        // Plumbing: the completed match carries the rule's must-fire flag.
        #expect(matches.first { $0.ruleId == "seq-mustfire" }?.suppressible == false,
                "rule.suppressible:false must reach the RuleMatch")
        // End-to-end: NoiseFilter against /bin/dd (an Apple platform binary, the
        // ransomware impact-step shape) must NOT drop it. Pre-fix, the sequence
        // match defaulted suppressible:true and Gate 7 silently ate it.
        let dd = MacCrabCore.ProcessInfo(
            pid: 100, ppid: 1, rpid: 1, name: "dd", executable: "/bin/dd",
            commandLine: "/bin/dd", args: ["/bin/dd"], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: CodeSignatureInfo(signerType: .apple, teamId: nil, signingId: nil,
                authorities: [], flags: 0, isNotarized: false, issuerChain: nil,
                certHashes: nil, isAdhocSigned: nil, entitlements: nil),
            ancestors: [], architecture: "arm64", isPlatformBinary: true)
        NoiseFilter.apply(&matches, event: Event(eventCategory: .process, eventType: .start,
                                                 eventAction: "exec", process: dd), isWarmingUp: false)
        #expect(matches.contains { $0.ruleId == "seq-mustfire" },
                "a completed must-fire sequence must survive NoiseFilter on /bin/dd")
    }

    @Test("a default sequence (no suppressible key) yields a suppressible match")
    func defaultSequenceSuppressible() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule(id: "seq-default"))   // suppressible nil → true
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 101))
        let matches = await engine.evaluate(procEvent("/tmp/payload", pid: 101))
        #expect(matches.first { $0.ruleId == "seq-default" }?.suppressible == true)
    }

    @Test("EVERY compiled sequence rule loads — no silent decode drops")
    func realRulesLoad() async throws {
        // The silent-drop guard. SequenceEngine.loadRules catches per-file
        // decode errors and logs them, so a step using a token the Swift model
        // can't decode (e.g. an unknown ProcessRelation like same_tree/
        // same_process/any, or an unknown correlation) drops the WHOLE rule at
        // load while it still counts toward the compiled total — exactly how 7
        // of 41 sequence rules shipped dead before v1.18. Asserting
        // loaded == compiled-file-count converts that silent drop into a test
        // failure.
        ensureRulesCompiled()
        let seqDir = URL(fileURLWithPath: "/tmp/maccrab_v3/sequences")
        guard FileManager.default.fileExists(atPath: seqDir.path) else {
            Issue.record("compiled sequence dir missing — ensureRulesCompiled() did not produce it")
            return
        }
        let jsonCount = try FileManager.default
            .contentsOfDirectory(at: seqDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }.count
        #expect(jsonCount > 0, "no compiled sequence rules found")
        let engine = SequenceEngine(lineage: ProcessLineage())
        let loaded = try await engine.loadRules(from: seqDir)
        #expect(loaded == jsonCount,
                "sequence rules silently dropped at load: \(loaded)/\(jsonCount) — a step uses a token the engine can't decode (unknown ProcessRelation/correlation). See SequenceEngine load catch.")
    }

    // MARK: - #95: out-of-order (A2 cross-consumer) backfill

    /// procEvent with an explicit event timestamp so a test can decouple the
    /// event's REAL time (what ordering checks) from its delivery order (which
    /// `evaluate` call comes first).
    private func procEventAt(_ exec: String, pid: Int32, ts: Date) -> Event {
        Event(timestamp: ts, eventCategory: .process, eventType: .start,
              eventAction: "exec", process: proc(exec, pid: pid))
    }

    @Test("#95: ordered sequence still completes when the LATER step is DELIVERED before the initial step")
    func outOfOrderBackfillCompletes() async throws {
        // Models the A2 split: `download` (file consumer) lags, so `execute`
        // (priority consumer) reaches evaluate() first — but its REAL event time
        // is still after the download's. The backfill buffer + replay must
        // assemble the chain once the initial step finally seeds a partial.
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule(id: "seq-ooo", window: 600))
        let t0 = Date()
        let downloadTs = t0
        let executeTs = t0.addingTimeInterval(1)   // execute genuinely happened AFTER download

        // Delivery order reversed: the later step arrives first.
        let early = await engine.evaluate(procEventAt("/tmp/payload", pid: 100, ts: executeTs))
        #expect(!early.contains { $0.ruleId == "seq-ooo" },
                "the later step alone must not complete the sequence")

        let final = await engine.evaluate(procEventAt("/usr/bin/curl", pid: 100, ts: downloadTs))
        #expect(final.contains { $0.ruleId == "seq-ooo" },
                "out-of-order later step must be backfilled once the initial step seeds the partial")
    }

    @Test("#95: backfill preserves timestamp ordering — a later step whose REAL time precedes the initial step must NOT complete")
    func outOfOrderBackfillRespectsTimestamps() async throws {
        // Even under delivery inversion, ordered-mode semantics hold: if the
        // buffered step's real event time is BEFORE the initial step, it is not
        // a valid step[1] and the chain must stay open (no false completion).
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule(id: "seq-ooo-neg", window: 600))
        let t0 = Date()
        // execute's real time is BEFORE download's — invalid ordering.
        let early = await engine.evaluate(procEventAt("/tmp/payload", pid: 100, ts: t0))
        _ = early
        let final = await engine.evaluate(procEventAt("/usr/bin/curl", pid: 100, ts: t0.addingTimeInterval(1)))
        #expect(!final.contains { $0.ruleId == "seq-ooo-neg" },
                "a buffered step older than the initial step must not complete the ordered chain")
    }

    @Test("#95: a buffered later step older than the window is pruned and cannot complete")
    func outOfOrderBackfillWindowExpiry() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(dlExecRule(id: "seq-ooo-exp", window: 0.1))
        // Deliver the later step, then let the buffer window lapse before the
        // initial step arrives.
        _ = await engine.evaluate(procEvent("/tmp/payload", pid: 100))
        try await Task.sleep(nanoseconds: 300_000_000)   // 0.3 s > 0.1 s window
        let final = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        #expect(!final.contains { $0.ruleId == "seq-ooo-exp" },
                "an expired buffered step must have been pruned and cannot backfill")
    }

    @Test("REGRESSION (pre-GA #1): a process.lineage rule's `.any` step completes for an UNRELATED process")
    func processLineageAnyStepNotBlockedByLineageGate() async throws {
        // Mirrors archive_to_cloud_exfil.yml: ordered, correlation process.lineage,
        // whose `upload` step declares `.any` (the author's explicit "no process
        // constraint" — the upload tool is launched independently by the shell,
        // never in the archive process's ancestry). The #274 lineage gate must
        // NOT override that `.any`, or the HIGH bulk-exfil rule can never fire.
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(SequenceRule(
            id: "seq-lineage-any", title: "archive then upload (test)", description: "test",
            level: .high, tags: ["attack.exfiltration", "attack.t1567"],
            window: 60, correlationType: .processLineage, ordered: true,
            steps: [
                SequenceStep(id: "archive", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/tar"], negate: false)],
                             condition: .allOf, afterStep: nil, processRelation: nil),
                SequenceStep(id: "upload", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/rclone"], negate: false)],
                             condition: .allOf, afterStep: "archive",
                             processRelation: ProcessRelationSpec(relation: .any, relativeToStep: "archive")),
            ],
            trigger: .allSteps, enabled: true))
        _ = await engine.evaluate(procEvent("/usr/bin/tar", pid: 100))
        // rclone: a DIFFERENT, unrelated process (not in tar's ancestry) — the
        // two-process staging+upload pattern the rule targets.
        let final = await engine.evaluate(procEvent("/usr/bin/rclone", pid: 200))
        #expect(final.contains { $0.ruleId == "seq-lineage-any" },
                "a `.any` step under process.lineage must complete for an unrelated process")
    }

    // MARK: - Tier-A #8: pre-folded rule-constant parity

    /// Single-step, unordered, uncorrelated rule that fires the instant its one
    /// step's predicate matches (trigger .allSteps over one step). Lets a test
    /// assert predicate case-folding directly through `evaluate`.
    private func singleStepRule(
        id: String,
        modifier: PredicateModifier,
        values: [String]
    ) -> SequenceRule {
        SequenceRule(
            id: id, title: "single-step (test)", description: "test",
            level: .high, tags: ["attack.execution"],
            window: 60, correlationType: .none, ordered: false,
            steps: [
                SequenceStep(id: "only", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: modifier, values: values, negate: false)],
                             condition: .allOf, afterStep: nil, processRelation: nil),
            ],
            trigger: .allSteps, enabled: true)
    }

    @Test("Tier-A #8: mixed-case rule constant matches a mixed-case event value across all string modifiers")
    func preFoldedConstantParity() async throws {
        // Rule constants and the event value use DIFFERENT casings. Case-insensitive
        // matching (now via Predicate.lowercasedValues, folded once at rule LOAD)
        // must still match — byte-identical to the prior per-comparison
        // `$0.lowercased()`. One engine per case so no partial/correlation carries over.
        let execPath = "/Users/Alice/Downloads/PaYLoAd.App"

        let eqEngine = SequenceEngine(lineage: ProcessLineage())
        try await eqEngine.addRule(singleStepRule(id: "fold-equals", modifier: .equals,
                                                  values: ["/users/alice/downloads/payload.APP"]))
        let eq = await eqEngine.evaluate(procEvent(execPath, pid: 100))
        #expect(eq.contains { $0.ruleId == "fold-equals" }, "equals must fold both sides")

        let coEngine = SequenceEngine(lineage: ProcessLineage())
        try await coEngine.addRule(singleStepRule(id: "fold-contains", modifier: .contains,
                                                  values: ["DOWNLOADS/payLOAD"]))
        let co = await coEngine.evaluate(procEvent(execPath, pid: 101))
        #expect(co.contains { $0.ruleId == "fold-contains" }, "contains must fold both sides")

        let swEngine = SequenceEngine(lineage: ProcessLineage())
        try await swEngine.addRule(singleStepRule(id: "fold-starts", modifier: .startswith,
                                                  values: ["/USERS/alice/"]))
        let sw = await swEngine.evaluate(procEvent(execPath, pid: 102))
        #expect(sw.contains { $0.ruleId == "fold-starts" }, "startswith must fold both sides")

        let ewEngine = SequenceEngine(lineage: ProcessLineage())
        try await ewEngine.addRule(singleStepRule(id: "fold-ends", modifier: .endswith,
                                                  values: ["PAYLOAD.app"]))
        let ew = await ewEngine.evaluate(procEvent(execPath, pid: 103))
        #expect(ew.contains { $0.ruleId == "fold-ends" }, "endswith must fold both sides")
    }

    @Test("Tier-A #8: a distinct mixed-case constant still does NOT match after folding")
    func preFoldedConstantNegative() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(singleStepRule(id: "fold-neg", modifier: .equals,
                                                values: ["/some/OTHER/path"]))
        let r = await engine.evaluate(procEvent("/Users/Alice/Downloads/PaYLoAd.App", pid: 104))
        #expect(!r.contains { $0.ruleId == "fold-neg" }, "distinct paths must not match after folding")
    }
}
