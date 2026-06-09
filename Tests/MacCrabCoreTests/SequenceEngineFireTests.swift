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
}
