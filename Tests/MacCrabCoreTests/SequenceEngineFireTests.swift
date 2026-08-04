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

private actor SequenceEngineTestGate {
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func open() {
        guard !isOpen else { return }
        isOpen = true
        let pending = waiters
        waiters.removeAll()
        for waiter in pending { waiter.resume() }
    }
}

private actor SequenceEngineOrderRecorder {
    private var values: [Int] = []
    func append(_ value: Int) { values.append(value) }
    func snapshot() -> [Int] { values }
}

@Suite("SequenceEngine: end-to-end fires (v1.18)")
struct SequenceEngineFireTests {

    private func waitForLeaseState(
        _ engine: SequenceEngine,
        waiterCount: Int? = nil,
        held: Bool? = nil
    ) async -> Bool {
        for _ in 0..<10_000 {
            let diagnostics = await engine.mutationLeaseDiagnostics()
            if waiterCount.map({ diagnostics.waiterCount == $0 }) ?? true,
               held.map({ diagnostics.held == $0 }) ?? true {
                return true
            }
            await Task.yield()
        }
        return false
    }

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

    @Test("adversarial initializer values clamp before cap arithmetic")
    func initializerBoundsAreSafe() async throws {
        let negative = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: Int.min,
            sweepInterval: -.infinity
        )
        let negativeConfiguration = await negative.configurationDiagnostics()
        #expect(negativeConfiguration.maxPartialMatches == 1)
        #expect(negativeConfiguration.sweepInterval == 1)

        try await negative.addRule(dlExecRule(id: "seq-clamped-min", window: 600))
        _ = await negative.evaluate(procEvent("/usr/bin/curl", pid: 1))
        _ = await negative.evaluate(procEvent("/usr/bin/curl", pid: 2))
        #expect(await negative.activePartialMatchCount == 1)
        #expect(await negative.partialsEvictedTotal == 1)

        let maximum = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: Int.max,
            sweepInterval: .nan
        )
        let maximumConfiguration = await maximum.configurationDiagnostics()
        #expect(maximumConfiguration.maxPartialMatches > 0)
        #expect(maximumConfiguration.maxPartialMatches <= Int.max / 8)
        #expect(maximumConfiguration.sweepInterval == 1)

        // Before the constructor clamp, evaluate() overflowed while computing
        // Int.max * 8 / 10 even with an otherwise tiny partial pool.
        try await maximum.addRule(dlExecRule(id: "seq-clamped-max", window: 600))
        _ = await maximum.evaluate(procEvent("/usr/bin/curl", pid: 3))
        #expect(await maximum.activePartialMatchCount == 1)

        let zeroSweep = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: 10,
            sweepInterval: 0
        )
        let zeroSweepConfiguration = await zeroSweep.configurationDiagnostics()
        #expect(zeroSweepConfiguration.sweepInterval == 0)

        let infiniteSweep = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: 10,
            sweepInterval: .infinity
        )
        let infiniteSweepConfiguration = await infiniteSweep.configurationDiagnostics()
        #expect(infiniteSweepConfiguration.sweepInterval == 1)
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

    @Test("partial count stays exact through cap eviction and completion")
    func capEvictionAndCompletionKeepExactCount() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 3)
        try await engine.addRule(dlExecRule(id: "seq-count-cap", window: 600))

        for pid in Int32(1)...Int32(10) {
            _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: pid))
        }
        #expect(await engine.activePartialMatchCount == 3,
                "the source-of-truth pool must be capped at exactly three partials")
        #expect(await engine.partialsEvictedTotal == 7)

        let completed = await engine.evaluate(procEvent("/tmp/payload", pid: 10))
        #expect(completed.count == 1)
        #expect(await engine.activePartialMatchCount == 2,
                "completing one retained partial must remove exactly one")

        _ = await engine.evaluate(procEvent("/tmp/payload", pid: 1))
        #expect(await engine.activePartialMatchCount == 2,
                "an event for an already-evicted partial must not change the count")
    }

    @Test("equal-createdAt partials have distinct stable eviction identities")
    func equalCreatedAtPartialsUseDistinctEvictionIds() async throws {
        let engine = SequenceEngine(
            lineage: ProcessLineage(), maxPartialMatches: 10, sweepInterval: 0
        )
        try await engine.addRule(SequenceRule(
            id: "seq-equal-created", title: "equal timestamp identities", description: "test",
            level: .high, tags: ["attack.execution"], window: 600,
            correlationType: .none, ordered: false,
            steps: [
                // One event matches BOTH unconstrained steps. evaluate() captures
                // `now` once, so the two stored partials have identical createdAt.
                SequenceStep(
                    id: "a", logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .endswith,
                                           values: ["/dual-seed"], negate: false)]
                ),
                SequenceStep(
                    id: "b", logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .endswith,
                                           values: ["/dual-seed"], negate: false)]
                ),
                SequenceStep(
                    id: "finish", logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .endswith,
                                           values: ["/dual-finish"], negate: false)],
                    processRelation: ProcessRelationSpec(relation: .any, relativeToStep: "a")
                ),
            ],
            trigger: .steps(["a", "finish"]), enabled: true
        ))

        _ = await engine.evaluate(procEvent("/tmp/dual-seed", pid: 700))
        let collision = await engine.evictionQueueDiagnostics()
        #expect(await engine.activePartialMatchCount == 2)
        #expect(collision.referenceCount == 2)
        #expect(collision.uniqueCreationTimeCount == 1,
                "precondition: both partials must share one createdAt")
        #expect(collision.uniquePartialIdCount == 2,
                "timestamp collision must not collapse eviction identity")
        #expect(collision.referencesMatchLivePartials)

        let completed = await engine.evaluate(procEvent("/tmp/dual-finish", pid: 701))
        #expect(completed.count == 1)
        // sweepInterval=0: this no-match evaluation forces the live-ID compactor
        // to discard the completed sibling's stale reference.
        _ = await engine.evaluate(procEvent("/bin/noop", pid: 702))
        let compacted = await engine.evictionQueueDiagnostics()
        #expect(await engine.activePartialMatchCount == 1)
        #expect(compacted.referenceCount == 1)
        #expect(compacted.referencesMatchLivePartials)
    }

    @Test("completed partials cannot grow eviction metadata without bound")
    func completedSeedMetadataIsBounded() async throws {
        let engine = SequenceEngine(
            lineage: ProcessLineage(), maxPartialMatches: 4, sweepInterval: 3_600
        )
        try await engine.addRule(dlExecRule(id: "seq-metadata-bound", window: 600))

        for pid in Int32(1)...Int32(1_000) {
            _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: pid))
            let matches = await engine.evaluate(procEvent("/tmp/payload", pid: pid))
            #expect(matches.count == 1)
        }

        #expect(await engine.activePartialMatchCount == 0)
        let bounded = await engine.evictionQueueDiagnostics()
        #expect(bounded.referenceCount <= bounded.retentionLimit,
                "metadata refs \(bounded.referenceCount) exceeded bound \(bounded.retentionLimit)")
        #expect(bounded.referenceCount < 1_000,
                "metadata must not scale linearly with completed seed count")

        await engine.setEnabled("seq-metadata-bound", enabled: false)
        let purged = await engine.evictionQueueDiagnostics()
        #expect(purged.referenceCount == 0)
        #expect(purged.referencesMatchLivePartials)
    }

    @Test("partial count stays exact through expiration sweep and disable")
    func sweepAndDisableKeepExactCount() async throws {
        let engine = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: 100,
            sweepInterval: 0.01
        )
        try await engine.addRule(dlExecRule(id: "seq-count-housekeeping", window: 0.02))

        for pid in Int32(1)...Int32(4) {
            _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: pid))
        }
        #expect(await engine.activePartialMatchCount == 4)

        try await Task.sleep(nanoseconds: 100_000_000)
        _ = await engine.evaluate(procEvent("/bin/true", pid: 99))
        #expect(await engine.activePartialMatchCount == 0,
                "the expiration sweep must remove every expired stored partial")

        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        #expect(await engine.activePartialMatchCount == 1)
        await engine.setEnabled("seq-count-housekeeping", enabled: false)
        #expect(await engine.activePartialMatchCount == 0,
                "disabling a rule must remove its full partial bucket")
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

    private func fileEventAt(_ exec: String, pid: Int32, ts: Date) -> Event {
        Event(
            timestamp: ts,
            eventCategory: .file,
            eventType: .creation,
            eventAction: "write",
            process: proc(exec, pid: pid),
            file: FileInfo(path: "/tmp/sequence-overlap", action: .write)
        )
    }

    /// A file-lane seed followed by two priority-lane process steps. The middle
    /// step is deliberately process-agnostic; the final relation is selected by
    /// each test so delivery-order parity can challenge both fan-out and exact
    /// anchoring to the seed partial.
    private func overlappingLaneRule(
        id: String,
        finalRelation: ProcessRelation,
        finishSuffix: String = "/finish"
    ) -> SequenceRule {
        SequenceRule(
            id: id,
            title: "overlapping lane replay",
            description: "test",
            level: .high,
            tags: ["attack.execution"],
            window: 600,
            correlationType: .none,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "seed",
                    logsourceCategory: "file_event",
                    predicates: [Predicate(
                        field: "Image", modifier: .endswith,
                        values: ["/seed"], negate: false
                    )]
                ),
                SequenceStep(
                    id: "middle",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image", modifier: .endswith,
                        values: ["/middle"], negate: false
                    )],
                    afterStep: "seed",
                    processRelation: ProcessRelationSpec(
                        relation: .any,
                        relativeToStep: "seed"
                    )
                ),
                SequenceStep(
                    id: "finish",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image", modifier: .endswith,
                        values: [finishSuffix], negate: false
                    )],
                    afterStep: "middle",
                    processRelation: ProcessRelationSpec(
                        relation: finalRelation,
                        relativeToStep: "seed"
                    )
                ),
            ],
            trigger: .allSteps,
            enabled: true
        )
    }

    private func fireCount(
        _ events: [Event],
        rule: SequenceRule
    ) async throws -> (fires: Int, partials: Int) {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule)
        var fires = 0
        for event in events {
            fires += await engine.evaluate(event).filter { $0.ruleId == rule.id }.count
        }
        return (fires, await engine.activePartialMatchCount)
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
        #expect(await engine.activePartialMatchCount == 0,
                "backfill completion must consume its seeded partial exactly once")
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

    @Test("#95: replay fans retained later events across every overlapping partial")
    func outOfOrderReplayFansOutAcrossCompatiblePartials() async throws {
        let rule = overlappingLaneRule(id: "seq-ooo-fanout", finalRelation: .any)
        let t0 = Date()
        let a1 = fileEventAt("/tmp/seed", pid: 100, ts: t0)
        let a2 = fileEventAt("/tmp/seed", pid: 101, ts: t0.addingTimeInterval(0.5))
        let a3 = fileEventAt("/tmp/seed", pid: 102, ts: t0.addingTimeInterval(1))
        let middle = procEventAt("/tmp/middle", pid: 900, ts: t0.addingTimeInterval(2))
        let finish = procEventAt("/tmp/finish", pid: 901, ts: t0.addingTimeInterval(3))

        // Canonical delivery: all three seeds exist when middle/finish arrive, so
        // Phase 1 fans each event across all three partials and fires three times.
        let canonical = try await fireCount(
            [a1, a2, a3, middle, finish],
            rule: rule
        )
        #expect(canonical.fires == 3)
        #expect(canonical.partials == 0)

        // Adversarial split-lane delivery: finish arrives before middle, and the
        // third (file-lane) seed arrives last despite its earlier event timestamp.
        // Replaying finish into only one partial, consuming it after one advance,
        // or failing to retain middle after it advanced A1/A2 yields only one fire.
        let reordered = try await fireCount(
            [a1, a2, finish, middle, a3],
            rule: rule
        )
        #expect(reordered.fires == canonical.fires,
                "lane reordering must not shrink three compatible completions")
        #expect(reordered.partials == canonical.partials)
    }

    @Test("#95: a later event that already advanced one partial remains available to a delayed seed")
    func advancedLaterEventReplaysWithExactSeedRelation() async throws {
        let rule = overlappingLaneRule(id: "seq-ooo-anchor", finalRelation: .same)
        let t0 = Date()
        let a1 = fileEventAt("/tmp/seed", pid: 100, ts: t0)
        let a2 = fileEventAt("/tmp/seed", pid: 200, ts: t0.addingTimeInterval(1))
        let middle = procEventAt("/tmp/middle", pid: 900, ts: t0.addingTimeInterval(2))
        let finishForA2 = procEventAt(
            "/tmp/finish", pid: 200, ts: t0.addingTimeInterval(3)
        )

        let canonical = try await fireCount(
            [a1, a2, middle, finishForA2],
            rule: rule
        )
        #expect(canonical.fires == 1)
        #expect(canonical.partials == 1,
                "A1 remains open because finish is same-process with A2 only")

        // Middle first advances A1. A2 happened before middle but its file-lane
        // delivery is late. If middle is retained only when it advanced NO
        // partial, A2 never receives it and its same-process finish is lost.
        let reordered = try await fireCount(
            [a1, middle, a2, finishForA2],
            rule: rule
        )
        #expect(reordered.fires == canonical.fires,
                "the delayed A2 partial must replay middle and preserve its own PID anchor")
        #expect(reordered.partials == canonical.partials)
    }

    @Test("#95: replay cannot bind one retained event to two sequence steps")
    func retainedEventAdvancesEachPartialOnlyOnce() async throws {
        let rule = overlappingLaneRule(
            id: "seq-ooo-one-event-one-step",
            finalRelation: .any,
            finishSuffix: "/middle"
        )
        let t0 = Date()
        let seed = fileEventAt("/tmp/seed", pid: 100, ts: t0)
        let dualMatch = procEventAt(
            "/tmp/middle", pid: 200, ts: t0.addingTimeInterval(1)
        )

        // Live Phase 1 binds the event to `middle` and stops; it cannot also bind
        // `finish`, even though both predicates match. Replay must be identical.
        let canonical = try await fireCount([seed, dualMatch], rule: rule)
        let reordered = try await fireCount([dualMatch, seed], rule: rule)
        #expect(canonical.fires == 0 && canonical.partials == 1)
        #expect(reordered == canonical,
                "delivery inversion must not let one event satisfy two steps")

        // A distinct second event with the same fields may satisfy the remaining
        // step, proving the identity guard does not suppress legitimate progress.
        let distinctDualMatch = procEventAt(
            "/tmp/middle", pid: 201, ts: t0.addingTimeInterval(2)
        )
        let completed = try await fireCount(
            [dualMatch, seed, distinctDualMatch],
            rule: rule
        )
        #expect(completed.fires == 1 && completed.partials == 0)
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

    // MARK: - #20: pre-emptive-sweep throttle (detection-exactness under load)

    /// A distinct seed-only rule used to flood the partial pool. Its download
    /// step (`/wget`) is disjoint from `dlExecRule`'s (`/curl`) and its execute
    /// step (`/var/`) is disjoint from `dlExecRule`'s (`/tmp/`), so its partials
    /// never interfere with the rule under test and never complete in these
    /// tests (a `/var/` execute is never sent).
    private func fillerRule(id: String, window: TimeInterval) -> SequenceRule {
        SequenceRule(
            id: id, title: "filler (test)", description: "test",
            level: .high, tags: ["attack.execution"],
            window: window, correlationType: .processSame, ordered: true,
            steps: [
                SequenceStep(id: "download", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/wget"], negate: false)],
                             condition: .allOf, afterStep: nil, processRelation: nil),
                SequenceStep(id: "execute", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .startswith, values: ["/var/"], negate: false)],
                             condition: .allOf, afterStep: "download", processRelation: nil),
            ],
            trigger: .allSteps, enabled: true)
    }

    @Test("#20: throttled pre-emptive sweep still completes a live sequence above 80% capacity")
    func throttledPreemptiveSweepStillFires() async throws {
        // The pre-emptive sweep is throttled (no longer a full pool scan per
        // event above 80% capacity). Ordinary completion under a partial-pool
        // flood must be unaffected.
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 20)
        try await engine.addRule(dlExecRule(id: "seq-live", window: 600))
        try await engine.addRule(fillerRule(id: "filler", window: 600))

        // Seed the live sequence's first step, then flood with 18 unrelated
        // filler seeds → 19 partials total, above 80% of 20 (=16) but under the
        // cap, so the throttled pre-emptive path runs without any eviction.
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        for pid in Int32(200)...Int32(217) {
            _ = await engine.evaluate(procEvent("/usr/bin/wget", pid: pid))
        }
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 100))
        #expect(final.contains { $0.ruleId == "seq-live" },
                "a live sequence must still complete when the pool is above the 80% pre-emptive-sweep threshold")
    }

    @Test("#20: expired partials are swept before eviction, so a live sequence is not crowded out")
    func sweepBeforeEvictProtectsLivePartial() async throws {
        // Detection-exactness guard for the throttle. `evictOldest` removes
        // oldest-by-createdAt, so the FIRST-created partial (rule A, long window,
        // still live) sits at the front of the eviction queue. Short-window
        // EXPIRED filler partials then saturate the pool. Without the sweep-
        // before-evict guard the throttle could let those expired filler partials
        // push the total over the cap and evict the older, LIVE A partial first.
        // The guard clears the expired filler before eviction, so A survives —
        // matching the pre-throttle behavior where the per-event pre-emptive
        // sweep had already cleared them.
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 10)
        try await engine.addRule(dlExecRule(id: "seq-live", window: 600))   // long window (live)
        try await engine.addRule(fillerRule(id: "filler", window: 0.05))    // short window (expires)

        // A's first step is the OLDEST partial (front of the eviction queue).
        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        // Fill to the cap with short-window filler partials.
        for pid in Int32(200)...Int32(208) {
            _ = await engine.evaluate(procEvent("/usr/bin/wget", pid: pid))
        }
        // Let the filler partials expire (0.05s window); A stays live (600s). The
        // 0.2s wait is under the 0.25s throttle so the next seeds take the
        // sweep-before-evict path rather than a fresh pre-emptive sweep.
        try await Task.sleep(nanoseconds: 200_000_000)
        // Push over the cap: sweep-before-evict must drop the expired filler
        // rather than the older, live A partial.
        for pid in Int32(300)...Int32(305) {
            _ = await engine.evaluate(procEvent("/usr/bin/wget", pid: pid))
        }
        let final = await engine.evaluate(procEvent("/tmp/payload", pid: 100))
        #expect(final.contains { $0.ruleId == "seq-live" },
                "the live long-window partial must survive eviction: expired filler is swept first")
    }

    @Test("concurrent completion consumes one partial exactly once")
    func concurrentCompletionKeepsPartialAccountingExact() async throws {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/usr/bin/curl",
                                    name: "curl", startTime: Date())
        await lineage.recordProcess(pid: 101, ppid: 100, path: "/tmp/payload",
                                    name: "payload", startTime: Date())
        let engine = SequenceEngine(lineage: lineage)
        try await engine.addRule(dlExecRule(id: "seq-concurrent", window: 600,
                                            correlation: .processLineage))

        _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: 100))
        #expect(await engine.activePartialMatchCount == 1)

        let fireCount = await withTaskGroup(of: Int.self, returning: Int.self) { group in
            for _ in 0..<2_000 {
                group.addTask {
                    let matches = await engine.evaluate(self.procEvent("/tmp/payload", pid: 101))
                    return matches.filter { $0.ruleId == "seq-concurrent" }.count
                }
            }
            var total = 0
            for await count in group { total += count }
            return total
        }

        #expect(fireCount == 1, "one in-flight partial may complete only once (got \(fireCount) fires)")
        #expect(await engine.activePartialMatchCount == 0,
                "reported count must remain in lockstep with the now-empty partial pool")
    }

    @Test("two consumers make deterministic progress through lineage awaits")
    func twoLineageConsumersDoNotStallMutationLease() async throws {
        let lineage = ProcessLineage()
        let pairCount = 100
        for i in 0..<pairCount {
            let parent = Int32(10_000 + i * 2)
            let child = parent + 1
            await lineage.recordProcess(pid: parent, ppid: 1, path: "/usr/bin/curl",
                                        name: "curl", startTime: Date())
            await lineage.recordProcess(pid: child, ppid: parent, path: "/tmp/payload",
                                        name: "payload", startTime: Date())
        }

        let engine = SequenceEngine(lineage: lineage)
        try await engine.addRule(dlExecRule(
            id: "seq-two-consumers", window: 600, correlation: .processLineage
        ))

        let fires = await withTaskGroup(of: Int.self, returning: Int.self) { group in
            for lane in 0..<2 {
                group.addTask {
                    var laneFires = 0
                    for i in stride(from: lane, to: pairCount, by: 2) {
                        let parent = Int32(10_000 + i * 2)
                        let child = parent + 1
                        _ = await engine.evaluate(self.procEvent("/usr/bin/curl", pid: parent))
                        let matches = await engine.evaluate(
                            self.procEvent("/tmp/payload", pid: child)
                        )
                        laneFires += matches.filter { $0.ruleId == "seq-two-consumers" }.count
                    }
                    return laneFires
                }
            }
            var total = 0
            for await laneFires in group { total += laneFires }
            return total
        }

        #expect(fires == pairCount,
                "both lanes must complete every lineage-correlated pair (got \(fires))")
        #expect(await engine.activePartialMatchCount == 0)
        let stats = await engine.statsSnapshot()
        #expect(stats.first { $0.ruleId == "seq-two-consumers" }?.evaluationCount
                == UInt64(pairCount * 2))
    }

    @Test("cancelled mutation waiters leave a bounded FIFO without occupying capacity")
    func cancelledMutationWaitersAreRemovedAndFIFOIsPreserved() async throws {
        let engine = SequenceEngine(
            lineage: ProcessLineage(),
            mutationWaiterLimit: 4
        )
        let releaseGate = SequenceEngineTestGate()
        let recorder = SequenceEngineOrderRecorder()

        let holder = Task {
            await engine.holdMutationLeaseForTesting {
                await releaseGate.wait()
            }
        }
        #expect(await waitForLeaseState(engine, waiterCount: 0, held: true))

        var queued: [Task<Void, Never>] = []
        for value in 0..<4 {
            queued.append(Task {
                await engine.holdMutationLeaseForTesting {
                    await recorder.append(value)
                }
            })
            #expect(await waitForLeaseState(engine, waiterCount: value + 1, held: true),
                    "waiter \(value) did not enter the FIFO deterministically")
        }

        // Capacity is exact: this operation is rejected and cannot run later.
        let overflow = Task {
            await engine.holdMutationLeaseForTesting {
                await recorder.append(99)
            }
        }
        await overflow.value
        var diagnostics = await engine.mutationLeaseDiagnostics()
        #expect(diagnostics.waiterCount == 4)
        #expect(diagnostics.waiterStorageCount <= diagnostics.waiterLimit + 1_023)
        #expect(diagnostics.saturatedWaiterCount == 1)

        // Cancellation removes arbitrary queued entries immediately. Their
        // operations must never run, and the released slots accept replacements.
        queued[1].cancel()
        queued[3].cancel()
        #expect(await waitForLeaseState(engine, waiterCount: 2, held: true))
        let replacement = Task {
            await engine.holdMutationLeaseForTesting {
                await recorder.append(4)
            }
        }
        #expect(await waitForLeaseState(engine, waiterCount: 3, held: true))

        await releaseGate.open()
        await holder.value
        for task in queued { await task.value }
        await replacement.value

        #expect(await recorder.snapshot() == [0, 2, 4],
                "surviving waiters must retain FIFO order")
        diagnostics = await engine.mutationLeaseDiagnostics()
        #expect(!diagnostics.held)
        #expect(diagnostics.waiterCount == 0)
        #expect(diagnostics.waiterStorageCount == 0)
        #expect(diagnostics.waiterHighWatermark == 4)
        #expect(diagnostics.cancelledWaiterCount == 2)
    }

    @Test("a cancelled queued evaluation never mutates partial state")
    func cancelledQueuedEvaluationDoesNotRunLater() async throws {
        let engine = SequenceEngine(
            lineage: ProcessLineage(),
            mutationWaiterLimit: 2
        )
        try await engine.addRule(dlExecRule(id: "seq-cancelled-waiter", window: 600))
        let releaseGate = SequenceEngineTestGate()
        let holder = Task {
            await engine.holdMutationLeaseForTesting {
                await releaseGate.wait()
            }
        }
        #expect(await waitForLeaseState(engine, waiterCount: 0, held: true))

        let cancelledEvaluation = Task {
            await engine.evaluate(self.procEvent("/usr/bin/curl", pid: 77_777))
        }
        #expect(await waitForLeaseState(engine, waiterCount: 1, held: true))
        cancelledEvaluation.cancel()
        #expect(await waitForLeaseState(engine, waiterCount: 0, held: true))

        await releaseGate.open()
        await holder.value
        #expect(await cancelledEvaluation.value.isEmpty)
        #expect(await engine.activePartialMatchCount == 0,
                "a cancelled queued event must not seed after cancellation")
    }

    @Test("saturated lineage pool uses one bounded actor batch and priority still progresses")
    func saturatedLineagePoolBatchesRelationshipQueries() async throws {
        let lineage = ProcessLineage(maxAncestorDepth: 20)
        let poolLimit = 256
        let engine = SequenceEngine(
            lineage: lineage,
            maxPartialMatches: poolLimit,
            sweepInterval: 3_600
        )
        try await engine.addRule(dlExecRule(
            id: "seq-lineage-batch",
            window: 600,
            correlation: .processLineage
        ))

        // Do not seed PID 1: the synthetic event fixture truthfully carries
        // launchd (PID 1) as an ancestor, so using PID 1 as a bound step would
        // make the later candidate lineage-related rather than a miss.
        let firstSeedPID: Int32 = 10_000
        for offset in 0..<poolLimit {
            let pid = firstSeedPID + Int32(offset)
            _ = await engine.evaluate(procEvent("/usr/bin/curl", pid: pid))
        }
        #expect(await engine.activePartialMatchCount == poolLimit)
        let before = await lineage.relationshipSnapshotDiagnostics()

        async let saturatedMiss = engine.evaluate(
            procEvent("/tmp/unrelated-payload", pid: 900_000)
        )
        async let priorityNoMatch = engine.evaluate(
            procEvent("/usr/bin/priority-noop", pid: 900_001)
        )
        let (misses, priority) = await (saturatedMiss, priorityNoMatch)
        #expect(misses.isEmpty)
        #expect(priority.isEmpty)

        let after = await lineage.relationshipSnapshotDiagnostics()
        #expect(after.requestCount - before.requestCount == 1,
                "one event over a saturated pool must make one lineage actor hop, not O(partials)")
        #expect(after.requestedPIDCount - before.requestedPIDCount
                == UInt64(poolLimit + 1))
        #expect(after.largestBatch >= poolLimit + 1)
        #expect(await engine.activePartialMatchCount == poolLimit)
    }

    @Test("batched lineage relationships preserve scalar edge and depth semantics")
    func relationshipSnapshotMatchesScalarSemantics() async {
        let lineage = ProcessLineage(maxAncestorDepth: 2)
        let observed = Date()

        // Tracked parent and two siblings.
        await lineage.recordProcess(
            pid: 10, ppid: 999, path: "/parent", name: "parent", startTime: observed
        )
        await lineage.recordProcess(
            pid: 20, ppid: 10, path: "/child-a", name: "child-a", startTime: observed
        )
        await lineage.recordProcess(
            pid: 21, ppid: 10, path: "/child-b", name: "child-b", startTime: observed
        )
        await lineage.recordProcess(
            pid: 22, ppid: 20, path: "/grandchild", name: "grandchild", startTime: observed
        )

        // Same numeric parent but the parent node itself is untracked. Scalar
        // ancestors(of:) therefore exposes no direct parent for sibling checks.
        await lineage.recordProcess(
            pid: 30, ppid: 888, path: "/orphan-a", name: "orphan-a", startTime: observed
        )
        await lineage.recordProcess(
            pid: 31, ppid: 888, path: "/orphan-b", name: "orphan-b", startTime: observed
        )

        // A cycle exercises isDescendant's equality-before-cycle-guard behavior.
        await lineage.recordProcess(
            pid: 40, ppid: 41, path: "/cycle-a", name: "cycle-a", startTime: observed
        )
        await lineage.recordProcess(
            pid: 41, ppid: 40, path: "/cycle-b", name: "cycle-b", startTime: observed
        )

        let snapshot = await lineage.relationshipSnapshot(
            for: [10, 20, 21, 22, 30, 31, 40, 41]
        )

        // An untracked immediate parent is still a positive scalar descendant
        // edge, while max depth 2 reaches 22 -> 20 -> 10 but not 10 -> 999.
        #expect(snapshot.isDescendant(10, of: 999)
                == (await lineage.isDescendant(10, of: 999)))
        #expect(snapshot.isDescendant(22, of: 10)
                == (await lineage.isDescendant(22, of: 10)))
        #expect(snapshot.isDescendant(22, of: 999)
                == (await lineage.isDescendant(22, of: 999)))
        #expect(snapshot.isDescendant(40, of: 40)
                == (await lineage.isDescendant(40, of: 40)))

        #expect(snapshot.areSiblings(20, 21),
                "a shared tracked direct parent is visible to scalar ancestors(of:)")
        #expect(!snapshot.areSiblings(30, 31),
                "an untracked numeric parent must not manufacture scalar siblings")
    }

    @Test("eviction telemetry saturates instead of trapping or wrapping")
    func evictionTelemetryAdditionSaturates() {
        #expect(SequenceEngine.saturatingTelemetryAdd(Int.max - 1, 1) == Int.max)
        #expect(SequenceEngine.saturatingTelemetryAdd(Int.max - 1, 2) == Int.max)
        #expect(SequenceEngine.saturatingTelemetryAdd(Int.max, 1) == Int.max)
        #expect(SequenceEngine.saturatingTelemetryAdd(7, 0) == 7)
    }
}
