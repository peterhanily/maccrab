import Foundation
import Testing
@testable import MacCrabCore

@Suite("Incremental sequence pending admission")
struct SequencePendingAppendTests {
    private func rule(_ id: String = "ordinary-pending") -> SequenceRule {
        SequenceRule(
            id: id, title: "ordinary file sequence", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600,
            correlationType: .processSame, ordered: true,
            steps: [
                SequenceStep(id: "created", logsourceCategory: "file_event",
                             predicates: [Predicate(field: "FileAction", modifier: .equals,
                                                    values: ["create"], negate: false)]),
                SequenceStep(id: "written", logsourceCategory: "file_event",
                             predicates: [Predicate(field: "FileAction", modifier: .equals,
                                                    values: ["write"], negate: false)],
                             afterStep: "created"),
            ], trigger: .allSteps, enabled: true
        )
    }

    private func event(initial: Bool = false, at timestamp: Date) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 41, ppid: 1, rpid: 41, name: "fixture", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: [], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(
            timestamp: timestamp, eventCategory: .file, eventType: .creation,
            eventAction: initial ? "create" : "write", process: process,
            file: FileInfo(path: "/private/tmp/ordinary-fixture.txt",
                           action: initial ? .create : .write)
        )
    }

    private func checkedCapture(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        // This performs the independent field-by-field semantic weight audit,
        // and verifies that eviction order covers every exact live identity.
        return try await engine.checkpointCapture()
    }

    @Test("Unique appends count once across buckets and preserve replay history order")
    func uniqueAppendAndDuplicateAccounting() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let rules = [rule("ordinary-a"), rule("ordinary-b")]
        for rule in rules { try await engine.addRule(rule) }
        let reference = Date()
        let later = (0..<128).map { _ in event(at: reference) }
        for item in later { _ = await engine.evaluate(item) }
        let before = try await checkedCapture(engine)
        let beforeLedger = await engine.pendingStepConservation()
        #expect(beforeLedger.offered == 256 && beforeLedger.queued == 256)
        #expect(beforeLedger.completed == 0 && beforeLedger.explicitlyShed == 0)
        #expect(before.pendingBuckets.count == 2)
        for bucket in before.pendingBuckets {
            #expect(bucket.steps.map(\.matched.eventID) == later.map(\.id))
            #expect(before.pendingEvictionOrder.filter { $0.ruleID == bucket.ruleID }
                .map(\.eventID) == later.map(\.id))
        }

        // A repeated delivery must not acquire another ledger entry or weight.
        for item in later { _ = await engine.evaluate(item) }
        let afterDuplicate = try await checkedCapture(engine)
        #expect(await engine.pendingStepConservation() == beforeLedger)
        #expect(afterDuplicate.pendingBuckets == before.pendingBuckets)
        #expect(afterDuplicate.pendingEvictionOrder == before.pendingEvictionOrder)

        let matches = await engine.evaluate(event(initial: true, at: reference.addingTimeInterval(-1)))
        #expect(Set(matches.map(\.ruleId)) == Set(rules.map(\.id)))
        let afterReplay = try await checkedCapture(engine)
        #expect(afterReplay.pendingBuckets == before.pendingBuckets,
                "Replay history is reusable by a subsequently delivered earlier event")
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("Retirement followed by append charges fresh bucket overhead exactly once")
    func appendAfterRetirement() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let fixtureRule = rule()
        try await engine.addRule(fixtureRule)
        let first = event(at: Date())
        _ = await engine.evaluate(first)
        _ = try await checkedCapture(engine)
        await engine.setEnabled(fixtureRule.id, enabled: false)
        let retired = try await checkedCapture(engine)
        #expect(retired.pendingBuckets.isEmpty && retired.pendingEvictionOrder.isEmpty)
        var ledger = await engine.pendingStepConservation()
        #expect(ledger.offered == 1 && ledger.completed == 1 && ledger.queued == 0)
        await engine.setEnabled(fixtureRule.id, enabled: true)
        let second = event(at: Date())
        _ = await engine.evaluate(second)
        let appended = try await checkedCapture(engine)
        #expect(appended.pendingBuckets.flatMap(\.steps).map(\.matched.eventID) == [second.id])
        ledger = await engine.pendingStepConservation()
        #expect(ledger.offered == 2 && ledger.completed == 1 && ledger.queued == 1)
        #expect(ledger.explicitlyShed == 0)
    }

    @Test("Restored pending history accepts exact new appends without changing old order")
    func appendAfterRestore() async throws {
        let source = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let fixtureRule = rule()
        try await source.addRule(fixtureRule)
        let reference = Date()
        let original = (0..<8).map { _ in event(at: reference) }
        for item in original { _ = await source.evaluate(item) }
        let capture = try await checkedCapture(source)
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: capture.capturedAt,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(capture.rules),
            sourceGeneration: capture.sourceGeneration,
            partialBuckets: capture.partialBuckets, pendingBuckets: capture.pendingBuckets,
            evictionOrder: capture.evictionOrder, pendingEvictionOrder: capture.pendingEvictionOrder
        )
        let target = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await target.addRule(fixtureRule)
        let restored = try await target.restoreCheckpoint(payload)
        #expect(restored.pendingCount == original.count)
        let next = event(at: reference)
        _ = await target.evaluate(next)
        let after = try await checkedCapture(target)
        let expected = original.map(\.id) + [next.id]
        #expect(after.pendingBuckets.flatMap(\.steps).map(\.matched.eventID) == expected)
        #expect(after.pendingEvictionOrder.map(\.eventID) == expected)
        let ledger = await target.pendingStepConservation()
        #expect(ledger.offered == UInt64(expected.count) && ledger.queued == UInt64(expected.count))
        #expect(ledger.completed == 0 && ledger.explicitlyShed == 0)
    }
}
