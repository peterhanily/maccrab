import Foundation
import Testing
@testable import MacCrabCore

/// Ordinary in-memory file metadata only: no processes, files, live collectors,
/// security rules or elapsed-time assertions. This is resident deduplication,
/// not a permanent event ledger or a remedy for distinct-state cap pressure.
@Suite("Uncorrelated sequence resident identity")
struct SequenceResidentIdempotencyTests {
    private func rule(ordered: Bool = true, actions: [FileAction] = [.create, .write, .close],
                      window: TimeInterval = 3_600) -> SequenceRule {
        SequenceRule(
            id: "ordinary-resident-identity", title: "ordinary file metadata",
            description: "in-memory identity fixture", level: .low, tags: [],
            window: window, correlationType: .none, ordered: ordered,
            steps: actions.enumerated().map { index, action in
                SequenceStep(id: "step-\(index)", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: [action.rawValue], negate: false)],
                    afterStep: ordered && index > 0 ? "step-\(index - 1)" : nil)
            }, trigger: .allSteps
        )
    }

    private func event(_ action: FileAction, id: UInt8, at timestamp: Date) -> Event {
        let identity = UUID(uuid: (0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, id))
        let process = MacCrabCore.ProcessInfo(
            pid: 41, ppid: 1, rpid: 41, name: "fixture", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: [], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(id: identity, timestamp: timestamp, eventCategory: .file,
            eventType: .info, eventAction: action.rawValue, process: process,
            file: FileInfo(path: "/private/tmp/ordinary-resident.txt", action: action))
    }

    private func capture(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        let result = try await engine.checkpointCapture()
        #expect(result.evictionOrder == result.partialBuckets.flatMap(\.partials).map(\.id))
        return result
    }

    private func expectSameState(_ before: SequenceCheckpointCapture, _ after: SequenceCheckpointCapture) {
        #expect(after.partialBuckets == before.partialBuckets)
        #expect(after.pendingBuckets == before.pendingBuckets)
        #expect(after.evictionOrder == before.evictionOrder)
        #expect(after.pendingEvictionOrder == before.pendingEvictionOrder)
        #expect(after.sourceGeneration == before.sourceGeneration)
    }

    @Test("A resident same-event same-step seed is idempotent", arguments: [true, false])
    func residentSeedsAreIdempotent(ordered: Bool) async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule(ordered: ordered))
        let seed = event(.create, id: 1, at: Date().addingTimeInterval(-10))
        #expect(await engine.evaluate(seed).isEmpty)
        let before = try await capture(engine)
        #expect(before.partialBuckets.flatMap(\.partials).count == 1)
        for _ in 0..<8 { #expect(await engine.evaluate(seed).isEmpty) }
        expectSameState(before, try await capture(engine))
        #expect(await engine.partialsEvictedTotal == 0)
    }

    @Test("Distinct UUIDs retain separate seeds even with identical other fields", arguments: [true, false])
    func distinctIDsRemainSeparate(ordered: Bool) async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule(ordered: ordered))
        let time = Date().addingTimeInterval(-10)
        let seeds = (1...4).map { event(.create, id: UInt8($0), at: time) }
        for seed in seeds { #expect(await engine.evaluate(seed).isEmpty) }
        let before = try await capture(engine)
        let partials = before.partialBuckets.flatMap(\.partials)
        #expect(partials.flatMap(\.matchedSteps).map(\.eventID) == seeds.map(\.id))
        #expect(Set(partials.map(\.id)).count == seeds.count)
        #expect(partials.allSatisfy { $0.correlationKey == nil })
        for seed in seeds.reversed() { #expect(await engine.evaluate(seed).isEmpty) }
        expectSameState(before, try await capture(engine))
        #expect(await engine.evaluate(event(.write, id: 5, at: time.addingTimeInterval(1))).isEmpty)
        let completions = await engine.evaluate(event(.close, id: 6, at: time.addingTimeInterval(2)))
        #expect(completions.count == seeds.count)
        #expect(completions.allSatisfy { $0.ruleId == rule().id })
        _ = try await capture(engine)
        #expect(await engine.partialsEvictedTotal == 0)
    }

    @Test("A new unordered event still advances old branches and seeds its own branch")
    func unorderedAdvanceKeepsIndependentSeed() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule(ordered: false))
        let time = Date().addingTimeInterval(-10)
        let first = event(.create, id: 1, at: time)
        let middle = event(.write, id: 2, at: time.addingTimeInterval(1))
        #expect(await engine.evaluate(first).isEmpty)
        #expect(await engine.evaluate(middle).isEmpty)
        let before = try await capture(engine)
        let partials = before.partialBuckets.flatMap(\.partials)
        try #require(partials.count == 2)
        #expect(partials[0].matchedSteps.map(\.eventID) == [first.id, middle.id])
        #expect(partials[1].matchedSteps.map(\.eventID) == [middle.id])
        #expect(await engine.evaluate(middle).isEmpty)
        expectSameState(before, try await capture(engine))
        #expect(await engine.evaluate(event(.close, id: 3, at: time.addingTimeInterval(2))).count == 1)
        #expect(await engine.evaluate(event(.create, id: 4, at: time.addingTimeInterval(3))).count == 1,
                "The independently seeded middle branch must retain its later distinct completion")
        _ = try await capture(engine)
    }

    @Test("One event may seed distinct steps but never occupy two steps in one chain")
    func distinctStepBindingsRemainSeparate() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule(ordered: false, actions: [.create, .create, .close]))
        let time = Date().addingTimeInterval(-10)
        let seed = event(.create, id: 1, at: time)
        #expect(await engine.evaluate(seed).isEmpty)
        let before = try await capture(engine)
        let original = before.partialBuckets.flatMap(\.partials)
        #expect(original.count == 2)
        #expect(original.map { $0.matchedSteps.map(\.stepID) } == [["step-0"], ["step-1"]])
        #expect(await engine.evaluate(seed).isEmpty)
        expectSameState(before, try await capture(engine))
        #expect(await engine.evaluate(event(.create, id: 2, at: time.addingTimeInterval(1))).isEmpty)
        let advanced = try await capture(engine).partialBuckets.flatMap(\.partials)
        #expect(advanced.count == 4)
        #expect(advanced.allSatisfy { Set($0.matchedSteps.map(\.eventID)).count == $0.matchedSteps.count })
        #expect(await engine.evaluate(event(.close, id: 3, at: time.addingTimeInterval(2))).count == 2)
        _ = try await capture(engine)
    }

    @Test("Out-of-order replay preserves resident identity and fans out to distinct delayed seeds")
    func retainedHistoryReplayDoesNotMultiplyResidentSeed() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule())
        let time = Date().addingTimeInterval(-10)
        let seed = event(.create, id: 1, at: time)
        let middle = event(.write, id: 2, at: time.addingTimeInterval(1))
        #expect(await engine.evaluate(middle).isEmpty)
        #expect(await engine.evaluate(seed).isEmpty)
        let before = try await capture(engine)
        #expect(before.partialBuckets.flatMap(\.partials).first?.matchedSteps.map(\.eventID) == [seed.id, middle.id])
        #expect(before.pendingBuckets.flatMap(\.steps).count == 1)
        #expect(await engine.evaluate(seed).isEmpty)
        expectSameState(before, try await capture(engine))
        #expect(await engine.evaluate(event(.create, id: 3, at: time)).isEmpty)
        let replayed = try await capture(engine)
        #expect(replayed.partialBuckets.flatMap(\.partials).count == 2)
        #expect(replayed.pendingBuckets == before.pendingBuckets)
        #expect(await engine.evaluate(event(.close, id: 4, at: time.addingTimeInterval(2))).count == 2)
        #expect(try await capture(engine).partialBuckets.isEmpty)
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("Restored resident bindings retain identity and independent keys", arguments: [true, false])
    func restoredResidentIdentityRetained(ordered: Bool) async throws {
        let definition = rule(ordered: ordered)
        let source = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await source.addRule(definition)
        let time = Date().addingTimeInterval(-10)
        let seed = event(.create, id: 1, at: time)
        #expect(await source.evaluate(seed).isEmpty)
        let before = try await capture(source)
        let prepared = try SequenceCheckpointCodec.prepare(before)
        let target = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await target.addRule(definition)
        #expect(try await target.restoreCheckpoint(prepared.payload).partialCount == 1)
        let restored = try await capture(target)
        #expect(restored.partialBuckets == before.partialBuckets)
        #expect(restored.evictionOrder == before.evictionOrder)
        #expect(await target.evaluate(seed).isEmpty)
        expectSameState(restored, try await capture(target))
        #expect(await target.evaluate(event(.create, id: 2, at: time)).isEmpty)
        #expect(try await capture(target).partialBuckets.flatMap(\.partials).count == 2)
        #expect(await target.evaluate(event(.write, id: 3, at: time.addingTimeInterval(1))).isEmpty)
        #expect(await target.evaluate(event(.close, id: 4, at: time.addingTimeInterval(2))).count == 2)
        _ = try await capture(target)
    }

    @Test("Duplicates do not consume capacity and genuine distinct pressure remains explicit")
    func distinctCountPressureStillReported() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4, sweepInterval: 3_600)
        try await engine.addRule(rule())
        let time = Date().addingTimeInterval(-10)
        let seeds = (1...6).map { event(.create, id: UInt8($0), at: time) }
        for seed in seeds.prefix(4) { _ = await engine.evaluate(seed) }
        let before = try await capture(engine)
        for seed in seeds.prefix(4) { _ = await engine.evaluate(seed) }
        expectSameState(before, try await capture(engine))
        #expect(await engine.partialsEvictedTotal == 0)
        for seed in seeds.suffix(2) { _ = await engine.evaluate(seed) }
        let after = try await capture(engine)
        #expect(after.partialBuckets.flatMap(\.partials).flatMap(\.matchedSteps).map(\.eventID) == seeds.suffix(4).map(\.id))
        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountLimit == 4 && pressure.globalCountShedTotal == 2)
        #expect(pressure.semanticWeightShedTotal == 0 && pressure.totalShed == 2)
        #expect(pressure.classificationConserved && !pressure.countersAtLimit)
    }

    @Test("Completed identities do not become permanent deduplication tombstones")
    func completedIdentityCanSeedAgain() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule(actions: [.create, .write]))
        let time = Date().addingTimeInterval(-10)
        let seed = event(.create, id: 1, at: time)
        #expect(await engine.evaluate(seed).isEmpty)
        #expect(await engine.evaluate(event(.write, id: 2, at: time.addingTimeInterval(1))).count == 1)
        #expect(try await capture(engine).partialBuckets.isEmpty)
        #expect(await engine.evaluate(seed).count == 1,
                "With no resident binding, retained later history can complete a fresh seed as before")
        #expect(try await capture(engine).partialBuckets.isEmpty)
    }

    @Test("An unswept expired binding does not suppress a fresh seed")
    func expiredResidentDoesNotBlockReadmission() async throws {
        let definition = rule(actions: [.create, .write], window: 60)
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(definition)
        let oldTime = Date().addingTimeInterval(-90)
        let seed = event(.create, id: 1, at: oldTime)
        let expired = SequenceCheckpointPartial(id: UUID(), ruleID: definition.id,
            createdAt: oldTime, matchedSteps: [SequenceCheckpointMatchedStep(
                stepID: "step-0", eventID: seed.id, timestamp: oldTime,
                processPID: 41, processParentPID: 0, processParentWasTracked: false,
                processAncestorPIDs: [], filePath: nil, networkDestination: nil)],
            correlationKey: nil)
        let payload = SequenceCheckpointPayload(schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: oldTime, ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint([definition]),
            sourceGeneration: 1, partialBuckets: [.init(ruleID: definition.id, partials: [expired])],
            pendingBuckets: [], evictionOrder: [expired.id], pendingEvictionOrder: [])
        // Restore at an earlier valid instant. The long sweep cadence leaves the
        // now-expired record resident without sleep or a production clock hook.
        #expect(try await engine.restoreCheckpoint(payload, now: oldTime).partialCount == 1)
        #expect(await engine.evaluate(seed).isEmpty)
        let after = try await capture(engine).partialBuckets.flatMap(\.partials)
        #expect(after.count == 2 && after.first == expired)
        #expect(after.last?.id != expired.id)
        #expect(await engine.evaluate(event(.write, id: 2, at: oldTime.addingTimeInterval(1))).count == 1)
        #expect(await engine.partialsEvictedTotal == 0)
    }
}
