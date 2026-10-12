import Foundation
import Testing
@testable import MacCrabCore

/// Synthetic in-memory ordinary file events only; no filesystem or processes.
@Suite("Sequence partial admission and unchanged bounded semantics")
struct SequencePartialAdmissionTests {
    private func rule(id: String = "ordinary-partials", ordered: Bool = true) -> SequenceRule {
        SequenceRule(
            id: id, title: "ordinary file lifecycle", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600, correlationType: .processSame,
            ordered: ordered,
            steps: [
                SequenceStep(id: "created", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: ["create"], negate: false)]),
                SequenceStep(id: "written", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: ["write"], negate: false)],
                    afterStep: ordered ? "created" : nil),
            ], trigger: .allSteps
        )
    }

    private func event(initial: Bool = true, pid: Int32 = 41, at timestamp: Date) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid, name: "fixture", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: [], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(timestamp: timestamp, eventCategory: .file, eventType: .creation,
            eventAction: initial ? "create" : "write", process: process,
            file: FileInfo(path: "/private/tmp/ordinary-file.txt", action: initial ? .create : .write))
    }

    private func capture(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let diagnostics = await engine.checkpointWeightDiagnostics()
        #expect(diagnostics.cachedWeight == diagnostics.recomputedWeight)
        #expect(diagnostics.cachedWeight <= diagnostics.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        return try await engine.checkpointCapture()
    }

    private func payload(_ capture: SequenceCheckpointCapture) throws -> SequenceCheckpointPayload {
        SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: capture.capturedAt,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(capture.rules),
            sourceGeneration: capture.sourceGeneration, partialBuckets: capture.partialBuckets,
            pendingBuckets: capture.pendingBuckets, evictionOrder: capture.evictionOrder,
            pendingEvictionOrder: capture.pendingEvictionOrder
        )
    }

    @Test("Distinct seeds and duplicate delivery preserve exact partial accounting")
    func uniqueSeedsAndDuplicates() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule())
        let reference = Date()
        let seeds = (0..<1_024).map { _ in event(at: reference) }
        for seed in seeds { #expect(await engine.evaluate(seed).isEmpty) }
        let before = try await capture(engine)
        #expect(before.partialBuckets.flatMap(\.partials).count == seeds.count)
        #expect(before.partialBuckets.flatMap(\.partials).flatMap(\.matchedSteps).map(\.eventID) == seeds.map(\.id))
        for index in [0, 511, 1_023] { #expect(await engine.evaluate(seeds[index]).isEmpty) }
        let after = try await capture(engine)
        #expect(after.partialBuckets == before.partialBuckets)
        #expect(after.evictionOrder == before.evictionOrder)
        #expect(await engine.partialsEvictedTotal == 0)
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("Mass completion retains unrelated partials in their exact original order")
    func completionPreservesSurvivorOrder() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(rule())
        let reference = Date()
        for index in 0..<256 {
            _ = await engine.evaluate(event(pid: index.isMultiple(of: 2) ? 41 : 42, at: reference))
        }
        let before = try await capture(engine)
        let expected = before.partialBuckets.flatMap(\.partials).filter { $0.correlationKey == "42" }
        let first = await engine.evaluate(event(initial: false, at: reference.addingTimeInterval(1)))
        #expect(first.count == 128)
        let middle = try await capture(engine)
        #expect(middle.partialBuckets.flatMap(\.partials) == expected)
        #expect(middle.evictionOrder == expected.map(\.id))
        let second = await engine.evaluate(event(initial: false, pid: 42, at: reference.addingTimeInterval(2)))
        #expect(second.count == 128)
        #expect(try await capture(engine).partialBuckets.isEmpty)
        #expect(await engine.partialsEvictedTotal == 0)
    }

    @Test("Restore, append, retirement and bucket recreation retain audited accounting")
    func appendAfterRestoreAndRetirement() async throws {
        let source = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let definition = rule()
        try await source.addRule(definition)
        let reference = Date()
        for _ in 0..<16 { _ = await source.evaluate(event(at: reference)) }
        let before = try await capture(source)
        let target = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await target.addRule(definition)
        let restored = try await target.restoreCheckpoint(payload(before))
        #expect(restored.partialCount == 16)
        let next = event(at: reference)
        _ = await target.evaluate(next)
        let after = try await capture(target)
        #expect(after.partialBuckets.flatMap(\.partials).prefix(16) == before.partialBuckets.flatMap(\.partials)[...])
        #expect(after.partialBuckets.flatMap(\.partials).last?.matchedSteps.first?.eventID == next.id)
        await target.setEnabled(definition.id, enabled: false)
        #expect(try await capture(target).partialBuckets.isEmpty)
        await target.setEnabled(definition.id, enabled: true)
        _ = await target.evaluate(next)
        #expect(try await capture(target).partialBuckets.flatMap(\.partials).count == 1)
    }

    @Test("Ordered seed fast path leaves unordered advances and delayed replay unchanged")
    func unorderedAndDelayedReplay() async throws {
        let reference = Date()
        let unordered = SequenceEngine(lineage: ProcessLineage())
        try await unordered.addRule(rule(ordered: false))
        _ = await unordered.evaluate(event(initial: false, at: reference))
        #expect(await unordered.evaluate(event(at: reference.addingTimeInterval(1))).count == 1)
        _ = try await capture(unordered)

        let ordered = SequenceEngine(lineage: ProcessLineage())
        try await ordered.addRule(rule())
        _ = await ordered.evaluate(event(initial: false, at: reference.addingTimeInterval(1)))
        for _ in 0..<3 { #expect(await ordered.evaluate(event(at: reference)).count == 1) }
        let result = try await capture(ordered)
        #expect(result.partialBuckets.isEmpty)
        #expect(result.pendingBuckets.flatMap(\.steps).count == 1,
                "The same retained later event must remain reusable for delayed seeds")
    }

    @Test("The unchanged count cap still evicts the oldest exact partial identities")
    func countCapStillEnforced() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4, sweepInterval: 3_600)
        try await engine.addRule(rule())
        let reference = Date()
        let seeds = (0..<12).map { _ in event(at: reference) }
        for seed in seeds { _ = await engine.evaluate(seed) }
        let final = try await capture(engine)
        #expect(final.partialBuckets.flatMap(\.partials).flatMap(\.matchedSteps).map(\.eventID) == seeds.suffix(4).map(\.id))
        #expect(await engine.partialsEvictedTotal == 8)
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("Ordinary ASCII state fits the same byte cap without losing seeds or pending history")
    func conservativeASCIIBudgetRetainsExactHistory() async throws {
        let definition = rule(id: String(repeating: "r", count: 64))
        let reference = Date()
        func matched(_ step: String) -> SequenceCheckpointMatchedStep {
            SequenceCheckpointMatchedStep(stepID: step, eventID: UUID(), timestamp: reference,
                processPID: 41, processParentPID: 0, processParentWasTracked: false,
                processAncestorPIDs: [], filePath: nil, networkDestination: nil)
        }
        let partials = (0..<8_000).map { _ in
            SequenceCheckpointPartial(id: UUID(), ruleID: definition.id, createdAt: reference,
                matchedSteps: [matched("created")], correlationKey: "41")
        }
        let pending = (0..<96).map { _ in
            SequenceCheckpointPendingStep(ruleID: definition.id, stepID: "written",
                matched: matched("written"), arrivedAt: reference)
        }
        let retained = SequenceCheckpointCapture(capturedAt: reference, sourceGeneration: 1,
            rules: [definition],
            partialBuckets: [SequenceCheckpointPartialBucket(ruleID: definition.id, partials: partials)],
            pendingBuckets: [SequenceCheckpointPendingBucket(ruleID: definition.id, steps: pending)],
            evictionOrder: partials.map(\.id), pendingEvictionOrder: pending.map {
                SequenceCheckpointPendingIdentity(ruleID: $0.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID)
            })
        // RC3's six-bytes-for-every-ASCII-byte estimate rejected this ordinary
        // pool even before counting pending history. The budget itself stays fixed.
        let previousPartialWeight = 280 + 6 * (64 + 2) + 320 + 6 * 7
        #expect(previousPartialWeight * partials.count > SequenceCheckpointCodec.maximumSemanticStateWeight)
        let prepared = try SequenceCheckpointCodec.prepare(retained)
        #expect(prepared.encodedFile.count <= SequenceCheckpointCodec.maximumFileBytes)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let rawSize = try encoder.encode(prepared.payload).count
        let estimate = SequenceCheckpointCodec.estimatedSemanticStateWeight(
            partialBuckets: retained.partialBuckets, pendingBuckets: retained.pendingBuckets)
        #expect(rawSize <= estimate && estimate <= SequenceCheckpointCodec.maximumSemanticStateWeight,
                "The upper bound must hold for raw canonical bytes, not just compressed output")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(definition)
        let restored = try await engine.restoreCheckpoint(prepared.payload)
        #expect(restored.partialCount == 8_000 && restored.pendingCount == 96)
        let after = try await capture(engine)
        #expect(after.partialBuckets == retained.partialBuckets)
        #expect(after.pendingBuckets == retained.pendingBuckets)
        #expect(after.evictionOrder == retained.evictionOrder)
        #expect(after.pendingEvictionOrder == retained.pendingEvictionOrder)
        #expect(await engine.partialsEvictedTotal == 0)
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }
}
