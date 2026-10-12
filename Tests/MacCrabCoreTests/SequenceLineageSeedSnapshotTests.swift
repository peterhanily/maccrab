import Foundation
import Testing
@testable import MacCrabCore

/// Benign in-memory file lifecycle events and synthetic process relationships.
/// Operation counts are deterministic; no timing, host activity or threat rules.
@Suite("Sequence seed-only lineage snapshot scope")
struct SequenceLineageSeedSnapshotTests {
    private func rule(ordered: Bool = true, relation: ProcessRelation? = nil) -> SequenceRule {
        SequenceRule(
            id: "ordinary-lineage-lifecycle", title: "ordinary file lifecycle",
            description: "in-memory fixture", level: .low, tags: [], window: 3_600,
            correlationType: .processLineage, ordered: ordered,
            steps: [
                SequenceStep(id: "created", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: ["create"], negate: false)]),
                SequenceStep(id: "written", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: ["write"], negate: false)],
                    afterStep: ordered ? "created" : nil,
                    processRelation: relation.map { ProcessRelationSpec(relation: $0, relativeToStep: "created") }),
            ], trigger: .allSteps
        )
    }

    private func event(initial: Bool = true, pid: Int32, ppid: Int32 = 0, at timestamp: Date) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: ppid, rpid: pid, name: "fixture", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: [], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(timestamp: timestamp, eventCategory: .file, eventType: .creation,
            eventAction: initial ? "create" : "write", process: process,
            file: FileInfo(path: "/private/tmp/ordinary-lineage.txt", action: initial ? .create : .write))
    }

    private func record(_ lineage: ProcessLineage, pid: Int32, ppid: Int32, at timestamp: Date) async {
        await lineage.recordProcess(pid: pid, ppid: ppid, path: "/usr/bin/true",
                                    name: "fixture", startTime: timestamp)
    }

    private func capture(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight && weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.partialPressureDiagnostics().totalShed == 0)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        return try await engine.checkpointCapture()
    }

    private func payload(_ capture: SequenceCheckpointCapture) throws -> SequenceCheckpointPayload {
        SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: capture.capturedAt, ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(capture.rules),
            sourceGeneration: capture.sourceGeneration, partialBuckets: capture.partialBuckets,
            pendingBuckets: capture.pendingBuckets, evictionOrder: capture.evictionOrder,
            pendingEvictionOrder: capture.pendingEvictionOrder
        )
    }

    @Test("Ordered seed-only pool requests one PID per event and retains exact ancestry across restore")
    func seedOnlySnapshotIsIndependentOfPoolDepth() async throws {
        let lineage = ProcessLineage()
        let engine = SequenceEngine(lineage: lineage, maxPartialMatches: 256, sweepInterval: 3_600)
        let definition = rule(relation: .ancestor)
        try await engine.addRule(definition)
        let reference = Date()
        let parent: Int32 = 70
        await record(lineage, pid: parent, ppid: 1, at: reference)
        let seeds = (0..<128).map { event(pid: 1_000 + Int32($0), ppid: parent, at: reference) }
        for seed in seeds { await record(lineage, pid: seed.process.pid, ppid: parent, at: reference) }
        let operationsBefore = await lineage.relationshipSnapshotDiagnostics()
        for seed in seeds { #expect(await engine.evaluate(seed).isEmpty) }
        let operationsAfter = await lineage.relationshipSnapshotDiagnostics()
        #expect(operationsAfter.requestCount - operationsBefore.requestCount == UInt64(seeds.count))
        #expect(operationsAfter.requestedPIDCount - operationsBefore.requestedPIDCount == UInt64(seeds.count))
        #expect(operationsAfter.largestBatch == 1)
        let before = try await capture(engine)
        let partials = before.partialBuckets.flatMap(\.partials)
        #expect(partials.count == seeds.count)
        let exactSeedOrder = partials.flatMap(\.matchedSteps).map(\.eventID) == seeds.map(\.id)
        let exactEvictionOrder = before.evictionOrder == partials.map(\.id)
        let exactAncestry = partials.flatMap(\.matchedSteps).allSatisfy {
            $0.processParentPID == parent && $0.processAncestorPIDs == [1, parent]
        }
        #expect(exactSeedOrder && exactEvictionOrder && exactAncestry)
        #expect(before.pendingBuckets.isEmpty)

        let restored = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 256, sweepInterval: 3_600)
        try await restored.addRule(definition)
        _ = try await restored.restoreCheckpoint(payload(before))
        let afterRestore = try await capture(restored)
        let exactRestoredRecords = afterRestore.partialBuckets == before.partialBuckets
            && afterRestore.evictionOrder == before.evictionOrder
        #expect(exactRestoredRecords)
        let later = event(initial: false, pid: parent, at: reference.addingTimeInterval(1))
        let liveMatches = await engine.evaluate(later)
        let restoredMatches = await restored.evaluate(later)
        #expect(liveMatches.count == seeds.count && restoredMatches.count == seeds.count)
        let sameDescriptions = liveMatches.map(\.description) == restoredMatches.map(\.description)
        #expect(sameDescriptions, "Restored event-time ancestry must yield exactly the same completions")
        #expect(liveMatches.allSatisfy { $0.ruleId == definition.id })
        #expect(restoredMatches.allSatisfy { $0.ruleId == definition.id })
        let fullAdvance = await lineage.relationshipSnapshotDiagnostics()
        #expect(fullAdvance.requestedPIDCount - operationsAfter.requestedPIDCount == UInt64(seeds.count + 1))
        #expect(try await capture(engine).partialBuckets.isEmpty)
        #expect(try await capture(restored).partialBuckets.isEmpty)
    }

    @Test("Seed-only snapshot keeps tracked-parent proof for sibling completion after restore")
    func siblingProofIsNotOmitted() async throws {
        let reference = Date()
        let lineage = ProcessLineage()
        await record(lineage, pid: 70, ppid: 1, at: reference)
        await record(lineage, pid: 80, ppid: 70, at: reference)
        let definition = rule(relation: .sibling)
        let source = SequenceEngine(lineage: lineage)
        try await source.addRule(definition)
        let seed = event(pid: 80, ppid: 70, at: reference)
        _ = await source.evaluate(seed)
        let saved = try await capture(source)
        let evidence = try #require(saved.partialBuckets.first?.partials.first?.matchedSteps.first)
        #expect(evidence.eventID == seed.id && evidence.processParentPID == 70 && evidence.processParentWasTracked)
        #expect(await lineage.relationshipSnapshotDiagnostics().largestBatch == 1)

        // The new tracker knows the later sibling and its parent, but not the
        // original seed. Its side of the proof must come from the checkpoint.
        let afterRestart = ProcessLineage()
        await record(afterRestart, pid: 70, ppid: 1, at: reference)
        await record(afterRestart, pid: 90, ppid: 70, at: reference)
        let target = SequenceEngine(lineage: afterRestart)
        try await target.addRule(definition)
        _ = try await target.restoreCheckpoint(payload(saved))
        let restored = try await capture(target)
        let exactRecords = restored.partialBuckets == saved.partialBuckets && restored.evictionOrder == saved.evictionOrder
        #expect(exactRecords)
        let completions = await target.evaluate(event(initial: false, pid: 90, ppid: 70, at: reference.addingTimeInterval(1)))
        #expect(completions.count == 1 && completions.first?.ruleId == definition.id)
        #expect(try await capture(target).partialBuckets.isEmpty)
    }

    @Test("Pending history keeps full old-partial and pending-PID snapshot for fresh lineage replay")
    func pendingHistoryStillReplaysExistingPartials() async throws {
        let reference = Date()
        let lineage = ProcessLineage()
        let engine = SequenceEngine(lineage: lineage)
        try await engine.addRule(rule())
        let oldSeed = event(pid: 800, at: reference)
        let later = event(initial: false, pid: 900, at: reference.addingTimeInterval(2))
        _ = await engine.evaluate(oldSeed)
        #expect(await engine.evaluate(later).isEmpty)
        let before = try await capture(engine)
        #expect(before.partialBuckets.flatMap(\.partials).count == 1)
        #expect(before.pendingBuckets.flatMap(\.steps).count == 1)

        // The relationship was absent at first evaluation. Replaying only the
        // newly created partial, or querying only its PID, would miss this
        // completion of the OLD partial under the newly available lineage.
        await record(lineage, pid: 800, ppid: 0, at: reference)
        await record(lineage, pid: 900, ppid: 800, at: reference)
        let operationsBefore = await lineage.relationshipSnapshotDiagnostics()
        let newSeed = event(pid: 1_000, at: reference.addingTimeInterval(1))
        let completions = await engine.evaluate(newSeed)
        #expect(completions.count == 1)
        let operationsAfter = await lineage.relationshipSnapshotDiagnostics()
        #expect(operationsAfter.requestCount - operationsBefore.requestCount == 1)
        #expect(operationsAfter.requestedPIDCount - operationsBefore.requestedPIDCount == 3)
        let after = try await capture(engine)
        let survivors = after.partialBuckets.flatMap(\.partials)
        #expect(survivors.count == 1 && survivors.first?.matchedSteps.first?.eventID == newSeed.id)
        let pendingUnchanged = after.pendingBuckets == before.pendingBuckets
            && after.pendingEvictionOrder == before.pendingEvictionOrder
        #expect(pendingUnchanged)
        #expect(after.evictionOrder == survivors.map(\.id))
    }

    @Test("Unordered first-step event keeps retained ancestry needed for an existing later-step seed")
    func unorderedPlanKeepsFullSnapshot() async throws {
        let reference = Date()
        let lineage = ProcessLineage()
        let engine = SequenceEngine(lineage: lineage)
        let definition = rule(ordered: false)
        try await engine.addRule(definition)
        let previous = event(initial: false, pid: 900, at: reference)
        _ = await engine.evaluate(previous)
        let before = try await capture(engine)
        #expect(before.partialBuckets.flatMap(\.partials).count == 1 && before.pendingBuckets.isEmpty)
        await record(lineage, pid: 800, ppid: 0, at: reference)
        await record(lineage, pid: 900, ppid: 800, at: reference)
        let operationsBefore = await lineage.relationshipSnapshotDiagnostics()
        let current = event(pid: 800, at: reference.addingTimeInterval(1))
        let matches = await engine.evaluate(current)
        #expect(matches.count == 1 && matches.first?.ruleId == definition.id)
        let operationsAfter = await lineage.relationshipSnapshotDiagnostics()
        #expect(operationsAfter.requestedPIDCount - operationsBefore.requestedPIDCount == 2)
        let after = try await capture(engine)
        let survivors = after.partialBuckets.flatMap(\.partials)
        #expect(survivors.count == 1 && survivors.first?.matchedSteps.first?.eventID == current.id)
        #expect(after.pendingBuckets.isEmpty && after.evictionOrder == survivors.map(\.id))
    }
}
