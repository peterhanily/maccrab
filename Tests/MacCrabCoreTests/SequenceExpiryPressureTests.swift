import Foundation
import Testing
@testable import MacCrabCore

@Suite("Sequence history expiry before pressure")
struct SequenceExpiryPressureTests {
    private func rule(id: String = "r", filePath: Bool = false, finish: String = "/usr/bin/true") -> SequenceRule {
        SequenceRule(
            id: id, title: "ordinary sequence fixture", description: "ordered fixture",
            level: .low, tags: [], window: 60,
            correlationType: filePath ? .filePath : .processSame, ordered: true,
            steps: [
                SequenceStep(id: "a", logsourceCategory: filePath ? "file_event" : "process_creation",
                             predicates: [Predicate(field: filePath ? "FileAction" : "Image",
                                                    modifier: .equals, values: [filePath ? "create" : "/bin/echo"],
                                                    negate: false)]),
                SequenceStep(id: "b", logsourceCategory: filePath ? "file_event" : "process_creation",
                             predicates: [Predicate(field: filePath ? "FileAction" : "Image",
                                                    modifier: .equals, values: [filePath ? "write" : finish],
                                                    negate: false)], afterStep: "a"),
            ], trigger: .allSteps, enabled: true
        )
    }

    private func event(initial: Bool = false, filePath: String? = nil, at timestamp: Date = Date()) -> Event {
        let executable = initial ? "/bin/echo" : "/usr/bin/true"
        let process = MacCrabCore.ProcessInfo(
            pid: 41, ppid: 1, rpid: 41, name: "fixture", executable: executable,
            commandLine: executable, args: [], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(
            timestamp: timestamp, eventCategory: filePath == nil ? .process : .file,
            eventType: .creation, eventAction: filePath == nil ? "exec" : (initial ? "create" : "write"),
            process: process,
            file: filePath.map { FileInfo(path: $0, action: initial ? .create : .write) }
        )
    }

    private func pending(ruleID: String, at timestamp: Date, filePath: String? = nil) -> SequenceCheckpointPendingStep {
        SequenceCheckpointPendingStep(
            ruleID: ruleID, stepID: "b",
            matched: SequenceCheckpointMatchedStep(
                stepID: "b", eventID: UUID(), timestamp: timestamp,
                processPID: 41, processParentPID: 0, processParentWasTracked: false,
                processAncestorPIDs: [], filePath: filePath, networkDestination: nil
            ), arrivedAt: timestamp
        )
    }

    private func restore(
        _ buckets: [SequenceCheckpointPendingBucket], rules: [SequenceRule],
        into engine: SequenceEngine, at timestamp: Date
    ) async throws {
        for rule in rules { try await engine.addRule(rule) }
        let steps = buckets.flatMap(\.steps)
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: timestamp, ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(rules),
            sourceGeneration: 1, partialBuckets: [], pendingBuckets: buckets,
            evictionOrder: [], pendingEvictionOrder: steps.map {
                SequenceCheckpointPendingIdentity(ruleID: $0.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID)
            }
        )
        let restored = try await engine.restoreCheckpoint(payload, now: timestamp)
        #expect(restored.pendingCount == steps.count)
        #expect(restored.expiredPendingCount == 0)
    }

    private func assertRetainedLiveHistory(
        _ live: [Event], in engine: SequenceEngine, ruleID: String, filePath: String? = nil
    ) async throws {
        let capture = try await engine.checkpointCapture()
        let retained = Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
        #expect(retained == Set(live.map(\.id)))
        let matches = await engine.evaluate(event(initial: true, filePath: filePath,
                                                  at: live[0].timestamp.addingTimeInterval(-0.5)))
        #expect(matches.contains { $0.ruleId == ruleID }, "Retained later history must still replay for a delayed initial event")
        let afterReplay = try await engine.checkpointCapture()
        #expect(Set(afterReplay.pendingBuckets.flatMap(\.steps).map(\.matched.eventID)) == retained,
                "Replay history remains available to another delayed initial event")
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
    }

    @Test("Count pressure distinguishes expired history from per-rule and global eviction",
          arguments: [false, true], [false, true])
    func countPressureRetiresExpiredHistory(acrossRules: Bool, expired: Bool) async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let primary = rule()
        let secondary = rule(id: "s", finish: "/usr/bin/false")
        let reference = Date()
        let old = reference.addingTimeInterval(expired ? -90 : -1)
        let oldCount = SequenceEngine.maxPendingTotal - 1
        let secondaryCount = acrossRules ? oldCount / 2 : 0
        var buckets = [SequenceCheckpointPendingBucket(ruleID: primary.id, steps:
            (0..<(oldCount - secondaryCount)).map { _ in pending(ruleID: primary.id, at: old) })]
        if secondaryCount > 0 {
            buckets.append(SequenceCheckpointPendingBucket(ruleID: secondary.id, steps:
                (0..<secondaryCount).map { _ in pending(ruleID: secondary.id, at: old) }))
        }
        // Restore at an earlier instant when these records were valid. The
        // deliberately long periodic cadence isolates the last-chance sweep;
        // no sleep, clock mutation, or production-only hook is needed.
        try await restore(buckets, rules: acrossRules ? [primary, secondary] : [primary],
                          into: engine, at: expired ? old.addingTimeInterval(1) : reference)
        let live = [event(), event()]
        _ = await engine.evaluate(live[0])
        let before = await engine.pendingStepConservation()
        #expect(before.queued == UInt64(SequenceEngine.maxPendingTotal))
        #expect(before.completed == 0 && before.explicitlyShed == 0)
        let beforeWeight = await engine.checkpointWeightDiagnostics()
        #expect(beforeWeight.cachedWeight < beforeWeight.maximumWeight,
                "This fixture must reach the count limit independently of the byte limit")

        _ = await engine.evaluate(live[1])
        let ledger = await engine.pendingStepConservation()
        #expect(ledger.offered == UInt64(oldCount + 2))
        #expect(ledger.inFlight == 0 && ledger.conservationMaintained)
        #expect(await engine.partialsEvictedTotal == 0)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.classificationConserved)
        #expect(pressure.journalExplicitlyShedTotal == ledger.explicitlyShed)
        #expect(pressure.semanticWeightShedTotal == 0)
        for perRule in await engine.pendingStepConservationByRule().values {
            #expect(perRule.conservationMaintained)
        }
        if expired {
            #expect(ledger.completed == UInt64(oldCount))
            #expect(ledger.queued == 2 && ledger.explicitlyShed == 0)
            #expect(await engine.pendingStepsEvictedTotal == 0)
            #expect(pressure.perRuleCountShedTotal == 0 && pressure.globalCountShedTotal == 0)
            #expect(pressure.lastPressure == nil,
                    "Expired-only retirement must not manufacture a live-pressure observation")
            try await assertRetainedLiveHistory(live, in: engine, ruleID: primary.id)
        } else {
            #expect(ledger.completed == 0 && ledger.explicitlyShed == 1)
            #expect(ledger.queued == UInt64(SequenceEngine.maxPendingTotal))
            #expect(pressure.perRuleCountShedTotal == (acrossRules ? 0 : 1))
            #expect(pressure.globalCountShedTotal == (acrossRules ? 1 : 0))
            let last = try #require(pressure.lastPressure)
            #expect(last.reason == (acrossRules ? .globalCount : .perRuleCount))
            #expect(last.pendingCountBefore == SequenceEngine.maxPendingTotal + 1)
            #expect(last.stateWeightBytesBefore < pressure.stateWeightLimitBytes)
            #expect(last.rulePendingCountBefore == (acrossRules ? oldCount - secondaryCount + 2 : oldCount + 2))
            #expect(last.partialCountBefore == 0 && last.removedPendingSteps == 1)
            #expect(last.representativeVictimRuleID == primary.id && last.representativeVictimStepID == "b")
            let capture = try await engine.checkpointCapture()
            let retained = Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
            #expect(Set(live.map(\.id)).isSubset(of: retained))
        }
    }

    @Test("Byte pressure retires expired history but still sheds genuinely live overflow", arguments: [false, true])
    func bytePressurePreservesExpiryClassification(expired: Bool) async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let primary = rule(filePath: true)
        // Ordinary in-memory file metadata only: no filesystem activity. Wide
        // valid keys reach the existing byte ceiling far below the count cap.
        let path = "/private/tmp/" + String(repeating: "p", count: 8_192)
        let reference = Date()
        let timestamp = reference.addingTimeInterval(expired ? -90 : -1)
        let template = pending(ruleID: primary.id, at: timestamp, filePath: path)
        let itemWeight = SequenceCheckpointCodec.estimatedWeight(of: template)
        let fixedWeight = SequenceCheckpointCodec.semanticStateBaseWeight
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: primary.id)
        let capacity = (SequenceCheckpointCodec.maximumSemanticStateWeight - fixedWeight) / itemWeight
        #expect(capacity > 2 && capacity + 1 < SequenceEngine.maxPendingTotal)
        let oldCount = capacity - 1
        let bucket = SequenceCheckpointPendingBucket(ruleID: primary.id, steps:
            (0..<oldCount).map { _ in pending(ruleID: primary.id, at: timestamp, filePath: path) })
        try await restore([bucket], rules: [primary], into: engine,
                          at: expired ? timestamp.addingTimeInterval(1) : reference)
        let live = [event(filePath: path), event(filePath: path)]
        _ = await engine.evaluate(live[0])
        let before = await engine.checkpointWeightDiagnostics()
        #expect(before.pendingCount == capacity)
        #expect(before.cachedWeight <= before.maximumWeight)
        #expect(before.cachedWeight + itemWeight > before.maximumWeight)
        #expect(await engine.pendingStepsEvictedTotal == 0)

        _ = await engine.evaluate(live[1])
        let ledger = await engine.pendingStepConservation()
        #expect(ledger.offered == UInt64(oldCount + 2))
        #expect(ledger.inFlight == 0 && ledger.conservationMaintained)
        let after = await engine.checkpointWeightDiagnostics()
        #expect(after.cachedWeight == after.recomputedWeight)
        #expect(after.cachedWeight <= after.maximumWeight)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.classificationConserved)
        #expect(pressure.journalExplicitlyShedTotal == ledger.explicitlyShed)
        #expect(pressure.perRuleCountShedTotal == 0 && pressure.globalCountShedTotal == 0)
        if expired {
            #expect(ledger.completed == UInt64(oldCount))
            #expect(ledger.queued == 2 && ledger.explicitlyShed == 0)
            #expect(await engine.pendingStepsEvictedTotal == 0)
            #expect(pressure.semanticWeightShedTotal == 0 && pressure.lastPressure == nil)
            try await assertRetainedLiveHistory(live, in: engine, ruleID: primary.id, filePath: path)
        } else {
            #expect(ledger.completed == 0 && ledger.explicitlyShed > 0)
            #expect(await engine.pendingStepsEvictedTotal == Int(ledger.explicitlyShed))
            #expect(pressure.semanticWeightShedTotal == ledger.explicitlyShed)
            let last = try #require(pressure.lastPressure)
            #expect(last.reason == .semanticWeight)
            #expect(last.pendingCountBefore == capacity + 1 && last.pendingCountBefore < pressure.globalCountLimit)
            #expect(last.stateWeightBytesBefore > pressure.stateWeightLimitBytes)
            #expect(last.partialCountBefore == 0 && last.removedPendingSteps == ledger.explicitlyShed)
            #expect(last.representativeVictimRuleID == primary.id && last.representativeVictimStepID == "b")
            let capture = try await engine.checkpointCapture()
            let retained = Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
            #expect(Set(live.map(\.id)).isSubset(of: retained), "Actual pressure retains the newest live history")
        }
    }
}
