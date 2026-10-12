import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

/// Ordinary synthetic file metadata only. No files, processes, daemon or live
/// collector are used; wide values exercise the unchanged checkpoint budget.
@Suite("Sequence partial pressure classification")
struct SequencePartialPressureTests {
    private func rule(id: String = "ordinary-pressure", filePath: Bool = false) -> SequenceRule {
        SequenceRule(
            id: id, title: "ordinary file lifecycle", description: "in-memory fixture",
            level: .low, tags: [], window: 60,
            correlationType: filePath ? .filePath : .processSame, ordered: true,
            steps: [
                SequenceStep(id: "created", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: ["create"], negate: false)]),
                SequenceStep(id: "written", logsourceCategory: "file_event",
                    predicates: [Predicate(field: "FileAction", modifier: .equals,
                                           values: ["write"], negate: false)], afterStep: "created"),
            ], trigger: .allSteps
        )
    }

    private func event(initial: Bool = true, path: String = "/private/tmp/ordinary-pressure.txt",
                       at timestamp: Date = Date()) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 41, ppid: 1, rpid: 41, name: "fixture", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: [], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(timestamp: timestamp, eventCategory: .file, eventType: .creation,
            eventAction: initial ? "create" : "write", process: process,
            file: FileInfo(path: path, action: initial ? .create : .write))
    }

    private func matched(_ step: String, at timestamp: Date, path: String? = nil) -> SequenceCheckpointMatchedStep {
        SequenceCheckpointMatchedStep(stepID: step, eventID: UUID(), timestamp: timestamp,
            processPID: 41, processParentPID: 1, processParentWasTracked: false,
            processAncestorPIDs: [], filePath: path, networkDestination: nil)
    }

    private func partial(_ definition: SequenceRule, at timestamp: Date,
                         path: String? = nil) -> SequenceCheckpointPartial {
        SequenceCheckpointPartial(id: UUID(), ruleID: definition.id, createdAt: timestamp,
            matchedSteps: [matched("created", at: timestamp, path: path)],
            correlationKey: path ?? "41")
    }

    private func pending(_ definition: SequenceRule, at timestamp: Date,
                         path: String) -> SequenceCheckpointPendingStep {
        SequenceCheckpointPendingStep(ruleID: definition.id, stepID: "written",
            matched: matched("written", at: timestamp, path: path), arrivedAt: timestamp)
    }

    private func payload(rules: [SequenceRule], partials: [SequenceCheckpointPartial] = [],
                         pending: [SequenceCheckpointPendingStep] = [], at timestamp: Date) throws -> SequenceCheckpointPayload {
        let partialBuckets = Dictionary(grouping: partials, by: \.ruleID).map {
            SequenceCheckpointPartialBucket(ruleID: $0.key, partials: $0.value)
        }.sorted { $0.ruleID < $1.ruleID }
        let pendingBuckets = Dictionary(grouping: pending, by: \.ruleID).map {
            SequenceCheckpointPendingBucket(ruleID: $0.key, steps: $0.value)
        }.sorted { $0.ruleID < $1.ruleID }
        return SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: timestamp, ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(rules),
            sourceGeneration: 1, partialBuckets: partialBuckets, pendingBuckets: pendingBuckets,
            evictionOrder: partials.map(\.id), pendingEvictionOrder: pending.map {
                SequenceCheckpointPendingIdentity(ruleID: $0.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID)
            }
        )
    }

    private func expectZero(_ engine: SequenceEngine) async {
        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountShedTotal == 0 && pressure.semanticWeightShedTotal == 0)
        #expect(pressure.totalShed == 0 && pressure.classificationConserved)
        #expect(!pressure.countersAtLimit && pressure.lastPressure == nil)
        #expect(await engine.partialsEvictedTotal == 0)
    }

    private func capture(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        return try await engine.checkpointCapture()
    }

    @Test("New engine has no pressure observation and exposes unchanged limits")
    func zeroInitialState() async {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4)
        await expectZero(engine)
        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountLimit == 4)
        #expect(pressure.stateWeightLimitBytes == SequenceCheckpointCodec.maximumSemanticStateWeight)
        let fields = SequencePartialPressureHeartbeat.fields(pressure)
        #expect(fields["last_pressure"] == nil)
        #expect(fields.count == 7)
    }

    @Test("Count-only removals classify exact FIFO victims and update only the last boundary")
    func countPressureAndRepeatedBoundaries() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4, sweepInterval: 3_600)
        try await engine.addRule(rule())
        let seeds = (0..<7).map { _ in event() }
        for seed in seeds.prefix(4) { _ = await engine.evaluate(seed) }
        let before = try await capture(engine)
        await expectZero(engine)
        for (index, seed) in seeds.dropFirst(4).enumerated() {
            _ = await engine.evaluate(seed)
            let pressure = await engine.partialPressureDiagnostics()
            #expect(pressure.globalCountShedTotal == index + 1)
            #expect(pressure.semanticWeightShedTotal == 0 && pressure.totalShed == index + 1)
            #expect(pressure.classificationConserved && !pressure.countersAtLimit)
            #expect(pressure.totalShed == (await engine.partialsEvictedTotal))
            let boundary = try #require(pressure.lastPressure)
            #expect(boundary.reason == .globalCount && boundary.removedPartials == 1)
            #expect(boundary.partialCountBefore == 5 && boundary.partialCountAfter == 4)
            #expect(boundary.pendingCountBefore == 0)
            #expect(boundary.stateWeightBytesBefore < pressure.stateWeightLimitBytes)
            #expect(boundary.stateWeightBytesBefore > boundary.stateWeightBytesAfter)
            #expect(boundary.stateWeightBytesAfter == (await engine.checkpointWeightDiagnostics()).cachedWeight)
            #expect(boundary.observedAt.timeIntervalSince1970.isFinite)
        }
        let after = try await capture(engine)
        let survivors = after.partialBuckets.flatMap(\.partials)
        #expect(survivors.flatMap(\.matchedSteps).map(\.eventID) == seeds.suffix(4).map(\.id))
        #expect(survivors.first?.id == before.partialBuckets.flatMap(\.partials).last?.id)
        #expect(after.evictionOrder == survivors.map(\.id))
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("Semantic-only partial pressure remains separate from the count cap")
    func semanticWeightPressure() async throws {
        let definition = rule(filePath: true)
        let reference = Date()
        let path = "/private/tmp/" + String(repeating: "p", count: 8_192)
        let itemWeight = SequenceCheckpointCodec.estimatedWeight(of: partial(definition, at: reference, path: path))
        let fixedWeight = SequenceCheckpointCodec.semanticStateBaseWeight
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: definition.id)
        let capacity = (SequenceCheckpointCodec.maximumSemanticStateWeight - fixedWeight) / itemWeight
        try #require(capacity > 2 && capacity + 2 < 10_000)
        let retained = (0..<capacity).map { _ in partial(definition, at: reference, path: path) }
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(definition)
        let restored = try await engine.restoreCheckpoint(payload(rules: [definition], partials: retained, at: reference))
        #expect(restored.partialCount == capacity)
        await expectZero(engine)
        // The canonical checkpoint projection omits semantically irrelevant
        // lineage for this file-path rule: its parent PID is zero, even though
        // restore itself preserves the template's parent PID of one. Pressure
        // must preserve the complete canonical records, not the raw template.
        let baselineCapture = try await capture(engine)
        let baseline = baselineCapture.partialBuckets.flatMap(\.partials)
        try #require(baseline.count == capacity)
        let baselineIDsPreserved = baseline.map(\.id) == retained.map(\.id)
        let baselineEventIDsPreserved = baseline.flatMap(\.matchedSteps).map(\.eventID)
            == retained.flatMap(\.matchedSteps).map(\.eventID)
        let baselineParentsCanonical = baseline.flatMap(\.matchedSteps).allSatisfy { $0.processParentPID == 0 }
        let baselineOrderPreserved = baselineCapture.evictionOrder == retained.map(\.id)
        #expect(baselineIDsPreserved && baselineEventIDsPreserved && baselineOrderPreserved)
        #expect(baselineParentsCanonical)
        let seeds = [event(path: path), event(path: path)]
        for seed in seeds { _ = await engine.evaluate(seed) }
        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountShedTotal == 0 && pressure.semanticWeightShedTotal == 2)
        #expect(pressure.totalShed == 2 && pressure.classificationConserved)
        #expect(await engine.partialsEvictedTotal == 2)
        let boundary = try #require(pressure.lastPressure)
        #expect(boundary.reason == .semanticWeight && boundary.removedPartials == 1)
        #expect(boundary.partialCountBefore == capacity + 1 && boundary.partialCountAfter == capacity)
        #expect(boundary.partialCountBefore < pressure.globalCountLimit && boundary.pendingCountBefore == 0)
        #expect(boundary.stateWeightBytesBefore > pressure.stateWeightLimitBytes)
        #expect(boundary.stateWeightBytesAfter <= pressure.stateWeightLimitBytes)
        #expect(boundary.stateWeightBytesBefore - boundary.stateWeightBytesAfter == itemWeight)
        let after = try await capture(engine)
        let survivors = after.partialBuckets.flatMap(\.partials)
        // Precompute the exact comparison so a failure cannot make Testing
        // render hundreds of records containing wide synthetic path values.
        #expect(survivors.count == capacity)
        let completeSurvivorRecordsPreserved = Array(survivors.prefix(capacity - 2)) == Array(baseline.dropFirst(2))
        let newestSeedIDsPreserved = survivors.suffix(2).flatMap(\.matchedSteps).map(\.eventID) == seeds.map(\.id)
        let exactFIFOOrderPreserved = after.evictionOrder == survivors.map(\.id)
        #expect(completeSurvivorRecordsPreserved, "Every retained canonical record must equal the baseline suffix, in order")
        #expect(newestSeedIDsPreserved && exactFIFOOrderPreserved)
        #expect(await engine.pendingStepsEvictedTotal == 0)
    }

    @Test("Pending-only byte pressure never increments partial loss reasons")
    func pendingPressureDoesNotBecomePartialPressure() async throws {
        let definition = rule(filePath: true)
        let reference = Date()
        let path = "/private/tmp/" + String(repeating: "p", count: 8_192)
        let itemWeight = SequenceCheckpointCodec.estimatedWeight(of: pending(definition, at: reference, path: path))
        let fixedWeight = SequenceCheckpointCodec.semanticStateBaseWeight
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: definition.id)
        let capacity = (SequenceCheckpointCodec.maximumSemanticStateWeight - fixedWeight) / itemWeight
        try #require(capacity > 1 && capacity + 1 < SequenceEngine.maxPendingTotal)
        let retained = (0..<capacity).map { _ in pending(definition, at: reference, path: path) }
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(definition)
        _ = try await engine.restoreCheckpoint(payload(rules: [definition], pending: retained, at: reference))
        let next = event(initial: false, path: path)
        _ = await engine.evaluate(next)
        let pendingPressure = await engine.pendingPressureDiagnostics()
        #expect(pendingPressure.semanticWeightShedTotal == 1 && pendingPressure.classificationConserved)
        #expect(await engine.pendingStepsEvictedTotal == 1)
        await expectZero(engine)
        let after = try await capture(engine)
        #expect(after.partialBuckets.isEmpty)
        let exactPendingIDsPreserved = after.pendingBuckets.flatMap(\.steps).map(\.matched.eventID)
            == retained.dropFirst().map(\.matched.eventID) + [next.id]
        #expect(exactPendingIDsPreserved)
    }

    @Test("Completion and explicit rule retirement are not capacity loss", arguments: [false, true])
    func normalRetirementDoesNotCount(disableRule: Bool) async throws {
        let definition = rule()
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4)
        try await engine.addRule(definition)
        for _ in 0..<3 { _ = await engine.evaluate(event()) }
        if disableRule {
            await engine.setEnabled(definition.id, enabled: false)
        } else {
            #expect(await engine.evaluate(event(initial: false)).count == 3)
        }
        #expect(try await capture(engine).partialBuckets.isEmpty)
        await expectZero(engine)
    }

    @Test("Pressure boundary excludes already-expired partials without sleeping")
    func expiryIsRetiredBeforePressureObservation() async throws {
        // Three initial partials are below the preemptive sweep threshold (3).
        // One event seeds three rules, then the count-pressure sweep removes
        // the expired record before measuring the actual 5 -> 4 boundary.
        let definitions = [rule(id: "a"), rule(id: "b"), rule(id: "c")]
        let reference = Date()
        let old = reference.addingTimeInterval(-90)
        let retained = [partial(definitions[0], at: old),
                        partial(definitions[0], at: reference.addingTimeInterval(-1)),
                        partial(definitions[0], at: reference.addingTimeInterval(-1))]
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4, sweepInterval: 3_600)
        for definition in definitions { try await engine.addRule(definition) }
        let restored = try await engine.restoreCheckpoint(
            payload(rules: definitions, partials: retained, at: reference), now: old.addingTimeInterval(1))
        #expect(restored.partialCount == 3 && restored.expiredPartialCount == 0)
        _ = await engine.evaluate(event())
        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountShedTotal == 1 && pressure.totalShed == 1)
        #expect(pressure.semanticWeightShedTotal == 0 && pressure.classificationConserved)
        let boundary = try #require(pressure.lastPressure)
        #expect(boundary.partialCountBefore == 5 && boundary.partialCountAfter == 4)
        #expect(boundary.removedPartials == 1 && boundary.reason == .globalCount)
        let after = try await capture(engine)
        let survivors = Set(after.partialBuckets.flatMap(\.partials).map(\.id))
        #expect(!survivors.contains(retained[0].id), "Expired identity was retired")
        #expect(!survivors.contains(retained[1].id), "Oldest remaining identity was the one actual eviction")
        #expect(survivors.contains(retained[2].id))
        #expect(after.evictionOrder.first == retained[2].id)
    }

    @Test("Checkpoint restore starts a new pressure epoch and expiry-only restore stays zero")
    func restoreDoesNotReplayLifetimeTelemetry() async throws {
        let definition = rule()
        let source = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 2)
        try await source.addRule(definition)
        for _ in 0..<3 { _ = await source.evaluate(event()) }
        #expect(await source.partialPressureDiagnostics().totalShed == 1)
        let retained = try await capture(source)
        for expire in [false, true] {
            let target = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 2)
            try await target.addRule(definition)
            let restored = try await target.restoreCheckpoint(
                payload(rules: [definition], partials: retained.partialBuckets.flatMap(\.partials), at: retained.capturedAt),
                now: retained.capturedAt.addingTimeInterval(expire ? 90 : 0))
            #expect(restored.partialCount == (expire ? 0 : 2))
            #expect(restored.expiredPartialCount == (expire ? 2 : 0))
            await expectZero(target)
        }
    }

    @Test("Reason totals and classification use non-trapping saturation")
    func saturation() {
        var totals = SequenceEngine.PartialPressureTotals()
        totals.record(Int.max - 1, reason: .globalCount)
        totals.record(2, reason: .semanticWeight)
        #expect(totals.globalCount == Int.max - 1 && totals.semanticWeight == 2)
        #expect(totals.classifiedTotal == Int.max)
        totals.record(2, reason: .globalCount)
        totals.record(Int.max, reason: .semanticWeight)
        #expect(totals.globalCount == Int.max && totals.semanticWeight == Int.max)
        #expect(totals.classifiedTotal == Int.max)
        totals.record(0, reason: .globalCount)
        totals.record(-1, reason: .semanticWeight)
        #expect(totals.globalCount == Int.max && totals.semanticWeight == Int.max)
        #expect(SequenceEngine.saturatingTelemetryAdd(Int.max - 1, 2) == totals.classifiedTotal)
    }

    @Test("Concurrent readers receive producer-consistent totals, independent of scheduling")
    func producerAtomicSnapshots() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 4)
        try await engine.addRule(rule())
        let seeds = (0..<40).map { _ in event() }
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                for seed in seeds { _ = await engine.evaluate(seed) }
            }
            for _ in 0..<3 {
                group.addTask {
                    for _ in 0..<40 {
                        let pressure = await engine.partialPressureDiagnostics()
                        #expect(pressure.classificationConserved)
                        #expect(pressure.globalCountShedTotal == pressure.totalShed)
                        #expect(pressure.semanticWeightShedTotal == 0)
                        if let boundary = pressure.lastPressure {
                            #expect(pressure.totalShed > 0)
                            #expect(boundary.reason == .globalCount && boundary.removedPartials == 1)
                            #expect(boundary.partialCountBefore == 5 && boundary.partialCountAfter == 4)
                        } else {
                            #expect(pressure.totalShed == 0)
                        }
                    }
                }
            }
        }
        #expect(await engine.partialPressureDiagnostics().totalShed == 36)
        let final = try await capture(engine)
        #expect(final.partialBuckets.flatMap(\.partials).flatMap(\.matchedSteps).map(\.eventID)
                == seeds.suffix(4).map(\.id))
    }

    @Test("Production heartbeat projection is fixed-schema and contains no fixture identities or labels")
    func heartbeatProjection() async throws {
        let definition = rule(id: "PRIVATE_FIXTURE_RULE_LABEL")
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 1)
        try await engine.addRule(definition)
        let seeds = [event(path: "/private/tmp/PRIVATE_FIXTURE_PATH"), event()]
        for seed in seeds { _ = await engine.evaluate(seed) }
        let pressure = await engine.partialPressureDiagnostics()
        let fields = SequencePartialPressureHeartbeat.fields(pressure)
        #expect(Set(fields.keys) == Set([
            "global_count_shed_partials_total", "semantic_weight_shed_partials_total", "total_shed_partials",
            "classification_conserved", "counters_at_limit", "global_count_limit", "state_weight_limit_bytes", "last_pressure",
        ]))
        #expect(fields["total_shed_partials"] as? Int == 1)
        #expect(fields["global_count_shed_partials_total"] as? Int == 1)
        #expect(fields["semantic_weight_shed_partials_total"] as? Int == 0)
        #expect(fields["classification_conserved"] as? Bool == true)
        let boundary = try #require(fields["last_pressure"] as? [String: Any])
        #expect(Set(boundary.keys) == Set([
            "reason", "observed_at_unix", "pending_count_before", "partial_count_before", "partial_count_after",
            "state_weight_bytes_before", "state_weight_bytes_after", "removed_partials",
        ]))
        #expect(boundary["reason"] as? String == "global_count")
        #expect(boundary["partial_count_before"] as? Int == 2 && boundary["partial_count_after"] as? Int == 1)
        let encoded = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        let json = try #require(String(data: encoded, encoding: .utf8))
        #expect(!json.contains(definition.id) && !json.contains("PRIVATE_FIXTURE_PATH"))
        for seed in seeds { #expect(!json.contains(seed.id.uuidString)) }
        #expect(encoded.count < 1_024, "A boundary remains constant-size regardless of event content")
    }
}
