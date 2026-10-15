import Foundation
import Testing
@testable import MacCrabCore

/// Inert in-memory file/network metadata and private temporary checkpoint
/// carriers only. No real process, collector, network or installed store is used.
@Suite("Compact sequence checkpoint capacity and exact recovery")
struct SequenceCompactCheckpointTests {
    private func rule(id: String = "ordinary-compact", correlation: CorrelationType = .none,
                      relation: ProcessRelation? = nil, steps: Int = 3,
                      window: TimeInterval = 3_600) -> SequenceRule {
        let actions: [FileAction] = [.create, .write, .close]
        return SequenceRule(id: id, title: "Ordinary metadata progression",
            description: "benign in-memory fixture", level: .low, tags: [], window: window,
            correlationType: correlation, ordered: true,
            steps: (0..<steps).map { index in
                SequenceStep(id: "step-\(index)",
                    logsourceCategory: correlation == .networkEndpoint ? "network_connection" : "file_event",
                    predicates: [Predicate(field: "CommandLine", modifier: .equals,
                                           values: [actions[index].rawValue], negate: false)],
                    afterStep: index > 0 ? "step-\(index - 1)" : nil,
                    processRelation: index == steps - 1 ? relation.map {
                        ProcessRelationSpec(relation: $0, relativeToStep: "step-0")
                    } : nil)
            }, trigger: .allSteps)
    }

    private func event(_ action: FileAction, pid: Int32 = 41, ppid: Int32 = 1,
                       at timestamp: Date, path: String = "/private/tmp/ordinary-compact.txt",
                       network: Bool = false, destination: String = "192.0.2.10") -> Event {
        let process = MacCrabCore.ProcessInfo(pid: pid, ppid: ppid, rpid: pid,
            name: "fixture", executable: "/usr/bin/true", commandLine: action.rawValue,
            args: [], workingDirectory: "/private/tmp", userId: 501, userName: "fixture",
            groupId: 20, startTime: timestamp)
        return Event(timestamp: timestamp, eventCategory: network ? .network : .file,
            eventType: .info, eventAction: action.rawValue, process: process,
            file: network ? nil : FileInfo(path: path, action: action),
            network: network ? NetworkInfo(sourceIp: "192.0.2.1", sourcePort: 12_345,
                destinationIp: destination, destinationPort: 443, direction: .outbound,
                transport: "tcp") : nil)
    }

    private func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    private func capture(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.maximumWeight == 7_864_320 && weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        return try await engine.checkpointCapture()
    }

    private func roundTrip(_ saved: SequenceCheckpointCapture) throws -> SequenceCheckpointPayload {
        let prepared = try SequenceCheckpointCodec.prepare(saved)
        #expect(prepared.payload.schemaVersion == 2)
        let estimated = SequenceCheckpointCodec.estimatedSemanticStateWeight(
            partialBuckets: saved.partialBuckets, pendingBuckets: saved.pendingBuckets)
        #expect(try encoder().encode(prepared.payload).count <= estimated)
        #expect(prepared.encodedFile.count <= 8_388_608)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-compact-checkpoint-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("ordinary.chk")
        try SequenceCheckpointFileStore.write(prepared.encodedFile, to: file)
        let storedBytes = try SequenceCheckpointFileStore.read(from: file)
        let bytes = try #require(storedBytes)
        let decoded = try SequenceCheckpointCodec.decode(bytes)
        let exactPayloadPreserved = decoded == prepared.payload
        #expect(exactPayloadPreserved, "Private carrier round-trip must preserve every logical field")
        #expect(try SequenceCheckpointCodec.semanticDigest(of: decoded) == prepared.semanticDigest)
        return decoded
    }

    private func expectSameRecords(_ lhs: SequenceCheckpointCapture, _ rhs: SequenceCheckpointCapture) {
        let same = lhs.partialBuckets == rhs.partialBuckets && lhs.pendingBuckets == rhs.pendingBuckets
            && lhs.evictionOrder == rhs.evictionOrder && lhs.pendingEvictionOrder == rhs.pendingEvictionOrder
        #expect(same, "All retained records, bindings and both FIFO orders must remain exact")
    }

    @Test("Both constructors clamp requested capacity to the explicit 1 through 13k contract")
    func bothInitializerCapacityBoundaries() async {
        for (requested, expected) in [(Int.min, 1), (0, 1), (1, 1),
                                      (13_000, 13_000), (13_001, 13_000), (Int.max, 13_000)] {
            let ordinary = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: requested)
            let boundedQueue = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: requested,
                                              mutationWaiterLimit: 1)
            let ordinaryConfiguration = await ordinary.configurationDiagnostics()
            let boundedConfiguration = await boundedQueue.configurationDiagnostics()
            #expect(ordinaryConfiguration.maxPartialMatches == expected)
            #expect(boundedConfiguration.maxPartialMatches == expected)
            #expect(await ordinary.activePartialMatchCount == 0)
            #expect(await boundedQueue.activePartialMatchCount == 0)
        }
    }

    @Test("13k distinct admitted states fit unchanged byte budgets; overflow remains visible and FIFO-exact")
    func distinctCapacityPressureAndRecovery() async throws {
        let definition = rule(steps: 2)
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await engine.addRule(definition)
        #expect(await engine.configurationDiagnostics().maxPartialMatches == 13_000)
        #expect(SequenceCheckpointCodec.maximumFileBytes == 8_388_608)
        #expect(SequenceCheckpointCodec.maximumUncompressedBytes == 33_554_432)
        #expect(SequenceEngine.maxPendingTotal == 8_192)
        let time = Date().addingTimeInterval(-10)
        var seedIDs: [UUID] = []
        seedIDs.reserveCapacity(13_001)
        for index in 0..<13_000 {
            let seed = event(.create, pid: 1_000 + Int32(index), at: time)
            seedIDs.append(seed.id)
            let completed = await engine.evaluate(seed)
            #expect(completed.isEmpty)
        }
        let before = try await capture(engine)
        let beforePartials = before.partialBuckets.flatMap(\.partials)
        let beforeIDsExact = beforePartials.flatMap(\.matchedSteps).map(\.eventID) == seedIDs
        #expect(beforePartials.count == 13_000 && beforeIDsExact)
        #expect(Set(beforePartials.map(\.id)).count == 13_000)
        #expect(beforePartials.allSatisfy { $0.correlationKey == nil })
        #expect(await engine.partialPressureDiagnostics().totalShed == 0)
        let layout = await engine.partialRepresentationDiagnostics()
        #expect(layout.partialCount == 13_000 && layout.inlineSingleBindings == 13_000)
        #expect(layout.emptyBindings == 0 && layout.dictionaryBindings == 0 && layout.totalMatchedSteps == 13_000)

        let newest = event(.create, pid: 14_000, at: time)
        seedIDs.append(newest.id)
        #expect(await engine.evaluate(newest).isEmpty)
        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountLimit == 13_000 && pressure.globalCountShedTotal == 1)
        #expect(pressure.semanticWeightShedTotal == 0 && pressure.totalShed == 1 && pressure.classificationConserved)
        let boundary = try #require(pressure.lastPressure)
        #expect(boundary.reason == .globalCount && boundary.partialCountBefore == 13_001)
        #expect(boundary.partialCountAfter == 13_000 && boundary.removedPartials == 1)
        let saved = try await capture(engine)
        let survivors = saved.partialBuckets.flatMap(\.partials)
        let survivorEventsExact = survivors.flatMap(\.matchedSteps).map(\.eventID) == Array(seedIDs.dropFirst())
        let survivorRecordsExact = Array(survivors.dropLast()) == Array(beforePartials.dropFirst())
        let fifoExact = saved.evictionOrder == survivors.map(\.id)
        #expect(survivors.count == 13_000 && survivorEventsExact && survivorRecordsExact && fifoExact)

        let decoded = try roundTrip(saved)
        let target = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await target.addRule(definition)
        let applied = try await target.restoreCheckpoint(decoded, now: saved.capturedAt)
        #expect(applied.partialCount == 13_000 && applied.pendingCount == 0)
        expectSameRecords(saved, try await capture(target))
        #expect(await target.partialPressureDiagnostics().totalShed == 0,
                "Old pressure telemetry is not replayed into the new process epoch")
        let finish = event(.write, pid: 30_000, at: time.addingTimeInterval(1))
        let uninterrupted = await engine.evaluate(finish)
        let recovered = await target.evaluate(finish)
        let allCompletionsExact = recovered == uninterrupted
        #expect(uninterrupted.count == 13_000 && allCompletionsExact)
        #expect(Set(recovered.map(\.description)).count == 13_000,
                "Distinct seed PIDs must retain distinct complete sequence descriptions")
        #expect(recovered.allSatisfy { $0.ruleId == definition.id })
        #expect(try await capture(target).partialBuckets.isEmpty)
        let sourceLoss = await engine.partialsEvictedTotal, restoredLoss = await target.partialsEvictedTotal
        #expect(sourceLoss == 1 && restoredLoss == 0)
        print("SEQUENCE_COMPACT_BENIGN_CAPACITY partials=13000 semantic_bytes=\(SequenceCheckpointCodec.estimatedSemanticStateWeight(partialBuckets: saved.partialBuckets, pendingBuckets: saved.pendingBuckets)) payload_bytes=\(try encoder().encode(decoded).count)")
    }

    @Test("Every correlation mode preserves two bindings and exact completions through v2",
          arguments: [CorrelationType.processSame, .processLineage, .filePath, .networkEndpoint, .none])
    func correlationRecovery(correlation: CorrelationType) async throws {
        let definition = rule(correlation: correlation)
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(definition)
        let time = Date().addingTimeInterval(-10)
        let first = event(.create, pid: 100, at: time, network: correlation == .networkEndpoint)
        let laterPID: Int32 = correlation == .processLineage ? 200 : 100
        let laterParent: Int32 = correlation == .processLineage ? 100 : 1
        let middle = event(.write, pid: laterPID, ppid: laterParent,
                           at: time.addingTimeInterval(1), network: correlation == .networkEndpoint)
        #expect(await source.evaluate(first).isEmpty)
        #expect(await source.evaluate(middle).isEmpty)
        let saved = try await capture(source)
        let partial = try #require(saved.partialBuckets.first?.partials.first)
        #expect(partial.matchedSteps.map(\.eventID) == [first.id, middle.id])
        let representation = await source.partialRepresentationDiagnostics()
        #expect(representation.dictionaryBindings == 1 && representation.totalMatchedSteps == 2)
        let target = SequenceEngine(lineage: ProcessLineage())
        try await target.addRule(definition)
        _ = try await target.restoreCheckpoint(roundTrip(saved), now: saved.capturedAt)
        expectSameRecords(saved, try await capture(target))
        let finish = event(.close, pid: laterPID, ppid: laterParent,
                           at: time.addingTimeInterval(2), network: correlation == .networkEndpoint)
        let expected = await source.evaluate(finish)
        let actual = await target.evaluate(finish)
        #expect(expected.count == 1 && actual == expected)
        #expect(await target.partialPressureDiagnostics().totalShed == 0)
    }

    @Test("Every process relation uses the same persisted binding proof after restart",
          arguments: [ProcessRelation.same, .sameProcess, .descendant, .ancestor, .sibling, .sameTree, .any])
    func processRelationRecovery(relation: ProcessRelation) async throws {
        let definition = rule(relation: relation)
        let time = Date().addingTimeInterval(-10)
        let firstPID: Int32 = relation == .ancestor ? 200 : 100
        let firstParent: Int32 = relation == .ancestor ? 100 : (relation == .sibling ? 70 : 1)
        let finalPID: Int32
        let finalParent: Int32
        switch relation {
        case .same, .sameProcess: finalPID = firstPID; finalParent = firstParent
        case .ancestor: finalPID = 100; finalParent = 1
        case .descendant, .sameTree: finalPID = 300; finalParent = firstPID
        case .sibling: finalPID = 300; finalParent = 70
        case .any: finalPID = 999; finalParent = 1
        }
        let liveLineage = ProcessLineage(), restoredLineage = ProcessLineage()
        if relation == .sibling {
            for lineage in [liveLineage, restoredLineage] {
                await lineage.recordProcess(pid: 70, ppid: 1, path: "/usr/bin/true", name: "fixture", startTime: time)
            }
        }
        await liveLineage.recordProcess(pid: firstPID, ppid: firstParent, path: "/usr/bin/true", name: "fixture", startTime: time)
        let source = SequenceEngine(lineage: liveLineage)
        try await source.addRule(definition)
        #expect(await source.evaluate(event(.create, pid: firstPID, ppid: firstParent, at: time)).isEmpty)
        #expect(await source.evaluate(event(.write, pid: firstPID, ppid: firstParent, at: time.addingTimeInterval(1))).isEmpty)
        let saved = try await capture(source)
        let target = SequenceEngine(lineage: restoredLineage)
        try await target.addRule(definition)
        _ = try await target.restoreCheckpoint(roundTrip(saved), now: saved.capturedAt)
        expectSameRecords(saved, try await capture(target))
        for lineage in [liveLineage, restoredLineage] {
            await lineage.recordProcess(pid: finalPID, ppid: finalParent, path: "/usr/bin/true", name: "fixture", startTime: time.addingTimeInterval(2))
        }
        let finish = event(.close, pid: finalPID, ppid: finalParent, at: time.addingTimeInterval(2))
        let expected = await source.evaluate(finish)
        let actual = await target.evaluate(finish)
        #expect(expected.count == 1 && actual == expected)
    }

    @Test("Pending history replays distinct delayed seeds after compact recovery without becoming consumable")
    func pendingReplayRecovery() async throws {
        let definition = rule()
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(definition)
        let time = Date().addingTimeInterval(-10)
        let middle = event(.write, at: time.addingTimeInterval(1))
        #expect(await source.evaluate(middle).isEmpty)
        let saved = try await capture(source)
        #expect(saved.partialBuckets.isEmpty && saved.pendingBuckets.flatMap(\.steps).count == 1)
        let target = SequenceEngine(lineage: ProcessLineage())
        try await target.addRule(definition)
        _ = try await target.restoreCheckpoint(roundTrip(saved), now: saved.capturedAt)
        expectSameRecords(saved, try await capture(target))
        for pid in [Int32(101), 102, 103] {
            let seed = event(.create, pid: pid, at: time)
            #expect(await source.evaluate(seed).isEmpty)
            #expect(await target.evaluate(seed).isEmpty)
        }
        let live = try await capture(source), recovered = try await capture(target)
        // Each engine legitimately allocates new partial UUIDs; compare exact
        // matched evidence and ordering rather than equating random identities.
        #expect(live.partialBuckets.flatMap(\.partials).map(\.matchedSteps) == recovered.partialBuckets.flatMap(\.partials).map(\.matchedSteps))
        #expect(recovered.partialBuckets.flatMap(\.partials).count == 3)
        #expect(recovered.pendingBuckets == saved.pendingBuckets && recovered.pendingEvictionOrder == saved.pendingEvictionOrder)
        let finish = event(.close, at: time.addingTimeInterval(2))
        let expected = await source.evaluate(finish), actual = await target.evaluate(finish)
        // Creation times are process-local for delayed new seeds, so their
        // rounded elapsed description is not an identity oracle in this test.
        #expect(expected.count == 3 && actual.count == 3)
        #expect(actual.allSatisfy { $0.ruleId == definition.id })
        #expect(await target.pendingStepConservation().conservationMaintained)
        #expect(await target.pendingStepsEvictedTotal == 0)
    }

    @Test("Rule-window expiration on restore is exact retirement, never pressure loss")
    func expiryOnRecovery() async throws {
        let definition = rule(window: 20)
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(definition)
        let time = Date().addingTimeInterval(-2)
        #expect(await source.evaluate(event(.create, at: time)).isEmpty)
        #expect(await source.evaluate(event(.write, at: time.addingTimeInterval(1))).isEmpty)
        let saved = try await capture(source)
        let payload = try roundTrip(saved)
        for expired in [false, true] {
            let target = SequenceEngine(lineage: ProcessLineage())
            try await target.addRule(definition)
            let applied = try await target.restoreCheckpoint(payload,
                now: saved.capturedAt.addingTimeInterval(expired ? 21 : 0))
            #expect(applied.partialCount == (expired ? 0 : 1))
            #expect(applied.pendingCount == (expired ? 0 : 1))
            #expect(applied.expiredPartialCount == (expired ? 1 : 0))
            #expect(applied.expiredPendingCount == (expired ? 1 : 0))
            #expect(await target.partialPressureDiagnostics().totalShed == 0)
            #expect(await target.pendingStepsEvictedTotal == 0)
        }
    }
}
