import Foundation
import Testing
@testable import MacCrabCore

/// In-memory synthetic process and file events only: no files, processes,
/// daemon or collectors. Event times are fixed. Arrival ages come from
/// restoring checkpoint history at a chosen instant, and every engine sweeps
/// periodically only once an hour, so only the pressure path retires history.
/// Serialized because several cases drive a full 8,192-entry table.
@Suite("Sequence capacity: fairness, folding and saturation cost", .serialized)
struct SequencePendingFairnessTests {
    private let base = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Rules

    /// Ordered lineage rule: a `/seeder` exec, then a descendant `/writer` file
    /// write, then a descendant `/writer` connection.
    private func ruleD(id: String = "fairness-lineage",
                       correlation: CorrelationType = .processLineage) -> SequenceRule {
        SequenceRule(
            id: id, title: "lineage writer fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600, correlationType: correlation, ordered: true,
            steps: [
                SequenceStep(id: "seed", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/seeder"], negate: false)]),
                SequenceStep(id: "write", logsourceCategory: "file_event",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/writer"], negate: false)],
                             processRelation: ProcessRelationSpec(relation: .descendant, relativeToStep: "seed")),
                SequenceStep(id: "finish", logsourceCategory: "network_connection",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/writer"], negate: false)],
                             processRelation: ProcessRelationSpec(relation: .descendant, relativeToStep: "seed")),
            ], trigger: .allSteps
        )
    }

    /// Ordered `.processSame` rule: a seed exec, then a later exec by the same PID.
    private func ruleS(id: String, seedSuffix: String, laterSuffix: String,
                       window: TimeInterval = 3_600) -> SequenceRule {
        SequenceRule(
            id: id, title: "same-process fixture", description: "in-memory fixture",
            level: .low, tags: [], window: window, correlationType: .processSame, ordered: true,
            steps: [
                SequenceStep(id: "seed", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/\(seedSuffix)"], negate: false)]),
                SequenceStep(id: "later", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/\(laterSuffix)"], negate: false)],
                             afterStep: "seed"),
            ], trigger: .allSteps
        )
    }

    /// Ordered, uncorrelated seed and finish execs, for the partial pool.
    private func seedFinishRule(id: String, prefix: String) -> SequenceRule {
        SequenceRule(
            id: id, title: "uncorrelated seed fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600, correlationType: .none, ordered: true,
            steps: [
                SequenceStep(id: "seed", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/\(prefix)-seed"], negate: false)]),
                SequenceStep(id: "finish", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/\(prefix)-finish"], negate: false)],
                             afterStep: "seed"),
            ], trigger: .allSteps
        )
    }

    /// File-path rule whose partials carry a wide path, for the weight budget.
    private func filePathRule(id: String, imageSuffix: String) -> SequenceRule {
        func step(_ id: String, action: String) -> SequenceStep {
            SequenceStep(id: id, logsourceCategory: "file_event",
                         predicates: [Predicate(field: "Image", modifier: .endswith,
                                                values: ["/\(imageSuffix)"], negate: false),
                                      Predicate(field: "FileAction", modifier: .equals,
                                                values: [action], negate: false)],
                         afterStep: id == "created" ? nil : "created")
        }
        return SequenceRule(
            id: id, title: "wide file lifecycle fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600, correlationType: .filePath, ordered: true,
            steps: [step("created", action: "create"), step("written", action: "write")],
            trigger: .allSteps
        )
    }

    // MARK: - Events

    private func proc(_ executable: String, pid: Int32, at timestamp: Date, id: UUID = UUID()) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid, name: (executable as NSString).lastPathComponent,
            executable: executable, commandLine: executable, args: [executable],
            workingDirectory: "/private/tmp", userId: 501, userName: "fixture", groupId: 20,
            startTime: timestamp
        )
        return Event(id: id, timestamp: timestamp, eventCategory: .process, eventType: .start,
                     eventAction: "exec", process: process)
    }

    /// A `/writer` file write; it carries an ES audit identity only when
    /// `pidVersion` is set.
    private func write(pid: Int32, pidVersion: UInt32? = nil, ppid: Int32 = 1, ancestors: [Int32] = [],
                       at timestamp: Date, path: String = "/private/tmp/fairness/output") -> Event {
        let executable = "/usr/local/bin/writer"
        let identity = pidVersion.map {
            AuditIdentity(auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
                          pid: pid, pidversion: $0, asid: 100_001)
        }
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: ppid, rpid: pid, name: "writer", executable: executable,
            commandLine: executable, args: [executable], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp,
            ancestors: ancestors.map { ProcessAncestor(pid: $0, executable: "/bin/sh", name: "sh") },
            auditIdentity: identity
        )
        return Event(timestamp: timestamp, eventCategory: .file, eventType: .creation,
                     eventAction: "write", process: process, file: FileInfo(path: path, action: .write))
    }

    private func wideFileEvent(imageSuffix: String, path: String, at timestamp: Date) -> Event {
        let executable = "/usr/local/bin/\(imageSuffix)"
        let process = MacCrabCore.ProcessInfo(
            pid: 41, ppid: 1, rpid: 41, name: imageSuffix, executable: executable,
            commandLine: executable, args: [executable], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp
        )
        return Event(timestamp: timestamp, eventCategory: .file, eventType: .creation,
                     eventAction: "create", process: process, file: FileInfo(path: path, action: .create))
    }

    // MARK: - Restored state

    /// Restored later-step records with unique event IDs, no parent or
    /// ancestry, and event times after `base`.
    private func filler(_ rule: SequenceRule, stepID: String, count: Int, pid: Int32 = 9_999,
                        arrivedAt: Date) -> [SequenceCheckpointPendingStep] {
        (0..<count).map { index in
            SequenceCheckpointPendingStep(
                ruleID: rule.id, stepID: stepID,
                matched: SequenceCheckpointMatchedStep(
                    stepID: stepID, eventID: UUID(), timestamp: base.addingTimeInterval(Double(index + 1)),
                    processPID: pid, processParentPID: 0, processParentWasTracked: false,
                    processAncestorPIDs: [], filePath: nil, networkDestination: nil
                ), arrivedAt: arrivedAt
            )
        }
    }

    private func widePartial(_ rule: SequenceRule, path: String, at timestamp: Date) -> SequenceCheckpointPartial {
        SequenceCheckpointPartial(
            id: UUID(), ruleID: rule.id, createdAt: timestamp,
            matchedSteps: [SequenceCheckpointMatchedStep(
                stepID: "created", eventID: UUID(), timestamp: timestamp,
                processPID: 41, processParentPID: 0, processParentWasTracked: false,
                processAncestorPIDs: [], filePath: path, networkDestination: nil
            )],
            correlationKey: path
        )
    }

    private func identity(_ record: SequenceCheckpointPendingStep) -> SequenceCheckpointPendingIdentity {
        SequenceCheckpointPendingIdentity(ruleID: record.ruleID, stepID: record.stepID,
                                          eventID: record.matched.eventID)
    }

    private func identity(_ rule: SequenceRule, _ stepID: String, _ event: Event) -> SequenceCheckpointPendingIdentity {
        SequenceCheckpointPendingIdentity(ruleID: rule.id, stepID: stepID, eventID: event.id)
    }

    /// Install `rules` and restore the given history at `now`. The persisted
    /// global pending order defaults to the records' order.
    private func restore(
        _ engine: SequenceEngine, rules: [SequenceRule],
        pending: [SequenceCheckpointPendingStep] = [],
        order: [SequenceCheckpointPendingIdentity]? = nil,
        partials: [SequenceCheckpointPartial] = [],
        now: Date
    ) async throws {
        for rule in rules { try await engine.addRule(rule) }
        let pendingBuckets = rules.compactMap { rule -> SequenceCheckpointPendingBucket? in
            let steps = pending.filter { $0.ruleID == rule.id }
            return steps.isEmpty ? nil : SequenceCheckpointPendingBucket(ruleID: rule.id, steps: steps)
        }
        let partialBuckets = rules.compactMap { rule -> SequenceCheckpointPartialBucket? in
            let records = partials.filter { $0.ruleID == rule.id }
            return records.isEmpty ? nil : SequenceCheckpointPartialBucket(ruleID: rule.id, partials: records)
        }
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: now, ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(rules),
            sourceGeneration: 1, partialBuckets: partialBuckets, pendingBuckets: pendingBuckets,
            evictionOrder: partials.map(\.id), pendingEvictionOrder: order ?? pending.map { identity($0) }
        )
        let restored = try await engine.restoreCheckpoint(payload, now: now)
        #expect(restored.pendingCount == pending.count && restored.partialCount == partials.count)
        #expect(restored.expiredPendingCount == 0 && restored.expiredPartialCount == 0)
    }

    /// One rule's restored filler bucket, in bucket order.
    @discardableResult
    private func restoreFiller(
        _ engine: SequenceEngine, _ rule: SequenceRule, stepID: String, count: Int,
        pid: Int32 = 9_999, arrivedAt: Date, now: Date
    ) async throws -> [SequenceCheckpointPendingStep] {
        let records = filler(rule, stepID: stepID, count: count, pid: pid, arrivedAt: arrivedAt)
        try await restore(engine, rules: [rule], pending: records, now: now)
        return records
    }

    /// Exact weight, journal and pressure accounting, then a capture, which
    /// proves both global queues exactly cover the live state.
    @discardableResult
    private func assertExact(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.cachedWeight <= weight.maximumWeight)
        #expect(await engine.pendingStepConservation().conservationMaintained)
        for ledger in await engine.pendingStepConservationByRule().values {
            #expect(ledger.conservationMaintained)
        }
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.classificationConserved)
        #expect(pressure.victimPolicy == "largest_bucket_oldest_first")
        let evicted = await engine.pendingStepsEvictedTotal
        #expect(pressure.journalExplicitlyShedTotal == UInt64(evicted))
        #expect(await engine.partialPressureDiagnostics().classificationConserved)
        return try await engine.checkpointCapture()
    }

    // MARK: - Pending fairness

    @Test("A flooding rule sheds only its own pending history")
    func hotRuleFloodShedsOnlyItsOwnHistory() async throws {
        let hot = ruleS(id: "fairness-hot", seedSuffix: "hot-seed", laterSuffix: "hot-later")
        let victim = ruleS(id: "fairness-victim", seedSuffix: "victim-seed", laterSuffix: "victim-later")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let capacity = SequenceEngine.maxPendingTotal
        #expect(SequenceEngine.maxPendingPerRule == 8_192 && SequenceEngine.maxPendingTotal == 8_192)
        // The victim's history leads the persisted global order, which is where
        // the earlier global FIFO took its victims.
        let victimHistory = filler(victim, stepID: "later", count: 20, pid: 500, arrivedAt: reference)
        let hotHistory = filler(hot, stepID: "later", count: capacity - victimHistory.count, arrivedAt: reference)
        try await restore(engine, rules: [hot, victim], pending: victimHistory + hotHistory, now: reference)
        let flood = 828
        for index in 0..<flood {
            _ = await engine.evaluate(proc("/usr/local/bin/hot-later", pid: 10_000 + Int32(index),
                                           at: base.addingTimeInterval(Double(index))))
        }

        let expectedShed = UInt64(victimHistory.count + hotHistory.count + flood - capacity)
        #expect(expectedShed == 828)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[hot.id]?.explicitlyShed == expectedShed)
        #expect(byRule[victim.id]?.explicitlyShed == 0 && byRule[victim.id]?.queued == 20)
        #expect(await engine.pendingStepsEvictedTotal == Int(expectedShed))
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.globalCountShedTotal == expectedShed && pressure.perRuleCountShedTotal == 0)
        #expect(pressure.semanticWeightShedTotal == 0)
        let last = try #require(pressure.lastPressure)
        #expect(last.reason == .globalCount && last.representativeVictimRuleID == hot.id)
        #expect(last.representativeVictimStepID == "later" && last.removedPendingSteps == 1)
        #expect(last.rulePendingCountBefore == 8_173 && last.pendingCountBefore == 8_193)

        let matches = await engine.evaluate(proc("/usr/local/bin/victim-seed", pid: 500, at: base))
        #expect(matches.contains { $0.ruleId == victim.id },
                "the quiet rule's retained history still completes its late seed")
        let capture = try await assertExact(engine)
        let retained = Set(capture.pendingBuckets.first { $0.ruleID == victim.id }?.steps.map(\.matched.eventID) ?? [])
        #expect(retained == Set(victimHistory.map(\.matched.eventID)))
    }

    @Test("Expired history in another bucket retires before any live entry is shed")
    func expiredHistoryElsewhereRetiresBeforeShedding() async throws {
        let hot = ruleS(id: "fairness-hot", seedSuffix: "hot-seed", laterSuffix: "hot-later", window: 600)
        let idle = ruleS(id: "fairness-idle", seedSuffix: "idle-seed", laterSuffix: "idle-later", window: 600)
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let idleHistory = filler(idle, stepID: "later", count: 50, arrivedAt: reference.addingTimeInterval(-700))
        let hotHistory = filler(hot, stepID: "later", count: 8_142, arrivedAt: reference.addingTimeInterval(-1))
        // Restored 200 s earlier, while the idle history was still in its window.
        try await restore(engine, rules: [hot, idle], pending: idleHistory + hotHistory,
                          now: reference.addingTimeInterval(-200))
        let operationsBefore = await engine.pendingCapacityOperationDiagnostics()
        _ = await engine.evaluate(proc("/usr/local/bin/hot-later", pid: 10_000, at: base))

        let ledger = await engine.pendingStepConservation()
        #expect(ledger.completed == 50 && ledger.explicitlyShed == 0)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[idle.id]?.completed == 50 && byRule[idle.id]?.queued == 0)
        #expect(byRule[hot.id]?.queued == 8_143 && byRule[hot.id]?.explicitlyShed == 0)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.pendingPressureDiagnostics().lastPressure == nil,
                "expired-only retirement is not a live pressure observation")
        let operationsAfter = await engine.pendingCapacityOperationDiagnostics()
        #expect(operationsAfter.identityRebuilds == operationsBefore.identityRebuilds,
                "an expired prefix is retired in place, without rebuilding identities")
        #expect(operationsAfter.forcedQueueCompactions == operationsBefore.forcedQueueCompactions)
        try await assertExact(engine)
    }

    @Test("Expired entries behind a live entry are still retired as completed")
    func nonPrefixExpiryIsRetiredAsCompleted() async throws {
        let rule = ruleS(id: "fairness-skew", seedSuffix: "skew-seed", laterSuffix: "skew-later", window: 600)
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let stale = reference.addingTimeInterval(-700)
        let fresh = reference.addingTimeInterval(-1)
        let history = filler(rule, stepID: "later", count: 1, arrivedAt: stale)
            + filler(rule, stepID: "later", count: 1, arrivedAt: fresh)
            + filler(rule, stepID: "later", count: 1, arrivedAt: stale)
            + filler(rule, stepID: "later", count: 8_189, arrivedAt: fresh)
        try await restore(engine, rules: [rule], pending: history, now: reference.addingTimeInterval(-200))
        let operationsBefore = await engine.pendingCapacityOperationDiagnostics()
        let live = proc("/usr/local/bin/skew-later", pid: 10_000, at: base)
        _ = await engine.evaluate(live)

        let ledger = await engine.pendingStepConservation()
        #expect(ledger.completed == 2 && ledger.explicitlyShed == 0 && ledger.queued == 8_191)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.pendingPressureDiagnostics().lastPressure == nil)
        let operationsAfter = await engine.pendingCapacityOperationDiagnostics()
        let rebuilds = operationsAfter.identityRebuilds - operationsBefore.identityRebuilds
        #expect(rebuilds == 1, "out-of-order expiry takes the audited setter")
        let capture = try await assertExact(engine)
        let expectedOrder = [identity(history[1])] + history.dropFirst(3).map { identity($0) }
            + [identity(rule, "later", live)]
        let exactOrder = capture.pendingEvictionOrder == expectedOrder
        #expect(exactOrder, "the persisted order is the admission order filtered to survivors")
    }

    @Test("A restored full table sheds the largest bucket's front whatever its persisted order",
          arguments: [false, true])
    func restoredTableShedsLargestBucketFront(interleaved: Bool) async throws {
        let hot = ruleS(id: "fairness-hot", seedSuffix: "hot-seed", laterSuffix: "hot-later")
        let victim = ruleS(id: "fairness-victim", seedSuffix: "victim-seed", laterSuffix: "victim-later")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let hotHistory = filler(hot, stepID: "later", count: interleaved ? 8_000 : 8_192, arrivedAt: reference)
        let victimHistory = interleaved
            ? filler(victim, stepID: "later", count: 192, pid: 500, arrivedAt: reference) : []
        // Single bucket: the reverse of bucket order. Two buckets: the victim's
        // entries first, interleaved with the hot rule's.
        var order: [SequenceCheckpointPendingIdentity] = []
        if interleaved {
            for (index, record) in hotHistory.enumerated() {
                if index < victimHistory.count { order.append(identity(victimHistory[index])) }
                order.append(identity(record))
            }
        } else {
            order = hotHistory.reversed().map { identity($0) }
        }
        try await restore(engine, rules: [hot, victim], pending: hotHistory + victimHistory,
                          order: order, now: reference)
        let live = interleaved
            ? proc("/usr/local/bin/victim-later", pid: 500, at: base)
            : proc("/usr/local/bin/hot-later", pid: 10_000, at: base)
        _ = await engine.evaluate(live)

        let pressure = await engine.pendingPressureDiagnostics()
        let last = try #require(pressure.lastPressure)
        #expect(last.reason == (interleaved ? .globalCount : .perRuleCount))
        #expect(last.representativeVictimRuleID == hot.id && last.removedPendingSteps == 1)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[hot.id]?.explicitlyShed == 1)
        if interleaved {
            #expect(byRule[victim.id]?.explicitlyShed == 0 && byRule[victim.id]?.queued == 193)
        }
        let capture = try await assertExact(engine)
        let shed = identity(hotHistory[0])
        #expect(shed != order[0], "the shed entry is the bucket front, not the persisted order's front")
        let expectedOrder = order.filter { $0 != shed } + [identity(interleaved ? victim : hot, "later", live)]
        let exactOrder = capture.pendingEvictionOrder == expectedOrder
        #expect(exactOrder, "the persisted order is the restored order minus the shed entry, plus the admission")
    }

    @Test("A shed identity admitted again keeps a single global reference")
    func readmittedIdentityKeepsOneQueueReference() async throws {
        let rule = ruleS(id: "fairness-readmit", seedSuffix: "readmit-seed", laterSuffix: "readmit-later")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let capacity = SequenceEngine.maxPendingTotal
        let restored = try await restoreFiller(engine, rule, stepID: "later", count: capacity,
                                               arrivedAt: reference, now: reference)
        let first = proc("/usr/local/bin/readmit-later", pid: 10_000, at: base)
        _ = await engine.evaluate(first)
        // The same event identity as the entry just shed. Its earlier global
        // reference is still waiting for the lazy compaction.
        let again = proc("/usr/local/bin/readmit-later", pid: 9_999, at: base,
                         id: restored[0].matched.eventID)
        _ = await engine.evaluate(again)

        let ledger = await engine.pendingStepConservation()
        let offered = UInt64(capacity + 2)
        #expect(ledger.offered == offered && ledger.explicitlyShed == 2)
        #expect(ledger.queued == UInt64(capacity))
        let capture = try await assertExact(engine)
        let expectedOrder = [identity(restored[0])] + restored.dropFirst(2).map { identity($0) }
            + [identity(rule, "later", first)]
        let exactOrder = capture.pendingEvictionOrder == expectedOrder
        #expect(exactOrder, "compaction keeps the first reference to the re-admitted identity")
    }

    // MARK: - Partial fairness

    @Test("Partial count pressure sheds the largest partial bucket's oldest seeds")
    func partialCountPressureShedsLargestBucket() async throws {
        let small = seedFinishRule(id: "fairness-partial-a", prefix: "a")
        let large = seedFinishRule(id: "fairness-partial-b", prefix: "b")
        let engine = SequenceEngine(lineage: ProcessLineage(), maxPartialMatches: 8, sweepInterval: 3_600)
        try await engine.addRule(small)
        try await engine.addRule(large)
        let smallSeeds = (0..<2).map { proc("/usr/local/bin/a-seed", pid: 100 + Int32($0), at: base) }
        let largeSeeds = (0..<20).map { proc("/usr/local/bin/b-seed", pid: 200 + Int32($0), at: base) }
        for seed in smallSeeds + largeSeeds { _ = await engine.evaluate(seed) }

        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.globalCountShedTotal == 14 && pressure.totalShed == 14)
        #expect(pressure.semanticWeightShedTotal == 0)
        #expect(await engine.partialsEvictedTotal == 14)
        let last = try #require(pressure.lastPressure)
        #expect(last.reason == .globalCount && last.removedPartials == 1)
        #expect(last.partialCountBefore == 9 && last.partialCountAfter == 8)
        let capture = try await assertExact(engine)
        var partialBySeed: [UUID: UUID] = [:]
        for partial in capture.partialBuckets.flatMap(\.partials) {
            for matched in partial.matchedSteps { partialBySeed[matched.eventID] = partial.id }
        }
        let survivors = smallSeeds + largeSeeds.suffix(6)
        #expect(Set(partialBySeed.keys) == Set(survivors.map(\.id)), "both small-bucket seeds survive")
        #expect(capture.evictionOrder == survivors.compactMap { partialBySeed[$0.id] })

        let matches = await engine.evaluate(proc("/usr/local/bin/a-finish", pid: 300,
                                                 at: base.addingTimeInterval(1)))
        #expect(matches.filter { $0.ruleId == small.id }.count == 2)
        try await assertExact(engine)
    }

    @Test("Partial weight pressure sheds the heaviest partial bucket's oldest seed")
    func partialWeightPressureShedsHeaviestBucket() async throws {
        let light = filePathRule(id: "fairness-wide-a", imageSuffix: "wide-a")
        let heavy = filePathRule(id: "fairness-wide-b", imageSuffix: "wide-b")
        let path = "/private/tmp/" + String(repeating: "p", count: 8_192)
        let reference = Date()
        let itemWeight = SequenceCheckpointCodec.estimatedWeight(of: widePartial(light, path: path, at: reference))
        let fixedWeight = SequenceCheckpointCodec.semanticStateBaseWeight
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: light.id)
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: heavy.id)
        let capacity = (SequenceCheckpointCodec.maximumSemanticStateWeight - fixedWeight) / itemWeight
        try #require(capacity > 4 && capacity < 10_000)
        let lightPartials = (0..<2).map { _ in widePartial(light, path: path, at: reference) }
        let heavyPartials = (0..<(capacity - 2)).map { _ in widePartial(heavy, path: path, at: reference) }
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        // The light partials lead the persisted order, where the earlier
        // global walk took its victims.
        try await restore(engine, rules: [light, heavy], partials: lightPartials + heavyPartials, now: reference)
        let seed = wideFileEvent(imageSuffix: "wide-b", path: path, at: base)
        _ = await engine.evaluate(seed)

        let pressure = await engine.partialPressureDiagnostics()
        #expect(pressure.semanticWeightShedTotal == 1 && pressure.globalCountShedTotal == 0)
        #expect(await engine.partialsEvictedTotal == 1)
        let last = try #require(pressure.lastPressure)
        #expect(last.reason == .semanticWeight && last.removedPartials == 1)
        #expect(last.stateWeightBytesBefore > pressure.stateWeightLimitBytes)
        #expect(last.stateWeightBytesAfter <= pressure.stateWeightLimitBytes)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        let capture = try await assertExact(engine)
        let survivors = capture.partialBuckets.flatMap(\.partials)
        let survivorIDs = Set(survivors.map(\.id))
        #expect(!survivorIDs.contains(heavyPartials[0].id), "the heaviest bucket's oldest seed is the victim")
        #expect(lightPartials.allSatisfy { survivorIDs.contains($0.id) })
        let seeded = try #require(survivors.first { $0.matchedSteps.first?.eventID == seed.id })
        let expectedOrder = (lightPartials + heavyPartials.dropFirst()).map(\.id) + [seeded.id]
        let exactOrder = capture.evictionOrder == expectedOrder
        #expect(exactOrder, "the persisted order is the seed order filtered to survivors")
    }

    // MARK: - Saturation cost

    @Test("Saturation relief needs no forced compaction and only lazy identity rebuilds")
    func saturationCostIsAmortizedForDistinctWriters() async throws {
        let rule = ruleD()
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let capacity = SequenceEngine.maxPendingTotal
        let restored = try await restoreFiller(engine, rule, stepID: "write", count: capacity,
                                               arrivedAt: reference, now: reference)
        let before = await engine.pendingCapacityOperationDiagnostics()
        let writes = 1_024
        var live: [Event] = []
        for index in 0..<writes {
            let event = write(pid: 20_000 + Int32(index), pidVersion: 1,
                              at: base.addingTimeInterval(Double(index)))
            live.append(event)
            _ = await engine.evaluate(event)
        }
        let after = await engine.pendingCapacityOperationDiagnostics()

        #expect(after.forcedQueueCompactions == before.forcedQueueCompactions)
        let rebuilds = after.identityRebuilds - before.identityRebuilds
        #expect(rebuilds == 3, "only the lazy compactions at admissions 257, 514 and 771 rebuild identities")
        // Each over-cap admission scans the full bucket for expiry once and
        // shifts it once to remove the front: linear, but no hashing.
        let visitsPerAdmission = UInt64(2 * (capacity + 1))
        let expectedVisits = UInt64(writes) * visitsPerAdmission
        let visits = after.elementVisits - before.elementVisits
        #expect(visits == expectedVisits)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.perRuleCountShedTotal == UInt64(writes))
        #expect(pressure.globalCountShedTotal == 0 && pressure.semanticWeightShedTotal == 0)
        #expect(await engine.pendingStepsEvictedTotal == writes)
        let capture = try await assertExact(engine)
        let expectedOrder = restored.dropFirst(writes).map { identity($0) } + live.map { identity(rule, "write", $0) }
        let exactOrder = capture.pendingEvictionOrder == expectedOrder
        #expect(exactOrder, "the newest live writes are retained in admission order")
    }
}
