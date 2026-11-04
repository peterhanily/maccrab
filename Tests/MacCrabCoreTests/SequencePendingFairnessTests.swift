import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

/// In-memory synthetic process and file events only: no processes, daemon or
/// collectors. Event times are fixed. Arrival ages come from restoring
/// checkpoint history at a chosen instant, and every engine sweeps
/// periodically only once an hour, so only the pressure path retires history.
/// Two cases touch files: the heartbeat wiring check reads one source file of
/// this repository, and the fold-eligibility map check reloads two rule files
/// it writes to a temporary directory.
/// Serialized because several cases drive a full 8,192-entry table.
@Suite("Sequence capacity: fairness, folding and saturation cost", .serialized)
struct SequencePendingFairnessTests {
    private let base = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Rules

    /// Ordered lineage rule: a `/seeder` exec, then a descendant `/writer` file
    /// write, then a descendant `/writer` connection. Its `write` step is the
    /// one pendingFoldStepID names.
    private func ruleD(id: String = "fairness-lineage",
                       correlation: CorrelationType = .processLineage,
                       window: TimeInterval = 3_600) -> SequenceRule {
        SequenceRule(
            id: id, title: "lineage writer fixture", description: "in-memory fixture",
            level: .low, tags: [], window: window, correlationType: correlation, ordered: true,
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

    /// Ordered `.processSame` rule whose later step is a `/writer` write to a
    /// path ending `/co-admitted`: such a write is also ruleD's `write` step,
    /// so one event is admitted into both rules. Never fold-eligible.
    private func sharedWriteRule(id: String) -> SequenceRule {
        SequenceRule(
            id: id, title: "shared write fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600, correlationType: .processSame, ordered: true,
            steps: [
                SequenceStep(id: "seed", logsourceCategory: "process_creation",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/shared-seed"], negate: false)]),
                SequenceStep(id: "later", logsourceCategory: "file_event",
                             predicates: [Predicate(field: "Image", modifier: .endswith,
                                                    values: ["/writer"], negate: false),
                                          Predicate(field: "TargetFilename", modifier: .endswith,
                                                    values: ["/co-admitted"], negate: false)],
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

    /// A `/writer` process; it carries an ES audit identity only when
    /// `pidVersion` is set.
    private func writerProcess(pid: Int32, pidVersion: UInt32?, ppid: Int32, ancestors: [Int32],
                               at timestamp: Date) -> MacCrabCore.ProcessInfo {
        let executable = "/usr/local/bin/writer"
        let identity = pidVersion.map {
            AuditIdentity(auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
                          pid: pid, pidversion: $0, asid: 100_001)
        }
        return MacCrabCore.ProcessInfo(
            pid: pid, ppid: ppid, rpid: pid, name: "writer", executable: executable,
            commandLine: executable, args: [executable], workingDirectory: "/private/tmp",
            userId: 501, userName: "fixture", groupId: 20, startTime: timestamp,
            ancestors: ancestors.map { ProcessAncestor(pid: $0, executable: "/bin/sh", name: "sh") },
            auditIdentity: identity
        )
    }

    /// A `/writer` file write: the fixture rule's `write` step.
    private func write(pid: Int32, pidVersion: UInt32? = nil, ppid: Int32 = 1, ancestors: [Int32] = [],
                       at timestamp: Date, path: String = "/private/tmp/fairness/output") -> Event {
        Event(timestamp: timestamp, eventCategory: .file, eventType: .creation, eventAction: "write",
              process: writerProcess(pid: pid, pidVersion: pidVersion, ppid: ppid, ancestors: ancestors,
                                     at: timestamp),
              file: FileInfo(path: path, action: .write))
    }

    /// A `/writer` outbound connection: the fixture rule's `finish` step.
    private func connection(pid: Int32, pidVersion: UInt32? = nil, ppid: Int32 = 1,
                            at timestamp: Date) -> Event {
        Event(timestamp: timestamp, eventCategory: .network, eventType: .creation, eventAction: "connect",
              process: writerProcess(pid: pid, pidVersion: pidVersion, ppid: ppid, ancestors: [],
                                     at: timestamp),
              network: NetworkInfo(sourceIp: "10.0.0.2", sourcePort: 51_000, destinationIp: "93.184.216.34",
                                   destinationPort: 443, destinationHostname: nil, direction: .outbound,
                                   transport: "tcp"))
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

    /// Exact weight, journal and pressure accounting.
    private func assertAccounting(_ engine: SequenceEngine) async {
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
    }

    /// Exact accounting, then a capture, which proves both global queues
    /// exactly cover the live state.
    @discardableResult
    private func assertExact(_ engine: SequenceEngine) async throws -> SequenceCheckpointCapture {
        await assertAccounting(engine)
        return try await engine.checkpointCapture()
    }

    /// Arrival times come from the wall clock, so a step back during a run
    /// (rare, but possible while the host syncs time) legitimately reorders
    /// them. Callers assert arrival order only when their own samples, taken
    /// around every evaluation, never ran backwards.
    private struct WallClockMonitor {
        private var last = Date()
        private(set) var regressed = false

        mutating func sample() {
            let now = Date()
            if now < last { regressed = true }
            last = now
        }
    }

    private func nonDecreasing(_ dates: [Date]) -> Bool {
        zip(dates, dates.dropFirst()).allSatisfy { $0 <= $1 }
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

    // MARK: - Folding

    @Test("A burst of repeated writes folds each writer's history instead of shedding it")
    func writerBurstFoldsWithoutEviction() async throws {
        let rule = ruleD()
        let lineage = ProcessLineage()
        let writers = 6
        for index in 0..<writers {
            let seed = Int32(1_000 + index)
            await lineage.recordProcess(pid: seed, ppid: 1, path: "/usr/local/bin/seeder",
                                        name: "seeder", startTime: base)
            await lineage.recordProcess(pid: seed + 1_000, ppid: seed, path: "/usr/local/bin/writer",
                                        name: "writer", startTime: base)
        }
        let engine = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        try await engine.addRule(rule)
        var clock = WallClockMonitor()
        var writes: [Event] = []
        for index in 0..<12_000 {
            let writer = Int32(index % writers)
            let event = write(pid: 2_000 + writer, pidVersion: 7, ppid: 1_000 + writer,
                              at: base.addingTimeInterval(10 + Double(index) * 0.001))
            writes.append(event)
            clock.sample()
            _ = await engine.evaluate(event)
        }
        clock.sample()

        // The 8,193rd write fills the table past its cap; one fold leaves one
        // entry per writer and nothing is shed.
        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.evictionIsOngoing(within: 300) == false)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldedStepsTotal == 8_187 && pressure.foldAttemptsTotal == 1)
        #expect(pressure.lastPressure == nil)
        let fold = try #require(pressure.lastFold)
        #expect(fold.ruleID == rule.id && fold.stepID == "write")
        #expect(fold.removedPendingSteps == 8_187 && fold.foldedGroups == 6)
        let ledger = await engine.pendingStepConservation()
        #expect(ledger.offered == 12_000 && ledger.completed == 8_187)
        #expect(ledger.explicitlyShed == 0 && ledger.queued == 3_813)
        #expect(await engine.pendingStepConservationByRule()[rule.id] == ledger)
        let folded = try await assertExact(engine)
        if !clock.regressed {
            #expect(nonDecreasing(folded.pendingBuckets.flatMap(\.steps).map(\.arrivedAt)))
        }

        // Late seeds: each binds its own writer's earliest write.
        var seeds: [Event] = []
        for index in 0..<writers {
            let seed = proc("/usr/local/bin/seeder", pid: Int32(1_000 + index), at: base)
            seeds.append(seed)
            _ = await engine.evaluate(seed)
        }
        let capture = try await assertExact(engine)
        let partials = capture.partialBuckets.flatMap(\.partials)
        #expect(partials.count == writers)
        for (index, seed) in seeds.enumerated() {
            let partial = partials.first { $0.matchedSteps.contains { $0.eventID == seed.id } }
            let bound = partial?.matchedSteps.first { $0.stepID == "write" }?.eventID
            #expect(bound == writes[index].id, "writer \(index) binds its earliest write")
        }
    }

    /// One generated writer of the folded-versus-reference differential.
    private enum DifferentialMode: CaseIterable {
        /// Every write after the seed.
        case normal
        /// Every write before the seed.
        case allBefore
        /// Half before and half after the seed: the accepted fold residual.
        case straddle
        /// One pid, two process instances: before the seed, then after it.
        case pidReuse
        /// After the seed, but without an ES audit identity.
        case noIdentity
        /// After the seed, by a process outside the seed's tree.
        case unrelated
    }

    private struct DifferentialWriter {
        let mode: DifferentialMode
        let t0: Date
        let seed: Event
        let writes: [Event]
        /// Fold groups of the writer's identity-carrying writes.
        let groupSizes: [Int]
        let finish: Event
    }

    @Test("Folded replay binds what unfolded replay binds, except for the accepted residual")
    func foldedReplayMatchesReference() async throws {
        let rule = ruleD()
        let lineage = ProcessLineage()
        var rng = SplitMix64(seed: 0x5EED_CAFE_F00D_0001)
        var scenarios: [[DifferentialWriter]] = []
        var deliveries: [[Event]] = []
        for scenario in 0..<50 {
            var writers: [DifferentialWriter] = []
            let writerCount = 1 + Int(rng.next() % 3)
            for index in 0..<writerCount {
                let seedPID = Int32(100_000 + scenario * 100 + index * 10)
                let writerPID = seedPID + 1
                let t0 = base.addingTimeInterval(Double(scenario * 1_000 + index * 100))
                var mode = DifferentialMode.allCases[Int(rng.next() % 6)]
                if index == 0, scenario < 3 { mode = [.straddle, .pidReuse, .normal][scenario] }
                let count = 2 + Int(rng.next() % 11)
                let before = mode == .allBefore ? count : (mode == .straddle || mode == .pidReuse ? count / 2 : 0)
                let ppid = mode == .unrelated ? 1 : seedPID
                await lineage.recordProcess(pid: seedPID, ppid: 1, path: "/usr/local/bin/seeder",
                                            name: "seeder", startTime: base)
                await lineage.recordProcess(pid: writerPID, ppid: ppid, path: "/usr/local/bin/writer",
                                            name: "writer", startTime: base)
                let writes = (0..<count).map { offset -> Event in
                    let isBefore = offset < before
                    let seconds = isBefore ? -Double(offset + 1) : Double(offset - before + 1)
                    let pidVersion: UInt32? = switch mode {
                    case .noIdentity: nil
                    case .pidReuse: isBefore ? 1 : 2
                    default: 5
                    }
                    return write(pid: writerPID, pidVersion: pidVersion, ppid: ppid,
                                 at: t0.addingTimeInterval(seconds))
                }
                let groupSizes: [Int] = switch mode {
                case .noIdentity: []
                case .pidReuse: [before, count - before]
                default: [count]
                }
                writers.append(DifferentialWriter(
                    mode: mode, t0: t0,
                    seed: proc("/usr/local/bin/seeder", pid: seedPID, at: t0),
                    writes: writes, groupSizes: groupSizes,
                    finish: connection(pid: writerPID, ppid: ppid, at: t0.addingTimeInterval(500))
                ))
            }
            var order = writers.flatMap(\.writes)
            for index in stride(from: order.count - 1, to: 0, by: -1) {
                order.swapAt(index, Int(rng.next() % UInt64(index + 1)))
            }
            scenarios.append(writers)
            deliveries.append(order)
        }
        let scenarioWrites = deliveries.reduce(0) { $0 + $1.count }
        let capacity = SequenceEngine.maxPendingTotal

        let folded = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        let reference = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        try await folded.addRule(rule)
        try await reference.addRule(rule)
        // One unrelated filler writer brings the folded engine to the cap, so
        // a single fold also collapses the filler and later replays stay cheap.
        let filler = (0...(capacity - scenarioWrites)).map {
            write(pid: 999_000, pidVersion: 1, at: base.addingTimeInterval(-1_000 + Double($0) * 0.001))
        }
        for event in filler.dropLast() { _ = await folded.evaluate(event) }
        for event in deliveries.joined() {
            _ = await folded.evaluate(event)
            _ = await reference.evaluate(event)
        }
        #expect(await folded.pendingPressureDiagnostics().foldAttemptsTotal == 0)
        _ = await folded.evaluate(filler[filler.count - 1])

        let groups = scenarios.joined().flatMap(\.groupSizes)
        let expectedFolded = UInt64(filler.count - 1 + groups.reduce(0) { $0 + $1 - 1 })
        let foldedPressure = await folded.pendingPressureDiagnostics()
        #expect(foldedPressure.foldAttemptsTotal == 1)
        #expect(foldedPressure.foldedStepsTotal == expectedFolded)
        #expect(await folded.pendingStepsEvictedTotal == 0)

        var referenceMismatches: [String] = []
        var foldedMismatches: [String] = []
        var residuals = 0
        var expectedReferenceFires = 0
        var expectedFoldedFires = 0
        var referenceFires = 0
        var foldedFires = 0
        for (scenario, writers) in scenarios.enumerated() {
            for writer in writers {
                _ = await folded.evaluate(writer.seed)
                _ = await reference.evaluate(writer.seed)
            }
            let foldedBindings = try await writeBindings(folded)
            let referenceBindings = try await writeBindings(reference)
            for (index, writer) in writers.enumerated() {
                let expected = writer.mode == .unrelated ? nil
                    : writer.writes.filter { $0.timestamp >= writer.t0 }.min { $0.timestamp < $1.timestamp }?.id
                let expectedAfterFold = writer.mode == .straddle ? nil : expected
                if expected != expectedAfterFold { residuals += 1 }
                if expected != nil { expectedReferenceFires += 1 }
                if expectedAfterFold != nil { expectedFoldedFires += 1 }
                let label = "scenario \(scenario) writer \(index) (\(writer.mode))"
                if referenceBindings[writer.seed.id] != .some(expected) { referenceMismatches.append(label) }
                if foldedBindings[writer.seed.id] != .some(expectedAfterFold) { foldedMismatches.append(label) }
            }
            for writer in writers {
                foldedFires += await folded.evaluate(writer.finish).filter { $0.ruleId == rule.id }.count
                referenceFires += await reference.evaluate(writer.finish).filter { $0.ruleId == rule.id }.count
            }
        }
        #expect(referenceMismatches.isEmpty, "unfolded replay binds the earliest related write at or after the seed")
        #expect(foldedMismatches.isEmpty, "folded replay binds the same write, except for a straddling writer")
        #expect(residuals >= 1, "the generated data includes the accepted residual")
        #expect(referenceFires == expectedReferenceFires && foldedFires == expectedFoldedFires)

        let referencePressure = await reference.pendingPressureDiagnostics()
        #expect(referencePressure.foldAttemptsTotal == 0 && referencePressure.foldedStepsTotal == 0)
        #expect(await reference.pendingStepsEvictedTotal == 0)
        #expect(await folded.pendingStepsEvictedTotal == 0)
        try await assertExact(folded)
        try await assertExact(reference)
    }

    /// Each live partial's seed event mapped to the event bound to `write`, or
    /// nil when that step is still unbound.
    private func writeBindings(_ engine: SequenceEngine) async throws -> [UUID: UUID?] {
        var bindings: [UUID: UUID?] = [:]
        for partial in try await engine.checkpointCapture().partialBuckets.flatMap(\.partials) {
            guard let seed = partial.matchedSteps.first(where: { $0.stepID == "seed" }) else { continue }
            let bound: UUID? = partial.matchedSteps.first { $0.stepID == "write" }?.eventID
            // Store an unbound step as a value; assigning nil would remove the key.
            bindings[seed.eventID] = .some(bound)
        }
        return bindings
    }

    /// Two live admissions into a table one short of its cap. They fold only
    /// when every part of the key matches.
    enum FoldEligibilityCase: String, CaseIterable, Sendable {
        case sameWriter
        case noIdentity
        case otherProcessInstance
        case otherParent
        case otherAncestry
        case parentNowTracked
        case laterStep
        case ineligibleRule
    }

    @Test("Only entries with one writer's identity and identical relation evidence fold",
          arguments: FoldEligibilityCase.allCases)
    func foldRequiresEqualKeys(_ kind: FoldEligibilityCase) async throws {
        let rule = kind == .ineligibleRule ? ruleD(correlation: .filePath) : ruleD()
        let lineage = ProcessLineage()
        let engine = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        let reference = Date()
        let restored = try await restoreFiller(engine, rule, stepID: "write", count: SequenceEngine.maxPendingTotal - 1,
                                               arrivedAt: reference, now: reference)
        let writer: Int32 = 3_001
        let early = base.addingTimeInterval(20_000)
        let late = base.addingTimeInterval(20_001)
        let pair: (Event, Event) = switch kind {
        case .sameWriter, .ineligibleRule:
            (write(pid: writer, pidVersion: 7, ppid: 70, at: early), write(pid: writer, pidVersion: 7, ppid: 70, at: late))
        case .noIdentity:
            (write(pid: writer, ppid: 70, at: early), write(pid: writer, ppid: 70, at: late))
        case .otherProcessInstance:
            (write(pid: writer, pidVersion: 1, ppid: 70, at: early), write(pid: writer, pidVersion: 2, ppid: 70, at: late))
        case .otherParent:
            (write(pid: writer, pidVersion: 7, ppid: 70, at: early), write(pid: writer, pidVersion: 7, ppid: 71, at: late))
        case .otherAncestry:
            (write(pid: writer, pidVersion: 7, ppid: 70, ancestors: [50], at: early),
             write(pid: writer, pidVersion: 7, ppid: 70, ancestors: [51], at: late))
        case .parentNowTracked:
            // Identical recorded ancestry; only processParentWasTracked differs.
            (write(pid: writer, pidVersion: 7, ppid: 70, ancestors: [70, 1], at: early),
             write(pid: writer, pidVersion: 7, ppid: 70, ancestors: [70, 1], at: late))
        case .laterStep:
            (connection(pid: writer, pidVersion: 7, ppid: 70, at: early),
             connection(pid: writer, pidVersion: 7, ppid: 70, at: late))
        }
        _ = await engine.evaluate(pair.0)
        if kind == .parentNowTracked {
            await lineage.recordProcess(pid: 70, ppid: 1, path: "/bin/sh", name: "sh", startTime: base)
            await lineage.recordProcess(pid: writer, ppid: 70, path: "/usr/local/bin/writer",
                                        name: "writer", startTime: base)
        }
        _ = await engine.evaluate(pair.1)

        let folds = kind == .sameWriter
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldedStepsTotal == (folds ? 1 : 0))
        #expect(pressure.foldAttemptsTotal == (kind == .ineligibleRule ? 0 : 1))
        #expect(await engine.pendingStepsEvictedTotal == (folds ? 0 : 1))
        let capture = try await assertExact(engine)
        let retained = Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
        #expect(retained.contains(pair.0.id), "the earlier event survives either way")
        #expect(retained.contains(pair.1.id) == !folds)
        #expect(retained.contains(restored[0].matched.eventID) == folds,
                "without a fold the oldest restored entry is shed")
    }

    /// The fixture rule with one dimension changed, for the static fold
    /// eligibility check. Nothing is installed, so no rule validation applies.
    private enum FinishShape { case absent, relatedToSeed, relatedToWrite, unrelated }

    private func foldShape(
        ordered: Bool = true,
        correlation: CorrelationType = .processLineage,
        seedCategory: String = "process_creation",
        writeRelation: ProcessRelation? = .descendant,
        finish: FinishShape = .relatedToSeed
    ) -> SequenceRule {
        func image(_ suffix: String) -> [MacCrabCore.Predicate] {
            [MacCrabCore.Predicate(field: "Image", modifier: .endswith, values: [suffix], negate: false)]
        }
        var steps = [
            SequenceStep(id: "seed", logsourceCategory: seedCategory, predicates: image("/seeder")),
            SequenceStep(id: "write", logsourceCategory: "file_event", predicates: image("/writer"),
                         processRelation: writeRelation.map { ProcessRelationSpec(relation: $0, relativeToStep: "seed") }),
        ]
        let finishRelation: ProcessRelationSpec? = switch finish {
        case .relatedToSeed: ProcessRelationSpec(relation: .descendant, relativeToStep: "seed")
        case .relatedToWrite: ProcessRelationSpec(relation: .descendant, relativeToStep: "write")
        case .absent, .unrelated: nil
        }
        if finish != .absent {
            steps.append(SequenceStep(id: "finish", logsourceCategory: "network_connection",
                                      predicates: image("/writer"), processRelation: finishRelation))
        }
        return SequenceRule(id: "fold-shape", title: "fold shape fixture", description: "in-memory fixture",
                            level: .low, tags: [], window: 3_600, correlationType: correlation, ordered: ordered,
                            steps: steps, trigger: .allSteps)
    }

    @Test("Fold eligibility is a descendant second step, alone in its category, that later steps cannot tell apart")
    func foldEligibilityRuleShapes() {
        #expect(SequenceEngine.pendingFoldStepID(for: ruleD()) == "write")
        #expect(SequenceEngine.pendingFoldStepID(for: foldShape(finish: .absent)) == "write")
        #expect(SequenceEngine.pendingFoldStepID(for: foldShape(correlation: .none, finish: .unrelated)) == "write")

        #expect(SequenceEngine.pendingFoldStepID(for: foldShape(ordered: false)) == nil)
        let otherRelations: [ProcessRelation?] = [.same, .sameProcess, .ancestor, .sibling, .sameTree, .any, nil]
        for relation in otherRelations {
            #expect(SequenceEngine.pendingFoldStepID(for: foldShape(writeRelation: relation)) == nil,
                    "write relation \(String(describing: relation))")
        }
        #expect(SequenceEngine.pendingFoldStepID(for: foldShape(seedCategory: "file_event")) == nil,
                "another step shares the folded step's category")
        for correlation in [CorrelationType.filePath, .networkEndpoint, .processSame] {
            #expect(SequenceEngine.pendingFoldStepID(for: foldShape(correlation: correlation)) == nil,
                    "correlation \(correlation)")
        }
        #expect(SequenceEngine.pendingFoldStepID(for: foldShape(finish: .relatedToWrite)) == nil,
                "a later step relates to the folded step")
        #expect(SequenceEngine.pendingFoldStepID(for: foldShape(finish: .unrelated)) == nil,
                "a later step relies on lineage correlation without its own relation")
    }

    @Test("The fold-eligibility map follows rule installs, disables and reloads")
    func foldEligibilityMapFollowsRuleChanges() async throws {
        let eligible = ruleD(id: "fairness-map")
        let ineligible = ruleD(id: "fairness-map", correlation: .filePath)
        let folds = [eligible.id: "write"]
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sequence-fold-map-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let eligibleFolder = root.appendingPathComponent("eligible")
        let ineligibleFolder = root.appendingPathComponent("ineligible")
        for (rule, folder) in [(eligible, eligibleFolder), (ineligible, ineligibleFolder)] {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try JSONEncoder().encode(rule).write(to: folder.appendingPathComponent("rule.json"))
        }
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)

        try await engine.addRule(eligible)
        #expect(await engine.pendingFoldStepIDByRule == folds, "install")
        // Eligibility belongs to the definition; a disabled rule holds no history.
        await engine.setEnabled(eligible.id, enabled: false)
        #expect(await engine.pendingFoldStepIDByRule == folds, "disable")
        await engine.setEnabled(eligible.id, enabled: true)
        #expect(await engine.pendingFoldStepIDByRule == folds, "enable")
        #expect(try await engine.reloadRules(from: ineligibleFolder) == 1)
        #expect(await engine.pendingFoldStepIDByRule.isEmpty, "reload: eligible to ineligible")
        #expect(try await engine.reloadRules(from: eligibleFolder) == 1)
        #expect(await engine.pendingFoldStepIDByRule == folds, "reload: ineligible to eligible")
        try await engine.addRule(ineligible)
        #expect(await engine.pendingFoldStepIDByRule.isEmpty, "install over the same ID")
        #expect(try await engine.reloadRules(from: eligibleFolder) == 1)
        #expect(await engine.pendingFoldStepIDByRule == folds, "reload: ineligible to eligible again")

        // Relief reads the map the last reload rebuilt: in a table one short
        // of its cap, one writer's second write folds into its first.
        let reference = Date()
        let records = filler(eligible, stepID: "write", count: SequenceEngine.maxPendingTotal - 1,
                             arrivedAt: reference)
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion, capturedAt: reference,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(await engine.listRules()),
            sourceGeneration: 1, partialBuckets: [],
            pendingBuckets: [SequenceCheckpointPendingBucket(ruleID: eligible.id, steps: records)],
            evictionOrder: [], pendingEvictionOrder: records.map { identity($0) }
        )
        _ = try await engine.restoreCheckpoint(payload, now: reference)
        for offset in 0..<2 {
            _ = await engine.evaluate(write(pid: 3_001, pidVersion: 5, at: base.addingTimeInterval(20_000 + Double(offset))))
        }
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.foldedStepsTotal == 1)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        try await assertExact(engine)
    }

    @Test("Restored history never folds, even with the live writer's own evidence")
    func restoredHistoryNeverFolds() async throws {
        let rule = ruleD()
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let restored = try await restoreFiller(engine, rule, stepID: "write", count: SequenceEngine.maxPendingTotal,
                                               pid: 2_001, arrivedAt: reference, now: reference)
        let live = write(pid: 2_001, pidVersion: 7, ppid: 0, at: base.addingTimeInterval(20_000))
        _ = await engine.evaluate(live)

        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.foldedStepsTotal == 0)
        #expect(pressure.perRuleCountShedTotal == 1 && pressure.lastFold == nil)
        #expect(await engine.pendingStepsEvictedTotal == 1)
        let capture = try await assertExact(engine)
        let retained = Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
        #expect(retained.contains(live.id) && !retained.contains(restored[0].matched.eventID))
    }

    @Test("Folded history round-trips through a checkpoint, and restored representatives never fold again")
    func foldedHistoryRoundTrips() async throws {
        let rule = ruleD()
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        try await restoreFiller(engine, rule, stepID: "write", count: 8_180, arrivedAt: reference, now: reference)
        let writerA = (0...6).map { write(pid: 2_001, pidVersion: 3, at: base.addingTimeInterval(20_000 + Double($0))) }
        let writerB = (0...5).map { write(pid: 2_002, pidVersion: 4, at: base.addingTimeInterval(30_000 + Double($0))) }
        var clock = WallClockMonitor()
        // A5...A0 (event times descending) interleaved with B0...B5 (ascending).
        for index in 0..<6 {
            clock.sample()
            _ = await engine.evaluate(writerA[5 - index])
            clock.sample()
            _ = await engine.evaluate(writerB[index])
        }
        let before = try await assertExact(engine)
        clock.sample()
        _ = await engine.evaluate(writerA[6])
        clock.sample()

        let fold = try #require(await engine.pendingPressureDiagnostics().lastFold)
        #expect(fold.removedPendingSteps == 11 && fold.foldedGroups == 2)
        let ledger = await engine.pendingStepConservation()
        #expect(ledger.offered == 8_193 && ledger.completed == 11 && ledger.explicitlyShed == 0)
        let after = try await assertExact(engine)
        let bucket = try #require(after.pendingBuckets.first { $0.ruleID == rule.id }?.steps)
        #expect(bucket.suffix(2).map(\.matched.eventID) == [writerB[0].id, writerA[0].id],
                "each representative is its writer's earliest event, at its writer's last position")
        let writerBIDs = Set(writerB.map(\.id))
        let latestB = before.pendingBuckets.flatMap(\.steps)
            .filter { writerBIDs.contains($0.matched.eventID) }.map(\.arrivedAt).max()
        let representativeB = bucket[bucket.count - 2]
        #expect(representativeB.arrivedAt == latestB, "a representative takes its group's latest arrival")
        if !clock.regressed {
            #expect(bucket.last?.arrivedAt == bucket.map(\.arrivedAt).max())
            #expect(nonDecreasing(bucket.map(\.arrivedAt)))
        }
        let survivors = Set(bucket.map { SequenceCheckpointPendingIdentity(
            ruleID: rule.id, stepID: $0.stepID, eventID: $0.matched.eventID) })
        let survivingOrder = before.pendingEvictionOrder.filter { survivors.contains($0) }
        #expect(after.pendingEvictionOrder == survivingOrder,
                "a representative keeps its own admission position in the global order")

        let restarted = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await restarted.addRule(rule)
        _ = try await restarted.restoreCheckpoint(try SequenceCheckpointCodec.prepare(after).payload, now: Date())
        let roundTrip = try await assertExact(restarted)
        #expect(roundTrip.pendingBuckets == after.pendingBuckets)
        #expect(roundTrip.pendingEvictionOrder == after.pendingEvictionOrder)
        let more = (0..<11).map { write(pid: 2_001, pidVersion: 3, at: base.addingTimeInterval(20_100 + Double($0))) }
        for event in more { _ = await restarted.evaluate(event) }
        let refold = try #require(await restarted.pendingPressureDiagnostics().lastFold)
        #expect(refold.removedPendingSteps == 10 && refold.foldedGroups == 1, "only the live writes fold")
        #expect(await restarted.pendingStepsEvictedTotal == 0)
        let final = try await assertExact(restarted)
        let retained = Set(final.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
        #expect(retained.contains(writerA[0].id) && retained.contains(writerB[0].id))
        #expect(retained.contains(more[0].id) && more.dropFirst().allSatisfy { !retained.contains($0.id) })
    }

    @Test("A foldable burst in a smaller bucket folds before a larger rule's history is shed")
    func smallerFoldableBurstFoldsBeforeShedding() async throws {
        let quiet = ruleS(id: "fairness-quiet", seedSuffix: "quiet-seed", laterSuffix: "quiet-later")
        let burst = ruleD(id: "fairness-burst")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let history = filler(quiet, stepID: "later", count: 5_000, arrivedAt: reference)
        try await restore(engine, rules: [quiet, burst], pending: history, now: reference)
        for index in 0..<3_500 {
            _ = await engine.evaluate(write(pid: 4_001, pidVersion: 2, at: base.addingTimeInterval(Double(index))))
        }

        // The 3,193rd write passes the global cap while the quiet rule is the
        // largest bucket; the burst's own fold makes room instead.
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.foldedStepsTotal == 3_192)
        let fold = try #require(pressure.lastFold)
        #expect(fold.ruleID == burst.id && fold.removedPendingSteps == 3_192 && fold.foldedGroups == 1)
        #expect(pressure.lastPressure == nil)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[quiet.id]?.queued == 5_000 && byRule[quiet.id]?.explicitlyShed == 0)
        #expect(byRule[burst.id]?.queued == 308 && byRule[burst.id]?.completed == 3_192)
        try await assertExact(engine)
    }

    @Test("Duplicates in a bucket that is neither the victim nor the admitting rule fold before any shed")
    func thirdBucketFoldsBeforeShedding() async throws {
        let quiet = ruleS(id: "fairness-quiet", seedSuffix: "quiet-seed", laterSuffix: "quiet-later")
        let burst = ruleD(id: "fairness-burst")
        let third = ruleS(id: "fairness-third", seedSuffix: "third-seed", laterSuffix: "third-later")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let history = filler(quiet, stepID: "later", count: 5_000, arrivedAt: reference)
        try await restore(engine, rules: [quiet, burst, third], pending: history, now: reference)
        // One writer's 3,000 writes leave the table 192 short of its cap.
        for index in 0..<3_000 {
            _ = await engine.evaluate(write(pid: 4_001, pidVersion: 2, at: base.addingTimeInterval(Double(index))))
        }
        #expect(await engine.pendingPressureDiagnostics().foldAttemptsTotal == 0)
        for index in 0..<1_000 {
            _ = await engine.evaluate(proc("/usr/local/bin/third-later", pid: 20_000 + Int32(index),
                                           at: base.addingTimeInterval(Double(index))))
        }

        // The third rule's 193rd admission passes the cap. The quiet rule is
        // the largest bucket and neither it nor the admitting rule can fold,
        // so the burst's duplicates fold instead of live history being shed.
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.foldedStepsTotal == 2_999)
        let fold = try #require(pressure.lastFold)
        #expect(fold.ruleID == burst.id && fold.removedPendingSteps == 2_999 && fold.foldedGroups == 1)
        #expect(pressure.lastPressure == nil)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[quiet.id]?.queued == 5_000 && byRule[quiet.id]?.explicitlyShed == 0)
        #expect(byRule[third.id]?.queued == 1_000 && byRule[third.id]?.explicitlyShed == 0)
        #expect(byRule[burst.id]?.queued == 1 && byRule[burst.id]?.completed == 2_999)
        try await assertExact(engine)
    }

    /// What relief left after one co-admitted write.
    private struct CoAdmissionOutcome: Equatable {
        let shed: Int
        let foldAttempts: UInt64
        let folded: UInt64
        /// The last fold was the foldable rule's.
        let foldedFoldableRule: Bool
        let largeQueued: UInt64?
        let foldableQueued: UInt64?
    }

    @Test("A write admitted into two rules folds the same duplicates whichever rule's plan runs first")
    func coAdmissionFoldsWhicheverPlanRunsFirst() async throws {
        // One event's rule plans run in the hashed order of the rule index,
        // which a test cannot set but which differs between rule-ID pairs.
        // Fresh pairs run until both orders have been seen; alternate pairs
        // swap which name sorts first, so a sorted plan order yields both too.
        let capacity = SequenceEngine.maxPendingTotal
        var outcomes: [Bool: CoAdmissionOutcome] = [:]
        for pair in 0..<64 where outcomes.count < 2 {
            let names = ["fairness-co-\(pair)-a", "fairness-co-\(pair)-b"]
            let large = sharedWriteRule(id: names[pair % 2])
            let foldable = ruleD(id: names[1 - pair % 2])
            let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
            let reference = Date()
            try await restore(engine, rules: [large, foldable],
                              pending: filler(large, stepID: "later", count: capacity - 3, arrivedAt: reference),
                              now: reference)
            // Three writes by one writer fill the table to its cap.
            for index in 0..<3 {
                _ = await engine.evaluate(write(pid: 3_001, pidVersion: 5,
                                                at: base.addingTimeInterval(20_000 + Double(index))))
            }
            let shared = write(pid: 3_100, at: base.addingTimeInterval(20_010),
                               path: "/private/tmp/fairness/co-admitted")
            _ = await engine.evaluate(shared)

            let capture = try await assertExact(engine)
            let admitted = capture.pendingEvictionOrder.filter { $0.eventID == shared.id }
            try #require(admitted.count == 2, "both rules retain the shared write")
            let pressure = await engine.pendingPressureDiagnostics()
            let byRule = await engine.pendingStepConservationByRule()
            outcomes[admitted[0].ruleID == large.id] = CoAdmissionOutcome(
                shed: await engine.pendingStepsEvictedTotal, foldAttempts: pressure.foldAttemptsTotal,
                folded: pressure.foldedStepsTotal, foldedFoldableRule: pressure.lastFold?.ruleID == foldable.id,
                largeQueued: byRule[large.id]?.queued, foldableQueued: byRule[foldable.id]?.queued
            )
        }

        #expect(outcomes.count == 2, "both plan orders ran")
        // The first admission passes the cap and folds the writer's three
        // entries into one; the second fits.
        let expected = CoAdmissionOutcome(shed: 0, foldAttempts: 1, folded: 2, foldedFoldableRule: true,
                                          largeQueued: UInt64(capacity - 2), foldableQueued: 2)
        #expect(outcomes[true] == expected, "the larger rule's plan ran first")
        #expect(outcomes[false] == expected, "the foldable rule's plan ran first")
    }

    /// The relief step that first meets a fold-eligible bucket holding one
    /// entry: the writer's own first over-cap write, or another rule's
    /// over-cap admission.
    enum SingleEntryCase: String, CaseIterable, Sendable {
        case admittingRule
        case otherRule
    }

    @Test("A bucket holding one entry is never tried, so its writer's next write still folds",
          arguments: SingleEntryCase.allCases)
    func singleEntryBucketIsNotTried(_ kind: SingleEntryCase) async throws {
        let quiet = ruleS(id: "fairness-quiet", seedSuffix: "quiet-seed", laterSuffix: "quiet-later")
        let burst = ruleD(id: "fairness-burst")
        let third = ruleS(id: "fairness-third", seedSuffix: "third-seed", laterSuffix: "third-later")
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let capacity = SequenceEngine.maxPendingTotal
        // The writer's first write passes the cap, or fills the table for a
        // third rule's admission to pass it.
        let history = filler(quiet, stepID: "later", count: kind == .admittingRule ? capacity : capacity - 1,
                             arrivedAt: reference)
        try await restore(engine, rules: [quiet, burst, third], pending: history, now: reference)
        let first = write(pid: 4_001, pidVersion: 2, at: base.addingTimeInterval(20_000))
        _ = await engine.evaluate(first)
        if kind == .otherRule {
            _ = await engine.evaluate(proc("/usr/local/bin/third-later", pid: 20_000,
                                           at: base.addingTimeInterval(20_001)))
        }
        // Neither the quiet rule (the largest bucket) nor the third rule can
        // fold, and one write has nothing to merge: no attempt, one shed.
        #expect(await engine.pendingPressureDiagnostics().foldAttemptsTotal == 0)
        #expect(await engine.pendingStepsEvictedTotal == 1)

        // Nothing blocks the burst rule, so its writer's next write passes the
        // cap again and the admitting rule's fold merges the pair.
        let second = write(pid: 4_001, pidVersion: 2, at: base.addingTimeInterval(20_002))
        _ = await engine.evaluate(second)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.foldedStepsTotal == 1)
        let fold = try #require(pressure.lastFold)
        #expect(fold.ruleID == burst.id && fold.removedPendingSteps == 1 && fold.foldedGroups == 1)
        #expect(await engine.pendingStepsEvictedTotal == 1)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[quiet.id]?.explicitlyShed == 1)
        #expect(byRule[burst.id]?.queued == 1 && byRule[burst.id]?.completed == 1)
        let capture = try await assertExact(engine)
        let retained = Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
        #expect(retained.contains(first.id) && !retained.contains(second.id),
                "the earlier write represents the pair")
    }

    @Test("Weight pressure folds a writer's repeats before shedding pending history or partials")
    func weightPressureFoldsBeforeShedding() async throws {
        let wide = filePathRule(id: "fairness-wide", imageSuffix: "wide")
        let rule = ruleD()
        let path = "/private/tmp/" + String(repeating: "p", count: 8_192)
        let reference = Date()
        let itemWeight = SequenceCheckpointCodec.estimatedWeight(of: widePartial(wide, path: path, at: reference))
        let fixedWeight = SequenceCheckpointCodec.semanticStateBaseWeight
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: wide.id)
        // Wide partials fill the semantic-weight budget but for about two
        // partials' worth, so a few dozen writes reach it far below the count cap.
        let partialCount = (SequenceCheckpointCodec.maximumSemanticStateWeight - fixedWeight) / itemWeight - 2
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await restore(engine, rules: [wide, rule],
                          partials: (0..<partialCount).map { _ in widePartial(wide, path: path, at: reference) },
                          now: reference)
        var writes = 0
        while await engine.pendingPressureDiagnostics().foldAttemptsTotal == 0, writes < 1_000 {
            _ = await engine.evaluate(write(pid: 3_001, pidVersion: 5, at: base.addingTimeInterval(Double(writes))))
            writes += 1
        }

        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1)
        let folded = UInt64(writes - 1)
        #expect(pressure.foldedStepsTotal == folded, "every write folds into the first")
        #expect(pressure.semanticWeightShedTotal == 0 && pressure.lastPressure == nil)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        #expect(await engine.partialsEvictedTotal == 0)
        let capture = try await assertExact(engine)
        #expect(capture.pendingBuckets.flatMap(\.steps).count == 1)
        #expect(capture.partialBuckets.flatMap(\.partials).count == partialCount)
    }

    @Test("Weight pressure folds a lighter bucket's repeats before shedding the heaviest bucket's history")
    func weightPressureFoldsAnotherBucketFirst() async throws {
        let wide = filePathRule(id: "fairness-wide", imageSuffix: "wide")
        let rule = ruleD()
        let path = "/private/tmp/" + String(repeating: "p", count: 8_192)
        let reference = Date()
        func wideEntry() -> SequenceCheckpointPendingStep {
            SequenceCheckpointPendingStep(
                ruleID: wide.id, stepID: "written",
                matched: SequenceCheckpointMatchedStep(
                    stepID: "written", eventID: UUID(), timestamp: base, processPID: 41,
                    processParentPID: 0, processParentWasTracked: false, processAncestorPIDs: [],
                    filePath: path, networkDestination: nil
                ), arrivedAt: reference
            )
        }
        let itemWeight = SequenceCheckpointCodec.estimatedWeight(of: wideEntry())
        let fixedWeight = SequenceCheckpointCodec.semanticStateBaseWeight
            + SequenceCheckpointCodec.estimatedBucketOverhead(ruleID: wide.id)
        // The wide rule's history fills the semantic-weight budget but for
        // about two entries' worth, so its bucket stays the heaviest, and its
        // file-path correlation means it can never fold.
        let wideCount = (SequenceCheckpointCodec.maximumSemanticStateWeight - fixedWeight) / itemWeight - 2
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        try await restore(engine, rules: [wide, rule], pending: (0..<wideCount).map { _ in wideEntry() },
                          now: reference)
        var writes = 0
        while await engine.pendingPressureDiagnostics().foldAttemptsTotal == 0, writes < 1_000 {
            _ = await engine.evaluate(write(pid: 3_001, pidVersion: 5, at: base.addingTimeInterval(Double(writes))))
            writes += 1
        }

        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldAttemptsTotal == 1 && pressure.lastFold?.ruleID == rule.id)
        #expect(pressure.foldedStepsTotal == UInt64(writes - 1), "every write folds into the first")
        #expect(pressure.semanticWeightShedTotal == 0 && pressure.lastPressure == nil)
        #expect(await engine.pendingStepsEvictedTotal == 0)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[wide.id]?.queued == UInt64(wideCount) && byRule[wide.id]?.explicitlyShed == 0)
        try await assertExact(engine)
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
        // Every writer is distinct, so each fold attempt merges nothing and
        // blocks the next one for 256 admissions: attempts at 1, 257, 513, 769.
        let attempts = after.foldAttempts - before.foldAttempts
        #expect(attempts == 4)
        // Each over-cap admission scans the full bucket for expiry once and
        // shifts it once to remove the front, and each fold attempt reads it
        // once: linear, but no identity hashing.
        let visitsPerAdmission = UInt64(2 * (capacity + 1))
        let expectedVisits = UInt64(writes) * visitsPerAdmission + attempts * UInt64(capacity + 1)
        let visits = after.elementVisits - before.elementVisits
        #expect(visits == expectedVisits)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.perRuleCountShedTotal == UInt64(writes))
        #expect(pressure.globalCountShedTotal == 0 && pressure.semanticWeightShedTotal == 0)
        #expect(pressure.foldedStepsTotal == 0 && pressure.lastFold == nil)
        #expect(await engine.pendingStepsEvictedTotal == writes)
        let capture = try await assertExact(engine)
        let expectedOrder = restored.dropFirst(writes).map { identity($0) } + live.map { identity(rule, "write", $0) }
        let exactOrder = capture.pendingEvictionOrder == expectedOrder
        #expect(exactOrder, "the newest live writes are retained in admission order")
    }

    @Test("The fold throttle bounds attempts for one heavy writer in a full table")
    func foldThrottleBoundsHeavyWriter() async throws {
        let rule = ruleD()
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let reference = Date()
        let capacity = SequenceEngine.maxPendingTotal
        try await restoreFiller(engine, rule, stepID: "write", count: capacity - 1,
                                arrivedAt: reference, now: reference)
        let before = await engine.pendingCapacityOperationDiagnostics()
        for index in 0..<1_024 {
            _ = await engine.evaluate(write(pid: 3_001, pidVersion: 5,
                                            at: base.addingTimeInterval(20_000 + Double(index))))
        }
        let after = await engine.pendingCapacityOperationDiagnostics()

        // Attempts at admissions 2, 258, 514 and 770. The first merges a single
        // write, so it blocks the rule for 256 admissions and admissions 3-257
        // shed the restored front; each later attempt folds 256 writes.
        let attempts = after.foldAttempts - before.foldAttempts
        #expect(attempts == 4)
        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldedStepsTotal == 769 && pressure.perRuleCountShedTotal == 255)
        #expect(await engine.pendingStepsEvictedTotal == 255)
        let queued = UInt64(capacity - 1)
        #expect(await engine.pendingStepConservation().queued == queued)
        #expect(after.forcedQueueCompactions == before.forcedQueueCompactions)
        let rebuilds = after.identityRebuilds - before.identityRebuilds
        #expect(rebuilds == 6, "four fold commits plus the lazy compactions at admissions 258 and 770")
        try await assertExact(engine)
    }

    // MARK: - Heartbeat

    /// A table one short of its cap. One writer's second write folds into its
    /// first; a different writer's write, arriving while that fold attempt
    /// blocks the next, sheds the oldest restored entry.
    private func foldThenShed(
        _ engine: SequenceEngine, rule: SequenceRule
    ) async throws -> (restored: [SequenceCheckpointPendingStep], writes: [Event]) {
        let reference = Date()
        let restored = try await restoreFiller(engine, rule, stepID: "write",
                                               count: SequenceEngine.maxPendingTotal - 1,
                                               arrivedAt: reference, now: reference)
        let writes = [
            write(pid: 3_001, pidVersion: 5, at: base.addingTimeInterval(20_000)),
            write(pid: 3_001, pidVersion: 5, at: base.addingTimeInterval(20_001)),
            write(pid: 3_002, pidVersion: 5, at: base.addingTimeInterval(20_002)),
        ]
        for event in writes { _ = await engine.evaluate(event) }
        return (restored, writes)
    }

    @Test("The heartbeat's pending-pressure projection is fixed-schema and carries no event identities")
    func pendingPressureHeartbeatFields() async throws {
        let rule = ruleD()
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        let baseKeys: Set<String> = [
            "per_rule_count_shed_steps_total", "global_count_shed_steps_total", "semantic_weight_shed_steps_total",
            "journal_explicitly_shed_total", "classification_conserved", "per_rule_count_limit",
            "global_count_limit", "state_weight_limit_bytes", "victim_policy", "folded_steps_total",
            "fold_attempts_total", "advance_replay_bindings_total", "advance_replay_completions_total",
        ]
        let idle = SequencePendingPressureHeartbeat.fields(await engine.pendingPressureDiagnostics())
        #expect(Set(idle.keys) == baseKeys, "no removal or fold boundary has happened yet")
        let (restored, writes) = try await foldThenShed(engine, rule: rule)

        let fields = SequencePendingPressureHeartbeat.fields(await engine.pendingPressureDiagnostics())
        #expect(Set(fields.keys) == baseKeys.union(["last_pressure", "last_fold"]))
        #expect(fields["victim_policy"] as? String == "largest_bucket_oldest_first")
        #expect(fields["folded_steps_total"] as? UInt64 == 1 && fields["fold_attempts_total"] as? UInt64 == 1)
        #expect(fields["advance_replay_bindings_total"] as? UInt64 == 0
                    && fields["advance_replay_completions_total"] as? UInt64 == 0, "no partial was ever advanced")
        #expect(fields["per_rule_count_shed_steps_total"] as? UInt64 == 1)
        let pressure = try #require(fields["last_pressure"] as? [String: Any])
        #expect(Set(pressure.keys) == [
            "reason", "observed_at_unix", "pending_count_before", "partial_count_before",
            "rule_pending_count_before", "state_weight_bytes_before", "removed_pending_steps",
            "representative_fifo_victim_rule_id", "representative_fifo_victim_step_id",
        ])
        #expect(pressure["reason"] as? String == "per_rule_count")
        let fold = try #require(fields["last_fold"] as? [String: Any])
        #expect(Set(fold.keys) == ["observed_at_unix", "rule_id", "step_id", "removed", "groups"])
        #expect(fold["rule_id"] as? String == rule.id && fold["step_id"] as? String == "write")
        #expect(fold["removed"] as? UInt64 == 1 && fold["groups"] as? Int == 1)
        let encoded = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        let json = try #require(String(data: encoded, encoding: .utf8))
        #expect(!json.contains("/private/tmp"))
        for event in writes { #expect(!json.contains(event.id.uuidString)) }
        #expect(!json.contains(restored[0].matched.eventID.uuidString))
        #expect(encoded.count < 2_048, "the projection stays constant-size whatever the events carried")
    }

    @Test("The heartbeat reads pending history in one actor call, so its cross-checked pairs agree")
    func heartbeatReadsPendingHistoryOnce() async throws {
        let rule = ruleD()
        let engine = SequenceEngine(lineage: ProcessLineage(), sweepInterval: 3_600)
        _ = try await foldThenShed(engine, rule: rule)
        let history = await engine.pendingHistoryDiagnostics()
        #expect(history.journal.queued == UInt64(history.weight.pendingCount))
        #expect(history.evictedTotal == 1 && history.journal.explicitlyShed == UInt64(history.evictedTotal))
        #expect(history.pressure.journalExplicitlyShedTotal == history.journal.explicitlyShed)
        #expect(history.pressure.foldedStepsTotal == 1)
        #expect(history.journalByRule[rule.id] == history.journal)
        #expect(history.weight.cachedWeight == history.weight.recomputedWeight)

        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let timers = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"),
                                encoding: .utf8)
        let snapshotReads = timers.components(separatedBy: "await state.sequenceEngine.pendingHistoryDiagnostics()")
        #expect(snapshotReads.count == 2, "exactly one snapshot read")
        for separateRead in ["pendingStepConservation(", "pendingStepConservationByRule(",
                             "checkpointWeightDiagnostics(", "pendingPressureDiagnostics(",
                             "pendingStepsEvictedTotal"] {
            #expect(!timers.contains(separateRead), "\(separateRead) would be a second, separately timed read")
        }
        for derived in ["let sequencePendingStepsEvicted = sequencePendingHistory.evictedTotal",
                        "let sequenceJournalConservation = sequencePendingHistory.journal",
                        "let sequenceWeight = sequencePendingHistory.weight",
                        "let sequencePendingStepsCurrent = sequenceWeight.pendingCount"] {
            #expect(timers.contains(derived), "\(derived)")
        }
    }

    // MARK: - Randomized

    private enum RandomOperation {
        /// A write to the foldable rule, by one of 8 identified writers or an
        /// anonymous process.
        case write
        /// A later step of the non-foldable rule.
        case otherLaterStep
        case seed
        case finish
        /// Disable and re-enable the non-foldable rule, purging its state.
        case toggleOther
        case capture
    }

    @Test("Randomized pressure sequences keep exact accounting")
    func randomizedPressureStaysExact() async throws {
        let foldable = ruleD(id: "fairness-random-e", window: 600)
        let other = ruleS(id: "fairness-random-n", seedSuffix: "random-seed", laterSuffix: "random-later",
                          window: 600)
        let lineage = ProcessLineage()
        for index in 0..<8 {
            let seed = Int32(60_000 + index)
            await lineage.recordProcess(pid: seed, ppid: 1, path: "/usr/local/bin/seeder",
                                        name: "seeder", startTime: base)
            await lineage.recordProcess(pid: seed + 1_000, ppid: seed, path: "/usr/local/bin/writer",
                                        name: "writer", startTime: base)
        }
        let engine = SequenceEngine(lineage: lineage, sweepInterval: 3_600)
        let reference = Date()
        // Restored 200 s earlier, when the oldest 150 entries were still inside
        // the 600 s window; they have expired by the first operation. The
        // table starts two entries short of its cap, and the other rule stays
        // small, so purging it never relieves the pressure for long.
        let history = filler(foldable, stepID: "write", count: 150, arrivedAt: reference.addingTimeInterval(-700))
            + filler(foldable, stepID: "write", count: 8_000, arrivedAt: reference.addingTimeInterval(-1))
            + filler(other, stepID: "later", count: 40, pid: 9_998, arrivedAt: reference.addingTimeInterval(-1))
        try await restore(engine, rules: [foldable, other], pending: history,
                          now: reference.addingTimeInterval(-200))

        var rng = SplitMix64(seed: 0x5EED_CAFE_F00D_0017)
        var clock = WallClockMonitor()
        var seeds = 0
        for operation in 0..<600 {
            let roll = rng.next() % 100
            let at = base.addingTimeInterval(Double(rng.next() % 600))
            let writer = Int32(61_000 + Int(rng.next() % 8))
            // At most 20 seeds: each replays the whole foldable bucket.
            let kind: RandomOperation = switch roll {
            case 0..<25: .otherLaterStep
            case 25..<80: .write
            case 80..<86: seeds < 20 ? .seed : .write
            case 86..<91: .finish
            case 91: .toggleOther
            default: .capture
            }
            clock.sample()
            switch kind {
            case .write:
                if rng.next() % 9 == 0 {
                    _ = await engine.evaluate(write(pid: 62_000 + Int32(rng.next() % 1_000), at: at))
                } else {
                    _ = await engine.evaluate(write(pid: writer, pidVersion: 1, ppid: writer - 1_000, at: at))
                }
            case .otherLaterStep:
                _ = await engine.evaluate(proc("/usr/local/bin/random-later",
                                               pid: 63_000 + Int32(rng.next() % 100), at: at))
            case .seed:
                seeds += 1
                _ = await engine.evaluate(proc("/usr/local/bin/seeder", pid: writer - 1_000, at: at))
            case .finish:
                _ = await engine.evaluate(connection(pid: writer, ppid: writer - 1_000, at: at))
            case .toggleOther:
                await engine.setEnabled(other.id, enabled: false)
                await engine.setEnabled(other.id, enabled: true)
            case .capture:
                _ = try await engine.checkpointCapture()
            }
            clock.sample()
            await assertAccounting(engine)
            if operation % 50 == 49 {
                let capture = try await engine.checkpointCapture()
                let live = capture.pendingBuckets.flatMap { bucket in
                    bucket.steps.map { SequenceCheckpointPendingIdentity(
                        ruleID: bucket.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID) }
                }
                #expect(Set(capture.pendingEvictionOrder).count == capture.pendingEvictionOrder.count)
                #expect(Set(capture.pendingEvictionOrder) == Set(live))
                if !clock.regressed {
                    #expect(capture.pendingBuckets.allSatisfy { nonDecreasing($0.steps.map(\.arrivedAt)) })
                }
            }
        }

        let pressure = await engine.pendingPressureDiagnostics()
        #expect(pressure.foldedStepsTotal > 0, "the sequence folded at least once")
        #expect(await engine.pendingStepsEvictedTotal > 0, "and shed at least once")
        let completed = await engine.pendingStepConservationByRule()[foldable.id]?.completed ?? 0
        #expect(completed >= 150, "the expired restored history retired as completed")
        try await assertExact(engine)
    }
}
