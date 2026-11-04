import Foundation
import Testing
@testable import MacCrabCore

/// Synthetic in-memory process, file and network events over one fixed
/// process tree: 100 runs the seed, 101-104 are its children and 201-204 are
/// unrelated. No files, processes, collectors or daemon. Event times are
/// fixed offsets from one base date. Processing-time windows come from
/// restoring checkpoint state at a chosen instant, every engine sweeps
/// periodically only once an hour, and the property test draws from a fixed
/// seed. Serialized because the capacity cases drive a full 8,192-entry table.
@Suite("Sequence replay on advance", .serialized)
struct SequenceReplayOnAdvanceTests {
    private let base = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Rules

    private func step(_ id: String, _ category: String, image: String, after: String? = nil,
                      relation: ProcessRelation? = nil) -> SequenceStep {
        SequenceStep(id: id, logsourceCategory: category,
                     predicates: [Predicate(field: "Image", modifier: .endswith, values: [image], negate: false)],
                     afterStep: after,
                     processRelation: relation.map { ProcessRelationSpec(relation: $0, relativeToStep: "seed") })
    }

    /// seed (a `/seed` exec), then middle (a `/writer` file write) and finish
    /// (a `/caller` connection), each related to the seed: ordered, with the
    /// trigger shape of npm_postinstall_to_rat. Its middle step is the one
    /// the at-capacity fold may merge.
    private func threeStepRule(id: String = "replay-three", window: TimeInterval = 600,
                               correlation: CorrelationType = .processLineage,
                               relation: ProcessRelation = .descendant) -> SequenceRule {
        SequenceRule(
            id: id, title: "replay on advance fixture", description: "in-memory fixture",
            level: .low, tags: [], window: window, correlationType: correlation, ordered: true,
            steps: [
                step("seed", "process_creation", image: "/seed"),
                step("middle", "file_event", image: "/writer", after: "seed", relation: relation),
                step("finish", "network_connection", image: "/caller", after: "middle", relation: relation),
            ],
            trigger: .steps(["middle", "finish"])
        )
    }

    /// threeStepRule plus closer (a `/closer` exec by a descendant of the
    /// seed); every step is required.
    private func fourStepRule() -> SequenceRule {
        SequenceRule(
            id: "replay-four", title: "replay on advance cascade fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 600, correlationType: .processLineage, ordered: true,
            steps: [
                step("seed", "process_creation", image: "/seed"),
                step("middle", "file_event", image: "/writer", after: "seed", relation: .descendant),
                step("finish", "network_connection", image: "/caller", after: "middle", relation: .descendant),
                step("closer", "process_creation", image: "/closer", after: "finish", relation: .descendant),
            ],
            trigger: .allSteps
        )
    }

    /// One `/dual` exec matches both the seed and the middle step (a
    /// descendant of the seed); finish is a `/caller` connection.
    private func dualMatchRule() -> SequenceRule {
        SequenceRule(
            id: "replay-dual", title: "seed and advance fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 600, correlationType: .processLineage, ordered: true,
            steps: [
                step("seed", "process_creation", image: "/dual"),
                step("middle", "process_creation", image: "/dual", after: "seed", relation: .descendant),
                step("finish", "network_connection", image: "/caller", after: "middle", relation: .descendant),
            ],
            trigger: .allSteps
        )
    }

    // MARK: - Processes and events

    private func record(_ lineage: ProcessLineage, pid: Int32, ppid: Int32) async {
        await lineage.recordProcess(pid: pid, ppid: ppid, path: "/usr/local/bin/fixture", name: "fixture",
                                    startTime: base)
    }

    /// 100 runs the seed; 101-104 are its children; 201-204 are unrelated.
    private func fixtureLineage() async -> ProcessLineage {
        let lineage = ProcessLineage()
        await record(lineage, pid: 100, ppid: 1)
        for pid: Int32 in 101...104 { await record(lineage, pid: pid, ppid: 100) }
        for pid: Int32 in 201...204 { await record(lineage, pid: pid, ppid: 1) }
        return lineage
    }

    private func parent(of pid: Int32) -> Int32 {
        (101...104).contains(pid) ? 100 : 1
    }

    /// The event's process carries its parent as its only ancestor unless
    /// `ancestry` is false (then its parent is 1 and it carries none).
    private func processInfo(_ executable: String, pid: Int32, ancestry: Bool = true,
                             pidVersion: UInt32? = nil) -> MacCrabCore.ProcessInfo {
        let ppid = ancestry ? parent(of: pid) : 1
        return MacCrabCore.ProcessInfo(
            pid: pid, ppid: ppid, rpid: pid, name: (executable as NSString).lastPathComponent,
            executable: executable, commandLine: executable, args: [executable],
            workingDirectory: "/private/tmp", userId: 501, userName: "fixture", groupId: 20, startTime: base,
            ancestors: ancestry ? [ProcessAncestor(pid: ppid, executable: "/usr/local/bin/fixture", name: "fixture")] : [],
            auditIdentity: pidVersion.map {
                AuditIdentity(auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20, pid: pid, pidversion: $0,
                              asid: 100_001)
            }
        )
    }

    private func exec(_ executable: String, pid: Int32, at offset: TimeInterval) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .process, eventType: .start,
              eventAction: "exec", process: processInfo(executable, pid: pid))
    }

    private func seed(pid: Int32 = 100, at offset: TimeInterval) -> Event {
        exec("/usr/local/bin/seed", pid: pid, at: offset)
    }

    /// A `/writer` file write; it carries an ES audit identity only when
    /// `pidVersion` is set.
    private func middle(pid: Int32, at offset: TimeInterval, pidVersion: UInt32? = nil) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .file, eventType: .creation,
              eventAction: "write", process: processInfo("/usr/local/bin/writer", pid: pid, pidVersion: pidVersion),
              file: FileInfo(path: "/private/tmp/replay-fixture/out", action: .write))
    }

    private func finish(pid: Int32, at offset: TimeInterval, ancestry: Bool = true) -> Event {
        Event(timestamp: base.addingTimeInterval(offset), eventCategory: .network, eventType: .creation,
              eventAction: "connect", process: processInfo("/usr/local/bin/caller", pid: pid, ancestry: ancestry),
              network: NetworkInfo(sourceIp: "10.0.0.2", sourcePort: 51_000, destinationIp: "93.184.216.34",
                                   destinationPort: 443, destinationHostname: nil, direction: .outbound,
                                   transport: "tcp"))
    }

    private func closer(pid: Int32, at offset: TimeInterval) -> Event {
        exec("/usr/local/bin/closer", pid: pid, at: offset)
    }

    private func permutations(_ events: [Event]) -> [[Event]] {
        guard events.count > 1 else { return [events] }
        return events.indices.flatMap { index -> [[Event]] in
            var rest = events
            let head = rest.remove(at: index)
            return permutations(rest).map { [head] + $0 }
        }
    }

    // MARK: - Engine and accounting

    private func makeEngine(_ rules: [SequenceRule], lineage: ProcessLineage? = nil) async throws -> SequenceEngine {
        let tracker: ProcessLineage
        if let lineage { tracker = lineage } else { tracker = await fixtureLineage() }
        let engine = SequenceEngine(lineage: tracker, sweepInterval: 3_600)
        for rule in rules { try await engine.addRule(rule) }
        return engine
    }

    /// Exact weight, journal and pressure accounting; nothing shed unless the
    /// case sheds on purpose.
    private func assertExact(_ engine: SequenceEngine, shedAllowed: Bool = false) async {
        let weight = await engine.checkpointWeightDiagnostics()
        #expect(weight.cachedWeight == weight.recomputedWeight && weight.cachedWeight <= weight.maximumWeight)
        let journal = await engine.pendingStepConservation()
        #expect(journal.conservationMaintained && journal.inFlight == 0)
        #expect(await engine.pendingStepConservationByRule().values.allSatisfy(\.conservationMaintained))
        let pressure = await engine.pendingPressureDiagnostics()
        let evicted = await engine.pendingStepsEvictedTotal
        #expect(pressure.classificationConserved && pressure.journalExplicitlyShedTotal == UInt64(evicted))
        if !shedAllowed {
            #expect(evicted == 0)
            #expect(await engine.partialPressureDiagnostics().totalShed == 0)
        }
    }

    /// Completions of `rule` returned by each evaluation, with exact
    /// accounting checked after every one.
    private func fires(_ events: [Event], on engine: SequenceEngine, rule: SequenceRule,
                       shedAllowed: Bool = false) async -> [Int] {
        var counts: [Int] = []
        for event in events {
            counts.append(await engine.evaluate(event).filter { $0.ruleId == rule.id }.count)
            await assertExact(engine, shedAllowed: shedAllowed)
        }
        return counts
    }

    /// Replay-on-advance pending scans run while `events` were evaluated, and
    /// the completions they returned.
    private func scans(_ events: [Event], on engine: SequenceEngine,
                       rule: SequenceRule) async -> (scans: UInt64, fires: [Int]) {
        let before = await engine.advanceReplayScanCount()
        let counts = await fires(events, on: engine, rule: rule)
        let after = await engine.advanceReplayScanCount()
        return (after - before, counts)
    }

    private func ledger(offered: UInt64, queued: UInt64) -> SequenceConservationTelemetry {
        SequenceConservationTelemetry(offered: offered, completed: 0, queued: queued, inFlight: 0, explicitlyShed: 0)
    }

    // MARK: - Restored state

    /// A partial holding only a seed by pid 100 at event time 0, created at
    /// `createdAt`.
    private func seedPartial(_ rule: SequenceRule, createdAt: Date) -> SequenceCheckpointPartial {
        SequenceCheckpointPartial(
            id: UUID(), ruleID: rule.id, createdAt: createdAt,
            matchedSteps: [SequenceCheckpointMatchedStep(
                stepID: "seed", eventID: UUID(), timestamp: base, processPID: 100, processParentPID: 1,
                processParentWasTracked: false, processAncestorPIDs: [1], filePath: nil, networkDestination: nil
            )],
            correlationKey: rule.correlationType == .none ? nil : "100"
        )
    }

    /// A retained finish by `pid`, a child of the seed's process, with the
    /// ancestry its evaluation recorded.
    private func retainedFinish(_ rule: SequenceRule, pid: Int32 = 102, at offset: TimeInterval,
                                arrivedAt: Date) -> SequenceCheckpointPendingStep {
        SequenceCheckpointPendingStep(
            ruleID: rule.id, stepID: "finish",
            matched: SequenceCheckpointMatchedStep(
                stepID: "finish", eventID: UUID(), timestamp: base.addingTimeInterval(offset),
                processPID: pid, processParentPID: 100, processParentWasTracked: true,
                processAncestorPIDs: [1, 100], filePath: nil, networkDestination: "93.184.216.34:443"
            ),
            arrivedAt: arrivedAt
        )
    }

    /// Restored history with unique event IDs by a process the lineage does
    /// not know, with no parent or ancestry.
    private func filler(_ rule: SequenceRule, stepID: String, count: Int,
                        arrivedAt: Date) -> [SequenceCheckpointPendingStep] {
        (0..<count).map { index in
            SequenceCheckpointPendingStep(
                ruleID: rule.id, stepID: stepID,
                matched: SequenceCheckpointMatchedStep(
                    stepID: stepID, eventID: UUID(), timestamp: base.addingTimeInterval(Double(index) / 1_000),
                    processPID: 9_999, processParentPID: 0, processParentWasTracked: false,
                    processAncestorPIDs: [], filePath: nil, networkDestination: nil
                ),
                arrivedAt: arrivedAt
            )
        }
    }

    /// Restores the given state as a checkpoint taken at `now`; the global
    /// orders follow the records' order.
    private func restore(
        _ engine: SequenceEngine, rules: [SequenceRule], partials: [SequenceCheckpointPartial] = [],
        pending: [SequenceCheckpointPendingStep] = [], now: Date
    ) async throws {
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion, capturedAt: now,
            ruleFingerprint: try SequenceCheckpointCodec.ruleFingerprint(rules), sourceGeneration: 1,
            partialBuckets: rules.compactMap { rule in
                let records = partials.filter { $0.ruleID == rule.id }
                return records.isEmpty ? nil : SequenceCheckpointPartialBucket(ruleID: rule.id, partials: records)
            },
            pendingBuckets: rules.compactMap { rule in
                let steps = pending.filter { $0.ruleID == rule.id }
                return steps.isEmpty ? nil : SequenceCheckpointPendingBucket(ruleID: rule.id, steps: steps)
            },
            evictionOrder: partials.map(\.id),
            pendingEvictionOrder: pending.map {
                SequenceCheckpointPendingIdentity(ruleID: $0.ruleID, stepID: $0.stepID, eventID: $0.matched.eventID)
            }
        )
        let restored = try await engine.restoreCheckpoint(payload, now: now)
        #expect(restored.partialCount == partials.count && restored.pendingCount == pending.count)
        #expect(restored.expiredPartialCount == 0 && restored.expiredPendingCount == 0)
    }

    // MARK: - Ordering, cascade and binding

    @Test("Every delivery order of seed, middle and finish completes once, on the last event")
    func everyOrderCompletesOnceOnTheLastEvent() async throws {
        let rule = threeStepRule()
        for order in permutations([seed(at: 0), middle(pid: 101, at: 1), finish(pid: 102, at: 2)]) {
            let engine = try await makeEngine([rule])
            #expect(await fires(order, on: engine, rule: rule) == [0, 0, 1], "\(order.map(\.eventCategory))")
            #expect(await engine.activePartialMatchCount == 0)
            #expect(await engine.pendingStepConservationByRule()[rule.id] == ledger(offered: 2, queued: 2))
        }
    }

    @Test("Every delivery order of a four-step chain completes once, on the last event")
    func everyOrderOfFourStepsCompletesOnce() async throws {
        let rule = fourStepRule()
        let events = [seed(at: 0), middle(pid: 101, at: 1), finish(pid: 102, at: 2), closer(pid: 103, at: 3)]
        for order in permutations(events) {
            let engine = try await makeEngine([rule])
            #expect(await fires(order, on: engine, rule: rule) == [0, 0, 0, 1], "\(order.map(\.eventCategory))")
            #expect(await engine.activePartialMatchCount == 0)
        }
    }

    @Test("Binding the middle step replays every later step in one scan")
    func middleStepCascadesThroughLaterSteps() async throws {
        let rule = fourStepRule()
        let engine = try await makeEngine([rule])
        #expect(await fires([seed(at: 0), closer(pid: 103, at: 3), finish(pid: 102, at: 2)],
                            on: engine, rule: rule) == [0, 0, 0])
        let before = await engine.pendingPressureDiagnostics()
        let cascade = await scans([middle(pid: 101, at: 1)], on: engine, rule: rule)
        #expect(cascade.fires == [1] && cascade.scans == 1)
        let after = await engine.pendingPressureDiagnostics()
        let bindings = after.advanceReplayBindingsTotal - before.advanceReplayBindingsTotal
        let completions = after.advanceReplayCompletionsTotal - before.advanceReplayCompletionsTotal
        #expect(bindings == 2 && completions == 1, "finish, then closer")
    }

    @Test("Each later step binds its earliest passing retained entry")
    func earliestPassingEntryBinds() async throws {
        let rule = threeStepRule()
        let engine = try await makeEngine([rule])
        let retained = [finish(pid: 201, at: 2), finish(pid: 102, at: 3), finish(pid: 103, at: 4)]
        #expect(await fires([seed(at: 0)] + retained, on: engine, rule: rule) == [0, 0, 0, 0])
        let matches = await engine.evaluate(middle(pid: 101, at: 1)).filter { $0.ruleId == rule.id }
        await assertExact(engine)
        let description = try #require(matches.first?.description)
        #expect(matches.count == 1)
        #expect(description.contains("finish (pid:102"), "the unrelated earlier finish is skipped")
        #expect(!description.contains("pid:103") && !description.contains("pid:201"))
        #expect(await fires([finish(pid: 104, at: 5)], on: engine, rule: rule) == [0])
    }

    @Test("A later step timed before the middle step is never replayed into it")
    func earlierTimedLaterStepDoesNotBind() async throws {
        let rule = threeStepRule()
        let engine = try await makeEngine([rule])
        #expect(await fires([seed(at: 0), finish(pid: 102, at: 1), middle(pid: 101, at: 2)],
                            on: engine, rule: rule) == [0, 0, 0])
        #expect(await engine.activePartialMatchCount == 1)
        #expect(await fires([finish(pid: 103, at: 3)], on: engine, rule: rule) == [1])
    }

    @Test("A retained later step from an unrelated process is never replayed into the chain")
    func unrelatedLaterStepDoesNotBind() async throws {
        let rule = threeStepRule()
        let engine = try await makeEngine([rule])
        #expect(await fires([seed(at: 0), finish(pid: 201, at: 2), middle(pid: 101, at: 1)],
                            on: engine, rule: rule) == [0, 0, 0])
        #expect(await fires([finish(pid: 102, at: 3)], on: engine, rule: rule) == [1])
    }

    // MARK: - Windows

    @Test("A retained later step past its window is skipped and left in place", arguments: [true, false])
    func expiredLaterStepIsSkipped(expired: Bool) async throws {
        let rule = threeStepRule(window: 60)
        let engine = try await makeEngine([rule])
        let reference = Date()
        // Restored 30 s ago, when both records were inside the 60 s window. At
        // the middle step the partial is 30 s old and the finish either 70 s
        // or 35 s.
        let retained = retainedFinish(rule, at: 2, arrivedAt: reference.addingTimeInterval(expired ? -70 : -35))
        try await restore(engine, rules: [rule],
                          partials: [seedPartial(rule, createdAt: reference.addingTimeInterval(-30))],
                          pending: [retained], now: reference.addingTimeInterval(-30))
        let middleEvent = middle(pid: 101, at: 1)
        #expect(await fires([middleEvent], on: engine, rule: rule) == [expired ? 0 : 1])
        #expect(await engine.pendingStepConservationByRule()[rule.id] == ledger(offered: 2, queued: 2),
                "the replay retires nothing; the sweep does")
        let capture = try await engine.checkpointCapture()
        #expect(Set(capture.pendingBuckets.flatMap(\.steps).map(\.matched.eventID))
                    == [retained.matched.eventID, middleEvent.id])
    }

    @Test("A partial past its window is not advanced, so nothing is replayed into it")
    func expiredPartialIsNotAdvanced() async throws {
        let rule = threeStepRule(window: 60)
        let engine = try await makeEngine([rule])
        let reference = Date()
        // Restored 35 s ago, when the partial was 35 s old and the finish 5 s.
        // At the middle step the partial is 70 s old; the finish, 40 s, is
        // still inside its window.
        try await restore(engine, rules: [rule],
                          partials: [seedPartial(rule, createdAt: reference.addingTimeInterval(-70))],
                          pending: [retainedFinish(rule, at: 2, arrivedAt: reference.addingTimeInterval(-40))],
                          now: reference.addingTimeInterval(-35))
        let expiredAdvance = await scans([middle(pid: 101, at: 1)], on: engine, rule: rule)
        #expect(expiredAdvance.fires == [0] && expiredAdvance.scans == 0)
        let capture = try await engine.checkpointCapture()
        #expect(capture.partialBuckets.flatMap(\.partials).flatMap(\.matchedSteps).map(\.stepID) == ["seed"])
    }

    // MARK: - Fan-out, idempotency and history

    @Test("One retained later step completes every partial the middle step advanced, as in event order")
    func replayFansOutToEveryAdvancedPartial() async throws {
        let rule = threeStepRule(id: "replay-uncorrelated", correlation: .none, relation: .any)
        let seeds = [seed(pid: 100, at: 0), seed(pid: 201, at: 0.5)]
        let middleEvent = middle(pid: 203, at: 1)
        let finishEvent = finish(pid: 202, at: 2)
        let inOrder = try await makeEngine([rule])
        #expect(await fires(seeds + [middleEvent, finishEvent], on: inOrder, rule: rule) == [0, 0, 0, 2])
        let inverted = try await makeEngine([rule])
        #expect(await fires(seeds + [finishEvent, middleEvent], on: inverted, rule: rule) == [0, 0, 0, 2])
        #expect(await fires([finishEvent, finish(pid: 204, at: 3)], on: inverted, rule: rule) == [0, 0],
                "both partials completed and left the pool")
    }

    @Test("A duplicate middle event changes nothing")
    func duplicateMiddleIsIdempotent() async throws {
        let rule = threeStepRule()
        let engine = try await makeEngine([rule])
        let middleEvent = middle(pid: 101, at: 1)
        #expect(await fires([seed(at: 0), finish(pid: 201, at: 2), middleEvent], on: engine, rule: rule) == [0, 0, 0])
        let before = try await engine.checkpointCapture()
        let duplicate = await scans([middleEvent], on: engine, rule: rule)
        #expect(duplicate.fires == [0] && duplicate.scans == 0)
        let after = try await engine.checkpointCapture()
        #expect(after.partialBuckets == before.partialBuckets)
        #expect(after.pendingBuckets == before.pendingBuckets)
        #expect(after.evictionOrder == before.evictionOrder)
        #expect(after.pendingEvictionOrder == before.pendingEvictionOrder)
        #expect(after.sourceGeneration == before.sourceGeneration)
    }

    @Test("Replay on advance consumes no history: a second chain completes with the same retained step")
    func replayConsumesNoHistory() async throws {
        let rule = threeStepRule()
        let engine = try await makeEngine([rule])
        let retained = finish(pid: 102, at: 5)
        #expect(await fires([seed(at: 0), retained, middle(pid: 101, at: 1)], on: engine, rule: rule) == [0, 0, 1])
        let capture = try await engine.checkpointCapture()
        #expect(capture.pendingBuckets.flatMap(\.steps).contains { $0.matched.eventID == retained.id })
        #expect(await fires([seed(at: 2)], on: engine, rule: rule) == [0])
        let matches = await engine.evaluate(middle(pid: 103, at: 3)).filter { $0.ruleId == rule.id }
        await assertExact(engine)
        #expect(matches.count == 1)
        #expect(matches.first?.description.contains("finish (pid:102") == true)
    }

    @Test("A restored engine completes on the middle step exactly as the original")
    func restoredEngineMatchesOriginal() async throws {
        let rule = threeStepRule()
        let original = try await makeEngine([rule])
        #expect(await fires([seed(at: 0), finish(pid: 102, at: 2)], on: original, rule: rule) == [0, 0])
        let saved = try await original.checkpointCapture()
        let decoded = try SequenceCheckpointCodec.decode(try SequenceCheckpointCodec.prepare(saved).encodedFile)
        let restored = try await makeEngine([rule])
        #expect(try await restored.restoreCheckpoint(decoded, now: saved.capturedAt).partialCount == 1)
        let middleEvent = middle(pid: 101, at: 1)
        let originalMatches = await original.evaluate(middleEvent)
        let restoredMatches = await restored.evaluate(middleEvent)
        #expect(originalMatches.count == 1 && restoredMatches == originalMatches)
        await assertExact(original)
        await assertExact(restored)
    }

    // MARK: - Scan scope

    @Test("A pending scan runs only after a middle step advanced a partial without completing it")
    func scanRunsOnlyAfterANonCompletingAdvance() async throws {
        let rule = threeStepRule()
        let unseeded = try await makeEngine([rule])
        let noPartial = await scans([finish(pid: 201, at: 2), middle(pid: 101, at: 1)], on: unseeded, rule: rule)
        #expect(noPartial.scans == 0 && noPartial.fires == [0, 0])

        let engine = try await makeEngine([rule])
        #expect(await fires([seed(at: 0), finish(pid: 201, at: 2)], on: engine, rule: rule) == [0, 0])
        let advance = await scans([middle(pid: 101, at: 1)], on: engine, rule: rule)
        #expect(advance.scans == 1 && advance.fires == [0], "the unrelated retained finish is scanned, not bound")
        let alreadyBound = await scans([middle(pid: 103, at: 2)], on: engine, rule: rule)
        #expect(alreadyBound.scans == 0 && alreadyBound.fires == [0])
        let live = await scans([finish(pid: 102, at: 3)], on: engine, rule: rule)
        #expect(live.scans == 0 && live.fires == [1])
    }

    @Test("An event that both seeds and advances runs only the full replay and fires as in event order")
    func seedAndAdvanceInOneEvent() async throws {
        let rule = dualMatchRule()
        let first = exec("/usr/local/bin/dual", pid: 100, at: 0)
        let dual = exec("/usr/local/bin/dual", pid: 101, at: 1)
        let call = finish(pid: 102, at: 2)
        let inOrder = try await makeEngine([rule])
        let ordered = await scans([first, dual, call], on: inOrder, rule: rule)
        let inverted = try await makeEngine([rule])
        let reversed = await scans([first, call, dual], on: inverted, rule: rule)
        #expect(ordered.fires == [0, 0, 1] && reversed.fires == [0, 0, 1])
        #expect(ordered.scans == 0 && reversed.scans == 0, "the seeding event's full replay covers its advance")
        #expect(await inverted.activePartialMatchCount == 1, "the dual event's own partial stays open")
    }

    // MARK: - Differential property

    /// 500 generated scenarios: one seed at t = 0 and up to three middles and
    /// three finishes at t in 1...9, each by a child of the seed's process
    /// (101-104) or an unrelated one (201-204), delivered in a random order.
    /// The oracle: a chain is valid when some child's middle is timed no later
    /// than some child's finish.
    @Test("Replay on advance completes only valid chains, and every valid one in event-time order")
    func differentialAgainstTheEventTimeOracle() async throws {
        let rule = threeStepRule()
        let lineage = await fixtureLineage()
        var rng = SplitMix64(seed: 0x5EED_F10)
        func draw(_ bound: Int) -> Int { Int(rng.next() % UInt64(bound)) }
        func processID() -> Int32 {
            let slot = Int32(draw(8))
            return slot < 4 ? 101 + slot : 197 + slot
        }
        var validCount = 0
        var completedOnMiddle = 0
        for _ in 0..<500 {
            var events = [seed(at: 0)]
            var childMiddles: [Date] = []
            var childFinishes: [Date] = []
            for _ in 0..<draw(4) {
                let pid = processID()
                let event = middle(pid: pid, at: Double(1 + draw(9)))
                events.append(event)
                if pid < 200 { childMiddles.append(event.timestamp) }
            }
            for _ in 0..<draw(4) {
                let pid = processID()
                let event = finish(pid: pid, at: Double(1 + draw(9)))
                events.append(event)
                if pid < 200 { childFinishes.append(event.timestamp) }
            }
            let valid = childMiddles.contains { middleTime in childFinishes.contains { middleTime <= $0 } }
            if valid { validCount += 1 }
            var order = events
            for index in stride(from: order.count - 1, to: 0, by: -1) {
                order.swapAt(index, draw(index + 1))
            }

            let shuffled = try await makeEngine([rule], lineage: lineage)
            let counts = await fires(order, on: shuffled, rule: rule)
            let fired = counts.reduce(0, +)
            #expect(fired <= 1)
            if fired == 1 {
                #expect(valid, "a completion outside the event-time semantics")
                if let index = counts.firstIndex(of: 1), order[index].eventCategory == .file { completedOnMiddle += 1 }
            }
            let middleTimes = order.filter { $0.eventCategory == .file }.map(\.timestamp)
            if zip(middleTimes, middleTimes.dropFirst()).allSatisfy({ $0 <= $1 }) {
                #expect(fired == (valid ? 1 : 0), "middles delivered in event-time order miss no valid chain")
            }
            let timeOrdered = events.enumerated()
                .sorted { ($0.element.timestamp, $0.offset) < ($1.element.timestamp, $1.offset) }
                .map(\.element)
            let inTime = try await makeEngine([rule], lineage: lineage)
            let firedInTime = await fires(timeOrdered, on: inTime, rule: rule).reduce(0, +)
            #expect(firedInTime == (valid ? 1 : 0))
        }
        #expect(validCount >= 50 && completedOnMiddle >= 10, "the generator exercises replay on advance")
    }

    // MARK: - Lineage snapshot scope

    @Test("Replay on advance decides relations from each entry's recorded ancestry, requesting no pending PIDs")
    func replayUsesRecordedAncestry() async throws {
        let rule = threeStepRule()
        let lineage = await fixtureLineage()
        let engine = try await makeEngine([rule], lineage: lineage)
        #expect(await fires([seed(at: 0), finish(pid: 102, at: 2)], on: engine, rule: rule) == [0, 0])
        let before = await lineage.relationshipSnapshotDiagnostics()
        #expect(await fires([middle(pid: 101, at: 1)], on: engine, rule: rule) == [1])
        let after = await lineage.relationshipSnapshotDiagnostics()
        let requested = after.requestedPIDCount - before.requestedPIDCount
        #expect(requested == 2, "the middle's own PID and the partial's seed PID, not the retained finish's")
    }

    @Test("Lineage learned after a retained step was evaluated reaches it only through a later seed")
    func lateLineageWaitsForTheNextSeed() async throws {
        let rule = threeStepRule()
        let lineage = ProcessLineage()
        await record(lineage, pid: 100, ppid: 1)
        await record(lineage, pid: 101, ppid: 100)
        let engine = try await makeEngine([rule], lineage: lineage)
        // 102 is unknown when its finish is evaluated, and the event carries
        // no ancestry of its own, so the retained entry cannot prove it.
        #expect(await fires([seed(at: 0), finish(pid: 102, at: 2, ancestry: false)], on: engine, rule: rule) == [0, 0])
        await record(lineage, pid: 102, ppid: 100)
        #expect(await fires([middle(pid: 101, at: 1)], on: engine, rule: rule) == [0])
        #expect(await fires([seed(at: 3)], on: engine, rule: rule) == [1],
                "a seed's full replay requests the retained PID and completes the earlier partial")
    }

    // MARK: - Composition with capacity relief

    @Test("Replay on advance takes only later-step entries as candidates, never folded middle-step history")
    func replayNeverReadsFoldedHistory() async throws {
        let rule = threeStepRule()
        #expect(SequenceEngine.pendingFoldStepID(for: rule) == "middle")
        let engine = try await makeEngine([rule])
        let reference = Date()
        try await restore(engine, rules: [rule],
                          pending: filler(rule, stepID: "middle", count: SequenceEngine.maxPendingTotal - 4,
                                          arrivedAt: reference),
                          now: reference)
        // Five writes by one identified writer outside the seed's tree: the
        // fifth crosses the cap and folds all five into the first.
        let writes = (0..<5).map { middle(pid: 201, at: 20 + Double($0), pidVersion: 7) }
        #expect(await fires(writes, on: engine, rule: rule) == [0, 0, 0, 0, 0])
        let folded = await engine.pendingPressureDiagnostics()
        #expect(folded.foldedStepsTotal == 4 && folded.foldAttemptsTotal == 1)
        let candidatesBefore = await engine.advanceReplayCandidateCount()

        #expect(await fires([seed(at: 0), finish(pid: 102, at: 2), middle(pid: 101, at: 1)],
                            on: engine, rule: rule) == [0, 0, 1])
        let replayed = await engine.pendingPressureDiagnostics()
        let bindings = replayed.advanceReplayBindingsTotal - folded.advanceReplayBindingsTotal
        #expect(bindings == 1, "only the finish, step index 2, was replayed")
        // The bucket then held the finish and 8,189 middle-step entries,
        // the folded representative among them.
        let candidates = await engine.advanceReplayCandidateCount() - candidatesBefore
        #expect(candidates == 1, "the scan took only the finish as a candidate")
        let capture = try await engine.checkpointCapture()
        let writerHistory = capture.pendingBuckets.flatMap(\.steps).filter { $0.matched.processPID == 201 }
        #expect(writerHistory.map(\.matched.eventID) == [writes[0].id], "the folded representative is untouched")
    }

    @Test("A flood in a larger rule leaves the retained later step alone, so the middle step still completes")
    func floodElsewhereKeepsTheRetainedStep() async throws {
        let rule = threeStepRule()
        let other = SequenceRule(
            id: "replay-other", title: "same-process fixture", description: "in-memory fixture",
            level: .low, tags: [], window: 3_600, correlationType: .processSame, ordered: true,
            steps: [step("seed", "process_creation", image: "/other-seed"),
                    step("later", "process_creation", image: "/other-later", after: "seed")],
            trigger: .allSteps
        )
        let engine = try await makeEngine([rule, other])
        let reference = Date()
        try await restore(engine, rules: [rule, other],
                          pending: filler(other, stepID: "later", count: SequenceEngine.maxPendingTotal - 1,
                                          arrivedAt: reference),
                          now: reference)
        #expect(await fires([seed(at: 0), finish(pid: 102, at: 2)], on: engine, rule: rule) == [0, 0])
        let flood = (0..<100).map { exec("/usr/local/bin/other-later", pid: 30_000 + Int32($0), at: 10) }
        _ = await fires(flood, on: engine, rule: other, shedAllowed: true)
        let byRule = await engine.pendingStepConservationByRule()
        #expect(byRule[other.id]?.explicitlyShed == 100 && byRule[rule.id]?.explicitlyShed == 0)
        #expect(await fires([middle(pid: 101, at: 1)], on: engine, rule: rule, shedAllowed: true) == [1])
    }

    @Test("A self-flood of distinct writers sheds the retained later step first; the chain stays incomplete")
    func selfFloodShedsTheRetainedStep() async throws {
        let rule = threeStepRule()
        let engine = try await makeEngine([rule])
        let reference = Date()
        let retained = retainedFinish(rule, at: 2, arrivedAt: reference)
        try await restore(engine, rules: [rule],
                          pending: [retained] + filler(rule, stepID: "middle", count: SequenceEngine.maxPendingTotal - 2,
                                                       arrivedAt: reference),
                          now: reference)
        #expect(await fires([seed(at: 0)], on: engine, rule: rule) == [0])
        // Writes by distinct writers outside the seed's tree, without an
        // audit identity: nothing folds, and the second crosses the cap.
        let flood = [middle(pid: 202, at: 3), middle(pid: 203, at: 4)]
        #expect(await fires(flood, on: engine, rule: rule, shedAllowed: true) == [0, 0])
        #expect(await engine.pendingStepConservationByRule()[rule.id]?.explicitlyShed == 1)
        #expect(await engine.pendingPressureDiagnostics().lastPressure?.representativeVictimStepID == "finish")
        #expect(await fires([middle(pid: 101, at: 1)], on: engine, rule: rule, shedAllowed: true) == [0],
                "the shed finish cannot be replayed")
        #expect(await engine.evictionIsOngoing(within: 300), "the loss stays visible")
        let capture = try await engine.checkpointCapture()
        #expect(!capture.pendingBuckets.flatMap(\.steps).contains { $0.matched.eventID == retained.matched.eventID })
    }
}
