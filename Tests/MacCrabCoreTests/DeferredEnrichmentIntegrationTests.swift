import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

private actor QuietDrainReplayProbe {
    private(set) var eventIDs: [UUID] = []
    private(set) var userNames: [String] = []

    func record(_ batch: DeferredEnrichmentReplayBatch) {
        eventIDs.append(batch.event.id)
        userNames.append(batch.event.process.userName)
        #expect(batch.terminal)
    }
}

@Suite("Deferred heavy-enrichment integration")
struct DeferredEnrichmentIntegrationTests {
    private static let started = Date(timeIntervalSince1970: 1_750_000_000)
    private enum FixtureWaitError: Error { case deadlineExceeded }

    private func waitForCondition(_ predicate: () async -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        while !(await predicate()) {
            try Task.checkCancellation()
            guard clock.now < deadline else { throw FixtureWaitError.deadlineExceeded }
            try await Task.sleep(for: .milliseconds(5))
        }
    }

    private func waitForBuffer(
        _ buffer: DeferredEnrichmentBuffer,
        predicate: (DeferredEnrichmentBufferSnapshot) -> Bool
    ) async throws -> DeferredEnrichmentBufferSnapshot {
        try await waitForCondition { predicate(await buffer.snapshot()) }
        return await buffer.snapshot()
    }

    /// Wait on the actual actor condition, not a fixed number of executor
    /// yields. The watchdog seals this private fixture if a regression never
    /// returns the reservation; every exit also releases any queued waiter.
    private func withWaitingReservation(
        _ buffer: DeferredEnrichmentBuffer,
        operation: (Task<DeferredEnrichmentReservation?, Never>) async throws -> Void
    ) async throws {
        let waiting = Task { await buffer.reserveEventSlot() }
        let watchdog = Task {
            do { try await Task.sleep(for: .seconds(30)) }
            catch { return }
            Issue.record("private reservation fixture did not finish before its hang deadline")
            await buffer.seal()
        }
        do {
            try await operation(waiting)
        } catch {
            watchdog.cancel()
            waiting.cancel()
            await buffer.seal()
            _ = await waiting.value
            throw error
        }
        watchdog.cancel()
        waiting.cancel()
        await buffer.seal()
        _ = await waiting.value
    }

    private func isolatedMemoryBudget() -> EventPipelineLiveMemoryBudget {
        EventPipelineLiveMemoryBudget(
            maximumBytes: EventPipelineLiveMemoryBudget.productionMaximumBytes,
            forwardProgressReserveBytes: EventPipelineLiveMemoryBudget
                .productionForwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes: EventPipelineLiveMemoryBudget
                .productionEventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: EventPipelineLiveMemoryBudget
                .productionCompactReceiptReserveBytes
        )
    }

    private func event(
        id: UUID = UUID(),
        pending components: Set<HeavyEnrichmentComponent>,
        args: [String] = [],
        userName: String = "",
        collectorSignature: Bool = false
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 7_777,
            ppid: 1,
            rpid: 7_777,
            name: "fixture",
            executable: "/usr/bin/true",
            commandLine: "/usr/bin/true",
            args: args,
            workingDirectory: "/",
            userId: 501,
            userName: userName,
            groupId: 20,
            startTime: Self.started,
            codeSignature: collectorSignature ? CodeSignatureInfo(signerType: .apple) : nil,
            isPlatformBinary: collectorSignature
        )
        let coverage = Dictionary(uniqueKeysWithValues: components.map {
            ($0, HeavyEnrichmentCoverage.pending)
        })
        return Event(
            id: id,
            timestamp: Self.started,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process,
            enrichments: [
                DeferredEventEnrichment.coverageKey:
                    DeferredEventEnrichment.coverageMarker(coverage) ?? "",
            ]
        )
    }

    private func patch(
        event: Event,
        component: HeavyEnrichmentComponent,
        outcome: HeavyEnrichmentTerminalOutcome = .completed,
        value: HeavyEnrichmentValue?
    ) -> DeferredEventEnrichment {
        DeferredEventEnrichment(
            ticket: HeavyEnrichmentTicket(),
            binding: HeavyEnrichmentBinding(event: event),
            component: component,
            outcome: outcome,
            value: value
        )
    }

    private func match(_ id: String) -> RuleMatch {
        RuleMatch(
            ruleId: id,
            ruleName: "Rule \(id)",
            severity: .high,
            description: "reviewed \(id)",
            mitreTechniques: ["attack.t1059"],
            tags: ["attack.execution"],
            suppressible: false
        )
    }

    private func transfer(
        _ patches: [DeferredEventEnrichment],
        to buffer: DeferredEnrichmentBuffer
    ) async -> [DeferredEnrichmentReplayBatch] {
        let claim = await buffer.claimDrainCapacity(limit: patches.count)
        #expect(claim == patches.count)
        return await buffer.acceptDrained(patches)
    }

    private func waitUntilPlaneDrains(
        _ plane: HeavyEnrichmentPlane,
        timeoutSeconds: TimeInterval = 30
    ) async -> HeavyEnrichmentPlaneSnapshot {
        let interval = UInt64(max(0, timeoutSeconds) * 1_000_000_000)
        let addition = DispatchTime.now().uptimeNanoseconds
            .addingReportingOverflow(interval)
        let deadline = addition.overflow ? UInt64.max : addition.partialValue
        var snapshot = await plane.snapshot()
        while !snapshot.cleanlyDrained,
              DispatchTime.now().uptimeNanoseconds < deadline {
            try? await Task.sleep(nanoseconds: 5_000_000)
            snapshot = await plane.snapshot()
        }
        return snapshot
    }

    @Test("Deferred usernames reach UEBA only once, after terminal settlement eligibility",
          arguments: ["present", "success", "unavailable", "timeout"])
    func deferredUserObservationExactlyOnce(scenario: String) async throws {
        let known = scenario == "present"
        let engine = UEBAEngine()
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 1, patchCapacity: 8,
                                              liveMemoryBudget: isolatedMemoryBudget())
        let original = event(pending: known ? [.environment] : [.environment, .userName],
                             userName: known ? "operator" : "")
        _ = await engine.observe(event: original)
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        #expect((await buffer.markReady(original)).isEmpty)
        if !known {
            let value: HeavyEnrichmentValue? = scenario == "success" ? .userName("operator") : nil
            let result = patch(event: original, component: .userName,
                               outcome: scenario == "timeout" ? .timedOut : .completed,
                               value: value)
            let partial = await transfer([result], to: buffer)
            #expect(partial.allSatisfy { !$0.shouldObserveUserBehavior })
            #expect((await engine.profile(for: "operator")) == nil)
            // As the dispatcher does, a non-terminal replay merges back before
            // the event's next patch can replay.
            for batch in partial where !batch.terminal {
                #expect(await buffer.mergeReviewedMatches(
                    eventID: batch.event.id, event: batch.event,
                    primaryMatches: [], sequenceMatches: []
                ).isEmpty)
            }
            let repeated = await transfer([result], to: buffer)
            #expect(repeated.allSatisfy { !$0.shouldObserveUserBehavior })
            if scenario == "timeout" || scenario == "unavailable" {
                let late = await transfer([patch(event: original, component: .userName,
                                                  value: .userName("operator"))], to: buffer)
                #expect(late.isEmpty, "A late success cannot reopen a terminal username component")
            }
        }
        let final = await transfer([patch(event: original, component: .environment,
                                         value: .environment([:]))], to: buffer)
        let batch = try #require(final.first)
        #expect(final.count == 1 && batch.terminal)
        #expect(batch.shouldObserveUserBehavior == (scenario == "success"))
        if batch.shouldObserveUserBehavior { _ = await engine.observe(event: batch.event) }
        let count = await engine.profile(for: "operator")?.totalObservations ?? 0
        #expect(count == ((known || scenario == "success") ? 1 : 0))
        let duplicate = await transfer([patch(event: original, component: .userName,
                                              value: .userName("operator"))], to: buffer)
        #expect(duplicate.isEmpty)
        await buffer.completeTerminalReplay(eventID: original.id)
        await buffer.seal()
        let snapshot = await buffer.snapshot()
        #expect(snapshot.cleanlyDrained)
        #expect(snapshot.patchesConserved && snapshot.patchBytesConserved)
    }

    @Test("Busy username cache coalesces through the heavy plane into identity-bound rule replay")
    func busyUsernameDeferredRuleReplay() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let rule = CompiledRule(
            id: "username-fixture", title: "username-fixture", description: "inert rule",
            level: .high, tags: [], logsource: .init(category: "process_creation", product: "macos"),
            predicates: [.init(field: "User", modifier: .equals, values: ["operator"], negate: false)],
            condition: .allOf, falsepositives: [], enabled: true)
        try JSONEncoder().encode(rule).write(to: directory.appendingPathComponent("fixture.json"))
        let rules = RuleEngine()
        #expect(try await rules.loadRules(from: directory) == 1)
        let budget = isolatedMemoryBudget()
        let plane = HeavyEnrichmentPlane(configuration: .init(operationTimeoutSeconds: 30), liveMemoryBudget: budget)
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let enricher = EventEnricher(heavyEnrichmentPlane: plane, userNameResolver: { _ in
            entered.signal()
            _ = release.wait(timeout: .now() + 30)
            return "operator"
        })
        defer { release.signal() }
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 2, patchCapacity: 8, liveMemoryBudget: budget)
        var originals: [Event] = []
        for _ in 0..<2 {
            let reservation = try #require(await buffer.reserveEventSlot())
            let enriched = await enricher.enrich(event(pending: [], collectorSignature: true))
            #expect(DeferredEventEnrichment.coverageState(for: .userName, in: enriched) == .pending)
            #expect(await rules.evaluate(enriched).isEmpty)
            #expect(await buffer.retain(enriched, using: reservation))
            #expect((await buffer.markReady(enriched)).isEmpty)
            originals.append(enriched)
            if originals.count == 1 {
                try #require(entered.wait(timeout: .now() + 5) == .success)
            }
        }
        #expect((await plane.snapshot()).coalescedRequestsTotal == 1)
        release.signal()
        try await waitForCondition { (await plane.snapshot()).completedRequestsTotal == 2 }
        let patches = await plane.drainDeferredResults()
        let batches = await transfer(patches, to: buffer)
        #expect(Set(batches.map { $0.event.id }) == Set(originals.map(\.id)))
        #expect(batches.count == 2)
        for batch in batches {
            #expect(batch.event.timestamp == Self.started)
            #expect(batch.event.process.userName == "operator")
            #expect(await rules.reevaluate(batch.event, forCompleted: batch.completedComponents).map(\.ruleId) == ["username-fixture"])
        }
        #expect((await transfer(patches, to: buffer)).isEmpty, "Duplicate patches cannot re-run the rule")
        for batch in batches { await buffer.completeTerminalReplay(eventID: batch.event.id) }
        await buffer.seal()
        let snapshot = await buffer.snapshot()
        #expect(snapshot.cleanlyDrained)
        #expect(snapshot.patchesConserved && snapshot.patchBytesConserved)
        #expect((await enricher.shutdownHeavyEnrichment()).cleanlyDrained)
    }

    @Test("two ingestion lanes retain terminal patches that beat both originals")
    func twoLaneOrphanRace() async throws {
        let first = event(pending: [.userName])
        let second = event(pending: [.environment])
        let reservationCharge = max(
            try EventJournalAdmissionValidator.prepare(first)
                .sourceRetainedByteEstimate,
            try EventJournalAdmissionValidator.prepare(second)
                .sourceRetainedByteEstimate
        )
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 2,
            patchCapacity: 2,
            reservationRawEventByteCharge: reservationCharge,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let firstReservation = try #require(await buffer.reserveEventSlot())
        let secondReservation = try #require(await buffer.reserveEventSlot())

        let premature = await transfer([
            patch(event: first, component: .userName, value: .userName("alice")),
            patch(event: second, component: .environment, value: .environment(["PATH": "/usr/bin"])),
        ], to: buffer)
        #expect(premature.isEmpty)
        #expect((await buffer.snapshot()).orphanPatches == 2)

        #expect(await buffer.retain(first, using: firstReservation))
        #expect(await buffer.retain(second, using: secondReservation))
        let firstReplay = await buffer.markReady(first)
        let secondReplay = await buffer.markReady(second)
        let firstBatch = try #require(firstReplay.first)
        let secondBatch = try #require(secondReplay.first)
        #expect(firstReplay.count == 1)
        #expect(secondReplay.count == 1)
        #expect(firstBatch.event.process.userName == "alice")
        #expect(secondBatch.event.process.envVars == ["PATH": "/usr/bin"])
        #expect(firstBatch.terminal && secondBatch.terminal)
        await buffer.completeTerminalReplay(eventID: first.id)
        await buffer.completeTerminalReplay(eventID: second.id)

        await buffer.seal()
        let snapshot = await buffer.snapshot()
        #expect(snapshot.cleanlyDrained)
        #expect(snapshot.reservationConserved)
        #expect(snapshot.slotsConserved)
        #expect(snapshot.eventsConserved)
        #expect(snapshot.patchesConserved)
        #expect(snapshot.withinCapacity)
    }

    @Test("all components in one drained event batch trigger one replay batch")
    func multiComponentOneReplay() async throws {
        // Unit fixtures must not contend with processShared: Swift Testing runs
        // suites concurrently, and an unrelated queued R acquisition correctly
        // makes this synchronous P handoff back-pressure.
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: EventPipelineLiveMemoryBudget
                .productionMaximumBytes,
            forwardProgressReserveBytes: EventPipelineLiveMemoryBudget
                .productionForwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes: EventPipelineLiveMemoryBudget
                .productionEventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: EventPipelineLiveMemoryBudget
                .productionCompactReceiptReserveBytes
        )
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 4,
            liveMemoryBudget: budget
        )
        let original = event(pending: [.environment, .userName])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        #expect((await buffer.markReady(original)).isEmpty)

        let batches = await transfer([
            patch(event: original, component: .environment, value: .environment(["LANG": "C"])),
            patch(event: original, component: .userName, value: .userName("operator")),
        ], to: buffer)
        let batch = try #require(batches.first)
        #expect(batches.count == 1)
        #expect(batch.completedComponents == [.environment, .userName])
        #expect(batch.terminal)
        #expect(batch.event.process.envVars == ["LANG": "C"])
        #expect(batch.event.process.userName == "operator")
        #expect((await buffer.snapshot()).patchesConsumedTotal == 2)
        await buffer.completeTerminalReplay(eventID: original.id)
    }

    @Test("zero-match deferred evidence still requires a terminal delta")
    func zeroMatchDeferredTerminalIsCanonicalWork() async throws {
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 1,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let original = event(pending: [.environment])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        #expect((await buffer.markReady(
            original,
            initialPrimaryMatches: [],
            initialSequenceMatches: []
        )).isEmpty)

        let terminal = await transfer([
            patch(
                event: original,
                component: .environment,
                value: .environment(["LANG": "C"])
            ),
        ], to: buffer)
        let replay = try #require(terminal.first)
        #expect(replay.terminal)
        #expect(replay.undispatchedPrimaryMatches.isEmpty)
        #expect(replay.undispatchedSequenceMatches.isEmpty)
        #expect(replay.event.ruleMatches.isEmpty)
        #expect(replay.event.process.envVars == ["LANG": "C"])
        let composed = try #require(replay.terminalDelta)
        #expect(!composed.isEmpty)
        #expect(try composed.applying(to: original) == replay.event,
                "deferred replay must carry a base-free exact sparse delta")

        let base = try EventPrivacySanitizer.sanitize(original).event
        let finalized = try EventPrivacySanitizer.sanitize(replay.event).event
        let delta = try EventTerminalDelta(base: base, terminal: finalized)
        #expect(!delta.isEmpty,
                "terminal evidence is canonical work even with zero matches")
        #expect(try delta.applying(to: base) == finalized)
        await buffer.completeTerminalReplay(eventID: original.id)
    }

    @Test("a patch arriving during another replay's review waits for its merge")
    func concurrentReplaysAreSerializedPerEvent() async throws {
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 4,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let original = event(pending: [.environment, .userName, .processHashes])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        #expect((await buffer.markReady(original)).isEmpty)

        // Replay 1 (environment) is under review...
        let first = try #require(await transfer([
            patch(event: original, component: .environment, value: .environment(["LANG": "C"])),
        ], to: buffer).first)
        #expect(!first.terminal)
        // ...when the username patch is drained. It must not start a second
        // replay from the same revision.
        #expect(await transfer([
            patch(event: original, component: .userName, value: .userName("operator")),
        ], to: buffer).isEmpty)

        // Merging replay 1 releases the held patch, built on the merged revision.
        let fromFirst = match("from-first")
        var reviewed = first.event
        reviewed.ruleMatches = [fromFirst]
        let second = try #require(await buffer.mergeReviewedMatches(
            eventID: original.id, event: reviewed,
            primaryMatches: [fromFirst], sequenceMatches: []
        ).first)
        #expect(!second.terminal)
        #expect(second.completedComponents == [.userName])
        #expect(second.event.process.userName == "operator")
        #expect(second.event.process.envVars == ["LANG": "C"])
        #expect(second.undispatchedPrimaryMatches.map(\.ruleId) == ["from-first"])

        // The last component cannot strand the event or lose either review.
        #expect(await transfer([
            patch(event: original, component: .processHashes,
                  value: .processHashes(HeavyProcessHashEvidence(value: nil, fileIdentity: nil))),
        ], to: buffer).isEmpty)
        let fromSecond = match("from-second")
        let terminal = try #require(await buffer.mergeReviewedMatches(
            eventID: original.id, event: second.event,
            primaryMatches: [fromSecond], sequenceMatches: []
        ).first)
        #expect(terminal.terminal)
        #expect(Set(terminal.undispatchedPrimaryMatches.map(\.ruleId)) == ["from-first", "from-second"])
        await buffer.completeTerminalReplay(eventID: original.id)
        #expect(await buffer.snapshot().retainedEvents == 0)
    }

    @Test("pending-heavy review accumulates without fanout until terminal")
    func reviewedMatchesWaitForTerminal() async throws {
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 4,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let original = event(pending: [.environment, .userName])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        let initial = match("initial")
        var initialEvent = original
        initialEvent.ruleMatches = [initial]
        #expect((await buffer.markReady(
            initialEvent,
            initialPrimaryMatches: [initial, initial],
            initialSequenceMatches: []
        )).isEmpty)

        let first = await transfer([
            patch(
                event: original,
                component: .environment,
                value: .environment(["LANG": "C"])
            ),
        ], to: buffer)
        let firstBatch = try #require(first.first)
        #expect(first.count == 1 && !firstBatch.terminal)
        #expect(firstBatch.undispatchedPrimaryMatches == [initial])

        let deferred = match("deferred")
        var reviewedEvent = firstBatch.event
        reviewedEvent.ruleMatches = ReviewedRuleMatches.merged(
            reviewedEvent.ruleMatches,
            [deferred]
        )
        await buffer.mergeReviewedMatches(
            eventID: original.id,
            event: reviewedEvent,
            primaryMatches: [deferred, initial],
            sequenceMatches: [deferred]
        )

        let terminal = await transfer([
            patch(
                event: original,
                component: .userName,
                value: .userName("operator")
            ),
        ], to: buffer)
        let terminalBatch = try #require(terminal.first)
        #expect(terminal.count == 1 && terminalBatch.terminal)
        #expect(terminalBatch.undispatchedPrimaryMatches.map(\.ruleId)
            == ["deferred", "initial"])
        #expect(terminalBatch.undispatchedSequenceMatches == [deferred])
        #expect(terminalBatch.event.ruleMatches.map(\.ruleId)
            == ["deferred", "initial"])
        await buffer.completeTerminalReplay(eventID: original.id)
    }

    @Test("timeout is terminal degraded coverage and never claims completion")
    func timeoutClosesHonestly() async throws {
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 1,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let original = event(pending: [.codeSignature])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        _ = await buffer.markReady(original)

        let batches = await transfer([
            patch(
                event: original,
                component: .codeSignature,
                outcome: .timedOut,
                value: nil
            ),
        ], to: buffer)
        let batch = try #require(batches.first)
        #expect(batches.count == 1)
        #expect(batch.terminal)
        #expect(batch.completedComponents.isEmpty)
        #expect(DeferredEventEnrichment.coverageState(
            for: .codeSignature,
            in: batch.event
        ) == .timedOut)
        #expect((await buffer.snapshot()).retainedEvents == 1,
                "terminal replay remains charged until dispatch acknowledges")
        await buffer.completeTerminalReplay(eventID: original.id)
        #expect((await buffer.snapshot()).retainedEvents == 0)
    }

    @Test("rejected terminal evidence cannot exhaust retained-event capacity")
    func rejectedTerminalEvidenceReleasesCapacity() async throws {
        let first = event(pending: [.userName])
        let second = event(pending: [.environment])
        let reservationCharge = max(
            try EventJournalAdmissionValidator.prepare(first)
                .sourceRetainedByteEstimate,
            try EventJournalAdmissionValidator.prepare(second)
                .sourceRetainedByteEstimate
        )
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 2,
            patchCapacity: 2,
            reservationRawEventByteCharge: reservationCharge,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let firstReservation = try #require(await buffer.reserveEventSlot())
        let secondReservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(first, using: firstReservation))
        #expect(await buffer.retain(second, using: secondReservation))
        #expect((await buffer.markReady(first)).isEmpty)
        #expect((await buffer.markReady(second)).isEmpty)

        try await withWaitingReservation(buffer) { waiting in
            let waitingSnapshot = try await waitForBuffer(buffer) { $0.waitingReservations == 1 }
            #expect(waitingSnapshot.waitingReservations == 1)

            // Both terminal patches violate their component/value contract. Their
            // values must never attach, but each accepted offer must still close
            // the matching pending component and return its retained slot.
            let batches = await transfer([
                patch(
                    event: first,
                    component: .userName,
                    value: .environment(["UNTRUSTED": "1"])
                ),
                patch(
                    event: second,
                    component: .environment,
                    value: .userName("untrusted")
                ),
            ], to: buffer)
            #expect(batches.count == 2)
            for batch in batches {
                #expect(batch.terminal)
                #expect(batch.completedComponents.isEmpty)
                #expect(!DeferredEventEnrichment.hasPendingCoverage(in: batch.event))
                if batch.event.id == first.id {
                    #expect(DeferredEventEnrichment.coverageState(
                        for: .userName,
                        in: batch.event
                    ) == .unavailable)
                    #expect(batch.event.process.userName.isEmpty)
                } else if batch.event.id == second.id {
                    #expect(DeferredEventEnrichment.coverageState(
                        for: .environment,
                        in: batch.event
                    ) == .unavailable)
                    #expect(batch.event.process.envVars == nil)
                } else {
                    Issue.record("unexpected replay event identity")
                }
                await buffer.completeTerminalReplay(eventID: batch.event.id)
            }

            let thirdReservation = try #require(await waiting.value)
            #expect(await buffer.retain(
                event(pending: []),
                using: thirdReservation
            ) == false)
            await buffer.seal()
            let snapshot = await buffer.snapshot()
            #expect(snapshot.identityRejectedPatchesTotal == 2)
            #expect(snapshot.retainedEvents == 0)
            #expect(snapshot.waitingReservations == 0)
            #expect(snapshot.reservationConserved)
            #expect(snapshot.slotsConserved)
            #expect(snapshot.eventsConserved)
            #expect(snapshot.patchesConserved)
            #expect(snapshot.patchBytesConserved)
            #expect(snapshot.cleanlyDrained)
        }
    }

    @Test("plane shutdown terminalizes then buffer drains the accepted prefix")
    func shutdownDrain() async throws {
        let budget = isolatedMemoryBudget()
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1,
            maximumQueuedWorkItems: 0,
            maximumOutstandingResults: 1,
            cacheCapacity: 0,
            operationTimeoutSeconds: 10
        ), liveMemoryBudget: budget)
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 1,
            liveMemoryBudget: budget
        )
        let original = event(pending: [.environment])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        _ = await buffer.markReady(original)

        let offer = await plane.offer(
            component: .environment,
            binding: HeavyEnrichmentBinding(event: original),
            cacheResult: false
        ) {
            do { try await Task.sleep(nanoseconds: 60_000_000_000) }
            catch { }
            return .environment(["TOO_LATE": "1"])
        }
        guard case .pending = offer else {
            Issue.record("fixture request was not admitted")
            return
        }

        _ = await plane.shutdown(deadlineSeconds: 0.5)
        let claim = await buffer.claimDrainCapacity(limit: 1)
        let terminalPatches = await plane.drainDeferredResults(limit: claim)
        let batches = await buffer.acceptDrained(terminalPatches)
        await buffer.seal()

        let terminalPatch = try #require(terminalPatches.first)
        let batch = try #require(batches.first)
        #expect(terminalPatches.count == 1)
        #expect(terminalPatch.outcome == .cancelled)
        #expect(batches.count == 1)
        #expect(batch.terminal)
        #expect(batch.completedComponents.isEmpty)
        await buffer.completeTerminalReplay(eventID: original.id)
        // Cancellation terminalizes the logical request synchronously, while
        // the detached utility worker may need another scheduler turn to
        // publish its physical exit. Keep those two contracts distinct.
        let planeSnapshot = await waitUntilPlaneDrains(plane)
        let bufferSnapshot = await buffer.snapshot()
        #expect(planeSnapshot.cleanlyDrained)
        #expect(planeSnapshot.deferredResults == 0)
        #expect(planeSnapshot.requestsConserved)
        #expect(bufferSnapshot.cleanlyDrained)
        #expect(bufferSnapshot.patchesConserved)
        #expect(bufferSnapshot.rawEventBytesConserved)
    }

    @Test("owned terminal patch reaches replay while journal uses reserved headroom")
    func ownedPatchTransferUnderJournalPressure() async throws {
        let budget = isolatedMemoryBudget()
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1,
            patchCapacity: 1,
            liveMemoryBudget: budget
        )
        let original = event(pending: [.userName])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        #expect((await buffer.markReady(original)).isEmpty)

        let terminal = patch(
            event: original,
            component: .userName,
            value: .userName("operator")
        )
        let resultLease = try #require(budget.tryAcquire(
            bytes: terminal.retainedByteEstimate,
            owner: .heavyResult
        ))
        let noncriticalCeiling = EventPipelineLiveMemoryBudget
            .productionMaximumBytes
            - EventPipelineLiveMemoryBudget.productionForwardProgressReserveBytes
        var journalPressure: EventPipelineMemoryLease? = try #require(
            await budget.acquire(
                bytes: noncriticalCeiling,
                owner: .journalPrepared
            )
        )
        #expect(budget.snapshot().currentBytes > noncriticalCeiling,
                "the fixture must cross the ceiling that rejected rc.25's H-to-P transfers")

        #expect(await buffer.claimDrainCapacity(limit: 1) == 1)
        let batches = await buffer.acceptOwnedDrained([
            OwnedDeferredEventEnrichment(
                patch: terminal,
                memoryLease: resultLease
            ),
        ])
        let batch = try #require(batches.first)
        #expect(batches.count == 1)
        #expect(batch.terminal)
        #expect(batch.event.process.userName == "operator")
        var snapshot = await buffer.snapshot()
        #expect(snapshot.identityRejectedPatchesTotal == 0)
        #expect(snapshot.patchesConserved)
        #expect(snapshot.patchBytesConserved)

        await buffer.completeTerminalReplay(eventID: original.id)
        journalPressure = nil
        await buffer.seal()
        snapshot = await buffer.snapshot()
        #expect(snapshot.cleanlyDrained)
        #expect(snapshot.identityRejectedPatchesTotal == 0)
        #expect(budget.snapshot().leasesConserved)
    }

    @Test("512-slot buffer backpressures on raw Event bytes and conserves ownership")
    func rawEventByteBackpressure() async throws {
        let first = event(
            pending: [.userName],
            args: Array(repeating: "", count: 20_000)
        )
        let prepared = try EventJournalAdmissionValidator.prepare(first)
        let charge = prepared.sourceRetainedByteEstimate
        #expect(charge > prepared.canonicalJSON.count,
                "container backing must exceed its compact JSON bytes")

        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 512,
            patchCapacity: 512,
            rawEventByteCapacity: charge,
            reservationRawEventByteCharge: charge,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let firstReservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(
            first,
            using: firstReservation,
            sourceRetainedByteEstimate: prepared.sourceRetainedByteEstimate
        ))
        _ = await buffer.markReady(first)

        try await withWaitingReservation(buffer) { waiting in
            var snapshot = try await waitForBuffer(buffer) { $0.waitingReservations == 1 }
            #expect(snapshot.retainedEvents == 1)
            #expect(snapshot.waitingReservations == 1)
            #expect(snapshot.retainedRawEventBytes == charge)
            #expect(snapshot.retainedRawEventBytesHighWatermark == charge)
            #expect(snapshot.retainedRawEventBytes <= snapshot.rawEventByteCapacity)
            #expect(snapshot.withinCapacity)
            #expect(snapshot.rawEventBytesConserved)

            let batches = await transfer([
                patch(
                    event: first,
                    component: .userName,
                    value: .userName("operator")
                ),
            ], to: buffer)
            let batch = try #require(batches.first)
            #expect(batches.count == 1 && batch.terminal)
            snapshot = await buffer.snapshot()
            #expect(snapshot.retainedRawEventBytes == charge,
                    "dispatch handoff must remain inside the byte ledger")
            await buffer.completeTerminalReplay(eventID: first.id)

            let secondReservation = try #require(await waiting.value)
            #expect(await buffer.retain(
                event(pending: []),
                using: secondReservation
            ) == false)
            await buffer.seal()
            snapshot = await buffer.snapshot()
            #expect(snapshot.cleanlyDrained)
            #expect(snapshot.reservationConserved)
            #expect(snapshot.slotsConserved)
            #expect(snapshot.eventsConserved)
            #expect(snapshot.rawEventBytesConserved)
            #expect(snapshot.withinCapacity)
        }
    }

    @Test("patch byte ownership backpressures a 512-result drain without loss")
    func patchByteBackpressure() async throws {
        let first = event(pending: [.environment])
        let second = event(pending: [.environment])
        let environment = ["PATH": String(repeating: "x", count: 256 * 1_024)]
        let firstPatch = patch(
            event: first,
            component: .environment,
            value: .environment(environment)
        )
        let secondPatch = patch(
            event: second,
            component: .environment,
            value: .environment(environment)
        )
        let charge = firstPatch.retainedByteEstimate
        let reservationCharge = max(
            try EventJournalAdmissionValidator.prepare(first)
                .sourceRetainedByteEstimate,
            try EventJournalAdmissionValidator.prepare(second)
                .sourceRetainedByteEstimate
        )
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 512,
            patchCapacity: 512,
            reservationRawEventByteCharge: reservationCharge,
            patchByteCapacity: charge,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let firstReservation = try #require(await buffer.reserveEventSlot())
        let secondReservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(first, using: firstReservation))
        #expect(await buffer.retain(second, using: secondReservation))

        let firstClaim = await buffer.claimDrainCapacity(limit: 512)
        #expect(firstClaim == 512)
        #expect(await buffer.claimedDrainByteCapacity() == charge)
        #expect((await buffer.acceptDrained([firstPatch])).isEmpty)
        var snapshot = await buffer.snapshot()
        #expect(snapshot.bufferedPatchBytes == charge)
        #expect(snapshot.bufferedPatchBytesHighWatermark == charge)
        #expect(await buffer.claimDrainCapacity(limit: 512) == 0,
                "a second large patch must remain upstream until bytes drain")

        let firstBatch = await buffer.markReady(first)
        let firstReplay = try #require(firstBatch.first)
        #expect(firstBatch.count == 1 && firstReplay.terminal)
        snapshot = await buffer.snapshot()
        #expect(snapshot.bufferedPatchBytes == 0)
        #expect(snapshot.appliedPatchBytes == charge,
                "applied evidence remains charged through terminal dispatch")
        #expect(snapshot.patchBytesConserved)
        await buffer.completeTerminalReplay(eventID: first.id)
        snapshot = await buffer.snapshot()
        #expect(snapshot.appliedPatchBytes == 0)
        #expect(snapshot.patchBytesConserved)

        let secondClaim = await buffer.claimDrainCapacity(limit: 512)
        #expect(secondClaim > 0)
        #expect((await buffer.acceptDrained([secondPatch])).isEmpty)
        let secondBatch = await buffer.markReady(second)
        let secondReplay = try #require(secondBatch.first)
        #expect(secondBatch.count == 1 && secondReplay.terminal)
        await buffer.completeTerminalReplay(eventID: second.id)
        await buffer.seal()
        snapshot = await buffer.snapshot()
        #expect(snapshot.patchesReceivedTotal == 2)
        #expect(snapshot.patchesConsumedTotal == 2)
        #expect(snapshot.patchBytesConserved)
        #expect(snapshot.withinCapacity)
        #expect(snapshot.cleanlyDrained)
    }

    @Test("production quiet-timer callback replays a post-hint completion exactly once")
    func quietTimerCallbackReplaysAfterFalseHint() async throws {
        let budget = isolatedMemoryBudget()
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1, maximumQueuedWorkItems: 1,
            maximumOutstandingResults: 2, cacheCapacity: 0,
            operationTimeoutSeconds: 86_400
        ), liveMemoryBudget: budget)
        let buffer = DeferredEnrichmentBuffer(
            eventCapacity: 1, patchCapacity: 1, liveMemoryBudget: budget
        )
        let gate = HeavyEnrichmentTestGate()
        let lifecycle = DaemonTimerLifecycle(coalesceByLabel: true)
        let replay = QuietDrainReplayProbe()
        let original = event(pending: [.userName])
        // Explicit ticks execute the exact callback installed by DaemonTimers.
        // This does not assert DispatchSource timing or a 100-ms latency SLA.
        let tick = DeferredEnrichmentQuietTimer.makeEventHandler(lifecycle: lifecycle) {
            let claim = await buffer.claimDrainCapacity(limit: 1)
            let patches = await plane.drainDeferredResults(limit: claim)
            let batches = await buffer.acceptDrained(patches)
            for batch in batches {
                await replay.record(batch)
                await buffer.completeTerminalReplay(eventID: batch.event.id)
            }
        }
        func cleanup() async {
            await gate.release()
            _ = await lifecycle.shutdown(deadline: 1)
            await buffer.seal()
            _ = await plane.shutdown(deadlineSeconds: 1)
            _ = await plane.drainDeferredResults(limit: 2)
        }
        do {
            let reservation = try #require(await buffer.reserveEventSlot())
            #expect(await buffer.retain(original, using: reservation))
            #expect((await buffer.markReady(original)).isEmpty)
            let offer = await plane.offer(
                component: .userName, binding: HeavyEnrichmentBinding(event: original),
                cacheResult: false
            ) {
                await gate.runIgnoringCancellation()
                return .userName("quiet-worker")
            }
            guard case .pending = offer else {
                Issue.record("gated quiet-drain fixture was not accepted")
                await cleanup()
                return
            }
            try await gate.waitUntilEntered()
            #expect(!plane.hasDeferredResults)
            tick()
            try await waitForCondition { lifecycle.snapshot().completedHandlers == 1 }
            #expect(await replay.eventIDs.isEmpty)

            // Finish AFTER the false event-boundary hint and first empty tick.
            // No subsequent event is submitted; only the periodic callback runs.
            await gate.release()
            try await waitForCondition { (await plane.snapshot()).deferredResults == 1 }
            tick()
            try await waitForCondition { lifecycle.snapshot().completedHandlers == 2 }
            #expect(await replay.eventIDs == [original.id])
            #expect(await replay.userNames == ["quiet-worker"])
            #expect(!plane.hasDeferredResults)

            tick()
            try await waitForCondition { lifecycle.snapshot().completedHandlers == 3 }
            #expect(await replay.eventIDs == [original.id], "a later tick must not replay twice")
            let snapshot = await buffer.snapshot()
            #expect(snapshot.cleanlyDrained && snapshot.eventsConserved && snapshot.patchesConserved)
            #expect(await lifecycle.shutdown(deadline: 1))
            tick()
            let closed = lifecycle.snapshot()
            #expect(closed.acceptedHandlers == 3 && closed.completedHandlers == 3)
            #expect(closed.closedRejectedHandlers == 1 && closed.inFlightHandlers == 0)
            #expect(closed.conservesAcceptedHandlers && closed.conservesOfferedHandlers)
            #expect(await replay.eventIDs == [original.id])
        } catch {
            await cleanup()
            throw error
        }
        await cleanup()
    }

    @Test("quiet timer, initial-order gate, and shutdown drain stay wired")
    func lifecycleSourceGuards() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let timers = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabAgentKit/DaemonTimers.swift"
        ))
        let loop = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabAgentKit/EventLoop.swift"
        ))
        let lifecycle = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabAgentKit/DaemonLifecycle.swift"
        ))
        let dispatcher = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabAgentKit/DeferredEnrichmentDispatcher.swift"
        ))
        let quietTimer = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabAgentKit/DeferredEnrichmentQuietTimer.swift"
        ))

        #expect(timers.contains("repeating: .milliseconds(100)"))
        #expect(timers.contains("DeferredEnrichmentQuietTimer.makeEventHandler("))
        #expect(quietTimer.contains("label: \"deferred-enrichment-drain\""))
        #expect(timers.contains("timerLifecycle.register(timer)"))
        #expect(loop.contains("await dispatchReviewedMatches("))
        #expect(loop.contains(
            "let terminalAdmission = await settleTerminalJournalRevision("
        ))
        #expect(loop.contains(
            ".withTerminalRevision(terminalAdmission)"
        ))
        #expect(loop.contains(
            "EventJournalAdmissionContext.terminalRevision?.status == .verified"
        ), "failed canonical terminal work must not promote sparse projection")
        #expect(loop.contains("markReadyAndDispatch("))
        #expect(loop.contains("await DeferredEnrichmentDispatcher.drainAvailable"))
        #expect(loop.contains("if state.enricher.hasDeferredEnrichments"))
        #expect(!timers.contains("hasDeferredEnrichments"),
                "Quiet-period drain must not rely on a previous event's availability hint")
        #expect(!dispatcher.contains("hasDeferredEnrichments"),
                "Authoritative and shutdown drains must remain unconditional")
        let baseBoundary = try #require(loop.range(
            of: "let journalBaseEvent = enrichedEvent"
        ))
        let runBoundary = try #require(loop.range(
            of: "static func run("
        ))
        let reviewedBoundary = try #require(loop.range(
            of: "let reviewedDispatch = prepareReviewedMatches("
        ))
        let preBaseRun = String(loop[
            runBoundary.lowerBound..<baseBoundary.lowerBound
        ])
        for prematureSideEffect in [
            "alertSink.submit",
            "BehaviorScoreAlertEmitter",
            "responseEngine.execute",
            "detectionWorkLifecycle.submit",
            "advisoryWorkLifecycle.submit",
        ] {
            #expect(!preBaseRun.contains(prematureSideEffect),
                    "alert-capable work must follow immutable base admission")
        }
        #expect(baseBoundary.lowerBound < reviewedBoundary.lowerBound)
        let postBaseDetection = String(loop[
            baseBoundary.upperBound..<reviewedBoundary.lowerBound
        ])
        for mutationPattern in [
            #"\benrichedEvent\s*=(?!=)"#,
            #"enrichedEvent\.enrichments\[[^\n]*\]\s*=(?!=)"#,
            #"&enrichedEvent\.enrichments"#,
            #"enrichedEvent\.(severity|ruleMatches|process|file|network)\s*=(?!=)"#,
        ] {
            let expression = try NSRegularExpression(
                pattern: mutationPattern
            )
            let range = NSRange(
                postBaseDetection.startIndex..<postBaseDetection.endIndex,
                in: postBaseDetection
            )
            #expect(expression.firstMatch(
                in: postBaseDetection,
                range: range
            ) == nil,
            "direct alerts must not observe a post-base Event mutation")
        }
        let terminalSettle = try #require(dispatcher.range(
            of: ".settleTerminalJournalDelta("
        ))
        let terminalBranch = try #require(dispatcher.range(
            of: "if batch.terminal {"
        ))
        let reviewedFanout = try #require(dispatcher.range(
            of: "await EventLoop.dispatchReviewedMatches("
        ))
        let beforeTerminalSettle = String(dispatcher[
            terminalBranch.lowerBound..<terminalSettle.lowerBound
        ])
        #expect(!beforeTerminalSettle.contains("ruleMatches.isEmpty"),
                "zero-match deferred terminals must still settle canonically")
        #expect(terminalSettle.lowerBound < reviewedFanout.lowerBound,
                "deferred alert/promotion fanout must follow terminal settle")
        #expect(lifecycle.contains("DeferredEnrichmentDispatcher.shutdown("))
        #expect(lifecycle.contains("heavyEnrichmentPlane: heavyEnrichment.clean"))
    }

    @Test("item 6: the per-event .eventSource charge lets both EventLoop lanes reserve concurrently without serializing, and can never oversize")
    func reservationChargeFitsBothLanesUnderTheSourceCeiling() {
        let charge = DeferredEnrichmentBuffer.productionReservationRawEventByteCharge
        let sourceCeiling = EventPipelineLiveMemoryBudget.productionMaximumBytes
            - EventPipelineLiveMemoryBudget.productionForwardProgressReserveBytes
        // The regression this guards: at the old 24 MiB charge, two concurrent
        // reservations (48 MiB) exceeded the .eventSource class ceiling, so the
        // second lane FIFO-waited behind the first — the measured 4,973 waits
        // and 786 storage-write sheds. Both lanes must fit with headroom.
        #expect(2 * charge <= sourceCeiling,
                "two lanes' reservations must coexist under the .eventSource ceiling")
        // Safety (the ingest-headroom brief's CRITICAL note): a single charge at
        // or above the individual-request ceiling would make EVERY acquisition an
        // oversized request, and reserveEventSlot()==nil permanently breaks a
        // lane's consumer loop — far worse than one dropped event.
        #expect(charge < sourceCeiling)
        // Covers the installed-host observed maximum source size (~928 KiB) with
        // wide margin, so real non-overflow events never trip resizeReservation.
        #expect(charge >= 1_024 * 1_024)
    }
}
