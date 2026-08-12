import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Deferred heavy-enrichment integration")
struct DeferredEnrichmentIntegrationTests {
    private static let started = Date(timeIntervalSince1970: 1_750_000_000)

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
        args: [String] = []
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
            userName: "",
            groupId: 20,
            startTime: Self.started,
            codeSignature: nil,
            isPlatformBinary: false
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

        let waiting = Task { await buffer.reserveEventSlot() }
        for _ in 0..<100 {
            if (await buffer.snapshot()).waitingReservations == 1 { break }
            await Task.yield()
        }
        var snapshot = await buffer.snapshot()
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

        #expect(timers.contains("repeating: .milliseconds(100)"))
        #expect(timers.contains("label: \"deferred-enrichment-drain\""))
        #expect(timers.contains("timerLifecycle.register(timer)"))
        #expect(loop.contains("await dispatchReviewedMatches("))
        #expect(loop.contains(
            "let terminalAdmission = await settleTerminalJournalRevision("
        ))
        #expect(loop.contains(
            ".$terminalRevision.withValue(terminalAdmission)"
        ))
        #expect(loop.contains(
            "EventJournalAdmissionContext.terminalRevision?.status == .verified"
        ), "failed canonical terminal work must not promote sparse projection")
        #expect(loop.contains("markReadyAndDispatch("))
        #expect(loop.contains("await DeferredEnrichmentDispatcher.drainAvailable"))
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
}
