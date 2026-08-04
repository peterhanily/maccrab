import Foundation
import Testing
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Deferred heavy-enrichment integration")
struct DeferredEnrichmentIntegrationTests {
    private static let started = Date(timeIntervalSince1970: 1_750_000_000)

    private func event(
        id: UUID = UUID(),
        pending components: Set<HeavyEnrichmentComponent>
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 7_777,
            ppid: 1,
            rpid: 7_777,
            name: "fixture",
            executable: "/usr/bin/true",
            commandLine: "/usr/bin/true",
            args: [],
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
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 2, patchCapacity: 2)
        let first = event(pending: [.userName])
        let second = event(pending: [.environment])
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
        #expect(firstReplay.count == 1)
        #expect(secondReplay.count == 1)
        #expect(firstReplay[0].event.process.userName == "alice")
        #expect(secondReplay[0].event.process.envVars == ["PATH": "/usr/bin"])
        #expect(firstReplay[0].terminal && secondReplay[0].terminal)

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
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 1, patchCapacity: 4)
        let original = event(pending: [.environment, .userName])
        let reservation = try #require(await buffer.reserveEventSlot())
        #expect(await buffer.retain(original, using: reservation))
        #expect((await buffer.markReady(original)).isEmpty)

        let batches = await transfer([
            patch(event: original, component: .environment, value: .environment(["LANG": "C"])),
            patch(event: original, component: .userName, value: .userName("operator")),
        ], to: buffer)
        #expect(batches.count == 1)
        #expect(batches[0].completedComponents == [.environment, .userName])
        #expect(batches[0].terminal)
        #expect(batches[0].event.process.envVars == ["LANG": "C"])
        #expect(batches[0].event.process.userName == "operator")
        #expect((await buffer.snapshot()).patchesConsumedTotal == 2)
    }

    @Test("timeout is terminal degraded coverage and never claims completion")
    func timeoutClosesHonestly() async throws {
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 1, patchCapacity: 1)
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
        #expect(batches.count == 1)
        #expect(batches[0].terminal)
        #expect(batches[0].completedComponents.isEmpty)
        #expect(DeferredEventEnrichment.coverageState(
            for: .codeSignature,
            in: batches[0].event
        ) == .timedOut)
        #expect((await buffer.snapshot()).retainedEvents == 0)
    }

    @Test("plane shutdown terminalizes then buffer drains the accepted prefix")
    func shutdownDrain() async throws {
        let plane = HeavyEnrichmentPlane(configuration: .init(
            maximumConcurrentWorkers: 1,
            maximumQueuedWorkItems: 0,
            maximumOutstandingResults: 1,
            cacheCapacity: 0,
            operationTimeoutSeconds: 10
        ))
        let buffer = DeferredEnrichmentBuffer(eventCapacity: 1, patchCapacity: 1)
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

        #expect(terminalPatches.count == 1)
        #expect(terminalPatches[0].outcome == .cancelled)
        #expect(batches.count == 1)
        #expect(batches[0].terminal)
        #expect(batches[0].completedComponents.isEmpty)
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

        #expect(timers.contains("repeating: .milliseconds(100)"))
        #expect(timers.contains("label: \"deferred-enrichment-drain\""))
        #expect(timers.contains("timerLifecycle.register(timer)"))
        #expect(loop.contains("await dispatchReviewedMatches("))
        #expect(loop.contains("markReadyAndDispatch("))
        #expect(loop.contains("await DeferredEnrichmentDispatcher.drainAvailable"))
        #expect(lifecycle.contains("DeferredEnrichmentDispatcher.shutdown("))
        #expect(lifecycle.contains("heavyEnrichmentPlane: heavyEnrichment.clean"))
    }
}
