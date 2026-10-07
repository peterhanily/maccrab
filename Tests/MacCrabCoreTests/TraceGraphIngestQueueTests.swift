// TraceGraphIngestQueueTests.swift
// v1.22.7 lane-tracegraph — the detection lane hands enriched events to a
// bounded TraceGraph ingest queue and never waits on the graph store. These
// tests pin that contract deterministically: a store that blocks behind a
// simulated recovery barrier, a latched store that sheds on the nonisolated
// fast path, exact queue conservation, and the anchor shed dedup.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("TraceGraph: bounded lane ingest queue")
struct TraceGraphIngestQueueTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Seams

    /// Deterministic monotonic clock for the admission shed latch.
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var instant = ContinuousClock.now
        func now() -> ContinuousClock.Instant {
            lock.lock(); defer { lock.unlock() }
            return instant
        }
        func advance(_ seconds: Double) {
            lock.lock(); defer { lock.unlock() }
            instant = instant.advanced(by: .seconds(seconds))
        }
    }

    /// Simulated recovery barrier: every store write suspends here until the
    /// test releases it. Nothing times out, so the only way the lane loop can
    /// finish while the gate is closed is by never waiting on the store.
    private actor StoreGate {
        private var released = false
        private var entered = 0
        private var waiters: [CheckedContinuation<Void, Never>] = []
        private var entryObservers: [CheckedContinuation<Void, Never>] = []

        var isReleased: Bool { released }
        var entries: Int { entered }

        func enter() async {
            entered += 1
            entryObservers.forEach { $0.resume() }
            entryObservers.removeAll()
            guard !released else { return }
            await withCheckedContinuation { waiters.append($0) }
        }

        func waitForFirstEntry() async {
            guard entered == 0 else { return }
            await withCheckedContinuation { entryObservers.append($0) }
        }

        func release() {
            released = true
            waiters.forEach { $0.resume() }
            waiters.removeAll()
        }
    }

    /// Switchable admission failure for the injected persist seam.
    private final class AdmissionSwitch: @unchecked Sendable {
        private let lock = NSLock()
        private var rejecting: Bool
        init(rejecting: Bool) { self.rejecting = rejecting }
        var isRejecting: Bool {
            lock.lock(); defer { lock.unlock() }
            return rejecting
        }
        func set(rejecting: Bool) {
            lock.lock(); defer { lock.unlock() }
            self.rejecting = rejecting
        }
    }

    private final class TraceCollector: @unchecked Sendable {
        private let lock = NSLock()
        private var traces: [Trace] = []
        func append(_ new: [Trace]) {
            lock.lock(); defer { lock.unlock() }
            traces.append(contentsOf: new)
        }
        var count: Int {
            lock.lock(); defer { lock.unlock() }
            return traces.count
        }
    }

    // MARK: - Fixtures

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("ingest-queue-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func removeStore(at path: URL) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path.path + suffix)
        }
    }

    private func processInfo(pid: Int32, executable: String) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [], workingDirectory: "/",
            userId: 501, userName: "test", groupId: 20,
            startTime: now,
            codeSignature: CodeSignatureInfo(signerType: .apple, isNotarized: true),
            isPlatformBinary: true
        )
    }

    private func execEvent(_ index: Int, executable: String = "/usr/bin/true") -> Event {
        Event(
            timestamp: now.addingTimeInterval(Double(index) / 1_000),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: processInfo(pid: Int32(index + 1), executable: executable),
            enrichments: [
                EventToRollingCausalGraphBridge.processKeyEnrichmentKey:
                    "queue-process-\(index)"
            ]
        )
    }

    /// An ordinary build-output write by an Apple-signed tool: graph-schema
    /// mapped, but irrelevant to every anchor, so the rolling writer suppresses
    /// its physical row. The dominant event of a build storm.
    private func buildWriteEvent(_ index: Int, processName: String = "clang") -> Event {
        Event(
            timestamp: now.addingTimeInterval(Double(index) / 1_000),
            eventCategory: .file,
            eventType: .change,
            eventAction: "write",
            process: processInfo(pid: Int32(index + 1), executable: "/usr/bin/\(processName)"),
            file: FileInfo(
                path: "/Users/me/project/build/obj-\(index).o",
                name: "obj-\(index).o",
                directory: "/Users/me/project/build",
                action: .write
            ),
            enrichments: [
                EventToRollingCausalGraphBridge.processKeyEnrichmentKey:
                    "queue-build-\(index)"
            ]
        )
    }

    private func execInput(pid: Int32, at timestamp: Date) -> RollingCausalGraph.NormalizedEventInput {
        RollingCausalGraph.NormalizedEventInput(
            eventId: "exec-\(pid)",
            timestamp: timestamp,
            category: .process,
            action: .exec,
            process: RollingCausalGraph.ProcessObservation(
                processKey: "true-\(pid)",
                pid: pid,
                ppid: 1,
                executablePath: "/usr/bin/true",
                isAppleSigned: true,
                isNotarized: true,
                startTime: timestamp
            )
        )
    }

    private func credentialReadEvent(pid: Int32, at timestamp: Date) -> Event {
        Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .info,
            eventAction: "read",
            process: processInfo(pid: pid, executable: "/usr/bin/cat"),
            file: FileInfo(
                path: "/Users/me/.aws/credentials",
                name: "credentials",
                directory: "/Users/me/.aws",
                action: .open
            )
        )
    }

    /// Same behavioural credential anchor (executable, file, operation) from a
    /// fresh short-lived process, as the rolling writer sees it.
    private func credentialReadInput(pid: Int32, at timestamp: Date) -> RollingCausalGraph.NormalizedEventInput {
        RollingCausalGraph.NormalizedEventInput(
            eventId: "cred-\(pid)",
            timestamp: timestamp,
            category: .file,
            action: .fileRead,
            process: RollingCausalGraph.ProcessObservation(
                processKey: "cat-\(pid)",
                pid: pid,
                ppid: 1,
                executablePath: "/usr/bin/cat",
                isAppleSigned: true,
                isNotarized: true,
                startTime: timestamp
            ),
            file: RollingCausalGraph.FileObservation(
                path: "/Users/me/.aws/credentials",
                pathHash: "h-aws-credentials"
            )
        )
    }

    /// NOTIFY_SIGNAL and similar actions have no graph mapping; they must be
    /// counted as skipped at hand-off, never queued.
    private func signalEvent(_ index: Int) -> Event {
        Event(
            timestamp: now,
            eventCategory: .process,
            eventType: .info,
            eventAction: "signal",
            process: processInfo(pid: Int32(index + 1), executable: "/usr/bin/true")
        )
    }

    private func waitUntil(
        _ condition: @Sendable () async -> Bool
    ) async -> Bool {
        for _ in 0..<200_000 {
            if await condition() { return true }
            await Task.yield()
        }
        return false
    }

    // MARK: - Tests

    @Test("Lane hand-off completes while the store is blocked behind a barrier, and every event is accounted exactly once")
    func laneNeverWaitsOnBlockedStore() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let gate = StoreGate()
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .daemonCoalesced,
            monotonicNow: { ContinuousClock.now },
            persistBatch: { entities, edges in
                await gate.enter()
                try await store.upsertBatch(entities: entities, edges: edges)
            }
        )
        let capacity = 128
        let bridge = EventToRollingCausalGraphBridge(
            rollingGraph: graph,
            ingestQueueCapacity: capacity
        )
        let service = Task { await bridge.runIngestService { _, _ in } }

        let eventCount = 4_096
        let events = (0..<eventCount).map { execEvent($0) }
        var queuedOutcomes = 0
        for event in events {
            switch bridge.offer(event) {
            case .queued, .queuedEvictingOldest: queuedOutcomes += 1
            case .skippedNonGraph, .shedLatched, .terminated: break
            }
        }
        #expect(queuedOutcomes == eventCount)

        // The lane loop above has returned; the store write is still parked.
        let stillBlocked = await gate.isReleased == false
        #expect(stillBlocked, "the gate is only released by this test, after the lane loop")
        let duringStall = bridge.ingestQueueTelemetry()
        #expect(duringStall.handoffsTotal == UInt64(eventCount))
        #expect(duringStall.offeredTotal == UInt64(eventCount))
        #expect(duringStall.skippedNonGraphTotal == 0)
        #expect(duringStall.latchedShedTotal == 0)
        #expect(duringStall.terminatedTotal == 0)
        #expect(duringStall.backlog <= capacity)
        #expect(duringStall.conservesHandoffs)
        #expect(duringStall.conservesOffers)

        await gate.release()
        bridge.finishIngestQueue()
        await service.value
        try await bridge.flushPending()

        let queue = bridge.ingestQueueTelemetry()
        #expect(queue.backlog == 0)
        #expect(queue.inFlight == 0)
        #expect(queue.completedTotal == queue.dequeuedTotal)
        #expect(queue.conservesHandoffs)
        #expect(queue.conservesOffers)

        let writes = await bridge.writeTelemetry()
        #expect(writes.inputEventsTotal == queue.dequeuedTotal,
                "only dequeued events reach the rolling writer")
        #expect(writes.inputEventsTotal
                    == writes.eventsCommittedTotal + writes.eventsFailedTotal
                    + UInt64(writes.eventsInFlight) + UInt64(writes.eventsPending))
        #expect(writes.eventsFailedTotal == 0)
        #expect(queue.droppedTotal + writes.inputEventsTotal == UInt64(eventCount),
                "every hand-off is either dropped at the queue or ingested, never both or neither")
        await store.close()
    }

    @Test("Queue overflow with no consumer evicts exactly the excess and keeps conservation")
    func overflowAccountingIsExact() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .daemonCoalesced
        )
        let bridge = EventToRollingCausalGraphBridge(
            rollingGraph: graph,
            ingestQueueCapacity: 4
        )

        var outcomes: [TraceGraphIngestHandoff] = []
        for index in 0..<10 {
            outcomes.append(bridge.offer(execEvent(index)))
        }
        for index in 0..<3 {
            #expect(bridge.offer(signalEvent(index)) == .skippedNonGraph)
        }
        #expect(outcomes.prefix(4).allSatisfy { $0 == .queued })
        #expect(outcomes.dropFirst(4).allSatisfy { $0 == .queuedEvictingOldest })

        let parked = bridge.ingestQueueTelemetry()
        #expect(parked.capacity == 4)
        #expect(parked.handoffsTotal == 13)
        #expect(parked.skippedNonGraphTotal == 3)
        #expect(parked.offeredTotal == 10)
        #expect(parked.droppedTotal == 6)
        #expect(parked.dequeuedTotal == 0)
        #expect(parked.backlog == 4)
        #expect(parked.conservesHandoffs)
        #expect(parked.conservesOffers)

        bridge.finishIngestQueue()
        await bridge.runIngestService { _, _ in }
        #expect(bridge.offer(execEvent(99)) == .terminated)
        try await bridge.flushPending()

        let drained = bridge.ingestQueueTelemetry()
        #expect(drained.dequeuedTotal == 4)
        #expect(drained.completedTotal == 4)
        #expect(drained.terminatedTotal == 1)
        #expect(drained.backlog == 0)
        #expect(drained.conservesHandoffs)
        #expect(drained.conservesOffers)
        let writes = await bridge.writeTelemetry()
        #expect(writes.inputEventsTotal == 4)
        #expect(writes.eventsCommittedTotal == 4)
        await store.close()
    }

    @Test("A latched store sheds ordinary events on the nonisolated fast path, passes lineage/anchor events, probes once per interval, and the probe clears the latch after recovery")
    func latchedStoreShedsWithoutActorHop() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let clock = Clock()
        let admission = AdmissionSwitch(rejecting: true)
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .immediate,
            monotonicNow: { clock.now() },
            persistBatch: { entities, edges in
                if admission.isRejecting {
                    throw CausalGraphStorageAdmissionError.recoveryInProgress
                }
                try await store.upsertBatch(entities: entities, edges: edges)
            }
        )
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: graph)
        let service = Task { await bridge.runIngestService { _, _ in } }

        // First event takes the ordinary path, hits the refused write, and
        // arms the latch inside the rolling writer.
        #expect(bridge.offer(execEvent(0)) == .queued)
        let armed = await waitUntil {
            bridge.ingestQueueTelemetry().completedTotal == 1
        }
        #expect(armed)
        #expect(graph.admissionShedLatch.isArmed)

        // Frozen clock: the interval never elapses, so every ordinary build
        // write sheds here without touching the queue, the bridge actor, or
        // the writer.
        for index in 1...1_000 {
            #expect(bridge.offer(buildWriteEvent(index)) == .shedLatched)
        }
        let latched = bridge.ingestQueueTelemetry()
        #expect(latched.admissionLatched)
        #expect(latched.latchedShedTotal == 1_000)
        #expect(latched.lossTotal == 1_000)
        #expect(latched.lastLossAt != nil)
        #expect(latched.offeredTotal == 1)
        #expect(latched.handoffsTotal == 1_001)
        #expect(latched.admissionProbesTotal == 0)
        #expect(latched.conservesHandoffs)
        let shedWrites = await bridge.writeTelemetry()
        #expect(shedWrites.inputEventsTotal == 1)
        #expect(shedWrites.eventsFailedTotal == 1)
        #expect(shedWrites.writeAttemptsTotal == 1)

        // Lineage-critical events are not shed while latched: an exec passes
        // (counted), reaches the writer, and its refused flush re-arms.
        #expect(bridge.offer(execEvent(1)) == .queued)
        let passed = await waitUntil {
            bridge.ingestQueueTelemetry().completedTotal == 2
        }
        #expect(passed)
        #expect(bridge.ingestQueueTelemetry().latchedPassThroughTotal == 1)
        #expect(graph.admissionShedLatch.isArmed)
        let passWrites = await bridge.writeTelemetry()
        #expect(passWrites.writeAttemptsTotal == 2)
        #expect(passWrites.eventsFailedTotal == 2)

        // One probe per interval while still refused. The probe is an
        // ordinary build write, which would normally take the physical-write
        // suppression path and never touch the store; as a probe it must be
        // exactly one write attempt.
        clock.advance(1.5)
        #expect(bridge.offer(buildWriteEvent(1_001)) == .queued)
        #expect(bridge.offer(buildWriteEvent(1_002)) == .shedLatched)
        let probed = await waitUntil {
            bridge.ingestQueueTelemetry().completedTotal == 3
        }
        #expect(probed)
        #expect(graph.admissionShedLatch.isArmed)
        #expect(bridge.ingestQueueTelemetry().admissionProbesTotal == 1)
        let probeWrites = await bridge.writeTelemetry()
        #expect(probeWrites.writeAttemptsTotal == 3)
        #expect(probeWrites.eventsFailedTotal == 3)
        #expect(probeWrites.physicalWriteSuppressedEventsTotal == 0,
                "a probe is never suppressed, or it could not discover recovery")

        // Recovery: the next probe is again an ordinary build write. It
        // commits, clears the latch, and full flow resumes within one interval.
        admission.set(rejecting: false)
        clock.advance(1.5)
        #expect(bridge.offer(buildWriteEvent(1_003)) == .queued)
        let recovered = await waitUntil {
            bridge.ingestQueueTelemetry().completedTotal == 4
        }
        #expect(recovered)
        #expect(!graph.admissionShedLatch.isArmed)
        let recoveredWrites = await bridge.writeTelemetry()
        #expect(recoveredWrites.writeAttemptsTotal == 4)
        #expect(recoveredWrites.writeBatchesCommittedTotal == 1)
        for index in 1_004...1_010 {
            #expect(bridge.offer(buildWriteEvent(index)) == .queued)
        }
        bridge.finishIngestQueue()
        await service.value

        let final = bridge.ingestQueueTelemetry()
        #expect(!final.admissionLatched)
        #expect(final.latchedShedTotal == 1_001)
        #expect(final.latchedPassThroughTotal == 1)
        #expect(final.admissionProbesTotal == 2)
        #expect(final.admissionLatchArmsTotal == 1)
        #expect(final.completedTotal == 11)
        #expect(final.filteredTotal == 0)
        #expect(final.rejectedTotal == 0)
        #expect(final.conservesHandoffs)
        #expect(final.conservesOffers)
        let writes = await bridge.writeTelemetry()
        #expect(writes.inputEventsTotal == 11)
        #expect(writes.inputEventsTotal
                    == final.completedTotal - final.filteredTotal - final.rejectedTotal,
                "every dequeued event the filter kept is ledgered by the writer exactly once")
        // Two refused execs and one refused probe failed; the recovery probe
        // and the seven ordinary writes after it (suppressed, counted as
        // committed) succeeded.
        #expect(writes.eventsFailedTotal == 3)
        #expect(writes.eventsCommittedTotal == 8)
        #expect(writes.physicalWriteSuppressedEventsTotal == 7)
        #expect(writes.inputEventsTotal
                    == writes.eventsCommittedTotal + writes.eventsFailedTotal
                    + UInt64(writes.eventsInFlight) + UInt64(writes.eventsPending))
        await store.close()
    }

    @Test("A probe the insert filter drops reopens the window so the next hand-off probes immediately")
    func filteredProbeReopensTheWindow() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let clock = Clock()
        let admission = AdmissionSwitch(rejecting: true)
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .immediate,
            monotonicNow: { clock.now() },
            persistBatch: { entities, edges in
                if admission.isRejecting {
                    throw CausalGraphStorageAdmissionError.recoveryInProgress
                }
                try await store.upsertBatch(entities: entities, edges: edges)
            }
        )
        let bridge = EventToRollingCausalGraphBridge(
            rollingGraph: graph,
            insertFilter: EventInsertFilter(processNames: ["noise"])
        )
        let service = Task { await bridge.runIngestService { _, _ in } }

        #expect(bridge.offer(execEvent(0)) == .queued)
        let armed = await waitUntil { bridge.ingestQueueTelemetry().completedTotal == 1 }
        #expect(armed)
        #expect(graph.admissionShedLatch.isArmed)

        // The store recovers, but the only probe of this interval is an event
        // the production filter discards before ingestion: no write attempt.
        admission.set(rejecting: false)
        clock.advance(1.5)
        #expect(bridge.offer(buildWriteEvent(1, processName: "noise")) == .queued)
        let filteredProbe = await waitUntil { bridge.ingestQueueTelemetry().completedTotal == 2 }
        #expect(filteredProbe)
        #expect(bridge.ingestQueueTelemetry().filteredTotal == 1)
        #expect(graph.admissionShedLatch.isArmed, "a filtered probe cannot clear the latch")

        // Without advancing the clock the next ordinary hand-off is the probe
        // and discovers the recovery.
        #expect(bridge.offer(buildWriteEvent(2)) == .queued)
        let reopenedProbe = await waitUntil { bridge.ingestQueueTelemetry().completedTotal == 3 }
        #expect(reopenedProbe)
        #expect(!graph.admissionShedLatch.isArmed)
        bridge.finishIngestQueue()
        await service.value

        let queue = bridge.ingestQueueTelemetry()
        #expect(queue.admissionProbesTotal == 2)
        #expect(queue.latchedShedTotal == 0)
        let writes = await bridge.writeTelemetry()
        #expect(writes.writeAttemptsTotal == 2)
        #expect(writes.writeBatchesCommittedTotal == 1)
        #expect(writes.inputEventsTotal == queue.completedTotal - queue.filteredTotal)
        await store.close()
    }

    @Test("Filtered events are a counted outcome and dequeued = in_flight + filtered + rejected + writer input")
    func filteredEventsAreCountedAndTheChainCloses() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .daemonCoalesced
        )
        let bridge = EventToRollingCausalGraphBridge(
            rollingGraph: graph,
            insertFilter: EventInsertFilter(processNames: ["noise"])
        )
        for index in 0..<7 {
            #expect(bridge.offer(execEvent(index)) == .queued)
        }
        for index in 7..<10 {
            #expect(bridge.offer(execEvent(index, executable: "/usr/bin/noise")) == .queued)
        }
        bridge.finishIngestQueue()
        await bridge.runIngestService { _, _ in }
        try await bridge.flushPending()

        let queue = bridge.ingestQueueTelemetry()
        #expect(queue.dequeuedTotal == 10)
        #expect(queue.completedTotal == 10)
        #expect(queue.inFlight == 0)
        #expect(queue.filteredTotal == 3)
        #expect(queue.rejectedTotal == 0)
        #expect(queue.lossTotal == 0)
        #expect(queue.lastLossAt == nil)
        let writes = await bridge.writeTelemetry()
        #expect(writes.inputEventsTotal == 7)
        #expect(UInt64(queue.inFlight) + queue.filteredTotal + queue.rejectedTotal
                    + writes.inputEventsTotal == queue.dequeuedTotal)
        #expect(writes.eventsCommittedTotal == 7)
        await store.close()
    }

    @Test("A cancelled ingest service stops pulling buffered events; the remainder stays accounted as backlog")
    func cancelledServiceStopsPullingBufferedEvents() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let gate = StoreGate()
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .immediate,
            monotonicNow: { ContinuousClock.now },
            persistBatch: { entities, edges in
                await gate.enter()
                try await store.upsertBatch(entities: entities, edges: edges)
            }
        )
        let bridge = EventToRollingCausalGraphBridge(
            rollingGraph: graph,
            ingestQueueCapacity: 128
        )
        let service = Task { await bridge.runIngestService { _, _ in } }
        for index in 0..<64 {
            #expect(bridge.offer(execEvent(index)) == .queued)
        }
        // The service is inside the first event's store write; the other 63
        // are buffered in the stream, which keeps returning them after
        // cancellation unless the service checks.
        await gate.waitForFirstEntry()
        service.cancel()
        await gate.release()
        await service.value

        let queue = bridge.ingestQueueTelemetry()
        #expect(queue.dequeuedTotal == 1)
        #expect(queue.completedTotal == 1)
        #expect(queue.inFlight == 0)
        #expect(queue.droppedTotal == 0)
        #expect(queue.backlog == 63, "abandoned hand-offs remain visible, never silently consumed")
        #expect(queue.conservesOffers)
        let writes = await bridge.writeTelemetry()
        #expect(writes.inputEventsTotal == 1)
        bridge.finishIngestQueue()
        await store.close()
    }

    @Test("An anchor refused just before a flush recovered the store is retried by its next occurrence, not suppressed for a window")
    func shedAnchorRetriesOnceTheStoreRecovers() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 4_096,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4_096
        )
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 3_600,
                maximumPendingEvents: 256,
                maximumPendingRows: 1_024
            )
        )
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await graph.ingest(credentialReadInput(pid: 301, at: now))
        }
        #expect(graph.admissionShedLatch.isArmed)

        // Ordinary substrate arrives behind the refusal and the store recovers;
        // the scheduled flush of that backlog (driven explicitly here) commits,
        // which clears the latch and the shed-anchor cache together.
        _ = try await graph.ingest(execInput(pid: 400, at: now.addingTimeInterval(0.02)))
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 256 * 1_024 * 1_024,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4 * 1_024 * 1_024
        )
        try await graph.flushPending()
        #expect(!graph.admissionShedLatch.isArmed)

        // The same behavioural anchor 50 ms after the refusal materializes:
        // an event-time window alone would have suppressed it and, had it not
        // recurred later, the trace would never have existed.
        let traces = try await graph.ingest(
            credentialReadInput(pid: 302, at: now.addingTimeInterval(0.05)))
        #expect(traces.count == 1)
        let telemetry = await graph.writeTelemetry()
        #expect(telemetry.anchorShedTotal == 1)
        #expect(telemetry.anchorShedDedupSuppressedTotal == 0)
        await store.close()
    }

    @Test("A probe carrying a shed anchor retries that anchor and materializes once the store has recovered")
    func probeRetriesItsOwnShedAnchor() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 4_096,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4_096
        )
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 3_600,
                maximumPendingEvents: 256,
                maximumPendingRows: 1_024
            )
        )
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await graph.ingest(credentialReadInput(pid: 301, at: now))
        }
        #expect(graph.admissionShedLatch.isArmed)
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 256 * 1_024 * 1_024,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4 * 1_024 * 1_024
        )

        // Still inside the shed window with the latch armed: an ordinary
        // repeat is deduplicated and makes no write attempt.
        let suppressed = try await graph.ingest(
            credentialReadInput(pid: 302, at: now.addingTimeInterval(0.03)))
        #expect(suppressed.isEmpty)
        let afterSuppressed = await graph.writeTelemetry()
        #expect(afterSuppressed.anchorShedDedupSuppressedTotal == 1)
        #expect(afterSuppressed.writeAttemptsTotal == 1)

        // The probe bypasses the dedup: one write attempt, one trace, latch clear.
        let traces = try await graph.ingest(
            credentialReadInput(pid: 303, at: now.addingTimeInterval(0.05)),
            probe: true
        )
        #expect(traces.count == 1)
        #expect(!graph.admissionShedLatch.isArmed)
        let telemetry = await graph.writeTelemetry()
        #expect(telemetry.writeAttemptsTotal == 2)
        #expect(telemetry.writeBatchesCommittedTotal == 1)
        await store.close()
    }

    @Test("Materialized traces reach the service callback off the lane and finish drains the backlog")
    func serviceDeliversMaterializedTraces() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: .daemonCoalesced
        )
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: graph)
        let collected = TraceCollector()
        let service = Task {
            await bridge.runIngestService { traces, anchorEvent in
                #expect(anchorEvent.file?.path == "/Users/me/.aws/credentials")
                collected.append(traces)
            }
        }

        for index in 0..<32 {
            #expect(bridge.offer(execEvent(index)) == .queued)
        }
        #expect(bridge.offer(credentialReadEvent(pid: 300, at: now)) == .queued)
        bridge.finishIngestQueue()
        await service.value

        #expect(collected.count == 1, "one credential anchor materializes one trace")
        let queue = bridge.ingestQueueTelemetry()
        #expect(queue.offeredTotal == 33)
        #expect(queue.completedTotal == 33)
        #expect(queue.backlog == 0)
        #expect(queue.droppedTotal == 0)
        await store.close()
    }

    @Test("Shed anchors are not retried per event while latched, and the first anchor after recovery materializes")
    func shedAnchorDedupWhileLatched() async throws {
        let (store, dbPath) = try await makeStore()
        defer { removeStore(at: dbPath) }
        // A cap far below the fresh file's footprint latches every mutation,
        // including the materializer's trace write.
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 4_096,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4_096
        )
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            // Long scheduling delay: every commit boundary is driven
            // explicitly, so no timer flush can race the write-attempt counts.
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 3_600,
                maximumPendingEvents: 256,
                maximumPendingRows: 1_024
            )
        )

        // Same behavioural anchor (same executable, file, operation) from
        // short-lived polling processes, inside one shed window.
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await graph.ingest(credentialReadInput(pid: 301, at: now))
        }
        #expect(graph.admissionShedLatch.isArmed)
        let afterFirst = await graph.writeTelemetry()
        #expect(afterFirst.writeAttemptsTotal == 1)
        #expect(afterFirst.anchorShedTotal == 1)

        for pid in 302...311 {
            let traces = try await graph.ingest(
                credentialReadInput(pid: Int32(pid), at: now.addingTimeInterval(0.05)))
            #expect(traces.isEmpty)
        }
        let suppressed = await graph.writeTelemetry()
        #expect(suppressed.writeAttemptsTotal == 1,
                "a shed anchor must not force one failed flush per repeat")
        #expect(suppressed.anchorShedDedupSuppressedTotal == 10)
        #expect(suppressed.anchorShedTotal == 1)
        #expect(suppressed.eventsPending == 10)

        // Past the window the anchor is retried exactly once more.
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await graph.ingest(
                credentialReadInput(pid: 312, at: now.addingTimeInterval(1.5)))
        }
        let retried = await graph.writeTelemetry()
        #expect(retried.writeAttemptsTotal == 2)
        #expect(retried.anchorShedTotal == 2)

        // Recovery: lift the cap; the first anchor after it materializes.
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 256 * 1_024 * 1_024,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4 * 1_024 * 1_024
        )
        let traces = try await graph.ingest(
            credentialReadInput(pid: 313, at: now.addingTimeInterval(3)))
        #expect(traces.count == 1)
        #expect(!graph.admissionShedLatch.isArmed)
        let recovered = await graph.writeTelemetry()
        #expect(recovered.writeBatchesCommittedTotal == 1)
        #expect(recovered.eventsPending == 0)
        await store.close()
    }
}
