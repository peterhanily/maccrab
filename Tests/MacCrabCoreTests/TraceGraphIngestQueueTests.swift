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

    private func execEvent(_ index: Int) -> Event {
        Event(
            timestamp: now.addingTimeInterval(Double(index) / 1_000),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: processInfo(pid: Int32(index + 1), executable: "/usr/bin/true"),
            enrichments: [
                EventToRollingCausalGraphBridge.processKeyEnrichmentKey:
                    "queue-process-\(index)"
            ]
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
        let events = (0..<eventCount).map(execEvent)
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

    @Test("A latched store sheds on the nonisolated fast path, probes once per interval, and resumes after recovery")
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

        // Frozen clock: the interval never elapses, so every hand-off sheds
        // here without touching the queue, the bridge actor, or the writer.
        for index in 1...1_000 {
            #expect(bridge.offer(execEvent(index)) == .shedLatched)
        }
        let latched = bridge.ingestQueueTelemetry()
        #expect(latched.admissionLatched)
        #expect(latched.latchedShedTotal == 1_000)
        #expect(latched.offeredTotal == 1)
        #expect(latched.handoffsTotal == 1_001)
        #expect(latched.admissionProbesTotal == 0)
        #expect(latched.conservesHandoffs)
        let shedWrites = await bridge.writeTelemetry()
        #expect(shedWrites.inputEventsTotal == 1)
        #expect(shedWrites.eventsFailedTotal == 1)
        #expect(shedWrites.writeAttemptsTotal == 1)

        // One probe per interval while still refused: exactly one write attempt.
        clock.advance(1.5)
        #expect(bridge.offer(execEvent(1_001)) == .queued)
        #expect(bridge.offer(execEvent(1_002)) == .shedLatched)
        let probed = await waitUntil {
            bridge.ingestQueueTelemetry().completedTotal == 2
        }
        #expect(probed)
        #expect(graph.admissionShedLatch.isArmed)
        #expect(bridge.ingestQueueTelemetry().admissionProbesTotal == 1)
        let probeWrites = await bridge.writeTelemetry()
        #expect(probeWrites.writeAttemptsTotal == 2)
        #expect(probeWrites.eventsFailedTotal == 2)

        // Recovery: the next probe commits, clears the latch, and full flow resumes.
        admission.set(rejecting: false)
        clock.advance(1.5)
        #expect(bridge.offer(execEvent(1_003)) == .queued)
        let recovered = await waitUntil {
            bridge.ingestQueueTelemetry().completedTotal == 3
        }
        #expect(recovered)
        #expect(!graph.admissionShedLatch.isArmed)
        for index in 1_004...1_010 {
            #expect(bridge.offer(execEvent(index)) == .queued)
        }
        bridge.finishIngestQueue()
        await service.value

        let final = bridge.ingestQueueTelemetry()
        #expect(!final.admissionLatched)
        #expect(final.latchedShedTotal == 1_001)
        #expect(final.admissionProbesTotal == 2)
        #expect(final.admissionLatchArmsTotal == 1)
        #expect(final.completedTotal == 10)
        #expect(final.conservesHandoffs)
        #expect(final.conservesOffers)
        let writes = await bridge.writeTelemetry()
        #expect(writes.inputEventsTotal == 10)
        #expect(writes.eventsCommittedTotal == 8)
        #expect(writes.eventsFailedTotal == 2)
        #expect(writes.inputEventsTotal
                    == writes.eventsCommittedTotal + writes.eventsFailedTotal
                    + UInt64(writes.eventsInFlight) + UInt64(writes.eventsPending))
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
