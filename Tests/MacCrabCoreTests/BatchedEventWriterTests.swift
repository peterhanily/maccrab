// BatchedEventWriterTests.swift
// v1.21.4 (F2 / A1) — the async batched events.db writer that decouples the
// hot detection consumer from per-event SQLite transactions. These drive a
// REAL EventStore in a temp dir so batching + overflow behaviour travel the
// true insert path.

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("F2/A1 BatchedEventWriter")
struct BatchedEventWriterTests {

    private func makeEvent(_ i: Int) -> Event {
        let proc = ProcessInfo(
            pid: Int32(3000 + i), ppid: 1, rpid: 1,
            name: "bw\(i)", executable: "/bin/bw\(i)",
            commandLine: "/bin/bw\(i)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)), ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private func makeFileEvent(_ i: Int) -> Event {
        let proc = ProcessInfo(
            pid: Int32(9000 + i), ppid: 1, rpid: 1,
            name: "flood", executable: "/bin/flood",
            commandLine: "/bin/flood", args: [], workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)), ancestors: [],
            isPlatformBinary: false)
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .file, eventType: .creation, eventAction: "file",
            process: proc, file: FileInfo(path: "/tmp/flood/\(i).tmp", action: .write))
    }

    /// A fake inserter that fails transiently (EventStoreError.busy) until told to
    /// succeed — used to exercise the #13 retry-not-drop path deterministically.
    private actor FakeInserter: EventBatchInserting {
        private var failing = true
        private(set) var inserted: [Event] = []
        func setFailing(_ f: Bool) { failing = f }
        func insert(events: [Event]) throws -> EventBatchInsertResult {
            if failing { throw EventStoreError.busy("database is locked") }
            inserted.append(contentsOf: events)
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1
            )
        }
        var count: Int { inserted.count }
    }

    /// Simulates EventStore committing a prefix, then seeing SQLITE_BUSY in
    /// chunk N. The next call must contain exactly the uncommitted suffix.
    private actor PartialInserter: EventBatchInserting {
        private var failedOnce = false
        private(set) var insertedIDs: [UUID] = []
        private(set) var calls: [[UUID]] = []

        func insert(events: [Event]) throws -> EventBatchInsertResult {
            calls.append(events.map(\.id))
            if !failedOnce {
                failedOnce = true
                let prefix = min(3, events.count)
                insertedIDs.append(contentsOf: events.prefix(prefix).map(\.id))
                throw EventBatchInsertFailure(
                    progress: EventBatchInsertResult(
                        inputCount: events.count,
                        persistedCount: prefix,
                        filteredCount: 0,
                        committedTransactionCount: prefix == 0 ? 0 : 1
                    ),
                    uncommittedEvents: Array(events.dropFirst(prefix)),
                    underlyingError: EventStoreError.busy("chunk N busy")
                )
            }
            insertedIDs.append(contentsOf: events.map(\.id))
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1
            )
        }
    }

    /// Simulates corruption after an earlier reserve chunk committed. The
    /// active database is then quarantined, so the apparent committed prefix
    /// is no longer durable and EventStore returns the complete candidate set.
    private actor ReplacedDatabaseInserter: EventBatchInserting {
        let replacementReady: Bool
        private var failedOnce = false
        private(set) var insertedIDs: [UUID] = []
        private(set) var calls: [[UUID]] = []

        init(replacementReady: Bool) {
            self.replacementReady = replacementReady
        }

        func insert(events: [Event]) throws -> EventBatchInsertResult {
            calls.append(events.map(\.id))
            if !failedOnce {
                failedOnce = true
                throw EventBatchInsertFailure(
                    progress: EventBatchInsertResult(
                        inputCount: events.count,
                        persistedCount: 0,
                        filteredCount: 0,
                        committedTransactionCount: 0
                    ),
                    uncommittedEvents: events,
                    underlyingError: EventStoreError.stepFailed(
                        "active database quarantined"
                    ),
                    activeDatabaseWasReplaced: true,
                    replacementReadyForRetry: replacementReady
                )
            }
            insertedIDs.append(contentsOf: events.map(\.id))
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1
            )
        }
    }

    private final class InsertGate: @unchecked Sendable {
        private let lock = NSLock()
        private var entered = false
        private let release = DispatchSemaphore(value: 0)

        func markEntered() {
            lock.lock()
            entered = true
            lock.unlock()
        }

        func hasEntered() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return entered
        }

        func waitForRelease() { release.wait() }
        func releaseInsert() { release.signal() }
    }

    /// Blocks inside the store actor after the writer has detached its batch.
    /// The writer actor itself remains available at the `await`, which lets the
    /// test inspect the exact heartbeat state during the insert.
    private actor SuspendedInserter: EventBatchInserting {
        let gate: InsertGate

        init(gate: InsertGate) { self.gate = gate }

        func insert(events: [Event]) throws -> EventBatchInsertResult {
            gate.markEntered()
            gate.waitForRelease()
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1
            )
        }
    }

    private func tempStore() throws -> (EventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bw-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try EventStore(directory: dir.path), dir)
    }

    /// Poll count() until it reaches `target` or the retry budget is spent
    /// (the drain is async, so the row count converges rather than being
    /// instantaneous).
    private func waitForCount(_ store: EventStore, target: Int, tries: Int = 40) async throws -> Int {
        var last = 0
        for _ in 0..<tries {
            last = try await store.count()
            if last >= target { return last }
            try? await Task.sleep(nanoseconds: 25_000_000) // 25ms
        }
        return last
    }

    @Test("shutdown flushes a below-threshold partial batch — every event persists")
    func shutdownFlushesPartial() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // Threshold high enough that no auto-drain fires: the ONLY flush is
        // shutdown's, so this proves the shutdown path alone persists the batch.
        let writer = BatchedEventWriter(store: store, flushThreshold: 100_000, hardCap: 100_000)
        for i in 0..<100 { await writer.enqueue(makeEvent(i)) }
        let queued = await writer.telemetrySnapshot()
        #expect(queued.bufferDepth == 100)
        #expect(queued.persistedCount == 0)
        #expect(queued.retriedCount == 0)
        #expect(queued.droppedCount == 0)
        #expect(queued.inFlightDepth == 0)
        #expect(try await store.count() == 0, "nothing flushed before shutdown (batched, not inline)")
        await writer.shutdown()
        #expect(try await store.count() == 100, "shutdown flushes the partial batch")
        #expect(writer.droppedCount == 0)
        let drained = await writer.telemetrySnapshot()
        #expect(drained.bufferDepth == 0)
        #expect(drained.persistedCount == 100)
        #expect(drained.inFlightDepth == 0)
    }

    @Test("crossing the flush threshold drains automatically off the caller")
    func autoDrainOnThreshold() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = BatchedEventWriter(store: store, flushThreshold: 50, hardCap: 100_000)
        for i in 0..<500 { await writer.enqueue(makeEvent(i)) }
        // The auto-drain loops until the buffer empties, so all 500 land without
        // an explicit shutdown — poll for convergence.
        let n = try await waitForCount(store, target: 500)
        #expect(n == 500, "auto-drain persisted all events (got \(n))")
        #expect(writer.droppedCount == 0)
    }

    @Test("detached batch remains visible as in-flight while store insert is suspended")
    func inFlightDepthClosesReconciliationGap() async throws {
        let gate = InsertGate()
        let writer = BatchedEventWriter(
            store: SuspendedInserter(gate: gate),
            flushThreshold: 2,
            hardCap: 100
        )
        await writer.enqueue(makeEvent(0))
        await writer.enqueue(makeEvent(1))

        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        #expect(gate.hasEntered())
        let suspended = await writer.telemetrySnapshot()
        #expect(suspended.bufferDepth == 0)
        #expect(suspended.inFlightDepth == 2)
        #expect(suspended.persistedCount == 0)
        #expect(suspended.droppedCount == 0)

        gate.releaseInsert()
        var completed = await writer.telemetrySnapshot()
        for _ in 0..<100 where completed.inFlightDepth != 0 {
            try? await Task.sleep(nanoseconds: 5_000_000)
            completed = await writer.telemetrySnapshot()
        }
        #expect(completed.bufferDepth == 0)
        #expect(completed.inFlightDepth == 0)
        #expect(completed.persistedCount == 2)
        await writer.shutdown()
    }

    @Test("In-flight rows are accounted before any error-reporting suspension")
    func inFlightFailureAccountingDriftGuard() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/BatchedEventWriter.swift"
            ),
            encoding: .utf8
        )
        // Every reporting hop must follow both terminal row accounting and the
        // gauge clear in its catch branch. This is intentionally a source guard:
        // StorageErrorTracker.shared is a process singleton and cannot be paused
        // safely in a parallel test run.
        let partialDrop = try #require(source.range(
            of: "drops.add(suffix.count)"
        ))
        let partialClear = try #require(source.range(
            of: "inFlightDepth = 0",
            range: partialDrop.upperBound..<source.endIndex
        ))
        let partialReport = try #require(source.range(
            of: "await StorageErrorTracker.shared.recordEventError(\n                    partial.underlyingError",
            range: partialClear.upperBound..<source.endIndex
        ))
        #expect(partialDrop.lowerBound < partialClear.lowerBound)
        #expect(partialClear.lowerBound < partialReport.lowerBound)

        let transientCatch = try #require(source.range(
            of: "catch let e as EventStoreError where isTransient(e)"
        ))
        let transientDrop = try #require(source.range(
            of: "drops.add(batch.count)",
            range: transientCatch.lowerBound..<source.endIndex
        ))
        let transientClear = try #require(source.range(
            of: "inFlightDepth = 0",
            range: transientDrop.upperBound..<source.endIndex
        ))
        let transientReport = try #require(source.range(
            of: "await StorageErrorTracker.shared.recordEventError(e)",
            range: transientClear.upperBound..<source.endIndex
        ))
        #expect(transientDrop.lowerBound < transientClear.lowerBound)
        #expect(transientClear.lowerBound < transientReport.lowerBound)

        let permanentComment = try #require(source.range(
            of: "// PERMANENT (disk full, corruption, encoding)"
        ))
        let permanentDrop = try #require(source.range(
            of: "drops.add(batch.count)",
            range: permanentComment.lowerBound..<source.endIndex
        ))
        let permanentClear = try #require(source.range(
            of: "inFlightDepth = 0",
            range: permanentDrop.upperBound..<source.endIndex
        ))
        let permanentReport = try #require(source.range(
            of: "await StorageErrorTracker.shared.recordEventError(error)",
            range: permanentClear.upperBound..<source.endIndex
        ))
        #expect(permanentDrop.lowerBound < permanentClear.lowerBound)
        #expect(permanentClear.lowerBound < permanentReport.lowerBound)
    }

    @Test("insert-filter decisions remain distinct from writer persistence and sheds")
    func insertFilterLedgerIsDistinct() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        await store.setInsertFilter(EventInsertFilter(processNames: ["bw0"]))
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: 100_000
        )

        await writer.enqueue(makeEvent(0)) // policy-filtered by process name
        await writer.enqueue(makeEvent(1)) // persisted
        await writer.shutdown()

        let filter = try #require(await store.insertFilterCounters())
        let telemetry = await writer.telemetrySnapshot()
        #expect(filter.dropped == 1)
        #expect(filter.passed == 1)
        #expect(telemetry.persistedCount == 1)
        #expect(telemetry.droppedCount == 0,
                "intentional insert filtering is not a storage writer shed")
        #expect(telemetry.bufferDepth == 0)
        #expect(telemetry.inFlightDepth == 0)
    }

    @Test("hard cap drops the NEWEST events and counts them distinctly")
    func hardCapDropsAndCounts() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // High threshold so no drain runs until shutdown; cap at 10 so the
        // 11th..25th enqueue overflow and drop.
        let writer = BatchedEventWriter(store: store, flushThreshold: 100_000, hardCap: 10)
        for i in 0..<25 { await writer.enqueue(makeEvent(i)) }
        #expect(writer.droppedCount == 15, "25 enqueued, cap 10 → 15 dropped")
        await writer.shutdown()
        #expect(try await store.count() == 10, "only the first 10 (pre-overflow) persisted")
    }

    @Test("#24: at the cap, a high-value event evicts a file row rather than being shed")
    func highValueSurvivesFileFloodAtCap() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = BatchedEventWriter(store: store, flushThreshold: 100_000, hardCap: 10)
        // Fill the buffer to the cap with a file/write flood.
        for i in 0..<10 { await writer.enqueue(makeFileEvent(i)) }
        // A high-value process event at the cap → evict the oldest file, keep it.
        await writer.enqueue(makeEvent(999))          // pid 3999, category .process
        #expect(writer.droppedCount == 1, "one file row shed to make room for the process event")
        // Another FILE event at the cap → nothing cheaper to shed → drop incoming.
        await writer.enqueue(makeFileEvent(100))
        #expect(writer.droppedCount == 2)
        await writer.shutdown()
        #expect(try await store.count() == 10)
        let procRows = try await store.events(since: .distantPast, category: .process)
        #expect(procRows.contains { $0.process.pid == 3999 },
                "the process event must survive the file flood at the cap (not be the shed row)")
    }

    @Test("#13: a transient (SQLITE_BUSY) batch failure re-queues and retries, never drops")
    func transientBusyRetriesNotDrops() async throws {
        let fake = FakeInserter()
        let writer = BatchedEventWriter(store: fake, flushThreshold: 50, hardCap: 100_000)
        for i in 0..<200 { await writer.enqueue(makeEvent(i)) }
        // Auto-drains hit .busy and re-queue; give them a moment to run.
        try? await Task.sleep(nanoseconds: 150_000_000)
        #expect(writer.droppedCount == 0, "transient contention must NOT drop events")
        #expect(writer.retriedCount > 0, "the busy batch was re-queued for retry")
        #expect(await fake.count == 0, "nothing persisted while contention held")
        // Contention clears → the retried events flush on the next drain.
        await fake.setFailing(false)
        await writer.shutdown()
        #expect(await fake.count == 200, "all events persist once contention clears")
        #expect(writer.droppedCount == 0)
    }

    @Test("partial chunk failure retries only the uncommitted suffix")
    func partialFailureRetriesSuffixOnly() async throws {
        let fake = PartialInserter()
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000
        )
        let events = (0..<10).map(makeEvent)
        for event in events { await writer.enqueue(event) }

        // First shutdown attempt flushes, receives the partial BUSY, and leaves
        // exactly seven rows queued. Second attempt persists that suffix.
        await writer.shutdown()
        await writer.shutdown()

        let calls = await fake.calls
        #expect(calls.count == 2)
        #expect(calls[0] == events.map(\.id))
        #expect(calls[1] == Array(events.dropFirst(3)).map(\.id))
        #expect(await fake.insertedIDs == events.map(\.id),
                "committed prefix must not be rewritten and input order is preserved")
        #expect(writer.persistedCount == 10)
        #expect(writer.retriedCount == 7)
        #expect(writer.droppedCount == 0)
    }

    @Test("database replacement retries the complete candidate batch on the fresh store")
    func replacementRetriesCompleteBatch() async throws {
        let fake = ReplacedDatabaseInserter(replacementReady: true)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000
        )
        let events = (0..<10).map(makeEvent)
        for event in events { await writer.enqueue(event) }

        await writer.shutdown()
        await writer.shutdown()

        let expected = events.map(\.id)
        #expect(await fake.calls == [expected, expected],
                "the quarantined DB's old committed prefix is not durable")
        #expect(await fake.insertedIDs == expected)
        #expect(writer.persistedCount == events.count)
        #expect(writer.retriedCount == events.count)
        #expect(writer.droppedCount == 0)
    }

    @Test("failed replacement reopen drops the complete candidate batch without retry")
    func failedReplacementReopenDropsCompleteBatch() async throws {
        let fake = ReplacedDatabaseInserter(replacementReady: false)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000
        )
        let events = (0..<10).map(makeEvent)
        for event in events { await writer.enqueue(event) }

        await writer.shutdown()

        #expect(await fake.calls == [events.map(\.id)])
        #expect(await fake.insertedIDs.isEmpty)
        #expect(writer.persistedCount == 0)
        #expect(writer.retriedCount == 0)
        #expect(writer.droppedCount == events.count)
    }
}
