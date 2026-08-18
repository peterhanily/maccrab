// BatchedEventWriterTests.swift
// v1.21.4 (F2 / A1) — the async batched events.db writer that decouples the
// hot detection consumer from per-event SQLite transactions. These drive a
// REAL EventStore in a temp dir so batching + overflow behaviour travel the
// true insert path.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("F2/A1 BatchedEventWriter", .serialized)
struct BatchedEventWriterTests {

    private func isolatedMemoryBudget() -> EventPipelineLiveMemoryBudget {
        .isolatedProductionEquivalentForTesting()
    }

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

    private func makeFileEvent(
        _ i: Int,
        processName: String = "flood",
        eventAction: String = "file",
        fileAction: FileAction = .write
    ) -> Event {
        let proc = ProcessInfo(
            pid: Int32(9000 + i), ppid: 1, rpid: 1,
            name: processName, executable: "/bin/\(processName)",
            commandLine: "/bin/\(processName)", args: [], workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)), ancestors: [],
            isPlatformBinary: false)
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .file, eventType: .creation,
            eventAction: eventAction, process: proc,
            file: FileInfo(path: "/tmp/flood/\(i).tmp", action: fileAction)
        )
    }

    private func pragmaInt64(
        _ name: String,
        databasePath: String
    ) throws -> Int64 {
        var connection: OpaquePointer?
        guard sqlite3_open_v2(
            databasePath,
            &connection,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let connection else {
            throw EventStoreError.databaseOpenFailed("test PRAGMA connection")
        }
        defer { sqlite3_close(connection) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            connection,
            "PRAGMA \(name)",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            throw EventStoreError.prepareFailed("test PRAGMA \(name)")
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed("test PRAGMA \(name)")
        }
        return sqlite3_column_int64(statement, 0)
    }

    private func transactionEstimate(
        for events: [Event],
        pageSize: Int64
    ) throws -> Int64 {
        var rowMutationBytes: Int64 = 0
        for event in events {
            let encoded = try JSONEncoder().encode(event)
            guard let rawJSON = String(data: encoded, encoding: .utf8) else {
                throw EventStoreError.encodingFailed("test event JSON")
            }
            let rowBytes = EventStore.estimatedEventMutationBytes(
                event: event,
                indexedCommandLine: EventStore.boundIndexedText(
                    event.process.commandLine,
                    maxBytes: EventStore.maxIndexedCommandLineBytes
                ),
                rawJSON: rawJSON,
                pageSizeBytes: pageSize
            )
            rowMutationBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                rowMutationBytes,
                rowBytes
            )
        }
        return SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowMutationBytes,
            pageSizeBytes: pageSize,
            maximumTreePathPageTouches: 48
        )
    }

    /// Mirrors EventStore's current append-local block formation bound. Base
    /// commits reserve this mutation plus one complete future terminal/poison
    /// transaction, so footprint fixtures must include both rather than the
    /// obsolete wide-row estimate alone.
    private func journalBlockTransactionEstimate(
        for events: [Event],
        pageSize: Int64
    ) throws -> Int64 {
        guard !events.isEmpty,
              events.count <= EventJournalCodec.maximumEventsPerBlock else {
            throw EventStoreError.encodingFailed("invalid test journal block")
        }
        var payloadBytes: Int64 = 12
        for event in events {
            let canonical = try EventJournalAdmissionValidator.prepare(event)
                .canonicalJSON
            payloadBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                payloadBytes,
                Int64(4 + canonical.count)
            )
        }
        let rosterAndMetadata = SQLitePersistentStoreAdmission.saturatingAdd(
            Int64(events.count * (16 + 48)),
            4_096
        )
        let journalLogical = SQLitePersistentStoreAdmission.saturatingAdd(
            payloadBytes,
            rosterAndMetadata
        )
        let logical = SQLitePersistentStoreAdmission.saturatingAdd(
            journalLogical,
            1 * 1_024 * 1_024
        )
        let mutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: pageSize,
                maximumLeafPageTouches: 16
            )
        return SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: mutation,
            pageSizeBytes: pageSize,
            maximumTreePathPageTouches: 48
        )
    }

    /// A fake inserter that fails transiently (EventStoreError.busy) until told to
    /// succeed — used to exercise the #13 retry-not-drop path deterministically.
    private actor FakeInserter: EventBatchInserting {
        private var failing = true
        private(set) var inserted: [Event] = []
        func setFailing(_ f: Bool) { failing = f }
        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
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

        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
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
                        committedTransactionCount: prefix == 0 ? 0 : 1,
                        inputDispositions:
                            events.prefix(prefix).map {
                                .durable(eventID: $0.id)
                            } + events.dropFirst(prefix).map {
                                .uncommitted(eventID: $0.id)
                            }
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
                committedTransactionCount: events.isEmpty ? 0 : 1,
                inputDispositions: events.map {
                    .durable(eventID: $0.id)
                }
            )
        }
    }

    private enum InterleavedPartialMode: Sendable {
        case busy
        case replacement
    }

    /// Simulates [persisted A, uncommitted B, filtered F]. The retry is held so
    /// tests can prove the evidence-prefix ledger remains behind the true
    /// uncommitted identity rather than terminalizing B and retrying F.
    private actor InterleavedPartialInserter: EventBatchInserting {
        let mode: InterleavedPartialMode
        let retryGate: InsertGate
        private var failedOnce = false
        private(set) var insertedIDs: [UUID] = []
        private(set) var calls: [[UUID]] = []

        init(mode: InterleavedPartialMode, retryGate: InsertGate) {
            self.mode = mode
            self.retryGate = retryGate
        }

        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
            calls.append(events.map(\.id))
            if !failedOnce {
                failedOnce = true
                guard events.count == 3 else {
                    throw EventStoreError.stepFailed(
                        "interleaved partial fixture requires A, B, F"
                    )
                }
                switch mode {
                case .busy:
                    insertedIDs.append(events[0].id)
                    throw EventBatchInsertFailure(
                        progress: EventBatchInsertResult(
                            inputCount: 3,
                            persistedCount: 1,
                            filteredCount: 1,
                            committedTransactionCount: 1,
                            inputDispositions: [
                                .durable(eventID: events[0].id),
                                .uncommitted(eventID: events[1].id),
                                .filtered(eventID: events[2].id),
                            ]
                        ),
                        uncommittedEvents: [events[1]],
                        underlyingError: EventStoreError.busy(
                            "interleaved chunk busy"
                        )
                    )
                case .replacement:
                    throw EventBatchInsertFailure(
                        progress: EventBatchInsertResult(
                            inputCount: 3,
                            persistedCount: 0,
                            filteredCount: 1,
                            committedTransactionCount: 0,
                            inputDispositions: [
                                .uncommitted(eventID: events[0].id),
                                .uncommitted(eventID: events[1].id),
                                .filtered(eventID: events[2].id),
                            ]
                        ),
                        uncommittedEvents: [events[0], events[1]],
                        underlyingError: EventStoreError.stepFailed(
                            "active database quarantined"
                        ),
                        activeDatabaseWasReplaced: true,
                        replacementReadyForRetry: true
                    )
                }
            }
            retryGate.markEntered()
            retryGate.waitForRelease()
            insertedIDs.append(contentsOf: events.map(\.id))
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1,
                inputDispositions: events.map {
                    .durable(eventID: $0.id)
                }
            )
        }
    }

    /// Simulates a legal caller supplying two distinct Event values under one
    /// immutable persistence UUID. The later value is filtered, while the
    /// earlier value remains uncommitted. UUID-only reverse matching selects the
    /// wrong generation; complete Event multiset matching must retry the first.
    private actor DuplicateIdentityPartialInserter: EventBatchInserting {
        let retryGate: InsertGate
        private var failedOnce = false
        private(set) var calls: [[Event]] = []

        init(retryGate: InsertGate) {
            self.retryGate = retryGate
        }

        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
            calls.append(events)
            if !failedOnce {
                failedOnce = true
                guard events.count == 2,
                      events[0].id == events[1].id,
                      events[0] != events[1] else {
                    throw EventStoreError.stepFailed(
                        "duplicate-identity fixture requires distinct values"
                    )
                }
                throw EventBatchInsertFailure(
                    progress: EventBatchInsertResult(
                        inputCount: 2,
                        persistedCount: 0,
                        filteredCount: 1,
                        committedTransactionCount: 0,
                        inputDispositions: [
                            .uncommitted(eventID: events[0].id),
                            .filtered(eventID: events[1].id),
                        ]
                    ),
                    uncommittedEvents: [events[0]],
                    underlyingError: EventStoreError.busy(
                        "duplicate-identity partial busy"
                    )
                )
            }
            retryGate.markEntered()
            retryGate.waitForRelease()
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1,
                inputDispositions: events.map {
                    .durable(eventID: $0.id)
                }
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

        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
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

    private enum SaturatedRetryMode: Sendable {
        case busy
        case replacement
    }

    /// Holds the first priority write after the writer detaches it, then fails
    /// it only after the test has filled the live queue with file traffic. This
    /// reproduces the retry-admission race that ordinary immediate fakes miss.
    private actor SaturatedRetryInserter: EventBatchInserting {
        struct Call: Sendable {
            let lane: EventPipelineLane
            let ids: [UUID]
        }

        let mode: SaturatedRetryMode
        let gate: InsertGate
        private var failedOnce = false
        private(set) var calls: [Call] = []
        private(set) var insertedIDs: [UUID] = []

        init(mode: SaturatedRetryMode, gate: InsertGate) {
            self.mode = mode
            self.gate = gate
        }

        func insert(
            events: [Event],
            lane: EventPipelineLane
        ) throws -> EventBatchInsertResult {
            calls.append(Call(lane: lane, ids: events.map(\.id)))
            if !failedOnce {
                failedOnce = true
                gate.markEntered()
                gate.waitForRelease()
                switch mode {
                case .busy:
                    throw EventStoreError.busy("priority retry saturation")
                case .replacement:
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
                        replacementReadyForRetry: true
                    )
                }
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

    private final class CompletionFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var completed = false

        func markCompleted() {
            lock.lock()
            completed = true
            lock.unlock()
        }

        func isCompleted() -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return completed
        }
    }

    /// Blocks inside the store actor after the writer has detached its batch.
    /// The writer actor itself remains available at the `await`, which lets the
    /// test inspect the exact heartbeat state during the insert.
    private actor SuspendedInserter: EventBatchInserting {
        let gate: InsertGate

        init(gate: InsertGate) { self.gate = gate }

        func insert(
            events: [Event],
            lane _: EventPipelineLane
        ) throws -> EventBatchInsertResult {
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

    /// Captures the store-facing batch boundaries. The writer must never mix
    /// lanes in one call because EventStore returns aggregate counts only; a
    /// mixed batch would make per-lane persistence/filter telemetry guesswork.
    private actor RecordingInserter: EventBatchInserting {
        struct Call: Sendable {
            let events: [Event]
            let lane: EventPipelineLane
        }

        private(set) var calls: [Call] = []

        func insert(
            events: [Event],
            lane: EventPipelineLane
        ) throws -> EventBatchInsertResult {
            calls.append(Call(events: events, lane: lane))
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: events.count,
                filteredCount: 0,
                committedTransactionCount: events.isEmpty ? 0 : 1
            )
        }
    }

    private func expectConserved(
        _ snapshot: BatchedEventWriter.TelemetrySnapshot,
        lane: EventPipelineLane,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let key = lane.key
        let offered = snapshot.offeredByLane[key] ?? 0
        let terminalAndOutstanding = (snapshot.persistedByLane[key] ?? 0)
            + (snapshot.filteredByLane[key] ?? 0)
            + (snapshot.droppedByLane[key] ?? 0)
            + (snapshot.bufferDepthByLane[key] ?? 0)
            + (snapshot.inFlightDepthByLane[key] ?? 0)
        #expect(
            offered == terminalAndOutstanding,
            "\(key) lane must conserve exactly: offered \(offered), accounted \(terminalAndOutstanding)",
            sourceLocation: sourceLocation
        )
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
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )
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
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 50,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )
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
            hardCap: 100,
            liveMemoryBudget: isolatedMemoryBudget()
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

    @Test("shutdown joins a threshold-triggered in-flight database flush")
    func shutdownJoinsThresholdDrain() async throws {
        let gate = InsertGate()
        let completion = CompletionFlag()
        let writer = BatchedEventWriter(
            store: SuspendedInserter(gate: gate),
            flushThreshold: 2,
            hardCap: 100,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        await writer.enqueue(makeEvent(0), lane: .priority)
        await writer.enqueue(makeEvent(1), lane: .priority)

        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered())

        let shutdown = Task {
            await writer.shutdown()
            completion.markCompleted()
        }
        try? await Task.sleep(nanoseconds: 20_000_000)
        #expect(!completion.isCompleted(),
                "shutdown must wait for the detached threshold drain")

        gate.releaseInsert()
        await shutdown.value
        #expect(completion.isCompleted())
        let telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.persistedCount == 2)
        #expect(telemetry.bufferDepth == 0)
        #expect(telemetry.inFlightDepth == 0)
        expectConserved(telemetry, lane: .priority)
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
            of: "recordDrop(disposition.uncommitted.count, lane: lane)"
        ))
        let partialClear = try #require(source.range(
            of: "clearInFlight(lane: lane)",
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
            of: "recordDrop(batch.count, lane: lane)",
            range: transientCatch.lowerBound..<source.endIndex
        ))
        let transientClear = try #require(source.range(
            of: "clearInFlight(lane: lane)",
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
            of: "recordDrop(batch.count, lane: lane)",
            range: permanentComment.lowerBound..<source.endIndex
        ))
        let permanentClear = try #require(source.range(
            of: "clearInFlight(lane: lane)",
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
        await store.setInsertFilter(EventInsertFilter(
            processNames: ["bw0", "blocked-file"]
        ))
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )

        await writer.enqueue(makeEvent(0), lane: .priority) // filtered
        await writer.enqueue(makeEvent(1), lane: .priority) // persisted
        await writer.enqueue(
            makeFileEvent(0, processName: "blocked-file"), lane: .file
        ) // filtered
        await writer.enqueue(
            makeFileEvent(1, processName: "kept-file"), lane: .file
        ) // persisted
        await writer.shutdown()

        let filter = try #require(await store.insertFilterCounters())
        let telemetry = await writer.telemetrySnapshot()
        #expect(filter.dropped == 2)
        #expect(filter.passed == 2)
        #expect(telemetry.persistedCount == 2)
        #expect(telemetry.filteredCount == 2)
        #expect(telemetry.persistedByLane == ["priority": 1, "file": 1])
        #expect(telemetry.filteredByLane == ["priority": 1, "file": 1])
        #expect(telemetry.droppedCount == 0,
                "intentional insert filtering is not a storage writer shed")
        #expect(telemetry.bufferDepth == 0)
        #expect(telemetry.inFlightDepth == 0)
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)
    }

    @Test("priority drains first and every store batch is lane-homogeneous")
    func laneHomogeneousPriorityFirstDrain() async throws {
        let store = RecordingInserter()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )

        for i in 0..<4 {
            await writer.enqueue(makeFileEvent(i), lane: .file)
        }
        for i in 0..<2 {
            await writer.enqueue(makeEvent(i), lane: .priority)
        }
        await writer.shutdown()

        let calls = await store.calls
        #expect(calls.count == 2)
        #expect(calls[0].lane == .priority)
        #expect(calls[0].events.count == 2)
        #expect(calls[0].events.allSatisfy { $0.eventCategory == .process })
        #expect(calls[1].lane == .file)
        #expect(calls[1].events.count == 4)
        #expect(calls[1].events.allSatisfy { $0.eventCategory == .file })

        let telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.offeredByLane == ["priority": 2, "file": 4])
        #expect(telemetry.persistedByLane == ["priority": 2, "file": 4])
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)
    }

    @Test("EventStore rejects a mixed or mislabeled batch before writing")
    func eventStoreValidatesHomogeneousBatchLane() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let priority = makeEvent(0)
        let file = makeFileEvent(0)

        do {
            _ = try await store.insert(
                events: [priority, file],
                lane: .priority
            )
            Issue.record("mixed-lane batch unexpectedly reached SQLite")
        } catch let failure as EventBatchInsertFailure {
            #expect(failure.progress.inputCount == 2)
            #expect(failure.progress.persistedCount == 0)
            #expect(failure.progress.filteredCount == 0)
            #expect(failure.uncommittedEvents.map(\.id) == [priority.id, file.id])
            #expect(failure.underlyingError is EventStoreError)
        }
        #expect(try await store.count() == 0)
    }

    @Test("each file batch uses a fresh footprint before preserving priority headroom")
    func fileBatchGrowthIsFreshlyRefusedWithoutLatchingPriority() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bw-lane-cap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let transactionReserve = SQLitePersistentStorePolicy
            .eventTransactionReserveBytes
        let store = try EventStore(
            path: path,
            storagePolicy: SQLitePersistentStorePolicy(
                maxFootprintBytes: 128 * mib,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: transactionReserve,
                storageVolumePath: dir.path
            )
        )

        let pageSize = try pragmaInt64("page_size", databasePath: path)
        #expect(await store.walCheckpointTruncate())
        let footprint = try SQLitePersistentStoreAdmission.measureFamily(path)

        let firstFile = makeFileEvent(10)
        let secondFile = makeFileEvent(11)
        let firstEstimate = try journalBlockTransactionEstimate(
            for: [firstFile],
            pageSize: pageSize
        )
        #expect(try journalBlockTransactionEstimate(
            for: [secondFile],
            pageSize: pageSize
        ) == firstEstimate)
        #expect(firstEstimate <= transactionReserve)
        let priorityReserve = 16 * mib
        let cap = footprint + transactionReserve + priorityReserve
            + firstEstimate
        #expect(
            EventStore.priorityLaneReserveBytes(maxFootprintBytes: cap)
                == priorityReserve,
            "fixture relies on the priority reserve's 16 MiB floor"
        )
        let tight = SQLitePersistentStorePolicy(
            // The first file batch lands exactly at the lane boundary after
            // charging its complete transaction upper bound. Its real WAL
            // growth then moves the family into the priority-only band. A stale
            // last-footprint check would wrongly admit the second file batch.
            maxFootprintBytes: cap,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: transactionReserve,
            storageVolumePath: dir.path
        )
        let tightened = try await store.updateStorageAdmission(tight)
        #expect(tightened?.latchedFailure == nil)

        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100,
            hardCap: 100,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        await writer.enqueue(firstFile, lane: .file)
        await writer.shutdown()

        let afterFirst = await writer.telemetrySnapshot()
        #expect(afterFirst.droppedByLane == ["priority": 0, "file": 0])
        #expect(afterFirst.persistedByLane == ["priority": 0, "file": 1])
        #expect(try await store.count() == 1)
        let grownFootprint = try SQLitePersistentStoreAdmission.measureFamily(path)
        #expect(grownFootprint > footprint,
                "first batch must grow the family so the stale-probe bug is exercised")

        await writer.enqueue(secondFile, lane: .file)
        await writer.shutdown()

        let afterSecond = await writer.telemetrySnapshot()
        #expect(afterSecond.droppedByLane == ["priority": 0, "file": 1])
        #expect(afterSecond.persistedByLane == ["priority": 0, "file": 1])
        #expect(try await store.count() == 1)
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil,
                "the fresh file-only refusal must not poison shared admission")

        let priority = makeEvent(12)
        await writer.enqueue(priority, lane: .priority)
        await writer.shutdown()

        let final = await writer.telemetrySnapshot()
        #expect(final.droppedByLane == ["priority": 0, "file": 1])
        #expect(final.persistedByLane == ["priority": 1, "file": 1])
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil)
        let stored = try await store.exactEventsSnapshot(
            since: .distantPast
        )
        #expect(Set(stored.events.map(\.id)) == [firstFile.id, priority.id])
        expectConserved(final, lane: .priority)
        expectConserved(final, lane: .file)
    }

    @Test("one-call file chunks reserve their complete upper bound before BEGIN")
    func multirowFileChunkCannotConsumePriorityHeadroom() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bw-file-chunk-cap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("events.db").path
        let mib = SQLitePersistentStorePolicy.bytesPerMiB
        let transactionReserve = SQLitePersistentStorePolicy
            .eventTransactionReserveBytes
        let store = try EventStore(
            path: path,
            storagePolicy: SQLitePersistentStorePolicy(
                maxFootprintBytes: 128 * mib,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: transactionReserve,
                storageVolumePath: dir.path
            )
        )
        let pageSize = try pragmaInt64("page_size", databasePath: path)
        #expect(await store.walCheckpointTruncate())
        let footprint = try SQLitePersistentStoreAdmission.measureFamily(path)

        // This is one reserve-bounded transaction, not a collection of
        // single-row calls. The former bug admitted only the first row's
        // estimate, then appended the rest without another lane check.
        let fileBatch = (0..<256).map { makeFileEvent(1_000 + $0) }
        let firstEstimate = try journalBlockTransactionEstimate(
            for: [fileBatch[0]],
            pageSize: pageSize
        )
        let firstBlock = Array(
            fileBatch.prefix(EventJournalCodec.maximumEventsPerBlock)
        )
        let chunkEstimate = try journalBlockTransactionEstimate(
            for: firstBlock,
            pageSize: pageSize
        )
        #expect(chunkEstimate > firstEstimate)
        #expect(chunkEstimate <= transactionReserve,
                "fixture must fit in one EventStore transaction")

        let priorityReserve = EventStore.priorityLaneReserveBytes(
            maxFootprintBytes: footprint + transactionReserve
                + 16 * mib + firstEstimate
        )
        let cap = footprint + transactionReserve + priorityReserve
            + firstEstimate
        let effectivePriorityReserve = EventStore.priorityLaneReserveBytes(
            maxFootprintBytes: cap
        )
        #expect(effectivePriorityReserve == priorityReserve)
        #expect(
            firstEstimate + effectivePriorityReserve
                == cap - footprint - transactionReserve,
            "the obsolete first-row-only gate would admit this fixture"
        )
        #expect(
            chunkEstimate + effectivePriorityReserve
                > cap - footprint - transactionReserve,
            "the complete journal block must cross the same lane boundary"
        )
        let tightened = try await store.updateStorageAdmission(
            SQLitePersistentStorePolicy(
                maxFootprintBytes: cap,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: transactionReserve,
                storageVolumePath: dir.path
            )
        )
        #expect(tightened?.latchedFailure == nil)

        do {
            _ = try await store.insert(events: fileBatch, lane: .file)
            Issue.record("multi-row file chunk consumed priority headroom")
        } catch let failure as EventBatchInsertFailure {
            #expect(failure.progress.persistedCount == 0)
            #expect(failure.progress.committedTransactionCount == 0)
            #expect(failure.uncommittedEvents.map(\.id) == fileBatch.map(\.id))
            if let admission = failure.underlyingError
                as? SQLitePersistentStoreAdmissionError {
                if case .footprintLimit = admission {
                    // Expected non-latching file-lane refusal.
                } else {
                    Issue.record("unexpected admission failure: \(admission)")
                }
            } else {
                Issue.record("file chunk did not fail through typed admission")
            }
        }
        #expect(try await store.count() == 0)
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil,
                "file-only chunk refusal must remain non-latching")

        let priority = makeEvent(2_000)
        try await store.insert(event: priority)
        #expect(try await store.count() == 1)
        let stored = try await store.exactEventsSnapshot(since: .distantPast)
        #expect(stored.events.map(\.id) == [priority.id])
        #expect((await store.storageAdmissionSnapshot())?.latchedFailure == nil)
    }

    @Test("file OPEN and BTM events retain priority classification through the real writer")
    func specialFileActionsPersistOnPriorityLane() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100,
            hardCap: 100,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let credentialOpen = makeFileEvent(
            20,
            eventAction: "open",
            fileAction: .open
        )
        let btmAdd = makeFileEvent(
            21,
            eventAction: "btm_add",
            fileAction: .create
        )
        #expect(EventPipelineLane.finalLane(for: credentialOpen) == .priority)
        #expect(EventPipelineLane.finalLane(for: btmAdd) == .priority)

        await writer.enqueue(credentialOpen)
        await writer.enqueue(btmAdd)
        await writer.shutdown()

        let telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.offeredByLane == ["priority": 2, "file": 0])
        #expect(telemetry.persistedByLane == ["priority": 2, "file": 0])
        #expect(telemetry.droppedCount == 0)
        let stored = try await store.exactEventsSnapshot(
            since: .distantPast,
            category: .file
        )
        #expect(Set(stored.events.map(\.id)) == [credentialOpen.id, btmAdd.id])
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)
    }

    @Test("saturated lossless ingress drains within the cap and conserves both lanes")
    func saturatedFileLaneHasConstantTimeEvictionGuard() async throws {
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
        let boundaryStart = try #require(source.range(
            of: "/// Lossless production preparation boundary"
        ))
        let boundaryEnd = try #require(source.range(
            of: "func enqueuePrepared(",
            range: boundaryStart.upperBound..<source.endIndex
        ))
        let boundarySource = source[
            boundaryStart.lowerBound..<boundaryEnd.lowerBound
        ]
        #expect(boundarySource.contains(
            "await liveMemoryBudget.acquire("
        ))
        #expect(boundarySource.contains(
            "EventJournalAdmissionValidator.prepare("
        ))
        #expect(boundarySource.contains("await enqueuePreparedLosslessly("))

        let losslessStart = try #require(source.range(
            of: "private func enqueuePreparedLosslessly("
        ))
        let losslessEnd = try #require(source.range(
            of: "private func admitPreparedHandle(",
            range: losslessStart.upperBound..<source.endIndex
        ))
        let losslessSource = source[
            losslessStart.lowerBound..<losslessEnd.lowerBound
        ]
        #expect(losslessSource.contains("while !Task.isCancelled"))
        #expect(losslessSource.contains("ownershipBudget.adopt("))
        #expect(losslessSource.contains("hasPendingStorageWork { startDrain() }"))
        #expect(!losslessSource.contains(
            "evictNewestQueuedFileForPriorityAdmission()"
        ))

        // A bounded saturation exercise complements the source guard. Once the
        // local handle cap is full, the async production boundary drains before
        // adopting the priority handle; it neither exceeds the cap nor silently
        // discards already-admitted file evidence.
        let hardCap = 128
        let store = RecordingInserter()
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: hardCap,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        for i in 0..<hardCap {
            await writer.enqueue(makeFileEvent(i), lane: .file)
        }
        let atCap = await writer.telemetrySnapshot()
        #expect(atCap.bufferDepth == hardCap)
        #expect(atCap.preparedOwnershipCount <= hardCap)
        #expect(atCap.droppedCount == 0)

        await writer.enqueue(makeEvent(10_000), lane: .priority)
        let progressed = await writer.telemetrySnapshot()
        #expect(progressed.bufferDepth <= hardCap)
        #expect(progressed.preparedOwnershipCount <= hardCap)
        #expect(progressed.droppedCount == 0)
        #expect(progressed.offeredByLane == [
            "priority": 1,
            "file": hardCap,
        ])
        expectConserved(progressed, lane: .priority)
        expectConserved(progressed, lane: .file)
        await writer.shutdown()
        let drained = await writer.telemetrySnapshot()
        #expect(drained.bufferDepth == 0)
        #expect(drained.persistedByLane == [
            "priority": 1,
            "file": hardCap,
        ])
        #expect(drained.droppedCount == 0)
        expectConserved(drained, lane: .priority)
        expectConserved(drained, lane: .file)
    }

    @Test("hard cap drains and backpressures without dropping admitted events")
    func hardCapDropsAndCounts() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // The threshold is deliberately unreachable through ordinary batching.
        // Once ten handles are retained, lossless admission must force a drain
        // and wait rather than exceed the count cap or shed the next event.
        let hardCap = 10
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: hardCap,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        for i in 0..<25 {
            #expect(await writer.enqueue(makeEvent(i)) != nil)
            let bounded = await writer.telemetrySnapshot()
            #expect(bounded.preparedOwnershipCount <= hardCap)
            #expect(bounded.droppedCount == 0)
        }
        await writer.shutdown()
        let drained = await writer.telemetrySnapshot()
        #expect(try await store.count() == 25)
        #expect(drained.offeredByLane == ["priority": 25, "file": 0])
        #expect(drained.persistedByLane == ["priority": 25, "file": 0])
        #expect(drained.droppedCount == 0)
        #expect(drained.preparedOwnershipCount == 0)
        expectConserved(drained, lane: .priority)
    }

    @Test("priority and file evidence both survive a full file queue")
    func highValueSurvivesFileFloodAtCap() async throws {
        let (store, dir) = try tempStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let hardCap = 10
        let writer = BatchedEventWriter(
            store: store,
            flushThreshold: 100_000,
            hardCap: hardCap,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        // Fill the buffer to the cap with a file/write flood.
        for i in 0..<hardCap {
            #expect(await writer.enqueue(makeFileEvent(i)) != nil)
        }
        let atCap = await writer.telemetrySnapshot()
        #expect(atCap.preparedOwnershipCount == hardCap)
        #expect(atCap.droppedCount == 0)

        // Both lanes take the same lossless boundary. The priority event
        // forces progress, then the later file event is also admitted.
        #expect(await writer.enqueue(makeEvent(999)) != nil)
        #expect(await writer.enqueue(makeFileEvent(100)) != nil)
        let progressed = await writer.telemetrySnapshot()
        #expect(progressed.preparedOwnershipCount <= hardCap)
        #expect(progressed.droppedCount == 0)
        await writer.shutdown()
        #expect(try await store.count() == hardCap + 2)
        let procRows = try await store.exactEventsSnapshot(
            since: .distantPast,
            category: .process
        )
        #expect(procRows.events.contains { $0.process.pid == 3999 },
                "the process event must survive lossless cap backpressure")
        let drained = await writer.telemetrySnapshot()
        #expect(drained.persistedByLane == [
            "priority": 1,
            "file": hardCap + 1,
        ])
        #expect(drained.droppedCount == 0)
        expectConserved(drained, lane: .priority)
        expectConserved(drained, lane: .file)
    }

    @Test("#13: a transient (SQLITE_BUSY) batch failure re-queues and retries, never drops")
    func transientBusyRetriesNotDrops() async throws {
        let fake = FakeInserter()
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 50,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )
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

    @Test("a BUSY priority retry backpressures concurrent file work without loss")
    func saturatedBusyPriorityRetryPreservesPriority() async throws {
        try await saturatedPriorityRetryPreservesPriority(mode: .busy)
    }

    @Test("a replacement priority retry backpressures concurrent file work without loss")
    func saturatedReplacementPriorityRetryPreservesPriority() async throws {
        try await saturatedPriorityRetryPreservesPriority(mode: .replacement)
    }

    private func saturatedPriorityRetryPreservesPriority(
        mode: SaturatedRetryMode
    ) async throws {
        let gate = InsertGate()
        let fake = SaturatedRetryInserter(mode: mode, gate: gate)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 2,
            hardCap: 5,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let priority = [makeEvent(4_000), makeEvent(4_001)]
        for event in priority {
            _ = try #require(await writer.enqueue(event, lane: .priority))
        }
        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered(), "priority batch must be suspended in SQLite")

        let files = (0..<5).map { makeFileEvent(4_100 + $0) }
        let fileAdmissions = Task {
            var admitted = 0
            for event in files {
                if await writer.enqueue(event, lane: .file) != nil {
                    admitted += 1
                }
            }
            return admitted
        }
        var telemetry = await writer.telemetrySnapshot()
        for _ in 0..<100 {
            telemetry = await writer.telemetrySnapshot()
            if telemetry.bufferDepthByLane["file"] == 3 { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(telemetry.inFlightDepthByLane == ["priority": 2, "file": 0])
        #expect(telemetry.bufferDepthByLane == ["priority": 0, "file": 3])
        #expect(telemetry.preparedOwnershipCount <= 5)
        #expect(telemetry.droppedCount == 0)
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)

        gate.releaseInsert()
        #expect(await fileAdmissions.value == files.count)
        await writer.shutdown()

        let calls = await fake.calls
        #expect(calls.count >= 3)
        #expect(calls.first?.lane == .priority)
        #expect(calls.first?.ids == priority.map(\.id))
        #expect(calls.dropFirst().first?.lane == .priority)
        #expect(calls.dropFirst().first?.ids == priority.map(\.id),
                "the exact detached priority identities must retry first")
        let insertedIDs = await fake.insertedIDs
        #expect(Array(insertedIDs.prefix(priority.count)) == priority.map(\.id))
        #expect(Set(insertedIDs) == Set((priority + files).map(\.id)))

        telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.offeredByLane == ["priority": 2, "file": 5])
        #expect(telemetry.persistedByLane == ["priority": 2, "file": 5])
        #expect(telemetry.retriedByLane == ["priority": 2, "file": 0])
        #expect(telemetry.droppedByLane == ["priority": 0, "file": 0])
        #expect(telemetry.bufferDepth == 0)
        #expect(telemetry.inFlightDepth == 0)
        #expect(telemetry.terminalGeneration == telemetry.admittedGeneration)
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)
    }

    @Test("an older priority retry backpressures newer work and remains first")
    func mixedSaturatedPriorityRetryPreservesChronology() async throws {
        let gate = InsertGate()
        let fake = SaturatedRetryInserter(mode: .busy, gate: gate)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 2,
            hardCap: 5,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let older = [makeEvent(4_200), makeEvent(4_201)]
        for event in older {
            _ = try #require(await writer.enqueue(event, lane: .priority))
        }
        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered())

        let newerPriority = (0..<4).map { makeEvent(4_300 + $0) }
        let newerFile = makeFileEvent(4_400)
        let newerAdmissions = Task {
            var admitted = 0
            for event in newerPriority {
                if await writer.enqueue(event, lane: .priority) != nil {
                    admitted += 1
                }
            }
            if await writer.enqueue(newerFile, lane: .file) != nil {
                admitted += 1
            }
            return admitted
        }
        var saturated = await writer.telemetrySnapshot()
        for _ in 0..<100 {
            saturated = await writer.telemetrySnapshot()
            if saturated.bufferDepthByLane["priority"] == 3 { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(saturated.inFlightDepthByLane == ["priority": 2, "file": 0])
        #expect(saturated.bufferDepthByLane == ["priority": 3, "file": 0])
        #expect(saturated.preparedOwnershipCount <= 5)
        #expect(saturated.droppedCount == 0)

        gate.releaseInsert()
        #expect(await newerAdmissions.value == newerPriority.count + 1)
        await writer.shutdown()

        let calls = await fake.calls
        #expect(calls.first?.ids == older.map(\.id))
        let insertedIDs = await fake.insertedIDs
        #expect(Array(insertedIDs.prefix(older.count)) == older.map(\.id),
                "the older retry must precede newer priority rows")
        #expect(Set(insertedIDs) == Set(
            (older + newerPriority + [newerFile]).map(\.id)
        ))

        let telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.offeredByLane == ["priority": 6, "file": 1])
        #expect(telemetry.persistedByLane == ["priority": 6, "file": 1])
        #expect(telemetry.droppedByLane == ["priority": 0, "file": 0])
        #expect(telemetry.retriedByLane == ["priority": 2, "file": 0])
        #expect(telemetry.terminalGeneration == telemetry.admittedGeneration)
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)
    }

    @Test("an older file retry backpressures later work without losing either lane")
    func saturatedFileRetryPreservesLaneDominanceAndChronology() async throws {
        let gate = InsertGate()
        let fake = SaturatedRetryInserter(mode: .busy, gate: gate)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 2,
            hardCap: 5,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let olderFile = [makeFileEvent(4_500), makeFileEvent(4_501)]
        for event in olderFile {
            _ = try #require(await writer.enqueue(event, lane: .file))
        }
        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered())

        let priority = [makeEvent(4_600), makeEvent(4_601)]
        let newerFile = (0..<3).map { makeFileEvent(4_700 + $0) }
        let newerAdmissions = Task {
            var admitted = 0
            for event in priority {
                if await writer.enqueue(event, lane: .priority) != nil {
                    admitted += 1
                }
            }
            for event in newerFile {
                if await writer.enqueue(event, lane: .file) != nil {
                    admitted += 1
                }
            }
            return admitted
        }
        var saturated = await writer.telemetrySnapshot()
        for _ in 0..<100 {
            saturated = await writer.telemetrySnapshot()
            if saturated.bufferDepthByLane["priority"] == 2,
               saturated.bufferDepthByLane["file"] == 1 { break }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(saturated.inFlightDepthByLane == ["priority": 0, "file": 2])
        #expect(saturated.bufferDepthByLane == ["priority": 2, "file": 1])
        #expect(saturated.preparedOwnershipCount <= 5)
        #expect(saturated.droppedCount == 0)

        gate.releaseInsert()
        #expect(await newerAdmissions.value == priority.count + newerFile.count)
        await writer.shutdown()

        let calls = await fake.calls
        #expect(calls.first?.lane == .file)
        #expect(calls.first?.ids == olderFile.map(\.id))
        let insertedIDs = await fake.insertedIDs
        #expect(Array(insertedIDs.prefix(priority.count)) == priority.map(\.id),
                "priority remains the first successful lane after the retry")
        #expect(Set(insertedIDs) == Set(
            (olderFile + priority + newerFile).map(\.id)
        ))

        let telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.offeredByLane == ["priority": 2, "file": 5])
        #expect(telemetry.persistedByLane == ["priority": 2, "file": 5])
        #expect(telemetry.droppedByLane == ["priority": 0, "file": 0])
        #expect(telemetry.retriedByLane == ["priority": 0, "file": 2])
        #expect(telemetry.terminalGeneration == telemetry.admittedGeneration)
        expectConserved(telemetry, lane: .priority)
        expectConserved(telemetry, lane: .file)
    }

    @Test("partial chunk failure retries only the uncommitted suffix")
    func partialFailureRetriesSuffixOnly() async throws {
        let fake = PartialInserter()
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
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

    @Test("interleaved filtered rows cannot replace the exact partial BUSY retry")
    func interleavedFilterPartialBusyRetriesBAndHoldsEvidencePrefix() async throws {
        let gate = InsertGate()
        let fake = InterleavedPartialInserter(mode: .busy, retryGate: gate)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let a = makeEvent(3_000)
        let b = makeEvent(3_001)
        let filtered = makeEvent(3_002)
        let generationA = try #require(await writer.enqueue(a))
        let generationB = try #require(await writer.enqueue(b))
        let generationFiltered = try #require(await writer.enqueue(filtered))

        // First pass reports [persisted A, uncommitted B, filtered F]. Only B
        // may re-enter the queue; F is terminal despite being the array suffix.
        await writer.shutdown()
        #expect(await fake.calls == [[a.id, b.id, filtered.id]])
        var telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.bufferDepth == 1)
        #expect(telemetry.persistedCount == 1)
        #expect(telemetry.filteredCount == 1)
        #expect(telemetry.retriedCount == 1)
        #expect(telemetry.terminalGeneration == generationA)

        let prefixWait = Task {
            await writer.awaitEvidencePrefix(
                through: generationB,
                timeout: .seconds(2)
            )
        }
        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered())
        #expect(await writer.awaitEvidencePrefix(
            through: generationB,
            timeout: .milliseconds(30)
        ) == false, "evidence prefix must remain behind uncommitted B")
        telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.terminalGeneration == generationA)
        #expect(telemetry.inFlightDepth == 1)

        gate.releaseInsert()
        #expect(await prefixWait.value)
        await writer.shutdown()

        #expect(await fake.calls == [
            [a.id, b.id, filtered.id],
            [b.id],
        ])
        #expect(await fake.insertedIDs == [a.id, b.id])
        telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.persistedCount == 2)
        #expect(telemetry.filteredCount == 1)
        #expect(telemetry.droppedCount == 0)
        #expect(telemetry.terminalGeneration == generationFiltered)
        expectConserved(telemetry, lane: .priority)
    }

    @Test("partial retry distinguishes distinct Event values sharing one UUID")
    func partialRetryMatchesFullEventMultisetForDuplicateUUID() async throws {
        let gate = InsertGate()
        let fake = DuplicateIdentityPartialInserter(retryGate: gate)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let sharedID = UUID()
        let firstBase = makeEvent(3_050)
        let filteredBase = makeEvent(3_051)
        let first = Event(
            id: sharedID,
            timestamp: firstBase.timestamp,
            eventCategory: firstBase.eventCategory,
            eventType: firstBase.eventType,
            eventAction: "first-uncommitted",
            process: firstBase.process
        )
        let filtered = Event(
            id: sharedID,
            timestamp: filteredBase.timestamp,
            eventCategory: filteredBase.eventCategory,
            eventType: filteredBase.eventType,
            eventAction: "later-filtered",
            process: filteredBase.process
        )
        let firstGeneration = try #require(await writer.enqueue(first))
        let filteredGeneration = try #require(await writer.enqueue(filtered))

        await writer.shutdown()
        #expect(await fake.calls == [[first, filtered]])
        var telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.bufferDepth == 1)
        #expect(telemetry.persistedCount == 0)
        #expect(telemetry.filteredCount == 1)
        #expect(telemetry.retriedCount == 1)
        #expect(telemetry.terminalGeneration == 0,
                "the earlier uncommitted value must hold the evidence prefix")

        let retry = Task { await writer.shutdown() }
        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered())
        #expect(await writer.awaitEvidencePrefix(
            through: firstGeneration,
            timeout: .milliseconds(30)
        ) == false)

        gate.releaseInsert()
        await retry.value
        #expect(await fake.calls == [[first, filtered], [first]],
                "the exact earlier Event value must retry despite the shared UUID")
        telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.persistedCount == 1)
        #expect(telemetry.filteredCount == 1)
        #expect(telemetry.droppedCount == 0)
        #expect(telemetry.terminalGeneration == filteredGeneration)
        expectConserved(telemetry, lane: .priority)
    }

    @Test("replacement retries exact candidates while interleaved filters stay terminal")
    func interleavedFilterReplacementRetriesCandidatesAndHoldsPrefix() async throws {
        let gate = InsertGate()
        let fake = InterleavedPartialInserter(
            mode: .replacement,
            retryGate: gate
        )
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
        )
        let a = makeEvent(3_100)
        let b = makeEvent(3_101)
        let filtered = makeEvent(3_102)
        _ = try #require(await writer.enqueue(a))
        let generationB = try #require(await writer.enqueue(b))
        let generationFiltered = try #require(await writer.enqueue(filtered))

        // Replacement invalidates A's earlier commit, so A and B retry while
        // only the arbitrarily-positioned filtered event is terminal.
        await writer.shutdown()
        #expect(await fake.calls == [[a.id, b.id, filtered.id]])
        var telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.bufferDepth == 2)
        #expect(telemetry.persistedCount == 0)
        #expect(telemetry.filteredCount == 1)
        #expect(telemetry.retriedCount == 2)
        #expect(telemetry.terminalGeneration == 0)

        let prefixWait = Task {
            await writer.awaitEvidencePrefix(
                through: generationB,
                timeout: .seconds(2)
            )
        }
        for _ in 0..<100 where !gate.hasEntered() {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        #expect(gate.hasEntered())
        #expect(await writer.awaitEvidencePrefix(
            through: generationB,
            timeout: .milliseconds(30)
        ) == false, "replacement candidates must hold the evidence prefix")

        gate.releaseInsert()
        #expect(await prefixWait.value)
        await writer.shutdown()

        #expect(await fake.calls == [
            [a.id, b.id, filtered.id],
            [a.id, b.id],
        ])
        #expect(await fake.insertedIDs == [a.id, b.id])
        telemetry = await writer.telemetrySnapshot()
        #expect(telemetry.persistedCount == 2)
        #expect(telemetry.filteredCount == 1)
        #expect(telemetry.droppedCount == 0)
        #expect(telemetry.terminalGeneration == generationFiltered)
        expectConserved(telemetry, lane: .priority)
    }

    @Test("database replacement retries the complete candidate batch on the fresh store")
    func replacementRetriesCompleteBatch() async throws {
        let fake = ReplacedDatabaseInserter(replacementReady: true)
        let writer = BatchedEventWriter(
            store: fake,
            flushThreshold: 100_000,
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
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
            hardCap: 100_000,
            liveMemoryBudget: isolatedMemoryBudget()
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

// MARK: - rc.32 regressions: unbounded waits on in-process credit exhaustion
//
// rc.31 shipped with `EventStoreError.busy` covering BOTH SQLITE_BUSY/LOCKED and
// in-process pipeline credit exhaustion. Every retry path keyed off that single
// case, so waits that could only be satisfied by ANOTHER owner releasing credit
// were retried as if they were clearing lock contention. On an installed host the
// priority lane drained at ~11% of its offered rate and evicted ~98,000 events
// while the storage budget still reported `converged`.
@Suite("rc.32 bounded credit-pressure waits", .serialized)
struct BoundedCreditPressureRegressionTests {

    @Test("In-process credit exhaustion is not typed as SQLite lock contention")
    func memoryLeaseIsNotLockTimeout() {
        let lease = EventStoreError.memoryLeaseUnavailable(
            "terminal delta for journal block 7 is waiting for bounded terminal encoding ownership"
        )
        let kind = StorageErrorTracker.classifyEventInsertError(lease)

        #expect(kind == "memory_lease_unavailable")
        // The whole point of the split: this must NOT read as SQLite contention,
        // or triage goes to the WAL for a condition SQLite is not involved in.
        #expect(kind != "lock_timeout")
    }

    @Test("Real SQLITE_BUSY still classifies as lock contention")
    func sqliteBusyStillLockTimeout() {
        #expect(
            StorageErrorTracker.classifyEventInsertError(
                EventStoreError.busy("database is locked")
            ) == "lock_timeout"
        )
    }

    @Test("A blocked-journal message is not mistaken for a lock")
    func blockedIsNotLock() {
        // `lower.contains("lock")` matched "block", so any journal message about
        // a blocked condition was filed as lock_timeout and
        // last_event_insert_error_kind stopped being usable for triage.
        let kind = StorageErrorTracker.classifyEventInsertError(
            EventStoreError.stepFailed(
                "event journal block 42 is blocked behind a pending writer"
            )
        )
        #expect(kind != "lock_timeout")
    }

    @Test("Terminal settlement carries a finite deadline")
    func terminalSettlementDeadlineIsFinite() {
        // A deadline that is absent or non-positive reintroduces the stall: the
        // per-event lane consumer awaits terminal settlement inline, so an
        // unbounded wait stops the entire lane rather than shedding one event.
        #expect(BatchedEventWriter.terminalSettlementDeadline > .zero)
        #expect(BatchedEventWriter.terminalSettlementDeadline <= .seconds(10))
    }
}
