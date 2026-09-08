import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Journal expiry checkpoints preserve bounded progress")
struct JournalExpiryCheckpointCoalescingTests {
    private enum FixtureError: Error { case sqlite(Int32) }

    private struct Fixture: Sendable {
        let store: EventStore
        let directory: URL
        let path: String
        let policy: SQLitePersistentStorePolicy
        let cutoff: Date
    }

    /// Hooks observe real commits/checkpoint attempts. Admission probes can
    /// then impose pressure at a durable boundary without timing races or a
    /// fabricated database; every expiry transaction still uses real SQLite.
    private final class Boundaries: @unchecked Sendable {
        enum Pressure: Sendable, Equatable {
            case none, nominalCap, firstBlockRecovery, hardCap
            case projectedCheckpointSpace, persistentHardCap, checkpointProbeFailure
        }
        private let lock = NSLock()
        let pressure: Pressure
        let policy: SQLitePersistentStorePolicy
        private var commits = 0
        private var checkpoints: [Int] = []
        private var footprintProbesAfterCheckpoint = 0

        init(_ pressure: Pressure = .none, policy: SQLitePersistentStorePolicy) {
            self.pressure = pressure
            self.policy = policy
        }

        func committed() {
            lock.lock()
            defer { lock.unlock() }
            commits += 1
        }

        func checkpoint() {
            lock.lock()
            defer { lock.unlock() }
            checkpoints.append(commits)
            footprintProbesAfterCheckpoint = 0
        }

        var observed: (commits: Int, checkpoints: [Int]) {
            lock.lock()
            defer { lock.unlock() }
            return (commits, checkpoints)
        }

        func footprint(_ path: String) throws -> Int64 {
            let actual = try SQLitePersistentStoreAdmission.measureFamily(path)
            lock.lock()
            defer { lock.unlock() }
            footprintProbesAfterCheckpoint += 1
            if pressure == .firstBlockRecovery, checkpoints.count == 1 {
                return policy.maxFootprintBytes - 1
            }
            guard commits == 1 else { return actual }
            if checkpoints.count == 1 {
                switch pressure {
                case .nominalCap: return policy.maxFootprintBytes - 1
                case .hardCap, .persistentHardCap, .checkpointProbeFailure:
                    return policy.maxFootprintBytes + policy.transactionReserveBytes + 1
                default: break
                }
            }
            // Checkpoint admission gets one honest measurement; the refreshed
            // candidate is refused again. It must not trigger a second retry.
            if pressure == .persistentHardCap, checkpoints.count == 2,
               footprintProbesAfterCheckpoint > 1 {
                return policy.maxFootprintBytes + policy.transactionReserveBytes + 1
            }
            return actual
        }

        func freeSpace(_ path: String) throws -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            if pressure == .checkpointProbeFailure, commits == 1,
               checkpoints.count == 2 {
                throw SQLitePersistentStoreAdmissionError.freeSpaceProbeFailed(
                    path: path, systemErrno: EIO
                )
            }
            if pressure == .projectedCheckpointSpace, commits == 1,
               checkpoints.count == 1 {
                // Enough for this small maintenance transaction, whose floor
                // is zero, but not for the later checkpoint's floor + sidecar.
                return policy.freeSpaceFloorBytes
            }
            return 1 << 40
        }
    }

    private final class Reader: @unchecked Sendable {
        private let lock = NSLock()
        private var handle: OpaquePointer?
        private var statement: OpaquePointer?

        func pin(_ path: String) {
            lock.lock()
            defer { lock.unlock() }
            guard handle == nil else { return }
            var opened: OpaquePointer?
            let rc = sqlite3_open_v2(path, &opened,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
            guard rc == SQLITE_OK, let opened else {
                if let opened { sqlite3_close(opened) }
                return
            }
            var prepared: OpaquePointer?
            guard sqlite3_exec(opened, "BEGIN", nil, nil, nil) == SQLITE_OK,
                  sqlite3_prepare_v2(opened,
                    "SELECT COUNT(*) FROM event_journal_blocks", -1,
                    &prepared, nil) == SQLITE_OK,
                  let prepared, sqlite3_step(prepared) == SQLITE_ROW else {
                sqlite3_finalize(prepared)
                sqlite3_exec(opened, "ROLLBACK", nil, nil, nil)
                sqlite3_close(opened)
                return
            }
            handle = opened
            statement = prepared
        }

        var isPinned: Bool {
            lock.lock()
            defer { lock.unlock() }
            return handle != nil && statement != nil
        }

        func close() {
            lock.lock()
            defer { lock.unlock() }
            if let statement { sqlite3_finalize(statement) }
            if let handle {
                sqlite3_exec(handle, "ROLLBACK", nil, nil, nil)
                sqlite3_close(handle)
            }
            statement = nil
            handle = nil
        }

        deinit { close() }
    }

    private func scalar(_ sql: String, path: String) throws -> Int64 {
        var opened: OpaquePointer?
        let rc = sqlite3_open_v2(path, &opened,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(rc)
        }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        let prepared = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard prepared == SQLITE_OK, let statement else {
            throw FixtureError.sqlite(prepared)
        }
        defer { sqlite3_finalize(statement) }
        let step = sqlite3_step(statement)
        guard step == SQLITE_ROW else { throw FixtureError.sqlite(step) }
        return sqlite3_column_int64(statement, 0)
    }

    private func executeFixtureSQL(_ sql: String, path: String) throws {
        var opened: OpaquePointer?
        let rc = sqlite3_open_v2(path, &opened,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(rc)
        }
        defer { sqlite3_close(db) }
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw FixtureError.sqlite(result) }
    }

    private func fixture(blocks: Int, overlays: Bool = false) async throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("expiry-checkpoint-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory,
            withIntermediateDirectories: false)
        let path = directory.appendingPathComponent("events.db").path
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 256 * 1_048_576,
            freeSpaceFloorBytes: 32 * 1_048_576,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: directory.path
        )
        let store = try EventStore(path: path, storagePolicy: policy,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        _ = try await store.recoverJournalBeforeProducers()
        let now = Date()
        for block in 0..<blocks {
            let events = (0..<2).map { ordinal in
                let i = block * 2 + ordinal
                let process = MacCrabCore.ProcessInfo(
                    pid: Int32(20_000 + i), ppid: 1, rpid: 1,
                    name: "expiry-fixture", executable: "/usr/bin/expiry-fixture",
                    commandLine: "expiry-fixture ordinary \(i)", args: [],
                    workingDirectory: "/", userId: 501, userName: "fixture",
                    groupId: 20, startTime: now, ancestors: [],
                    isPlatformBinary: false
                )
                return Event(timestamp: now, eventCategory: .process,
                    eventType: .start, eventAction: "exec", process: process)
            }
            let result = try await store.insert(events: events, lane: .priority)
            #expect(result.persistedCount == 2)
            if overlays, block.isMultiple(of: 20) {
                var terminal = events[0]
                terminal.enrichments["expiry_fixture"] = "ordinary_overlay"
                #expect(try await store.appendTerminalRevision(terminal, lane: .priority)
                    == .inserted(eventID: terminal.id))
            }
        }
        #expect(await store.walCheckpointTruncate())
        #expect(try scalar("SELECT COUNT(*) FROM event_journal_blocks", path: path) == Int64(blocks))
        if overlays {
            #expect(try scalar("SELECT COUNT(*) FROM event_journal_terminal_revisions", path: path)
                == Int64((blocks + 19) / 20))
        }
        return Fixture(store: store, directory: directory, path: path, policy: policy,
            cutoff: Date().addingTimeInterval(EventStore.journalRetentionSeconds + 1))
    }

    private func observe(_ fixture: Fixture, with boundaries: Boundaries) async throws {
        await fixture.store.setJournalExpiryPostCommitHookForTesting { boundaries.committed() }
        await fixture.store.setJournalExpiryCheckpointHookForTesting { boundaries.checkpoint() }
        if boundaries.pressure != .none {
            try await fixture.store.setStorageAdmissionProbesForTesting(
                footprint: { try boundaries.footprint($0) },
                freeSpace: { try boundaries.freeSpace($0) }
            )
        }
    }

    private func aggregateSum(_ store: EventStore) async throws -> Int {
        try await store.aggregates(sinceDay: "0000-00-00").reduce(0) { $0 + $1.count }
    }

    @Test("130 real blocks checkpoint at 64-block boundaries and preserve exact rollup")
    func boundedSubquanta() async throws {
        let f = try await fixture(blocks: 130, overlays: true)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let boundaries = Boundaries(policy: f.policy)
        try await observe(f, with: boundaries)
        #expect(try scalar("SELECT COUNT(*) FROM events_fts", path: f.path) > 0)
        let expired = try await f.store.expireJournalBlocks(
            retainedThrough: f.cutoff, maximumBlocks: 1_024)
        #expect(expired == 260)
        #expect(boundaries.observed.commits == 130)
        #expect(boundaries.observed.checkpoints == [0, 64, 128, 130])
        #expect(try await f.store.count() == 0)
        #expect(try await aggregateSum(f.store) == 260)
        #expect(try scalar("SELECT COUNT(*) FROM events_fts", path: f.path) == 0)
        #expect(try scalar("SELECT COUNT(*) FROM event_journal_terminal_revisions", path: f.path) == 0)
        #expect(try scalar("SELECT COALESCE(SUM(considered_count),0) FROM event_projection_coverage", path: f.path) == 0)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(f.path) <= f.policy.maxFootprintBytes)
        let reopened = try EventStore(path: f.path, forceReadOnly: true,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        #expect(try await reopened.count() == 0)
        #expect(try await aggregateSum(reopened) == 260)
    }

    @Test("A reader arriving after block one stops writes at the bounded checkpoint")
    func readerPinConservesRuntimeCutoffWithoutChangingStartup() async throws {
        let f = try await fixture(blocks: 66)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let reader = Reader()
        defer { reader.close() }
        let readerPath = f.path
        let boundaries = Boundaries(policy: f.policy)
        await f.store.setJournalExpiryCheckpointHookForTesting { boundaries.checkpoint() }
        await f.store.setJournalExpiryPostCommitHookForTesting {
            boundaries.committed()
            reader.pin(readerPath)
        }
        let first = try await f.store.expireJournalBlocks(
            retainedThrough: f.cutoff, maximumBlocks: 1_024,
            pinnedEntry: .conserveCurrentCutoff)
        #expect(reader.isPinned)
        #expect(first == 128)
        #expect(boundaries.observed.checkpoints == [0, 64])
        #expect(try await f.store.count() == 4)
        #expect(try await aggregateSum(f.store) == 128)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(f.path) <= f.policy.maxFootprintBytes)

        // An empty eligible set is proven without any checkpoint, despite the
        // same real reader. A zero here must not spend the runtime busy budget.
        #expect(try await f.store.expireJournalBlocks(
            retainedThrough: .distantPast, pinnedEntry: .conserveCurrentCutoff) == 0)
        #expect(boundaries.observed.checkpoints == [0, 64])
        // Startup/default still defers; it must not inherit runtime's busy loop.
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff) == 0)
        do {
            _ = try await f.store.expireJournalBlocks(
                retainedThrough: f.cutoff, pinnedEntry: .conserveCurrentCutoff)
            Issue.record("runtime lost its eligible cutoff behind a reader")
        } catch let error as EventStoreError {
            guard case let .busy(_, failure) = error else { throw error }
            #expect(failure != nil)
        }
        #expect(boundaries.observed.commits == 64)
        let state = try await f.store.storageAdmissionConnectionStateForTesting()
        #expect(!state.inTransaction)
        reader.close()
        await f.store.setJournalExpiryPostCommitHookForTesting { boundaries.committed() }
        #expect(try await f.store.expireJournalBlocks(
            retainedThrough: f.cutoff, pinnedEntry: .conserveCurrentCutoff) == 4)
        #expect(try await aggregateSum(f.store) == 132)
        #expect(try await f.store.count() == 0)
    }

    @Test("Pressure drains prior progress and retries the same untouched block once",
          arguments: [Boundaries.Pressure.nominalCap, .firstBlockRecovery,
                      .hardCap, .projectedCheckpointSpace])
    private func pressureBoundaryRecovers(_ pressure: Boundaries.Pressure) async throws {
        let f = try await fixture(blocks: 3)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let boundaries = Boundaries(pressure, policy: f.policy)
        try await observe(f, with: boundaries)
        #expect(try await f.store.expireJournalBlocks(
            retainedThrough: f.cutoff, maximumBlocks: 64) == 6)
        #expect(boundaries.observed.commits == 3)
        #expect(boundaries.observed.checkpoints == [0, 1, 3])
        #expect(try await aggregateSum(f.store) == 6)
        #expect(try await f.store.count() == 0)
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
    }

    @Test("A refreshed capacity refusal preserves its cause and never retries twice")
    func persistentPressureStopsWithoutDuplicatingRollup() async throws {
        let f = try await fixture(blocks: 3)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let boundaries = Boundaries(.persistentHardCap, policy: f.policy)
        try await observe(f, with: boundaries)
        do {
            _ = try await f.store.expireJournalBlocks(retainedThrough: f.cutoff)
            Issue.record("persistent capacity refusal was hidden")
        } catch let error as SQLitePersistentStoreAdmissionError {
            guard case .footprintLimit = error else { throw error }
        }
        #expect(boundaries.observed.commits == 1)
        #expect(boundaries.observed.checkpoints == [0, 1])
        #expect(try await aggregateSum(f.store) == 2)
        #expect(try await f.store.count() == 4)
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        let reopened = try EventStore(path: f.path, forceReadOnly: true,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        #expect(try await reopened.count() == 4)
        #expect(try await aggregateSum(reopened) == 2)
    }

    @Test("A real checkpoint probe failure is not a reader pin or successful progress return")
    func checkpointFailurePreservesCause() async throws {
        let f = try await fixture(blocks: 3)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let boundaries = Boundaries(.checkpointProbeFailure, policy: f.policy)
        try await observe(f, with: boundaries)
        do {
            _ = try await f.store.expireJournalBlocks(retainedThrough: f.cutoff)
            Issue.record("checkpoint probe failure was hidden")
        } catch let error as SQLitePersistentStoreAdmissionError {
            guard case let .freeSpaceProbeFailed(_, systemErrno) = error else { throw error }
            #expect(systemErrno == EIO)
        }
        #expect(boundaries.observed.commits == 1)
        #expect(boundaries.observed.checkpoints == [0, 1])
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        #expect(try await aggregateSum(f.store) == 2)
        #expect(try await f.store.count() == 4)
    }

    @Test("A real mid-block SQL failure rolls back that block and never takes a capacity retry")
    func midBlockFailurePreservesEarlierDurableProgress() async throws {
        let f = try await fixture(blocks: 3)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let blockedID = try scalar(
            "SELECT block_id FROM event_journal_blocks ORDER BY block_id LIMIT 1 OFFSET 1",
            path: f.path
        )
        // This private trigger fails the final block deletion, after expiry
        // has already changed aggregates, FTS and coverage in that transaction.
        try executeFixtureSQL("""
            CREATE TRIGGER fixture_refuse_second_expiry
            BEFORE DELETE ON event_journal_blocks
            WHEN OLD.block_id = \(blockedID)
            BEGIN SELECT RAISE(ABORT, 'ordinary fixture rollback'); END
            """, path: f.path)
        let boundaries = Boundaries(policy: f.policy)
        try await observe(f, with: boundaries)
        do {
            _ = try await f.store.expireJournalBlocks(retainedThrough: f.cutoff)
            Issue.record("mid-block SQL failure was hidden")
        } catch let error as EventStoreError {
            guard case .decodingFailed = error else { throw error }
        }
        #expect(boundaries.observed.commits == 1)
        #expect(boundaries.observed.checkpoints == [0])
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        #expect(try await aggregateSum(f.store) == 2)
        #expect(try await f.store.count() == 4)
        #expect(try scalar("SELECT COALESCE(SUM(considered_count),0) FROM event_projection_coverage", path: f.path) == 4)
        try executeFixtureSQL("DROP TRIGGER fixture_refuse_second_expiry", path: f.path)
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff) == 4)
        #expect(try await aggregateSum(f.store) == 6)
        #expect(try await f.store.count() == 0)
    }
}
