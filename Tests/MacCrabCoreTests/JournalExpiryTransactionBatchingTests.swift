import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Journal expiry transaction batches preserve durable evidence")
struct JournalExpiryTransactionBatchingTests {
    private enum FixtureError: Error { case sqlite(Int32) }

    private struct Fixture: Sendable {
        let store: EventStore
        let directory: URL
        let path: String
        let policy: SQLitePersistentStorePolicy
        let budget: EventPipelineLiveMemoryBudget
        let cutoff: Date
        let events: [Event]
    }

    private final class Commits: @unchecked Sendable {
        private let lock = NSLock()
        private var value = 0
        private var checkpoints: [Int] = []

        func record() {
            lock.lock()
            defer { lock.unlock() }
            value += 1
        }

        var count: Int {
            lock.lock()
            defer { lock.unlock() }
            return value
        }

        func checkpoint() {
            lock.lock()
            defer { lock.unlock() }
            checkpoints.append(value)
        }

        var checkpointCommits: [Int] {
            lock.lock()
            defer { lock.unlock() }
            return checkpoints
        }
    }

    private final class ReaderPin: @unchecked Sendable {
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

    private final class WALCommits: @unchecked Sendable {
        struct Sample: Sendable {
            let bytes: Int64
            let pageSize: Int64
            let salt: Data
            var frames: Int64 { (bytes - 32) / (pageSize + 24) }
        }

        private let lock = NSLock()
        private var samples: [Sample] = []
        private var checkpoints: [Int] = []
        private var errors: [String] = []
        private let path: String

        init(path: String) { self.path = path + "-wal" }

        func record() {
            lock.lock()
            defer { lock.unlock() }
            do {
                let size = try FileManager.default.attributesOfItem(atPath: path)[.size] as? NSNumber
                guard let bytes = size?.int64Value, bytes > 32 else {
                    errors.append("committed WAL is absent or has no frames")
                    return
                }
                let file = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
                defer { try? file.close() }
                guard let header = try file.read(upToCount: 32), header.count == 32 else {
                    errors.append("committed WAL header is incomplete")
                    return
                }
                let pageSize = header[8..<12].reduce(Int64(0)) { $0 * 256 + Int64($1) }
                guard pageSize >= 512, pageSize <= 65_536,
                      pageSize.nonzeroBitCount == 1,
                      (bytes - 32) % (pageSize + 24) == 0 else {
                    errors.append("committed WAL does not contain complete page frames")
                    return
                }
                samples.append(Sample(bytes: bytes, pageSize: pageSize,
                    salt: Data(header[16..<24])))
            } catch {
                errors.append("could not sample the private fixture WAL: \(error)")
            }
        }

        func checkpoint() {
            lock.lock()
            defer { lock.unlock() }
            checkpoints.append(samples.count)
        }

        var observed: (samples: [Sample], checkpoints: [Int], errors: [String]) {
            lock.lock()
            defer { lock.unlock() }
            return (samples, checkpoints, errors)
        }
    }

    private func event(_ index: Int, at timestamp: Date) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: Int32(30_000 + index), ppid: 1, rpid: 1,
            name: "expiry-transaction-fixture",
            executable: "/usr/bin/expiry-fixture-\(index % 3)",
            commandLine: "expiry fixture ordinary \(index)", args: [],
            workingDirectory: "/", userId: 501, userName: "fixture",
            groupId: 20, startTime: timestamp, ancestors: [],
            isPlatformBinary: false
        )
        return Event(timestamp: timestamp, eventCategory: .process,
            eventType: .start, eventAction: "exec", process: process)
    }

    private func makeFixture(
        blocks: Int, eventsPerBlock: Int = 2, eventCounts: [Int]? = nil
    ) async throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("expiry-transaction-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory,
            withIntermediateDirectories: false)
        let path = directory.appendingPathComponent("events.db").path
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 256 * 1_048_576,
            freeSpaceFloorBytes: 32 * 1_048_576,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: directory.path
        )
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(path: path, storagePolicy: policy, liveMemoryBudget: budget)
        _ = try await store.recoverJournalBeforeProducers()
        let timestamp = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let counts = eventCounts ?? Array(repeating: eventsPerBlock, count: blocks)
        try #require(counts.count == blocks)
        var expected: [Event] = []
        for block in 0..<blocks {
            var events = (0..<counts[block]).map {
                event(expected.count + $0, at: timestamp)
            }
            let inserted = try await store.insert(events: events, lane: .priority)
            #expect(inserted.persistedCount == counts[block])
            if block.isMultiple(of: 2) {
                events[0].enrichments["expiry_fixture"] = "retained terminal overlay"
                #expect(try await store.appendTerminalRevision(events[0], lane: .priority)
                    == .inserted(eventID: events[0].id))
            }
            expected.append(contentsOf: events)
        }
        #expect(await store.walCheckpointTruncate())
        #expect(try rows("SELECT block_id FROM event_journal_blocks", path: path).count == blocks)
        return Fixture(store: store, directory: directory, path: path, policy: policy, budget: budget,
            cutoff: Date().addingTimeInterval(EventStore.journalRetentionSeconds + 1),
            events: expected)
    }

    /// Copy only our generated fixture, after its WAL is truncated and while
    /// no writer is running. Both paths then start with identical UUIDs,
    /// admission buckets, projection choices, terminal overlays and coverage.
    private func copyFixture(_ source: Fixture) async throws -> Fixture {
        #expect(await source.store.walCheckpointTruncate())
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("expiry-transaction-copy-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory,
            withIntermediateDirectories: false)
        let path = directory.appendingPathComponent("events.db").path
        try FileManager.default.copyItem(atPath: source.path, toPath: path)
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: source.policy.maxFootprintBytes,
            freeSpaceFloorBytes: source.policy.freeSpaceFloorBytes,
            transactionReserveBytes: source.policy.transactionReserveBytes,
            storageVolumePath: directory.path
        )
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let store = try EventStore(path: path, storagePolicy: policy, liveMemoryBudget: budget)
        _ = try await store.recoverJournalBeforeProducers()
        return Fixture(store: store, directory: directory, path: path,
            policy: policy, budget: budget, cutoff: source.cutoff, events: source.events)
    }

    private func rows(_ sql: String, path: String) throws -> [[String]] {
        var opened: OpaquePointer?
        let rc = sqlite3_open_v2(path, &opened,
            SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(rc)
        }
        defer { sqlite3_close(db) }
        var prepared: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &prepared, nil)
        guard result == SQLITE_OK, let statement = prepared else {
            throw FixtureError.sqlite(result)
        }
        defer { sqlite3_finalize(statement) }
        var output: [[String]] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { return output }
            guard step == SQLITE_ROW else { throw FixtureError.sqlite(step) }
            output.append((0..<sqlite3_column_count(statement)).map { column in
                guard let text = sqlite3_column_text(statement, column) else { return "<null>" }
                return String(cString: text)
            })
        }
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

    private func durableState(_ fixture: Fixture) throws -> [[[String]]] {
        try [
            "SELECT * FROM event_aggregates ORDER BY day,event_category,process_signer,process_path",
            "SELECT * FROM event_aggregate_gaps ORDER BY day,event_category,reason",
            "SELECT * FROM event_projection_coverage ORDER BY bucket_start",
            "SELECT * FROM event_projection_block_coverage ORDER BY block_id",
            "SELECT block_id FROM event_journal_blocks ORDER BY block_id",
            "SELECT block_id,ordinal FROM event_journal_terminal_revisions ORDER BY block_id,ordinal",
            "SELECT id,raw_json FROM events ORDER BY id",
            "SELECT rowid FROM events_fts ORDER BY rowid",
        ].map { try rows($0, path: fixture.path) }
    }

    private func assertExactEvents(_ store: EventStore, expected: [Event]) async throws {
        let snapshot = try await store.exactEventsSnapshot(since: .distantPast, limit: 10_000)
        #expect(snapshot.isComplete)
        #expect(snapshot.events.count == expected.count)
        #expect(Set(snapshot.events) == Set(expected))
        #expect(try await store.count() == expected.count)
    }

    private func aggregateCount(_ store: EventStore) async throws -> Int {
        try await store.aggregates(sinceDay: "0000-00-00").reduce(0) { $0 + $1.count }
    }

    @Test("Grouped expiry matches singleton rollups, coverage and exact survivors after reopen")
    func groupedAndSingletonHaveIdenticalDurableResults() async throws {
        let singleton = try await makeFixture(blocks: 12)
        defer { try? FileManager.default.removeItem(at: singleton.directory) }
        let grouped = try await copyFixture(singleton)
        defer { try? FileManager.default.removeItem(at: grouped.directory) }
        let singleCommits = Commits()
        let groupCommits = Commits()
        await singleton.store.setJournalExpiryPostCommitHookForTesting { singleCommits.record() }
        await grouped.store.setJournalExpiryPostCommitHookForTesting { groupCommits.record() }

        #expect(try await singleton.store.expireJournalBlocks(
            retainedThrough: singleton.cutoff, maximumBlocks: 9) == 18)
        #expect(try await grouped.store.expireJournalBlocks(
            retainedThrough: grouped.cutoff, maximumBlocks: 9,
            maximumBlocksPerTransaction: 4) == 18)
        #expect(singleCommits.count == 9)
        #expect(groupCommits.count == 3)
        #expect(try durableState(grouped) == durableState(singleton))
        #expect(try await aggregateCount(grouped.store) == 18)
        for fixture in [singleton, grouped] {
            let reopened = try EventStore(path: fixture.path, forceReadOnly: true,
                liveMemoryBudget: .isolatedProductionEquivalentForTesting())
            try await assertExactEvents(reopened, expected: Array(fixture.events.dropFirst(18)))
            #expect(try await aggregateCount(reopened) == 18)
            #expect(!(try await fixture.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        }
    }

    @Test("A failure in a group's second block rolls back that group and preserves earlier groups",
          arguments: [1, 5])
    func secondBlockFailureIsAtomic(blockOffset: Int) async throws {
        let f = try await makeFixture(blocks: 12)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let control = try await copyFixture(f)
        defer { try? FileManager.default.removeItem(at: control.directory) }
        let priorBlocks = (blockOffset / 4) * 4
        if priorBlocks > 0 {
            #expect(try await control.store.expireJournalBlocks(
                retainedThrough: control.cutoff, maximumBlocks: priorBlocks,
                maximumBlocksPerTransaction: 4) == priorBlocks * 2)
        }
        let selected = try rows(
            "SELECT block_id FROM event_journal_blocks ORDER BY block_id LIMIT 1 OFFSET \(blockOffset)",
            path: f.path)
        let blockID = try #require((selected.first?.first).flatMap { Int64($0) })
        // This ordinary SQLite trigger fails after rollup, coverage and FTS
        // changes in the second block, so rollback must undo the first too.
        try executeFixtureSQL("""
            CREATE TRIGGER fixture_refuse_expiry_group
            BEFORE DELETE ON event_journal_blocks
            WHEN OLD.block_id = \(blockID)
            BEGIN SELECT RAISE(ABORT, 'ordinary fixture rollback'); END
            """, path: f.path)
        let commits = Commits()
        await f.store.setJournalExpiryPostCommitHookForTesting { commits.record() }
        do {
            _ = try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
                maximumBlocks: 12, maximumBlocksPerTransaction: 4)
            Issue.record("the injected second-block failure was hidden")
        } catch let error as EventStoreError {
            guard case .decodingFailed = error else { throw error }
        }
        #expect(commits.count == priorBlocks / 4)
        #expect(try durableState(f) == durableState(control))
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        try await assertExactEvents(f.store, expected: Array(f.events.dropFirst(priorBlocks * 2)))
        let reopened = try EventStore(path: f.path, forceReadOnly: true,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        try await assertExactEvents(reopened, expected: Array(f.events.dropFirst(priorBlocks * 2)))
        #expect(try await aggregateCount(reopened) == priorBlocks * 2)

        try executeFixtureSQL("DROP TRIGGER fixture_refuse_expiry_group", path: f.path)
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 12, maximumBlocksPerTransaction: 4) == (12 - priorBlocks) * 2)
        #expect(commits.count == 3)
        #expect(try await aggregateCount(f.store) == 24)
        try await assertExactEvents(f.store, expected: [])
        // The already-open reader must also retire the rolled-back group's
        // events exactly once when that group later commits successfully.
        try await assertExactEvents(reopened, expected: [])
    }

    @Test("A deferred foreign-key COMMIT failure rebuilds the expiry cursor before a clean retry",
          arguments: [1, 5])
    func failedCommitDoesNotPublishItsGroup(blockOffset: Int) async throws {
        let f = try await makeFixture(blocks: 12)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let control = try await copyFixture(f)
        defer { try? FileManager.default.removeItem(at: control.directory) }
        let priorBlocks = (blockOffset / 4) * 4
        if priorBlocks > 0 {
            #expect(try await control.store.expireJournalBlocks(
                retainedThrough: control.cutoff, maximumBlocks: priorBlocks,
                maximumBlocksPerTransaction: 4) == priorBlocks * 2)
        }
        let selected = try rows(
            "SELECT block_id FROM event_journal_blocks ORDER BY block_id LIMIT 1 OFFSET \(blockOffset)",
            path: f.path)
        let blockID = try #require((selected.first?.first).flatMap { Int64($0) })
        // Every DELETE succeeds; an ordinary deferred FK is checked only at
        // COMMIT. No group cache state may escape that failed commit.
        try executeFixtureSQL("""
            CREATE TABLE fixture_commit_parent (id INTEGER PRIMARY KEY);
            CREATE TABLE fixture_commit_child (
                parent_id INTEGER REFERENCES fixture_commit_parent(id)
                    DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TRIGGER fixture_defer_commit_failure
            AFTER DELETE ON event_journal_blocks
            WHEN OLD.block_id = \(blockID)
            BEGIN INSERT INTO fixture_commit_child(parent_id) VALUES (OLD.block_id); END;
            """, path: f.path)
        let commits = Commits()
        await f.store.setJournalExpiryPostCommitHookForTesting { commits.record() }
        do {
            _ = try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
                maximumBlocks: 12, maximumBlocksPerTransaction: 4)
            Issue.record("the deferred foreign-key COMMIT failure was hidden")
        } catch let error as EventStoreError {
            guard case let .sqliteFailure(context, _, resultCode, _, _) = error else { throw error }
            #expect(context == "COMMIT")
            #expect((resultCode & 0xff) == SQLITE_CONSTRAINT)
        }
        #expect(commits.count == priorBlocks / 4)
        #expect(try durableState(f) == durableState(control))
        #expect(try rows("SELECT parent_id FROM fixture_commit_child", path: f.path).isEmpty)
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        let beforeRebuild = await f.store.journalIndexRefreshDiagnostics()
        try await assertExactEvents(f.store, expected: Array(f.events.dropFirst(priorBlocks * 2)))
        let afterRebuild = await f.store.journalIndexRefreshDiagnostics()
        #expect(afterRebuild.fullRebuilds > beforeRebuild.fullRebuilds)
        let reopened = try EventStore(path: f.path, forceReadOnly: true,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        try await assertExactEvents(reopened, expected: Array(f.events.dropFirst(priorBlocks * 2)))
        #expect(try await aggregateCount(reopened) == priorBlocks * 2)

        try executeFixtureSQL("DROP TRIGGER fixture_defer_commit_failure", path: f.path)
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 12, maximumBlocksPerTransaction: 4) == (12 - priorBlocks) * 2)
        #expect(commits.count == 3)
        #expect(try await aggregateCount(f.store) == 24)
        try await assertExactEvents(f.store, expected: [])
        try await assertExactEvents(reopened, expected: [])
    }

    @Test("The transaction block bound clamps oversized and nonpositive requests",
          arguments: [0, 1, 4, Int.max])
    func transactionBoundIsFinite(requested: Int) async throws {
        let f = try await makeFixture(blocks: 8)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let commits = Commits()
        await f.store.setJournalExpiryPostCommitHookForTesting { commits.record() }
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 8, maximumBlocksPerTransaction: requested) == 16)
        #expect(commits.count == (requested <= 1 ? 8 : 2))
        #expect(try await aggregateCount(f.store) == 16)
        try await assertExactEvents(f.store, expected: [])
    }

    @Test("The conservative byte bound limits a group even when its block bound allows four")
    func productionReserveBoundsLargeBlockGroups() async throws {
        // Each 128-event block's metadata-only expiry bound exceeds a third
        // of the 32 MiB reserve but is below half. It admits two, not four.
        let f = try await makeFixture(blocks: 5, eventsPerBlock: 128)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let commits = Commits()
        await f.store.setJournalExpiryPostCommitHookForTesting { commits.record() }
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 5, maximumBlocksPerTransaction: 4) == 640)
        #expect(commits.count == 3)
        #expect(try await aggregateCount(f.store) == 640)
        try await assertExactEvents(f.store, expected: [])
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(f.path) <= f.policy.maxFootprintBytes)
    }

    @Test("Grouped commits append fewer real WAL frames for identical SQLite evidence")
    func groupedExpiryReducesWALFrames() async throws {
        let singleton = try await makeFixture(blocks: 32)
        defer { try? FileManager.default.removeItem(at: singleton.directory) }
        let grouped = try await copyFixture(singleton)
        defer { try? FileManager.default.removeItem(at: grouped.directory) }
        let singleWAL = WALCommits(path: singleton.path)
        let groupWAL = WALCommits(path: grouped.path)
        await singleton.store.setJournalExpiryPostCommitHookForTesting { singleWAL.record() }
        await singleton.store.setJournalExpiryCheckpointHookForTesting { singleWAL.checkpoint() }
        await grouped.store.setJournalExpiryPostCommitHookForTesting { groupWAL.record() }
        await grouped.store.setJournalExpiryCheckpointHookForTesting { groupWAL.checkpoint() }
        #expect(try await singleton.store.expireJournalBlocks(retainedThrough: singleton.cutoff,
            maximumBlocks: 32) == 64)
        #expect(try await grouped.store.expireJournalBlocks(retainedThrough: grouped.cutoff,
            maximumBlocks: 32, maximumBlocksPerTransaction: 4) == 64)
        let single = singleWAL.observed
        let group = groupWAL.observed
        #expect(single.errors.isEmpty)
        #expect(group.errors.isEmpty)
        #expect(single.samples.count == 32)
        #expect(group.samples.count == 8)
        #expect(single.checkpoints == [0, 32])
        #expect(group.checkpoints == [0, 8])
        for observed in [single, group] {
            let first = try #require(observed.samples.first)
            #expect(observed.samples.allSatisfy { $0.salt == first.salt })
            #expect(observed.samples.allSatisfy { $0.pageSize == first.pageSize })
            // Stay below the configured auto-checkpoint threshold; unchanged
            // salts and strictly increasing sizes exclude a restarted WAL.
            #expect(observed.samples.allSatisfy {
                $0.frames < Int64(StoragePragmas.eventWalAutocheckpointPages)
            })
            #expect(zip(observed.samples, observed.samples.dropFirst())
                .allSatisfy { $0.bytes < $1.bytes })
        }
        let singleLast = try #require(single.samples.last)
        let groupLast = try #require(group.samples.last)
        #expect(singleLast.pageSize == groupLast.pageSize)
        // This is direct SQLite write-amplification evidence, not a claim
        // about physical SSD writes or the installed-host runtime budget.
        #expect(groupLast.frames < singleLast.frames)
        let reduction = 100 * (1 - Double(groupLast.frames) / Double(singleLast.frames))
        print("journal_expiry_wal_frames singleton=\(singleLast.frames) "
            + "grouped=\(groupLast.frames) reduction_percent="
            + String(format: "%.1f", reduction))
        #expect(try durableState(grouped) == durableState(singleton))
        #expect(try await aggregateCount(grouped.store) == 64)
    }

    @Test("Space for one transaction but not a group uses singleton fallback without losing evidence")
    func constrainedFreeSpaceUsesSingletonFallback() async throws {
        let f = try await makeFixture(blocks: 5)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        // Keep the production reserve and terminal-settlement headroom.
        // Inject only free-space pressure: one small expiry plus protected
        // headroom fits 26 MiB, while the planned four-block group does not.
        // The real SQLite transactions and family measurements are unchanged.
        let narrowPolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: f.policy.maxFootprintBytes,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: f.policy.transactionReserveBytes,
            storageVolumePath: f.directory.path
        )
        _ = try await f.store.updateStorageAdmission(narrowPolicy)
        try await f.store.setStorageAdmissionProbesForTesting(
            footprint: { try SQLitePersistentStoreAdmission.measureFamily($0) },
            freeSpace: { _ in 26 * 1_048_576 })
        let commits = Commits()
        await f.store.setJournalExpiryPostCommitHookForTesting { commits.record() }
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 5, maximumBlocksPerTransaction: 4) == 10)
        #expect(commits.count == 5)
        #expect(try await aggregateCount(f.store) == 10)
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(f.path) <= narrowPolicy.maxFootprintBytes)
        try await assertExactEvents(f.store, expected: [])
    }

    @Test("Ownership pressure after a group's first block rolls back before singleton progress")
    func secondBlockOwnershipRefusalFallsBackWithoutPartialDurability() async throws {
        let f = try await makeFixture(blocks: 3, eventCounts: [2, 128, 2])
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let control = try await copyFixture(f)
        defer { try? FileManager.default.removeItem(at: control.directory) }
        // Warm the verified index before applying ownership pressure: the
        // intended refusal is inside expiry, not during its entry verification.
        try await assertExactEvents(f.store, expected: f.events)
        let beforeBudget = f.budget.snapshot()
        #expect(beforeBudget.currentBytes == 0)
        let smallRetained = try f.events.prefix(2).reduce(0) {
            $0 + (try EventJournalAdmissionValidator.preflight($1)).sourceRetainedByteEstimate
        }
        let retainedSlack = smallRetained * 4 + 4_096
        let largePrefixRetained = try f.events[2..<129].reduce(0) {
            $0 + (try EventJournalAdmissionValidator.preflight($1)).sourceRetainedByteEstimate
        }
        try #require(largePrefixRetained > retainedSlack)
        // Keep the production budget/caps. A real J lease leaves enough for
        // S, one maximum record workspace and the first tiny block's complete
        // base+terminal graphs, but not the second block's 128 retained graphs.
        let occupiedBytes = beforeBudget.maximumBytes
            - EventJournalCodec.maximumWorkspaceBytes
            - EventJournalAdmissionValidator.maximumPreparationWorkspaceBytes
            - retainedSlack
        try #require(occupiedBytes > 0)
        let pressure = try #require(f.budget.tryAcquire(
            bytes: occupiedBytes, owner: .journalPrepared))
        let commits = Commits()
        await f.store.setJournalExpiryPostCommitHookForTesting {
            commits.record()
            // Only a successful singleton COMMIT releases the competing
            // ownership. A swallowed group error cannot receive this credit.
            #expect(pressure.resize(to: 0))
        }
        let before = try await f.store.storageAdmissionConnectionStateForTesting()
        let beforeControl = try await control.store.storageAdmissionConnectionStateForTesting()
        #expect(try await control.store.expireJournalBlocks(retainedThrough: control.cutoff,
            maximumBlocks: 3) == 132)
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 3, maximumBlocksPerTransaction: 4) == 132)
        #expect(commits.count == 3)
        let after = try await f.store.storageAdmissionConnectionStateForTesting()
        let afterControl = try await control.store.storageAdmissionConnectionStateForTesting()
        // sqlite_total_changes includes rolled-back DML. More changes than
        // the identical singleton control prove the refusal happened after
        // the first block mutated, not merely during pre-DML group admission.
        #expect(after.totalChanges - before.totalChanges
            > afterControl.totalChanges - beforeControl.totalChanges)
        #expect(!after.inTransaction)
        let afterBudget = f.budget.snapshot()
        #expect(afterBudget.nonblockingRejectionsTotal > beforeBudget.nonblockingRejectionsTotal)
        #expect(afterBudget.currentBytes == beforeBudget.currentBytes)
        #expect(afterBudget.withinCapacity)
        #expect(afterBudget.leasesConserved)
        #expect(try durableState(f) == durableState(control))
        #expect(try await aggregateCount(f.store) == 132)
        try await assertExactEvents(f.store, expected: [])
        let reopened = try EventStore(path: f.path, forceReadOnly: true,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        try await assertExactEvents(reopened, expected: [])
        #expect(try await aggregateCount(reopened) == 132)
    }

    @Test("A warm independent reader observes grouped expiry and appended events without a full rebuild")
    func groupedExpiryRefreshesTheIndependentReader() async throws {
        let f = try await makeFixture(blocks: 10)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let reader = try EventStore(path: f.path, forceReadOnly: true,
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        try await assertExactEvents(reader, expected: f.events)
        let before = await reader.journalIndexRefreshDiagnostics()
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 4, maximumBlocksPerTransaction: 4) == 8)
        let appendedAt = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        let appended = [event(200, at: appendedAt), event(201, at: appendedAt)]
        #expect(try await f.store.insert(events: appended, lane: .priority).persistedCount == 2)
        #expect(await f.store.walCheckpointTruncate())
        try await assertExactEvents(reader, expected: Array(f.events.dropFirst(8)) + appended)
        let after = await reader.journalIndexRefreshDiagnostics()
        #expect(after.fullRebuilds == before.fullRebuilds)
        #expect(after.appendRefreshes > before.appendRefreshes)
    }

    @Test("A reader pin stops grouped expiry at 64 blocks, not 64 transactions")
    func groupedExpiryRespectsPinnedReaderCheckpointBoundary() async throws {
        let f = try await makeFixture(blocks: 66)
        defer { try? FileManager.default.removeItem(at: f.directory) }
        let reader = ReaderPin()
        defer { reader.close() }
        let commits = Commits()
        let path = f.path
        await f.store.setJournalExpiryCheckpointHookForTesting { commits.checkpoint() }
        await f.store.setJournalExpiryPostCommitHookForTesting {
            commits.record()
            reader.pin(path)
        }

        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            maximumBlocks: 66, pinnedEntry: .conserveCurrentCutoff,
            maximumBlocksPerTransaction: 4) == 128)
        #expect(reader.isPinned)
        #expect(commits.count == 16)
        #expect(commits.checkpointCommits == [0, 16])
        #expect(try await aggregateCount(f.store) == 128)
        try await assertExactEvents(f.store, expected: Array(f.events.suffix(4)))
        #expect(!(try await f.store.storageAdmissionConnectionStateForTesting()).inTransaction)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(f.path) <= f.policy.maxFootprintBytes)

        // The unchanged startup default defers at a pinned entry; runtime
        // retains a typed busy outcome and does not forget the frozen cutoff.
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff) == 0)
        do {
            _ = try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
                pinnedEntry: .conserveCurrentCutoff, maximumBlocksPerTransaction: 4)
            Issue.record("a pinned reader must retain the remaining runtime cutoff")
        } catch let error as EventStoreError {
            guard case let .busy(_, failure) = error else { throw error }
            #expect(failure != nil)
        }
        #expect(commits.count == 16)
        reader.close()
        await f.store.setJournalExpiryPostCommitHookForTesting { commits.record() }
        #expect(try await f.store.expireJournalBlocks(retainedThrough: f.cutoff,
            pinnedEntry: .conserveCurrentCutoff, maximumBlocksPerTransaction: 4) == 4)
        #expect(commits.count == 17)
        #expect(try await aggregateCount(f.store) == 132)
        try await assertExactEvents(f.store, expected: [])
    }
}
