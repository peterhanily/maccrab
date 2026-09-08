import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore

@Suite("Dense published-store bootstrap", .serialized)
struct EventStoreDenseBootstrapTests {
    private struct Fixture {
        let directory: URL
        let events: [Event]
        let evidence: [[Column]]
        let policy: SQLitePersistentStorePolicy
        var path: String { directory.appendingPathComponent("events.db").path }
    }

    private struct Column: Equatable {
        let type: Int32
        let bytes: Data
    }

    private func connection<T>(_ path: String, _ body: (OpaquePointer) throws -> T) throws -> T {
        var raw: OpaquePointer?
        let rc = sqlite3_open_v2(path, &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        guard rc == SQLITE_OK, let db = raw else {
            if let raw { sqlite3_close(raw) }
            throw NSError(domain: "DenseUpgradeFixture", code: Int(rc))
        }
        defer { sqlite3_close(db) }
        return try body(db)
    }

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw NSError(domain: "DenseUpgradeFixture", code: Int(rc), userInfo: [
                NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(db)),
            ])
        }
    }

    private func rows(_ sql: String, on db: OpaquePointer) throws -> [[Column]] {
        var raw: OpaquePointer?
        try #require(sqlite3_prepare_v2(db, sql, -1, &raw, nil) == SQLITE_OK)
        let query = try #require(raw)
        defer { sqlite3_finalize(query) }
        var result: [[Column]] = []
        while true {
            let rc = sqlite3_step(query)
            if rc == SQLITE_DONE { return result }
            try #require(rc == SQLITE_ROW)
            var values: [Column] = []
            for index in 0..<sqlite3_column_count(query) {
                let type = sqlite3_column_type(query, index)
                let pointer = sqlite3_column_blob(query, index)
                let count = Int(sqlite3_column_bytes(query, index))
                values.append(Column(type: type,
                    bytes: pointer.map { Data(bytes: $0, count: count) } ?? Data()))
            }
            result.append(values)
        }
    }

    private func scalar(_ sql: String, on db: OpaquePointer) throws -> Int64 {
        var raw: OpaquePointer?
        try #require(sqlite3_prepare_v2(db, sql, -1, &raw, nil) == SQLITE_OK)
        let query = try #require(raw)
        defer { sqlite3_finalize(query) }
        try #require(sqlite3_step(query) == SQLITE_ROW)
        let result = sqlite3_column_int64(query, 0)
        try #require(sqlite3_step(query) == SQLITE_DONE)
        return result
    }

    private func fixture(count: Int, detailBytes: Int, changedIndex: String? = nil) throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("dense-legacy-bootstrap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        var succeeded = false
        defer { if !succeeded { try? FileManager.default.removeItem(at: directory) } }
        let path = directory.appendingPathComponent("events.db").path
        let epoch = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1, name: "true", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: ["/usr/bin/true"], workingDirectory: "/",
            userId: 501, userName: "tester", groupId: 20, startTime: epoch,
            ancestors: [], isPlatformBinary: false
        )
        let events = (0..<count).map { index in
            Event(timestamp: epoch.addingTimeInterval(-Double(index) * 0.01),
                eventCategory: .process, eventType: .start, eventAction: "exec", process: process,
                enrichments: ["fixture_detail": String(repeating: "x", count: detailBytes)])
        }
        let evidence = try connection(path) { db -> [[Column]] in
            try execute("PRAGMA page_size=4096; PRAGMA auto_vacuum=INCREMENTAL", on: db)
            let schema = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
                .appendingPathComponent("fixtures/event-store-v1.21.5.sql")
            try execute(try String(contentsOf: schema, encoding: .utf8), on: db)
            try execute("BEGIN IMMEDIATE", on: db)
            var raw: OpaquePointer?
            try #require(sqlite3_prepare_v2(db, """
                INSERT INTO events(id,timestamp,event_category,event_type,event_action,severity,
                    process_pid,process_name,process_path,process_commandline,process_ppid,
                    user_id,user_name,group_id,working_directory,responsible_pid,is_platform_binary,raw_json)
                VALUES(?1,?2,'process','start','exec','informational',4242,'true','/usr/bin/true',
                    '/usr/bin/true',1,501,'tester',20,'/',1,0,?3)
                """, -1, &raw, nil) == SQLITE_OK)
            let insert = try #require(raw)
            defer { sqlite3_finalize(insert) }
            let transient = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
            for event in events {
                sqlite3_reset(insert)
                sqlite3_clear_bindings(insert)
                let json = try JSONEncoder().encode(event)
                try #require(json.count <= 65_536)
                sqlite3_bind_text(insert, 1, event.id.uuidString, -1, transient)
                sqlite3_bind_double(insert, 2, event.timestamp.timeIntervalSince1970)
                sqlite3_bind_text(insert, 3, String(decoding: json, as: UTF8.self), -1, transient)
                try #require(sqlite3_step(insert) == SQLITE_DONE)
            }
            try execute("""
                INSERT INTO alert_evidence SELECT 'dense-fixture-alert', id,timestamp,event_category,
                    event_type,event_action,severity,process_pid,process_name,process_path,
                    process_commandline,process_ppid,process_signer,process_team_id,process_signing_id,
                    file_path,file_action,network_dest_ip,network_dest_port,tcc_service,tcc_client,
                    raw_json,mcp_server_name,mcp_server_category,ai_tool_session_id
                FROM events ORDER BY timestamp DESC LIMIT 1
                """, on: db)
            if let changedIndex {
                try execute("DROP INDEX idx_events_category", on: db)
                switch changedIndex {
                case "other-table":
                    try execute("CREATE TABLE unrelated_category(value TEXT); CREATE INDEX idx_events_category ON unrelated_category(value)", on: db)
                case "unique":
                    try execute("CREATE UNIQUE INDEX idx_events_category ON events(id)", on: db)
                default:
                    throw NSError(domain: "DenseUpgradeFixture", code: 1)
                }
            }
            try execute("COMMIT", on: db)
            var logged: Int32 = 0
            var checkpointed: Int32 = 0
            try #require(sqlite3_wal_checkpoint_v2(db, nil, SQLITE_CHECKPOINT_TRUNCATE,
                &logged, &checkpointed) == SQLITE_OK)
            try #require(logged == checkpointed)
            try #require(try scalar("PRAGMA user_version", on: db) == 6)
            try #require(try scalar("PRAGMA auto_vacuum", on: db) == 2)
            // FTS merges may free a few pages. They must still be insufficient
            // to cover the 256KiB deficit established by the policy below.
            try #require(try scalar("PRAGMA freelist_count", on: db) * 4096 < 256 * 1024)
            return try rows("SELECT * FROM alert_evidence ORDER BY alert_id,id", on: db)
        }
        // Actual disk occupancy sets the small test envelope. Its reserve is
        // the unchanged production 32MiB; no admission measurement is mocked.
        let family = try SQLitePersistentStoreAdmission.measureFamily(path)
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: family + SQLitePersistentStorePolicy.eventTransactionReserveBytes - 256 * 1024,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: directory.path)
        succeeded = true
        return Fixture(directory: directory, events: events, evidence: evidence, policy: policy)
    }

    private func expectExactEvents(_ fixture: Fixture, in store: EventStore) async throws {
        // Query bounded, disjoint time windows so all original full Events are
        // checked without retaining an unbounded journal query result.
        for offset in stride(from: 0, to: fixture.events.count, by: 128) {
            let expected = Array(fixture.events[offset..<min(offset + 128, fixture.events.count)])
            let first = try #require(expected.first)
            let last = try #require(expected.last)
            let found = try await store.exactEventsSnapshot(
                since: last.timestamp.addingTimeInterval(-0.001),
                until: first.timestamp.addingTimeInterval(0.001), limit: 128)
            #expect(found.isComplete)
            #expect(found.events == expected)
        }
        #expect(try await store.count() == fixture.events.count)
        let actual = try connection(fixture.path) {
            try rows("SELECT * FROM alert_evidence ORDER BY alert_id,id", on: $0)
        }
        #expect(actual == fixture.evidence)
    }

    @Test("Dense mode-2 upgrade retires only redundant indexes and restores the unchanged reserve")
    func denseStoreRecoversWithinItsCap() async throws {
        let fixture = try fixture(count: 8_192, detailBytes: 1_000)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let initial = try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
        try #require(initial < fixture.policy.maxFootprintBytes)
        try #require(initial + fixture.policy.transactionReserveBytes > fixture.policy.maxFootprintBytes)
        try #require(initial + fixture.policy.transactionReserveBytes
            - fixture.policy.maxFootprintBytes == 256 * 1024)
        func firstOpen() async throws -> EventStore.EventJournalRecoverySnapshot {
            let store = try EventStore(path: fixture.path, storagePolicy: fixture.policy)
            let recovery = try await store.recoverJournalBeforeProducers()
            #expect(recovery.complete)
            #expect(recovery.sourceEvents == fixture.events.count)
            #expect(recovery.migratedEvents == fixture.events.count)
            #expect(recovery.remainingEvents == 0 && recovery.corruptPreservedEvents == 0
                && recovery.rolledExpiredEvents == 0)
            try await expectExactEvents(fixture, in: store)
            #expect(try await store.recoverJournalBeforeProducers() == recovery)
            return recovery
        }
        let recovery = try await firstOpen()
        let reopened = try EventStore(path: fixture.path, storagePolicy: fixture.policy)
        #expect(try await reopened.recoverJournalBeforeProducers() == recovery)
        try await expectExactEvents(fixture, in: reopened)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
            + fixture.policy.transactionReserveBytes <= fixture.policy.maxFootprintBytes)
        let finalized = try connection(fixture.path) { db in
            try scalar("SELECT schema_finalized FROM event_journal_migration WHERE singleton=1", on: db)
        }
        #expect(finalized == 1)
    }

    @Test("Insufficient or invalid removable indexes refuse before the one-way barrier",
        arguments: ["insufficient", "other-table", "unique"])
    func refusalPreservesLegacyEvidence(reason: String) throws {
        let fixture = try fixture(count: 4, detailBytes: 58_000,
            changedIndex: reason == "insufficient" ? nil : reason)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let before = try connection(fixture.path) { db in
            (try rows("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name", on: db),
             try rows("SELECT * FROM events ORDER BY id", on: db))
        }
        for _ in 0..<2 {
            do {
                _ = try EventStore(path: fixture.path, storagePolicy: fixture.policy)
                Issue.record("Dense store entered bootstrap without a proven preserving reclaim route")
            } catch let error as EventStoreError {
                guard case .storageNotReady = error else { throw error }
            }
            try connection(fixture.path) { (db: OpaquePointer) throws -> Void in
                #expect(try scalar("PRAGMA user_version", on: db) == 6)
                #expect(try scalar("SELECT COUNT(*) FROM sqlite_schema WHERE type='view' AND name='idx_events_timestamp'", on: db) == 0)
                #expect(try rows("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name", on: db) == before.0)
                #expect(try rows("SELECT * FROM events ORDER BY id", on: db) == before.1)
                #expect(try rows("SELECT * FROM alert_evidence ORDER BY alert_id,id", on: db) == fixture.evidence)
            }
        }
    }

    @Test("WAL-only pressure checkpoints into ordinary admission without the dense exception")
    func walOnlyPressureUsesOrdinaryReclaim() async throws {
        let fixture = try fixture(count: 4, detailBytes: 1_000)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var raw: OpaquePointer?
        try #require(sqlite3_open(fixture.path, &raw) == SQLITE_OK)
        let writer = try #require(raw)
        // An idle open writer retains the actual WAL, while allowing the new
        // EventStore connection to checkpoint it. There is no pinned reader.
        defer { sqlite3_close(writer) }
        try execute("PRAGMA wal_autocheckpoint=0", on: writer)
        let main = try SQLitePersistentStoreAdmission.measureMainFile(fixture.path)
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: main + SQLitePersistentStorePolicy.eventTransactionReserveBytes + 1_048_576,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: fixture.directory.path)
        for _ in 0..<128 {
            // Return every typed value and JSON/evidence value to its original
            // state, but leave committed repeated pages in the untruncated WAL.
            try execute("UPDATE events SET process_pid=4243", on: writer)
            try execute("UPDATE events SET process_pid=4242", on: writer)
            if try SQLitePersistentStoreAdmission.measureFamily(fixture.path) - main >= 2 * 1_048_576 {
                break
            }
        }
        let family = try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
        try #require(main + policy.transactionReserveBytes < policy.maxFootprintBytes)
        try #require(family + policy.transactionReserveBytes > policy.maxFootprintBytes)
        try #require(family + (family - main) < policy.maxFootprintBytes)
        try #require(try scalar("PRAGMA freelist_count", on: writer) * 4096
            < family + policy.transactionReserveBytes - policy.maxFootprintBytes)
        let store = try EventStore(path: fixture.path, storagePolicy: policy)
        let recovery = try await store.recoverJournalBeforeProducers()
        #expect(recovery.complete && recovery.sourceEvents == 4 && recovery.migratedEvents == 4)
        #expect(recovery.remainingEvents == 0 && recovery.rolledExpiredEvents == 0
            && recovery.corruptPreservedEvents == 0)
        try await expectExactEvents(fixture, in: store)
        #expect(try SQLitePersistentStoreAdmission.measureFamily(fixture.path)
            + policy.transactionReserveBytes <= policy.maxFootprintBytes)
    }

    @Test("Incomplete legacy structural checks preserve evidence and do not quarantine",
        arguments: ["non-ok-verdict", "occupied-workspace"])
    func structuralCheckRefusalPreservesOriginal(reason: String) async throws {
        let fixture = try fixture(count: 4, detailBytes: 1_000)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 128 * 1_048_576,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: fixture.directory.path)
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        var occupied: [EventPipelineMemoryLease] = []
        if reason == "non-ok-verdict" {
            // SQLite itself emits a non-ok quick_check row for this ordinary
            // constraint inconsistency. No physical file corruption or guessed
            // SQLite error code is injected by the test.
            try connection(fixture.path) { db in
                try execute("""
                    CREATE TABLE quick_check_fixture(value INTEGER CHECK(value>0));
                    PRAGMA ignore_check_constraints=ON;
                    INSERT INTO quick_check_fixture VALUES(0);
                    PRAGMA ignore_check_constraints=OFF;
                    """, on: db)
                let verdict = try rows("PRAGMA main.quick_check(1)", on: db)
                try #require(verdict.count == 1)
                try #require(verdict[0][0].bytes != Data("ok".utf8))
            }
        } else {
            var remaining = budget.snapshot().maximumBytes
            while remaining > 0 {
                let bytes = min(remaining, EventJournalCodec.maximumWorkspaceBytes)
                let lease = try #require(budget.tryAcquire(bytes: bytes, owner: .eventStoreWorkspace))
                occupied.append(lease)
                remaining -= bytes
            }
        }
        defer { withExtendedLifetime(occupied) {} }
        let before = try connection(fixture.path) { db in
            (try rows("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name", on: db),
             try rows("SELECT * FROM events ORDER BY id", on: db))
        }
        let initialLeases = budget.snapshot().activeLeases
        for _ in 0..<2 {
            do {
                _ = try EventStore(path: fixture.path, storagePolicy: policy, liveMemoryBudget: budget)
                Issue.record("Legacy structural check incorrectly admitted an incomplete verdict")
            } catch let error as EventStoreError {
                guard case .storageNotReady = error else { throw error }
            }
            #expect(budget.snapshot().activeLeases == initialLeases)
            #expect(budget.snapshot().withinCapacity && budget.snapshot().leasesConserved)
            try connection(fixture.path) { (db: OpaquePointer) throws -> Void in
                #expect(try scalar("PRAGMA user_version", on: db) == 6)
                #expect(try rows("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name", on: db) == before.0)
                #expect(try rows("SELECT * FROM events ORDER BY id", on: db) == before.1)
                #expect(try rows("SELECT * FROM alert_evidence ORDER BY alert_id,id", on: db) == fixture.evidence)
            }
            let files = try FileManager.default.contentsOfDirectory(atPath: fixture.directory.path)
            #expect(Set(files).isSubset(of: ["events.db", "events.db-wal", "events.db-shm"]))
        }
        // The same original store can retry when the explicit fixture issue
        // or temporary workspace occupation is resolved; no reset is needed.
        occupied.removeAll()
        if reason == "non-ok-verdict" {
            try connection(fixture.path) {
                try execute("UPDATE quick_check_fixture SET value=1", on: $0)
            }
        }
        let store = try EventStore(path: fixture.path, storagePolicy: policy, liveMemoryBudget: budget)
        let recovery = try await store.recoverJournalBeforeProducers()
        #expect(recovery.complete && recovery.sourceEvents == 4 && recovery.migratedEvents == 4)
        #expect(recovery.corruptPreservedEvents == 0 && recovery.rolledExpiredEvents == 0)
        try await expectExactEvents(fixture, in: store)
    }

    @Test("A finalized reopen does not repeat the legacy whole-database structural scan")
    func finalizedReopenSkipsLegacyStructuralCheck() async throws {
        let fixture = try fixture(count: 4, detailBytes: 1_000)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 128 * 1_048_576,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: fixture.directory.path)
        func migrate() async throws -> EventStore.EventJournalRecoverySnapshot {
            let store = try EventStore(path: fixture.path, storagePolicy: policy)
            let recovered = try await store.recoverJournalBeforeProducers()
            try #require(recovered.complete && recovered.migratedEvents == 4)
            return recovered
        }
        let recovery = try await migrate()
        try connection(fixture.path) { db in
            try execute("""
                CREATE TABLE unrelated_check_fixture(value INTEGER CHECK(value>0));
                PRAGMA ignore_check_constraints=ON;
                INSERT INTO unrelated_check_fixture VALUES(0);
                PRAGMA ignore_check_constraints=OFF;
                """, on: db)
            let verdict = try rows("PRAGMA main.quick_check(1)", on: db)
            try #require(verdict.count == 1)
            try #require(verdict[0][0].bytes != Data("ok".utf8))
        }
        let reopened = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try await reopened.recoverJournalBeforeProducers() == recovery)
        try await expectExactEvents(fixture, in: reopened)
    }
}
