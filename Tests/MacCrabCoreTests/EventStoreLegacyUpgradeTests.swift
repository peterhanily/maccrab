import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore

@Suite("Shipped EventStore upgrade")
struct EventStoreLegacyUpgradeTests {
    private struct Fixture {
        let directory: URL
        let first: Event
        let last: Event
        let alertID: String
        let evidenceJSON: Data
        let timestampIndexBytes: Int64
        let pageSizeBytes: Int64
        var path: String { directory.appendingPathComponent("events.db").path }
    }

    private func fixture(rows: Int) throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("legacy-event-upgrade-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var succeeded = false
        defer { if !succeeded { try? FileManager.default.removeItem(at: directory) } }
        let path = directory.appendingPathComponent("events.db").path
        var raw: OpaquePointer?
        #expect(sqlite3_open(path, &raw) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        let schemaURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("fixtures/event-store-v1.21.5.sql")
        let schema = try String(contentsOf: schemaURL, encoding: .utf8)
        try execute(schema, on: db)
        try execute("BEGIN IMMEDIATE", on: db)
        var statement: OpaquePointer?
        let sql = """
            INSERT INTO events (
                id, timestamp, event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline, process_ppid, raw_json
            ) VALUES (?1, ?2, 'process', 'start', 'exec', 'informational',
                      4242, 'true', '/usr/bin/true', '/usr/bin/true', 1, ?3)
            """
        #expect(sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK)
        let insert = try #require(statement)
        defer { sqlite3_finalize(insert) }
        let transient = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        let now = Date()
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1, name: "true", executable: "/usr/bin/true",
            commandLine: "/usr/bin/true", args: ["/usr/bin/true"], workingDirectory: "/",
            userId: 501, userName: "tester", groupId: 20, startTime: now,
            ancestors: [], isPlatformBinary: false
        )
        var first: Event?
        var last: Event?
        var firstJSON: Data?
        for index in 0..<rows {
            let event = Event(
                timestamp: now.addingTimeInterval(-Double(index) / 1_000),
                eventCategory: .process, eventType: .start, eventAction: "exec", process: process
            )
            if first == nil { first = event }
            last = event
            let json = String(decoding: try JSONEncoder().encode(event), as: UTF8.self)
            if firstJSON == nil { firstJSON = Data(json.utf8) }
            sqlite3_reset(insert)
            sqlite3_bind_text(insert, 1, event.id.uuidString, -1, transient)
            sqlite3_bind_double(insert, 2, event.timestamp.timeIntervalSince1970)
            sqlite3_bind_text(insert, 3, json, -1, transient)
            guard sqlite3_step(insert) == SQLITE_DONE else {
                throw NSError(domain: "LegacyUpgradeFixture", code: Int(sqlite3_errcode(db)))
            }
        }
        let firstEvent = try #require(first)
        let alertID = UUID().uuidString
        var evidenceStatement: OpaquePointer?
        #expect(sqlite3_prepare_v2(db, """
            INSERT INTO alert_evidence (
                alert_id, id, timestamp, event_category, event_type,
                event_action, severity, process_pid, process_name, process_path, raw_json
            ) SELECT ?1, id, timestamp, event_category, event_type,
                     event_action, severity, process_pid, process_name, process_path, raw_json
              FROM events WHERE id = ?2
            """, -1, &evidenceStatement, nil) == SQLITE_OK)
        let evidenceInsert = try #require(evidenceStatement)
        defer { sqlite3_finalize(evidenceInsert) }
        sqlite3_bind_text(evidenceInsert, 1, alertID, -1, transient)
        sqlite3_bind_text(evidenceInsert, 2, firstEvent.id.uuidString, -1, transient)
        #expect(sqlite3_step(evidenceInsert) == SQLITE_DONE)
        #expect(sqlite3_changes(db) == 1)
        try execute("COMMIT", on: db)
        let result = Fixture(
            directory: directory, first: firstEvent, last: try #require(last),
            alertID: alertID, evidenceJSON: try #require(firstJSON),
            timestampIndexBytes: try scalar(
                "SELECT SUM(pgsize) FROM dbstat WHERE name = 'idx_events_timestamp'", on: db
            ),
            pageSizeBytes: try scalar("PRAGMA page_size", on: db)
        )
        succeeded = true
        return result
    }

    private func scalar(_ sql: String, on db: OpaquePointer) throws -> Int64 {
        var raw: OpaquePointer?
        #expect(sqlite3_prepare_v2(db, sql, -1, &raw, nil) == SQLITE_OK)
        let statement = try #require(raw)
        defer { sqlite3_finalize(statement) }
        #expect(sqlite3_step(statement) == SQLITE_ROW)
        return sqlite3_column_int64(statement, 0)
    }

    private func preservedEvidence(in fixture: Fixture) throws -> Data {
        var raw: OpaquePointer?
        #expect(sqlite3_open_v2(fixture.path, &raw, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            db, "SELECT raw_json FROM alert_evidence WHERE alert_id = ?1", -1, &statement, nil
        ) == SQLITE_OK)
        let query = try #require(statement)
        defer { sqlite3_finalize(query) }
        sqlite3_bind_text(query, 1, fixture.alertID, -1, unsafeBitCast(
            OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self
        ))
        #expect(sqlite3_step(query) == SQLITE_ROW)
        let bytes = try #require(sqlite3_column_blob(query, 0))
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(query, 0)))
    }

    private func hasInstalledBarrier(in fixture: Fixture) throws -> Bool {
        var raw: OpaquePointer?
        try #require(sqlite3_open_v2(fixture.path, &raw, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        return try scalar("""
            SELECT COUNT(*) FROM sqlite_master
            WHERE name = 'idx_events_timestamp' AND type = 'view'
            """, on: db) == 1
    }

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw NSError(domain: "LegacyUpgradeFixture", code: Int(rc), userInfo: [
                NSLocalizedDescriptionKey: String(cString: sqlite3_errmsg(db)),
            ])
        }
    }

    @Test("Shipped schema survives reopen before recovery and preserves exact events")
    func recoverAfterReopen() async throws {
        let fixture = try fixture(rows: 3)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        var initial: EventStore? = try EventStore(path: fixture.path)
        #expect(try await initial?.count() == 3)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        initial = nil
        let store = try EventStore(path: fixture.path)
        let recovery = try await store.recoverJournalBeforeProducers()
        #expect(recovery.complete)
        #expect(recovery.sourceEvents == 3)
        #expect(recovery.migratedEvents == 3)
        #expect(recovery.corruptPreservedEvents == 0)
        #expect(recovery.remainingEvents == 0)
        let evidence = try await store.evidenceFor(alertId: fixture.alertID)
        #expect(evidence.count == 1)
        #expect(evidence.first?.id == fixture.first.id)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
        for event in [fixture.first, fixture.last] {
            let snapshot = try await store.exactEventSnapshot(id: event.id)
            #expect(snapshot.event?.id == event.id)
            #expect(snapshot.event?.process.args == event.process.args)
            #expect(snapshot.event?.timestamp == event.timestamp)
        }
        let reopened = try EventStore(path: fixture.path)
        #expect(try await reopened.recoverJournalBeforeProducers().complete)
        #expect(try await reopened.count() == 3)
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
    }

    @Test("A legacy index uses available schema space independently of row-write reserve",
          arguments: [50_000, 1_500_000])
    func independentlySizedSchemaWork(rows: Int) async throws {
        let fixture = try fixture(rows: rows)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        // The large corpus crosses the actual production 32 MiB reserve.
        // Its explicit family cap models an operator retaining a larger store;
        // the ordinary default cap does not promise to hold 1.5M full events.
        let largeCorpus = rows > 50_000
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: (largeCorpus ? 8_192 : 512) * 1_048_576,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: largeCorpus
                ? SQLitePersistentStorePolicy.eventTransactionReserveBytes
                : 4 * 1_048_576,
            storageVolumePath: fixture.directory.path
        )
        // This shipped schema has 12 missing write guards and one barrier view.
        // Verify the fixture actually requires more than its ordinary reserve;
        // otherwise a smaller index after fixture changes could mask regression.
        let barrierEstimate = SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: fixture.timestampIndexBytes * 2
                + 13 * SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
            pageSizeBytes: fixture.pageSizeBytes,
            maximumTreePathPageTouches: 20
        )
        #expect(barrierEstimate > policy.transactionReserveBytes)
        print("Legacy upgrade fixture rows=\(rows) timestamp_index_bytes=\(fixture.timestampIndexBytes) schema_estimate_bytes=\(barrierEstimate) row_reserve_bytes=\(policy.transactionReserveBytes)")
        let store = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try hasInstalledBarrier(in: fixture))
        // This scale assertion measures schema transition and row preservation.
        // count() deliberately decodes/sanitizes the entire legacy corpus; its
        // evidence semantics are covered by the smaller case and recovery test.
        if largeCorpus {
            #expect(try await store.maintenanceRetainedRecordCount() == rows)
        } else {
            #expect(try await store.count() == rows)
        }
        let first = try await store.exactEventSnapshot(id: fixture.first.id)
        #expect(first.event?.id == fixture.first.id)
        #expect(first.event?.timestamp == fixture.first.timestamp)
        #expect(first.event?.process.args == fixture.first.process.args)
        let reopened = try EventStore(path: fixture.path, storagePolicy: policy)
        #expect(try hasInstalledBarrier(in: fixture))
        if largeCorpus {
            #expect(try await reopened.maintenanceRetainedRecordCount() == rows)
        } else {
            #expect(try await reopened.count() == rows)
        }
        #expect(try preservedEvidence(in: fixture) == fixture.evidenceJSON)
    }
}
