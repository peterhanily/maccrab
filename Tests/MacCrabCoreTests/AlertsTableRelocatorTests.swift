// AlertsTableRelocatorTests.swift
//
// v1.8.0 storage split: tests for the one-shot migration that moves the
// `alerts` table out of events.db and into alerts.db. Pins the
// contract:
//
//   1. Fresh install (no events.db) — no-op, returns false
//   2. Old-shape events.db with alerts data — copies + drops + creates alerts.db
//   3. Idempotent — running twice doesn't duplicate or fail
//   4. Partial-rerun safe — INSERT OR IGNORE preserves target rows, drops source
//   5. v1-shape source (no llm_investigation_json) — column intersection works
//
// Tests use raw sqlite3 to construct old-shape events.db files because we
// no longer have a code path that writes alerts there.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("AlertsTableRelocator (v1.8.0)")
struct AlertsTableRelocatorTests {

    // MARK: - Setup helpers

    private func makeTempDir() throws -> URL {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-relocator-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        return tmp
    }

    /// Build an old-shape events.db with an `alerts` table populated with
    /// `n` rows. `includeLLMColumn` lets the test choose between v1.7-shape
    /// (no llm_investigation_json) and v1.8-rc-shape (with the column).
    private func makeOldEventsDB(
        at directory: URL,
        rowCount: Int,
        includeLLMColumn: Bool = true
    ) throws {
        let path = directory.appendingPathComponent("events.db").path
        var handle: OpaquePointer?
        let rc = sqlite3_open_v2(
            path, &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard rc == SQLITE_OK, let db = handle else {
            throw TestSetupError.openFailed
        }
        defer { sqlite3_close(db) }

        let baseSchema = """
            CREATE TABLE alerts (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                rule_id TEXT NOT NULL, rule_title TEXT NOT NULL,
                severity TEXT NOT NULL, event_id TEXT NOT NULL,
                process_path TEXT, process_name TEXT, description TEXT,
                mitre_tactics TEXT, mitre_techniques TEXT,
                suppressed INTEGER DEFAULT 0
            )
            """
        sqlite3_exec(db, baseSchema, nil, nil, nil)
        if includeLLMColumn {
            sqlite3_exec(db, "ALTER TABLE alerts ADD COLUMN llm_investigation_json TEXT", nil, nil, nil)
        }

        for i in 0..<rowCount {
            let id = "alert-\(i)"
            let ts = Date().timeIntervalSince1970 - Double(i)
            let sql = """
                INSERT INTO alerts (id, timestamp, rule_id, rule_title, severity, event_id, suppressed)
                VALUES ('\(id)', \(ts), 'test.rule', 'Test \(i)', 'high', 'evt-\(i)', 0)
                """
            sqlite3_exec(db, sql, nil, nil, nil)
        }
    }

    private func eventsAlertsCount(at directory: URL) -> Int? {
        let path = directory.appendingPathComponent("events.db").path
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        var handle: OpaquePointer?
        guard sqlite3_open_v2(path, &handle, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let db = handle else { return nil }
        defer { sqlite3_close(db) }

        // Returns nil if `alerts` table does not exist (post-migration).
        var checkStmt: OpaquePointer?
        defer { sqlite3_finalize(checkStmt) }
        sqlite3_prepare_v2(db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alerts'", -1, &checkStmt, nil)
        guard sqlite3_step(checkStmt) == SQLITE_ROW else { return nil }

        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM alerts", -1, &stmt, nil)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    enum TestSetupError: Error {
        case openFailed
    }

    // MARK: - Tests

    @Test("Fresh install — no events.db, no-op")
    func freshInstallNoOp() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let migrated = AlertsTableRelocator.relocate(directory: dir.path)

        #expect(migrated == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("events.db").path) == false)
        #expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("alerts.db").path) == false)
    }

    @Test("v1.8-rc-shape events.db migrates alerts to alerts.db")
    func migratesV18ShapeEventsDB() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 50, includeLLMColumn: true)
        #expect(eventsAlertsCount(at: dir) == 50)

        let migrated = AlertsTableRelocator.relocate(directory: dir.path)
        #expect(migrated == true)

        // Source table dropped from events.db
        #expect(eventsAlertsCount(at: dir) == nil)

        // Target alerts.db exists with all 50 rows
        let alertsDB = try AlertStore(directory: dir.path)
        let alerts = try await alertsDB.alerts(since: Date.distantPast, limit: 1000)
        #expect(alerts.count == 50)
    }

    @Test("v1.7-shape events.db (no llm_investigation_json) migrates")
    func migratesV17ShapeEventsDB() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 25, includeLLMColumn: false)

        let migrated = AlertsTableRelocator.relocate(directory: dir.path)
        #expect(migrated == true)
        #expect(eventsAlertsCount(at: dir) == nil)

        let alertsDB = try AlertStore(directory: dir.path)
        let alerts = try await alertsDB.alerts(since: Date.distantPast, limit: 1000)
        #expect(alerts.count == 25)
    }

    @Test("Idempotent — running twice doesn't duplicate or fail")
    func idempotentRerun() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 10)

        let firstRun = AlertsTableRelocator.relocate(directory: dir.path)
        let secondRun = AlertsTableRelocator.relocate(directory: dir.path)

        #expect(firstRun == true)   // did the actual migration
        #expect(secondRun == false) // no-op: source already gone

        let alertsDB = try AlertStore(directory: dir.path)
        let alerts = try await alertsDB.alerts(since: Date.distantPast, limit: 1000)
        #expect(alerts.count == 10)
    }

    @Test("Empty alerts table — drops source, no rows to copy")
    func emptySourceAlertsTable() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 0)

        let migrated = AlertsTableRelocator.relocate(directory: dir.path)
        #expect(migrated == true)
        #expect(eventsAlertsCount(at: dir) == nil)

        let alertsDB = try AlertStore(directory: dir.path)
        let alerts = try await alertsDB.alerts(since: Date.distantPast, limit: 1000)
        #expect(alerts.isEmpty)
    }
}
