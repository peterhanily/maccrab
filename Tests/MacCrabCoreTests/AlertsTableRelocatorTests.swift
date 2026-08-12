// AlertsTableRelocatorTests.swift
//
// v1.8.0 storage split: tests for the one-shot migration that moves the
// `alerts` table out of events.db and into alerts.db. Pins the
// contract:
//
//   1. Fresh install (no events.db) — no-op, returns false
//   2. Old-shape events.db with alerts data — copies + drops + creates alerts.db
//   3. Idempotent — running twice doesn't duplicate or fail
//   4. Partial-rerun safe — identical target rows are verified before source drop
//   5. v1-shape source (no llm_investigation_json) — column intersection works
//   6. Divergent primary-key collision — fail closed and retain source
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
            let ts = 1_700_000_000.0 - Double(i)
            let sql = """
                INSERT INTO alerts (id, timestamp, rule_id, rule_title, severity, event_id, suppressed)
                VALUES ('\(id)', \(ts), 'test.rule', 'Test \(i)', 'high', 'evt-\(i)', 0)
                """
            sqlite3_exec(db, sql, nil, nil, nil)
        }
    }

    private func makeEventsDBWithoutLegacyAlerts(at directory: URL) throws {
        let path = directory.appendingPathComponent("events.db").path
        var handle: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let db = handle else {
            sqlite3_close(handle)
            throw TestSetupError.openFailed
        }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(
            db,
            "CREATE TABLE events (id TEXT PRIMARY KEY)",
            nil,
            nil,
            nil
        ) == SQLITE_OK else {
            throw TestSetupError.openFailed
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

    private func replaceLegacyRuleID(
        at directory: URL,
        with ruleID: String
    ) throws {
        let path = directory.appendingPathComponent("events.db").path
        var handle: OpaquePointer?
        guard sqlite3_open_v2(
            path,
            &handle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        ) == SQLITE_OK, let db = handle else {
            throw TestSetupError.openFailed
        }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "UPDATE alerts SET rule_id = ?1",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw TestSetupError.openFailed
        }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(
            statement,
            1,
            ruleID,
            -1,
            unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        )
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw TestSetupError.openFailed
        }
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

    @Test("already-migrated source does not preflight a shed-only target")
    func migratedSourceSkipsTargetAdmission() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        try makeEventsDBWithoutLegacyAlerts(at: dir)

        // This is a regular family member but it is deliberately above the
        // supplied target's ordinary cap-reserve boundary. It is also not a
        // SQLite database: touching/bootstrap-opening it would fail. With no
        // legacy source table, relocation must not inspect or mutate it.
        let alertsPath = dir.appendingPathComponent("alerts.db")
        let original = Data(repeating: 0xA5, count: 4 * 1_048_576)
        try original.write(to: alertsPath)
        let targetPolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 4 * 1_048_576,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: 1_048_576,
            storageVolumePath: dir.path
        )

        #expect(!AlertsTableRelocator.relocate(
            directory: dir.path,
            alertStoragePolicy: targetPolicy
        ))
        #expect(eventsAlertsCount(at: dir) == nil)
        #expect(try Data(contentsOf: alertsPath) == original)

        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent(
                    "Sources/MacCrabCore/Storage/AlertsTableRelocator.swift"
                ),
            encoding: .utf8
        )
        let noOpCheck = try #require(source.range(of:
            "guard tableExists(handle: src, schema: \"main\", name: \"alerts\")"
        ))
        let targetAdmission = try #require(source.range(of:
            "alertAdmission = try SQLitePersistentStoreAdmission("
        ))
        #expect(noOpCheck.lowerBound < targetAdmission.lowerBound)
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

    @Test("Divergent target primary-key collision retains authoritative source")
    func divergentTargetCollisionFailsClosed() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 1)
        var bootstrap: AlertStore? = try AlertStore(directory: dir.path)
        try await bootstrap?.insert(alert: Alert(
            id: "alert-0",
            timestamp: Date(timeIntervalSince1970: 1),
            ruleId: "conflicting.rule",
            ruleTitle: "Divergent target row",
            severity: .low,
            eventId: "conflicting-event"
        ))
        bootstrap = nil

        let migrated = AlertsTableRelocator.relocate(directory: dir.path)

        #expect(migrated == false)
        #expect(eventsAlertsCount(at: dir) == 1,
                "a divergent OR IGNORE collision must never drain the source")
        let target = try AlertStore(directory: dir.path)
        let alerts = try await target.alerts(
            since: Date.distantPast,
            limit: 10
        )
        #expect(alerts.count == 1)
        #expect(alerts.first?.ruleTitle == "Divergent target row")
    }

    @Test("Identical pre-existing target row is verified before source drain")
    func identicalTargetRowCompletesPartialRerun() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 1)
        var bootstrap: AlertStore? = try AlertStore(directory: dir.path)
        try await bootstrap?.insert(alert: Alert(
            id: "alert-0",
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            ruleId: "test.rule",
            ruleTitle: "Test 0",
            severity: .high,
            eventId: "evt-0"
        ))
        bootstrap = nil

        let migrated = AlertsTableRelocator.relocate(directory: dir.path)

        #expect(migrated == true)
        #expect(eventsAlertsCount(at: dir) == nil)
        let target = try AlertStore(directory: dir.path)
        let alerts = try await target.alerts(
            since: Date.distantPast,
            limit: 10
        )
        #expect(alerts.count == 1)
        #expect(alerts.first?.id == "alert-0")
    }

    @Test("Target indexed-text amplification is admitted before source copy or drain")
    func indexedTargetAmplificationFailsClosed() async throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        try makeOldEventsDB(at: dir, rowCount: 1)
        // The legacy table stores rule_id once. The current destination stores
        // it in the table and two independent indexes, so source dbstat bytes
        // alone are not a target-growth bound.
        try replaceLegacyRuleID(
            at: dir,
            with: String(repeating: "r", count: 4 * 1_048_576)
        )
        let eventPolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 64 * 1_048_576,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes: 1_048_576,
            storageVolumePath: dir.path
        )
        // Test-only alert policy: production has no named low-volume reserve
        // constant, and this fixture needs at least the 1.5 MiB schema bound.
        let alertFixtureTransactionReserveBytes = Int64(2 * 1_048_576)
        let alertPolicy = SQLitePersistentStorePolicy(
            maxFootprintBytes: 16 * 1_048_576,
            freeSpaceFloorBytes: 0,
            // Current alert bootstrap has a 1.5 MiB indexed-schema upper
            // bound. Keep that transaction valid so this fixture reaches the
            // intended indexed-copy headroom refusal rather than failing early
            // on an undersized schema reserve.
            transactionReserveBytes: alertFixtureTransactionReserveBytes,
            storageVolumePath: dir.path
        )

        let migrated = AlertsTableRelocator.relocate(
            directory: dir.path,
            eventStoragePolicy: eventPolicy,
            alertStoragePolicy: alertPolicy
        )

        #expect(!migrated)
        #expect(eventsAlertsCount(at: dir) == 1,
                "target headroom refusal must leave authoritative source intact")
        let target = try AlertStore(
            directory: dir.path,
            storagePolicy: alertPolicy
        )
        #expect(try await target.count() == 0,
                "admission must occur before INSERT...SELECT begins")
    }
}
