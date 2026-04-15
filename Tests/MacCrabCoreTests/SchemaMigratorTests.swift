// SchemaMigratorTests.swift
// Unit tests for the forward-only SchemaMigrator.

import Testing
import Foundation
import SQLite3
@testable import MacCrabCore

@Suite("Schema Migrator")
struct SchemaMigratorTests {

    /// Open a throwaway SQLite DB at a temp path and return the handle + cleanup closure.
    private func openTempDB() -> (handle: OpaquePointer, path: String, close: () -> Void) {
        let path = NSTemporaryDirectory() + "maccrab_schema_test_\(UUID().uuidString).sqlite"
        var db: OpaquePointer?
        let rc = sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard rc == SQLITE_OK, let handle = db else {
            fatalError("Failed to open test DB: \(rc)")
        }
        let close = {
            sqlite3_close(handle)
            try? FileManager.default.removeItem(atPath: path)
        }
        return (handle, path, close)
    }

    /// True iff the given table has a column with the given name.
    private func hasColumn(_ db: OpaquePointer, table: String, column: String) -> Bool {
        var stmt: OpaquePointer?
        let sql = "PRAGMA table_info(\(table))"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 1), String(cString: cstr) == column {
                return true
            }
        }
        return false
    }

    @Test("Fresh DB reports user_version = 0")
    func freshDBVersion() throws {
        let db = openTempDB()
        defer { db.close() }
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 0)
    }

    @Test("Empty migration list is a no-op")
    func noMigrations() throws {
        let db = openTempDB()
        defer { db.close() }
        try SchemaMigrator.run(on: db.handle, migrations: [])
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 0)
    }

    @Test("Applies a single migration end-to-end")
    func singleMigration() throws {
        let db = openTempDB()
        defer { db.close() }

        let migrations = [
            Migration(version: 1, name: "create_events",
                      sql: ["CREATE TABLE events (id TEXT PRIMARY KEY)"]),
        ]

        try SchemaMigrator.run(on: db.handle, migrations: migrations)
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 1)
        #expect(hasColumn(db.handle, table: "events", column: "id"))
    }

    @Test("Applies migrations in order, skips already-applied")
    func ordered() throws {
        let db = openTempDB()
        defer { db.close() }

        let migrations = [
            Migration(version: 2, name: "add_file_sha",
                      sql: ["ALTER TABLE events ADD COLUMN file_sha256 TEXT"]),
            Migration(version: 1, name: "create_events",
                      sql: ["CREATE TABLE events (id TEXT PRIMARY KEY)"]),
        ]

        try SchemaMigrator.run(on: db.handle, migrations: migrations)
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 2)
        #expect(hasColumn(db.handle, table: "events", column: "file_sha256"))

        // Running again is a no-op.
        try SchemaMigrator.run(on: db.handle, migrations: migrations)
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 2)
    }

    @Test("Skips duplicate-column failures idempotently")
    func duplicateColumnIdempotent() throws {
        let db = openTempDB()
        defer { db.close() }

        // v1: create table with col_a already present.
        let v1 = Migration(version: 1, name: "create",
                           sql: ["CREATE TABLE t (id INTEGER, col_a TEXT)"])
        try SchemaMigrator.run(on: db.handle, migrations: [v1])

        // v2: try to add col_a again (duplicate). Should be skipped without error.
        let v2 = Migration(version: 2, name: "add_col_a_again",
                           sql: ["ALTER TABLE t ADD COLUMN col_a TEXT"])
        // Manually set user_version back to 1 so the migrator retries the v2 step.
        sqlite3_exec(db.handle, "PRAGMA user_version = 1", nil, nil, nil)

        try SchemaMigrator.run(on: db.handle, migrations: [v1, v2])
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 2)
    }

    @Test("Rolls back a failing migration and leaves version unchanged")
    func rollbackOnFailure() throws {
        let db = openTempDB()
        defer { db.close() }

        let v1 = Migration(version: 1, name: "create",
                           sql: ["CREATE TABLE t (id INTEGER)"])
        try SchemaMigrator.run(on: db.handle, migrations: [v1])

        let broken = Migration(version: 2, name: "broken",
                               sql: [
                                 "ALTER TABLE t ADD COLUMN col_b TEXT",
                                 "THIS IS NOT SQL",
                               ])

        #expect(throws: SchemaMigrationError.self) {
            try SchemaMigrator.run(on: db.handle, migrations: [v1, broken])
        }
        // Version unchanged.
        #expect(try SchemaMigrator.readVersion(db: db.handle) == 1)
        // First statement of v2 also rolled back.
        #expect(!hasColumn(db.handle, table: "t", column: "col_b"))
    }

    @Test("Rejects DBs at a version newer than the binary knows about")
    func newerDBRejected() throws {
        let db = openTempDB()
        defer { db.close() }

        sqlite3_exec(db.handle, "PRAGMA user_version = 99", nil, nil, nil)

        let v1 = Migration(version: 1, name: "create",
                           sql: ["CREATE TABLE t (id INTEGER)"])
        #expect(throws: SchemaMigrationError.self) {
            try SchemaMigrator.run(on: db.handle, migrations: [v1])
        }
    }

    @Test("Reports migration progress via logger callback")
    func loggerCalled() throws {
        let db = openTempDB()
        defer { db.close() }

        let migrations = [
            Migration(version: 1, name: "first", sql: ["CREATE TABLE a (x INT)"]),
            Migration(version: 2, name: "second", sql: ["CREATE TABLE b (y INT)"]),
        ]

        var messages: [String] = []
        try SchemaMigrator.run(on: db.handle, migrations: migrations) { messages.append($0) }

        #expect(messages.contains(where: { $0.contains("v1") && $0.contains("first") }))
        #expect(messages.contains(where: { $0.contains("v2") && $0.contains("second") }))
    }
}
