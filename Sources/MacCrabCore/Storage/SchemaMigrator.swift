// SchemaMigrator.swift
// MacCrabCore
//
// Forward-only SQLite schema migrator keyed on PRAGMA user_version.
// Used by EventStore and AlertStore after base table creation.

import Foundation
import SQLite3

// MARK: - Migration

/// A single ordered schema migration step.
///
/// Each step runs `sql` statements in order inside a transaction, then bumps
/// `PRAGMA user_version` to `version`. Steps are idempotent for `ADD COLUMN`
/// failures: if SQLite reports a duplicate column, the statement is treated
/// as already-applied and skipped.
public struct Migration: Sendable {
    public let version: Int
    public let name: String
    public let sql: [String]

    public init(version: Int, name: String, sql: [String]) {
        self.version = version
        self.name = name
        self.sql = sql
    }
}

// MARK: - Errors

public enum SchemaMigrationError: Error, LocalizedError {
    case migrationFailed(version: Int, name: String, message: String)
    case versionReadFailed(String)
    case versionWriteFailed(String)
    case unknownVersion(current: Int, maxAvailable: Int)

    public var errorDescription: String? {
        switch self {
        case let .migrationFailed(v, n, m):
            return "Migration v\(v) '\(n)' failed: \(m)"
        case let .versionReadFailed(m):
            return "Failed to read user_version: \(m)"
        case let .versionWriteFailed(m):
            return "Failed to write user_version: \(m)"
        case let .unknownVersion(current, max):
            return "DB user_version=\(current) exceeds latest known v\(max); binary is older than DB."
        }
    }
}

// MARK: - SchemaMigrator

/// Forward-only SQLite schema migrator.
///
/// Usage (inside a store's static `openDatabase` helper):
/// ```
/// let (handle, _, _) = try openRawDB(at: path)
/// try SchemaMigrator.run(on: handle, migrations: Self.migrations)
/// ```
///
/// The migrator reads `PRAGMA user_version`, then applies each migration with
/// `version > current`, in ascending order, each wrapped in `BEGIN/COMMIT`.
/// On any statement failure the transaction is rolled back and the error is
/// propagated; `user_version` is only bumped after all statements for a step
/// succeed.
public enum SchemaMigrator {

    /// Apply any pending migrations to the given SQLite handle.
    ///
    /// - Parameters:
    ///   - db: Open SQLite handle (must be writable).
    ///   - migrations: All known migrations. Order-independent; sorted internally.
    ///   - logger: Optional callback for human-readable progress messages.
    /// - Throws: `SchemaMigrationError` on failure. State is left at the last
    ///   successfully committed version.
    public static func run(
        on db: OpaquePointer,
        migrations: [Migration],
        logger: ((String) -> Void)? = nil
    ) throws {
        let current = try readVersion(db: db)
        let latest = migrations.map(\.version).max() ?? 0

        // `PRAGMA user_version` is a single per-database counter. When
        // multiple stores (EventStore, AlertStore, CampaignStore) share
        // the same .db file, each runs its own migration chain against
        // the same counter. A store whose max version is behind the
        // counter must tolerate it — the counter simply records that
        // SOME store bumped the schema. SQLite's ALTER TABLE ADD COLUMN
        // is forward-compatible for readers, so our own tables keep
        // working even when another store has added columns to its.
        if current > latest {
            logger?("DB user_version=\(current) exceeds this store's latest known v\(latest) — another co-resident store bumped it; skipping")
            return
        }

        let pending = migrations
            .filter { $0.version > current }
            .sorted { $0.version < $1.version }

        if pending.isEmpty {
            logger?("Schema up to date at v\(current)")
            return
        }

        logger?("Migrating schema from v\(current) to v\(latest) (\(pending.count) step(s))")
        for m in pending {
            try apply(m, db: db, logger: logger)
        }
    }

    /// Read the current `PRAGMA user_version`. Returns 0 for a fresh DB.
    public static func readVersion(db: OpaquePointer) throws -> Int {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw SchemaMigrationError.versionReadFailed(msg)
        }
        defer { sqlite3_finalize(stmt) }

        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw SchemaMigrationError.versionReadFailed("no row from PRAGMA user_version")
        }
        return Int(sqlite3_column_int(stmt, 0))
    }

    // MARK: - Private

    private static func apply(
        _ m: Migration,
        db: OpaquePointer,
        logger: ((String) -> Void)?
    ) throws {
        logger?("  Applying v\(m.version): \(m.name)")

        guard sqlite3_exec(db, "BEGIN TRANSACTION", nil, nil, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw SchemaMigrationError.migrationFailed(
                version: m.version, name: m.name,
                message: "BEGIN failed: \(msg)"
            )
        }

        for sql in m.sql {
            var errmsg: UnsafeMutablePointer<CChar>?
            let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
            if rc != SQLITE_OK {
                let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
                sqlite3_free(errmsg)

                // Treat "duplicate column name" as already-applied — lets ADD COLUMN
                // be idempotent across partial-failure retries.
                if msg.lowercased().contains("duplicate column name") {
                    logger?("    skip (already applied): \(sql.prefix(80))")
                    continue
                }

                sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
                throw SchemaMigrationError.migrationFailed(
                    version: m.version, name: m.name,
                    message: "\(sql.prefix(120)) -> \(msg)"
                )
            }
        }

        // PRAGMA user_version supports parameterized values poorly; use literal.
        let bumpSQL = "PRAGMA user_version = \(m.version)"
        if sqlite3_exec(db, bumpSQL, nil, nil, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw SchemaMigrationError.versionWriteFailed(msg)
        }

        if sqlite3_exec(db, "COMMIT", nil, nil, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw SchemaMigrationError.migrationFailed(
                version: m.version, name: m.name,
                message: "COMMIT failed: \(msg)"
            )
        }
    }
}
