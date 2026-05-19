// SchemaMigrator.swift
// MacCrabCore
//
// Forward-only SQLite schema migrator keyed on PRAGMA user_version.
// Used by EventStore and AlertStore after base table creation.

import Foundation
import CSQLCipher

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
    case quickCheckFailed(String)

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
        case let .quickCheckFailed(m):
            return "PRAGMA quick_check failed after migrations: \(m)"
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
        logger: ((String) -> Void)? = nil,
        skipQuickCheck: Bool = false
    ) throws {
        let current = try readVersion(db: db)
        let latest = migrations.map(\.version).max() ?? 0

        // v1.7.6: `PRAGMA user_version` is a SINGLE per-database counter,
        // but EventStore + AlertStore (and CampaignStore in the campaigns DB)
        // share their respective files. The previous logic
        //
        //     pending = migrations.filter { $0.version > current }
        //
        // silently dropped a store's pending migrations whenever a co-resident
        // store had already bumped the counter. Reproduced in the field on
        // a v1.7.5 install: EventStore opened first, ran its v1..v2, counter=2;
        // AlertStore opened second, current==latest==2, pending=[], v2
        // ADD COLUMN llm_investigation_json was never applied → AlertStore's
        // INSERT prepare crashed at every boot, daemon crash-loop, "Detection
        // engine appears silent" banner.
        //
        // Fix: always run all of THIS store's migrations, in version order.
        // - apply() is idempotent for ADD COLUMN (duplicate-column-name handler).
        // - Callers use CREATE [TABLE|INDEX] IF NOT EXISTS for table/index ops.
        // - Bump user_version only on a forward step (m.version > current).
        //   Lowering the counter would mis-fire the leader store's filter
        //   on the next boot.
        //
        // Cost: a handful of cheap fail-fast SQLite calls per store init.
        // Non-idempotent ops (DROP, INSERT, UPDATE in a migration body) would
        // need per-store version tracking — none of our migrations use them.
        let sorted = migrations.sorted(by: { $0.version < $1.version })
        let alreadyAtOrAhead = current >= latest
        if alreadyAtOrAhead {
            logger?("DB user_version=\(current) at-or-ahead of v\(latest); re-applying \(sorted.count) migration(s) idempotently (no counter change)")
        } else {
            logger?("Migrating schema from v\(current) to v\(latest)")
        }
        for m in sorted {
            // Only bump on forward progress; otherwise leave the counter alone.
            let bump = m.version > current
            try apply(m, db: db, bumpVersion: bump, logger: logger)
        }

        // Post-migration quick_check: catches structure-level corruption
        // (orphan rowids, broken indexes, malformed pages) that didn't
        // surface during the migration's writes themselves. Originally
        // billed as "sub-second on a 500 MB DB" (v1.10 audit hardening),
        // but field measurement on a 962 MB events.db with FTS5 puts it
        // at 1–2 s of synchronous PRAGMA work — significant chunk of
        // daemon cold-start time. v1.12.0: callers that care about
        // boot latency pass `skipQuickCheck: true` and re-invoke
        // `SchemaMigrator.quickCheck(on:)` from a deferred Task once
        // the store is up. Corruption surfaces immediately on real
        // queries via SQLITE_CORRUPT, so deferring the up-front check
        // is a perf trade with no correctness loss.
        if !skipQuickCheck {
            try quickCheck(db: db, logger: logger)
        }
    }

    /// Run `PRAGMA quick_check`. Throws `quickCheckFailed` if SQLite reports
    /// anything other than the literal `ok` row — that's the documented
    /// SQLite contract. Logs the issues at warn level for diagnostic capture
    /// before throwing.
    public static func quickCheck(
        on db: OpaquePointer,
        logger: ((String) -> Void)? = nil
    ) throws {
        try quickCheck(db: db, logger: logger)
    }

    private static func quickCheck(
        db: OpaquePointer,
        logger: ((String) -> Void)?
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA quick_check", -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw SchemaMigrationError.quickCheckFailed("prepare failed: \(msg)")
        }
        defer { sqlite3_finalize(stmt) }

        var issues: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 0) {
                let row = String(cString: cstr)
                if row != "ok" { issues.append(row) }
            }
        }
        if !issues.isEmpty {
            let summary = issues.prefix(5).joined(separator: "; ")
            logger?("  quick_check FAILED: \(summary)")
            throw SchemaMigrationError.quickCheckFailed(summary)
        }
        logger?("  quick_check ok")
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
        bumpVersion: Bool = true,
        logger: ((String) -> Void)?
    ) throws {
        logger?("  Applying v\(m.version): \(m.name)\(bumpVersion ? "" : " (idempotent re-run, no version bump)")")

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

                // Treat "already-exists" failures as idempotent re-runs — lets the
                // co-resident-store branch in run() safely re-apply CREATE / ALTER
                // statements that previously succeeded. v1.7.6 broadened this from
                // ADD-COLUMN-only to also cover bare CREATE TABLE / CREATE INDEX
                // (callers should use IF NOT EXISTS, but this is defense in depth
                // for migrations that pre-date the convention).
                let lower = msg.lowercased()
                if lower.contains("duplicate column name")
                    || lower.contains("already exists") {
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
        // Skip the bump on idempotent re-runs (v1.7.6) — the counter is already
        // ahead of m.version, set by another co-resident store. Lowering it
        // would make EventStore's pending-migration filter mis-fire next boot.
        if bumpVersion {
            let bumpSQL = "PRAGMA user_version = \(m.version)"
            if sqlite3_exec(db, bumpSQL, nil, nil, nil) != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(db))
                sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
                throw SchemaMigrationError.versionWriteFailed(msg)
            }
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
