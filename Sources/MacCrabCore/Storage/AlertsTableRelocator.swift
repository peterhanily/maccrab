// AlertsTableRelocator.swift
// MacCrabCore
//
// v1.8.0 storage split: move the `alerts` table out of `events.db` into
// its own `alerts.db` file. Runs once at daemon startup before AlertStore
// opens the production handle.
//
// Why a separate file at all:
//   Pre-split, alerts and events shared a single SQLite file governed by
//   one `retentionDays` knob and one `maxDatabaseSizeMB` cap. On a heavy-
//   event machine the firehose evicted alerts as collateral damage — a
//   user wanting a year of alert history had to keep a year of raw events
//   too, which is impossible at the measured ~950k events/hour rate. By
//   splitting the file, alerts get their own retention budget and survive
//   any prune of the event tier.
//
// The relocator is idempotent: if events.db has no `alerts` table (fresh
// install, or already migrated), it returns immediately. If a previous run
// partially migrated (copy succeeded but DROP failed, or vice versa),
// re-running fills the gap via INSERT OR IGNORE on the primary key.
//
// Failure mode: leave both states present, log error, return. The next
// daemon start retries. Never deletes from the source until copy is
// confirmed.

import Foundation
import CSQLCipher
import os.log

public enum AlertsTableRelocator {

    /// Move the `alerts` table from `<directory>/events.db` to
    /// `<directory>/alerts.db`. Idempotent. Best-effort; logs and returns
    /// on any failure.
    ///
    /// Caller must invoke this BEFORE opening either `EventStore` or
    /// `AlertStore` for normal daemon use, so the migration's writes don't
    /// contend with the long-lived production handles.
    ///
    /// - Returns: true if rows were copied + source dropped on this call;
    ///   false if no migration was needed or if a step failed.
    @discardableResult
    public static func relocate(
        directory: String,
        logger: Logger? = nil
    ) -> Bool {
        let eventsDB = directory + "/events.db"
        let alertsDB = directory + "/alerts.db"

        // Fresh install (no events.db yet) — nothing to migrate.
        guard FileManager.default.fileExists(atPath: eventsDB) else {
            return false
        }

        // Open events.db read-write. We need write access for ATTACH /
        // INSERT INTO new.alerts / DROP TABLE alerts / VACUUM.
        var srcHandle: OpaquePointer?
        let openRC = sqlite3_open_v2(
            eventsDB,
            &srcHandle,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard openRC == SQLITE_OK, let src = srcHandle else {
            if let h = srcHandle { sqlite3_close(h) }
            logger?.warning("AlertsTableRelocator: events.db open failed (rc=\(openRC, privacy: .public))")
            return false
        }
        defer { sqlite3_close(src) }

        // Match AlertStore's busy_timeout so we don't lose to a transient
        // contender during the brief migration window.
        sqlite3_exec(src, "PRAGMA busy_timeout = 5000", nil, nil, nil)

        // 1. If events.db has no `alerts` table, the migration ran on a
        //    previous start (or this is a fresh v1.8 install). No-op.
        guard tableExists(handle: src, schema: "main", name: "alerts") else {
            return false
        }

        let sourceCount = countRows(handle: src, table: "main.alerts") ?? 0

        // 2. Bootstrap alerts.db with the canonical AlertStore schema.
        //    AlertStore.init creates the tables + indexes and runs
        //    SchemaMigrator to the current version. Closing the bootstrap
        //    handle here releases the connection before we ATTACH below;
        //    ARC drops the actor at end of expression.
        do {
            _ = try AlertStore(directory: directory)
        } catch {
            logger?.error("AlertsTableRelocator: AlertStore bootstrap failed: \(error.localizedDescription, privacy: .public)")
            return false
        }

        // 3. ATTACH alerts.db onto the events.db connection. Path is
        //    derived from supportDir so there's no injection vector;
        //    quote-escape defensively for any embedded `'`.
        let escaped = alertsDB.replacingOccurrences(of: "'", with: "''")
        if sqlite3_exec(src, "ATTACH DATABASE '\(escaped)' AS new", nil, nil, nil) != SQLITE_OK {
            logger?.error("AlertsTableRelocator: ATTACH failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            return false
        }

        // 4. Compute the column intersection between source and target
        //    `alerts` tables. A v1.7 user upgrading directly to v1.8.0 has
        //    a v1-shape source (no llm_investigation_json); we want the
        //    INSERT to include only columns that exist in BOTH.
        let sourceCols = columns(handle: src, schema: "main", table: "alerts")
        let targetCols = Set(columns(handle: src, schema: "new", table: "alerts"))
        let common = sourceCols.filter { targetCols.contains($0) }
        guard !common.isEmpty else {
            logger?.error("AlertsTableRelocator: no common columns between events.db::alerts and alerts.db::alerts")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        let colList = common.joined(separator: ", ")

        // 5. Copy in a single transaction. INSERT OR IGNORE on PRIMARY KEY
        //    means a partial-rerun (target already has some rows) doesn't
        //    fail or duplicate.
        sqlite3_exec(src, "BEGIN IMMEDIATE TRANSACTION", nil, nil, nil)
        let insertSQL = "INSERT OR IGNORE INTO new.alerts (\(colList)) SELECT \(colList) FROM main.alerts"
        if sqlite3_exec(src, insertSQL, nil, nil, nil) != SQLITE_OK {
            logger?.error("AlertsTableRelocator: copy failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            sqlite3_exec(src, "ROLLBACK", nil, nil, nil)
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        let copied = Int(sqlite3_changes(src))
        sqlite3_exec(src, "COMMIT", nil, nil, nil)

        // 6. DROP the source table. INSERT OR IGNORE may have copied 0
        //    rows on a partial-rerun where the target already has all of
        //    them — that's still a successful migration outcome, so we
        //    drop regardless of the `copied` count.
        if sqlite3_exec(src, "DROP TABLE alerts", nil, nil, nil) != SQLITE_OK {
            logger?.error("AlertsTableRelocator: DROP TABLE failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }

        // 7. DETACH (must come before VACUUM — VACUUM cannot run with
        //    other databases attached on the same handle).
        sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)

        // 8. VACUUM events.db to reclaim the pages the alerts table held.
        //    Skip if free disk is too tight: VACUUM rebuilds into a
        //    parallel temp file ~= source file size, and a 1.2 GB events.db
        //    needs ~1.5 GB headroom. Mirrors the disk-safety check in
        //    runAdaptiveRollupSweep.
        let dbBytes = (try? FileManager.default.attributesOfItem(atPath: eventsDB)[.size] as? UInt64) ?? 0
        let dbMB = Int(dbBytes / 1_000_000)
        let freeMB = freeDiskMB(forPath: eventsDB)
        if freeMB >= Int(Double(dbMB) * 1.3) {
            if sqlite3_exec(src, "VACUUM", nil, nil, nil) != SQLITE_OK {
                logger?.warning("AlertsTableRelocator: VACUUM after migration failed (non-fatal): \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            }
        } else {
            logger?.warning("AlertsTableRelocator: skipping post-migration VACUUM (free \(freeMB, privacy: .public) MB < 1.3x DB \(dbMB, privacy: .public) MB) — pages will be reclaimed by next sweep")
        }

        logger?.notice("AlertsTableRelocator: migrated \(sourceCount, privacy: .public) alerts from events.db -> alerts.db (newly inserted on this run: \(copied, privacy: .public))")
        return true
    }

    // MARK: - Helpers

    private static func tableExists(
        handle: OpaquePointer,
        schema: String,
        name: String
    ) -> Bool {
        let sql = "SELECT 1 FROM \(schema).sqlite_master WHERE type='table' AND name=?1 LIMIT 1"
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        sqlite3_bind_text(stmt, 1, name, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        return sqlite3_step(stmt) == SQLITE_ROW
    }

    private static func countRows(handle: OpaquePointer, table: String) -> Int? {
        let sql = "SELECT COUNT(*) FROM \(table)"
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Column names for `<schema>.<table>` via PRAGMA table_info.
    private static func columns(
        handle: OpaquePointer,
        schema: String,
        table: String
    ) -> [String] {
        // PRAGMA table_info doesn't accept bound parameters; the schema
        // and table are interpolated directly. Both are caller-controlled
        // (literal "main"/"new" + literal "alerts"), no injection vector.
        let sql = "PRAGMA \(schema).table_info(\(table))"
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        var cols: [String] = []
        // Columns: 0=cid, 1=name, 2=type, 3=notnull, 4=dflt_value, 5=pk
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 1) {
                cols.append(String(cString: cstr))
            }
        }
        return cols
    }

    private static func freeDiskMB(forPath path: String) -> Int {
        var stat = statvfs()
        guard statvfs((path as NSString).utf8String, &stat) == 0 else { return 0 }
        let bytes = UInt64(stat.f_bavail) * UInt64(stat.f_frsize)
        return Int(bytes / 1_000_000)
    }
}
