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
        eventStoragePolicy suppliedEventPolicy: SQLitePersistentStorePolicy? = nil,
        alertStoragePolicy suppliedAlertPolicy: SQLitePersistentStorePolicy? = nil,
        logger: Logger? = nil
    ) -> Bool {
        let eventsDB = directory + "/events.db"
        let alertsDB = directory + "/alerts.db"
        let eventPolicy = suppliedEventPolicy ?? SQLitePersistentStorePolicy(
            maxFootprintBytes: 340 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy
                .eventTransactionReserveBytes,
            storageVolumePath: directory
        )
        let alertPolicy = suppliedAlertPolicy ?? SQLitePersistentStorePolicy(
            maxFootprintBytes: AlertStore.combinedFamilyCapBytes(
                alertsMaxSizeMiB: 100,
                evidenceMaxSizeMiB: 100
            ),
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            storageVolumePath: directory
        )

        // Fresh install (no events.db yet) — nothing to migrate.
        guard FileManager.default.fileExists(atPath: eventsDB) else {
            return false
        }

        // Open events.db read-write. We need write access for ATTACH /
        // INSERT INTO new.alerts / DROP TABLE alerts / VACUUM.
        var srcHandle: OpaquePointer?
        let openRC = SQLiteOpenPathPolicy.open(
            eventsDB,
            database: &srcHandle,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        )
        guard openRC == SQLITE_OK, let src = srcHandle else {
            if let h = srcHandle { sqlite3_close(h) }
            logger?.warning("AlertsTableRelocator: events.db open failed (rc=\(openRC, privacy: .public))")
            return false
        }
        let checkpointController: SQLiteControlledCheckpointController
        do {
            checkpointController = try .install(
                on: src,
                thresholdPages: StoragePragmas.walAutocheckpointPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: eventsDB,
                        policy: eventPolicy
                    ),
                ]
            )
        } catch {
            sqlite3_close(src)
            logger?.error("AlertsTableRelocator: controlled checkpoint setup failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
        defer {
            checkpointController.detach(from: src)
            sqlite3_close(src)
        }

        // Match AlertStore's busy_timeout so we don't lose to a transient
        // contender during the brief migration window.
        sqlite3_exec(src, "PRAGMA busy_timeout = 5000", nil, nil, nil)

        // 1. If events.db has no `alerts` table, the migration ran on a
        //    previous start (or this is a fresh v1.8 install). No-op.
        guard tableExists(handle: src, schema: "main", name: "alerts") else {
            return false
        }

        // Admission belongs to the migration, not to the no-op startup probe.
        // In particular, an already-migrated alerts.db can legitimately open
        // shed-only while it awaits size-cap maintenance. Checking that target
        // before proving the legacy source table exists stranded every such
        // host in a useless "pre-open storage admission failed" path on every
        // boot. Once migration is actually required, keep both existing gates:
        // source deletion is maintenance, while target copy growth must fit the
        // ordinary alert-family policy before either database is mutated.
        var eventAdmission: SQLitePersistentStoreAdmission
        var alertAdmission: SQLitePersistentStoreAdmission
        do {
            eventAdmission = try SQLitePersistentStoreAdmission(
                databasePath: eventsDB,
                policy: eventPolicy,
                maintenance: true
            )
            alertAdmission = try SQLitePersistentStoreAdmission(
                databasePath: alertsDB,
                policy: alertPolicy
            )
            try eventAdmission.admitMaintenanceWrite(
                estimatedTransactionBytes: 0
            )
        } catch {
            logger?.error("AlertsTableRelocator: required migration storage admission failed: \(error.localizedDescription, privacy: .public)")
            return false
        }

        let sourceCount = countRows(handle: src, table: "main.alerts") ?? 0

        // 2. Bootstrap alerts.db with the canonical AlertStore schema.
        //    AlertStore.init creates the tables + indexes and runs
        //    SchemaMigrator to the current version. Closing the bootstrap
        //    handle here releases the connection before we ATTACH below;
        //    ARC drops the actor at end of expression.
        do {
            _ = try AlertStore(
                directory: directory,
                storagePolicy: alertPolicy
            )
        } catch {
            logger?.error("AlertsTableRelocator: AlertStore bootstrap failed: \(error.localizedDescription, privacy: .public)")
            return false
        }

        // 3. ATTACH alerts.db onto the events.db connection. Path is
        //    derived from supportDir so there's no injection vector;
        //    quote-escape defensively for any embedded `'`.
        // The hardened main connection carries SQLITE_OPEN_NOFOLLOW into
        // ATTACH. Normalize only macOS's two sanctioned root aliases exactly
        // as the central open boundary does; otherwise NSTemporaryDirectory's
        // `/var/...` spelling is rejected even though `/private/var/...` is the
        // same trusted file.
        let escaped = SQLiteOpenPathPolicy.normalizedPath(alertsDB)
            .replacingOccurrences(of: "'", with: "''")
        if sqlite3_exec(src, "ATTACH DATABASE '\(escaped)' AS new", nil, nil, nil) != SQLITE_OK {
            logger?.error("AlertsTableRelocator: ATTACH failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            return false
        }
        do {
            try checkpointController.updateFamily(
                schema: "new",
                configuration: SQLiteControlledCheckpointFamily(
                    databasePath: alertsDB,
                    policy: alertPolicy
                )
            )
        } catch {
            logger?.error("AlertsTableRelocator: attached checkpoint policy registration failed: \(error.localizedDescription, privacy: .public)")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }

        // Resolve the exact copy shape before sizing it. A legacy source may
        // have only table+PK while the current destination has 11 secondary
        // indexes, so a fixed multiple of source dbstat bytes is not a bound.
        let sourceCols = columns(handle: src, schema: "main", table: "alerts")
        let targetCols = Set(columns(handle: src, schema: "new", table: "alerts"))
        let common = sourceCols.filter { targetCols.contains($0) }
        guard !common.isEmpty, common.contains("id") else {
            logger?.error("AlertsTableRelocator: source and target alerts tables do not share the required id column")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        do {
            try alertAdmission.installPageLimit(on: src, schema: "new")
            // INSERT ... SELECT can copy the entire legacy alerts b-tree. Use
            // dbstat's allocated-page total (with a whole-events-file fallback)
            // as an explicit lower bound for target growth, and charge 2x for
            // target b-tree fragmentation/newer indexes. This operation must
            // never masquerade as an ordinary 8 MiB transaction.
            let sourceAlertBytes = conservativeAlertStorageBytes(
                handle: src,
                fallbackDatabasePath: eventsDB
            )
            let targetCopyBytes = conservativeTargetCopyBytes(
                handle: src,
                commonColumns: common
            )
            try alertAdmission.admitSchemaRebuild(
                operationCount: 1,
                minimumProjectedGrowthBytes: max(
                    sourceAlertBytes,
                    targetCopyBytes
                )
            )
            try eventAdmission.admitMaintenanceWrite(
                estimatedTransactionBytes: 0
            )
        } catch {
            logger?.error("AlertsTableRelocator: pre-transaction storage admission failed: \(error.localizedDescription, privacy: .public)")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }

        // 4. Compute the column intersection between source and target
        //    `alerts` tables. A v1.7 user upgrading directly to v1.8.0 has
        //    a v1-shape source (no llm_investigation_json); we want the
        //    INSERT to include only columns that exist in BOTH.
        let colList = common.map(quotedIdentifier).joined(separator: ", ")

        // 5. Copy in a single transaction. INSERT OR IGNORE on PRIMARY KEY
        //    means a partial-rerun (target already has some rows) doesn't
        //    fail or duplicate.
        guard sqlite3_exec(src, "BEGIN IMMEDIATE TRANSACTION", nil, nil, nil) == SQLITE_OK else {
            logger?.error("AlertsTableRelocator: BEGIN failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        let insertSQL = "INSERT OR IGNORE INTO new.alerts (\(colList)) SELECT \(colList) FROM main.alerts"
        if sqlite3_exec(src, insertSQL, nil, nil, nil) != SQLITE_OK {
            logger?.error("AlertsTableRelocator: copy failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            sqlite3_exec(src, "ROLLBACK", nil, nil, nil)
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        let copied = Int(sqlite3_changes(src))
        // OR IGNORE can also hide a conflicting pre-existing primary-key row
        // or another target constraint failure. Before committing the copy,
        // prove that every authoritative source row has an exact target match
        // across every common column. A divergent collision leaves both stores
        // untouched for operator inspection instead of draining the source.
        guard copiedRowsAreEquivalent(
            handle: src,
            commonColumns: common,
            logger: logger
        ) else {
            sqlite3_exec(src, "ROLLBACK", nil, nil, nil)
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        guard sqlite3_exec(src, "COMMIT", nil, nil, nil) == SQLITE_OK else {
            logger?.error("AlertsTableRelocator: COMMIT failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            sqlite3_exec(src, "ROLLBACK", nil, nil, nil)
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }

        // 6. Drain the source in explicitly reserve-bounded DELETE
        //    transactions before dropping it. SQLite implements DROP TABLE by
        //    deleting table contents; dropping a populated legacy table can
        //    therefore journal work proportional to that table. Draining first
        //    keeps this recovery operation available when the source is already
        //    over cap, and a crash is safe: the target copy is committed and a
        //    rerun's INSERT OR IGNORE fills only anything still missing.
        guard deleteLegacyAlertsInBoundedTransactions(
            handle: src,
            sourceColumns: sourceCols,
            admission: &eventAdmission,
            logger: logger
        ) else {
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }

        // The table is now empty, so DROP is a bounded sqlite_master/freelist
        // mutation instead of a hidden whole-table delete.
        do {
            try eventAdmission.admitMaintenanceWrite(
                estimatedTransactionBytes: SQLitePersistentStoreAdmission
                    .conservativeRowMutationBytes
            )
        } catch {
            logger?.error("AlertsTableRelocator: source DROP storage admission failed: \(error.localizedDescription, privacy: .public)")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }
        if sqlite3_exec(src, "DROP TABLE alerts", nil, nil, nil) != SQLITE_OK {
            logger?.error("AlertsTableRelocator: DROP TABLE failed: \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
            return false
        }

        // 7. DETACH (must come before VACUUM — VACUUM cannot run with
        //    other databases attached on the same handle).
        sqlite3_exec(src, "DETACH DATABASE new", nil, nil, nil)
        checkpointController.removeFamily(schema: "new")

        // 8. VACUUM events.db to reclaim the pages the alerts table held. The
        //    shared gate re-stats the authoritative main file and free blocks
        //    immediately before the rewrite, preserving the normal floor plus
        //    SQLite's worst-case 2x whole-file scratch requirement.
        do {
            try eventAdmission.admitFullVacuum()
            if sqlite3_exec(src, "VACUUM", nil, nil, nil) != SQLITE_OK {
                logger?.warning("AlertsTableRelocator: VACUUM after migration failed (non-fatal): \(String(cString: sqlite3_errmsg(src)), privacy: .public)")
            }
        } catch {
            logger?.warning("AlertsTableRelocator: skipping post-migration VACUUM (storage admission: \(error.localizedDescription, privacy: .public)) — pages remain reusable and later incremental/full maintenance can reclaim them")
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

    /// Allocated bytes for the legacy table and all of its indexes. dbstat is
    /// available in the shipping SQLite build; if a future build omits it, the
    /// whole source main file is a safe (if deliberately conservative) bound.
    private static func conservativeAlertStorageBytes(
        handle: OpaquePointer,
        fallbackDatabasePath: String
    ) -> Int64 {
        let sql = """
            SELECT COALESCE(SUM(pgsize), 0)
            FROM dbstat
            WHERE name IN (
                SELECT name FROM sqlite_master WHERE tbl_name = 'alerts'
            )
            """
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        if sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK,
           sqlite3_step(stmt) == SQLITE_ROW {
            let measured = sqlite3_column_int64(stmt, 0)
            if measured > 0 { return measured }
        }
        return (try? SQLitePersistentStoreAdmission.measureMainFile(
            fallbackDatabasePath
        )) ?? Int64.max
    }

    /// Conservative target table+PK+11-index transaction work for the exact
    /// authoritative source rows. Counting destination representations (rather
    /// than multiplying source allocation) handles old schemas whose indexed
    /// text existed only once in the source table but is duplicated across
    /// several current indexes.
    private static func conservativeTargetCopyBytes(
        handle: OpaquePointer,
        commonColumns: [String]
    ) -> Int64 {
        guard let pageSize = pragmaInt64(
            handle: handle,
            sql: "PRAGMA new.page_size"
        ), pageSize > 0,
           pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            return Int64.max
        }
        let projection = commonColumns.map(quotedIdentifier)
            .joined(separator: ", ")
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            handle,
            "SELECT \(projection) FROM main.alerts",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            return Int64.max
        }
        defer { sqlite3_finalize(statement) }
        let positions = Dictionary(uniqueKeysWithValues:
            commonColumns.enumerated().map { ($0.element, Int32($0.offset)) }
        )
        // PK + index text portions. Repetition is intentional: rule/severity
        // are copied into multiple independent b-trees.
        let indexedColumns = [
            "id", "rule_id", "rule_id", "severity", "severity", "severity",
            "event_id", "campaign_id", "ai_tool", "ai_tool_session_id",
        ]
        var total: Int64 = 0
        var step = sqlite3_step(statement)
        while step == SQLITE_ROW {
            func bytes(_ position: Int32) -> Int64 {
                sqlite3_column_type(statement, position) == SQLITE_NULL
                    ? 0 : Int64(sqlite3_column_bytes(statement, position))
            }
            // Latest target table has 26 columns. Twelve key representations
            // are PK + 11 explicit indexes; numeric key pieces use fixed slack.
            var logical = Int64(26 * 16 + 12 * 16)
            for position in Int32(0)..<Int32(commonColumns.count) {
                logical = SQLitePersistentStoreAdmission.saturatingAdd(
                    logical, bytes(position)
                )
            }
            for name in indexedColumns {
                guard let position = positions[name] else { continue }
                logical = SQLitePersistentStoreAdmission.saturatingAdd(
                    logical, bytes(position)
                )
            }
            let row = SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: logical,
                    pageSizeBytes: pageSize,
                    maximumLeafPageTouches: 13
                )
            total = SQLitePersistentStoreAdmission.saturatingAdd(total, row)
            step = sqlite3_step(statement)
        }
        guard step == SQLITE_DONE else { return Int64.max }
        return SQLitePersistentStoreAdmission.saturatingAdd(
            total,
            SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
                pageSizeBytes: pageSize,
                maximumTreePathPageTouches: 32
            )
        )
    }

    private static func quotedIdentifier(_ identifier: String) -> String {
        "\"\(identifier.replacingOccurrences(of: "\"", with: "\"\""))\""
    }

    /// Verify the copy inside the same transaction that performed it. SQLite
    /// storage class plus BLOB equality gives a NULL-safe, byte-level check for
    /// every shared value, while the explicit id predicate uses the target's
    /// primary-key index instead of turning verification into a quadratic scan.
    private static func copiedRowsAreEquivalent(
        handle: OpaquePointer,
        commonColumns: [String],
        logger: Logger?
    ) -> Bool {
        guard commonColumns.contains("id") else { return false }
        let comparisons = commonColumns.map { column -> String in
            let quoted = quotedIdentifier(column)
            return "(typeof(target.\(quoted)) = typeof(source.\(quoted)) "
                + "AND CAST(target.\(quoted) AS BLOB) "
                + "IS CAST(source.\(quoted) AS BLOB))"
        }.joined(separator: " AND ")
        let sql = """
            SELECT 1
            FROM main.alerts AS source
            WHERE NOT EXISTS (
                SELECT 1
                FROM new.alerts AS target
                WHERE target."id" IS source."id"
                  AND \(comparisons)
            )
            LIMIT 1
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            handle, sql, -1, &statement, nil
        ) == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            logger?.error("AlertsTableRelocator: copy verification prepare failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
            return false
        }
        defer { sqlite3_finalize(statement) }
        let result = sqlite3_step(statement)
        if result == SQLITE_DONE { return true }
        if result == SQLITE_ROW {
            logger?.error("AlertsTableRelocator: target copy differs from authoritative source; source retained")
        } else {
            logger?.error("AlertsTableRelocator: copy verification failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
        }
        return false
    }

    /// Delete legacy rows in transactions whose estimate is no larger than
    /// the configured maintenance reserve. Payload lengths are read from the
    /// exact source columns, then multiplied by the table+index representation
    /// count; page-image slack uses the source DB's authoritative page size.
    private static func deleteLegacyAlertsInBoundedTransactions(
        handle: OpaquePointer,
        sourceColumns: [String],
        admission: inout SQLitePersistentStoreAdmission,
        logger: Logger?
    ) -> Bool {
        guard !sourceColumns.isEmpty,
              let pageSize = pragmaInt64(handle: handle, sql: "PRAGMA main.page_size"),
              pageSize > 0,
              pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            logger?.error("AlertsTableRelocator: cannot establish source page size for bounded cleanup")
            return false
        }

        let rawIndexCount = max(0, pragmaInt64(
            handle: handle,
            sql: "SELECT COUNT(*) FROM main.sqlite_master WHERE type='index' AND tbl_name='alerts'"
        ) ?? 0)
        guard rawIndexCount <= Int64((Int.max - 1) / 8) else {
            logger?.error("AlertsTableRelocator: implausible source index count; source retained")
            return false
        }
        let indexCount = Int(rawIndexCount)
        let representations = rawIndexCount + 1
        let leafTouches = indexCount + 1
        let fixedBytes = SQLitePersistentStoreAdmission
            .transactionFixedOverheadBytes(
                pageSizeBytes: pageSize,
                maximumTreePathPageTouches: max(8, leafTouches * 8)
            )
        guard fixedBytes < admission.transactionReserveBytes else {
            logger?.error("AlertsTableRelocator: source cleanup fixed estimate exceeds maintenance reserve")
            return false
        }

        let lengthExpression = sourceColumns.map {
            "COALESCE(length(CAST(\(quotedIdentifier($0)) AS BLOB)), 0)"
        }.joined(separator: " + ")
        let selectSQL = """
            SELECT rowid, (\(lengthExpression))
            FROM main.alerts
            ORDER BY rowid
            LIMIT 512
            """

        while true {
            var selectStmt: OpaquePointer?
            guard sqlite3_prepare_v2(
                handle, selectSQL, -1, &selectStmt, nil
            ) == SQLITE_OK, let selectStmt else {
                sqlite3_finalize(selectStmt)
                logger?.error("AlertsTableRelocator: bounded cleanup selection failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
                return false
            }

            var rowIDs: [Int64] = []
            var estimate = fixedBytes
            var selectionResult = sqlite3_step(selectStmt)
            var stoppedAtReserveBoundary = false
            while selectionResult == SQLITE_ROW {
                let rowID = sqlite3_column_int64(selectStmt, 0)
                let logicalPayload = max(0, sqlite3_column_int64(selectStmt, 1))
                let representedPayload = SQLitePersistentStoreAdmission
                    .saturatingMultiply(
                        SQLitePersistentStoreAdmission.saturatingAdd(
                            logicalPayload,
                            256
                        ),
                        by: representations
                    )
                let rowEstimate = SQLitePersistentStoreAdmission
                    .conservativeEncodedRowMutationBytes(
                        logicalRepresentationBytes: representedPayload,
                        pageSizeBytes: pageSize,
                        maximumLeafPageTouches: leafTouches
                    )
                let nextEstimate = SQLitePersistentStoreAdmission
                    .saturatingAdd(estimate, rowEstimate)
                if nextEstimate > admission.transactionReserveBytes {
                    if rowIDs.isEmpty {
                        sqlite3_finalize(selectStmt)
                        logger?.error("AlertsTableRelocator: one legacy alert exceeds the bounded cleanup reserve; source retained")
                        return false
                    }
                    stoppedAtReserveBoundary = true
                    break
                }
                rowIDs.append(rowID)
                estimate = nextEstimate
                selectionResult = sqlite3_step(selectStmt)
            }
            if !stoppedAtReserveBoundary, selectionResult != SQLITE_DONE {
                logger?.error("AlertsTableRelocator: bounded cleanup selection step failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
                sqlite3_finalize(selectStmt)
                return false
            }
            sqlite3_finalize(selectStmt)

            if rowIDs.isEmpty { return true }
            do {
                try admission.admitMaintenanceWrite(
                    estimatedTransactionBytes: estimate
                )
            } catch {
                logger?.error("AlertsTableRelocator: bounded source cleanup admission failed: \(error.localizedDescription, privacy: .public)")
                return false
            }

            guard sqlite3_exec(
                handle, "BEGIN IMMEDIATE TRANSACTION", nil, nil, nil
            ) == SQLITE_OK else {
                logger?.error("AlertsTableRelocator: bounded cleanup BEGIN failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
                return false
            }
            var committed = false
            defer {
                if !committed { sqlite3_exec(handle, "ROLLBACK", nil, nil, nil) }
            }

            var deleteStmt: OpaquePointer?
            guard sqlite3_prepare_v2(
                handle,
                "DELETE FROM main.alerts WHERE rowid = ?1",
                -1,
                &deleteStmt,
                nil
            ) == SQLITE_OK, let deleteStmt else {
                sqlite3_finalize(deleteStmt)
                logger?.error("AlertsTableRelocator: bounded cleanup DELETE prepare failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
                return false
            }
            var deleteSucceeded = true
            for rowID in rowIDs {
                sqlite3_bind_int64(deleteStmt, 1, rowID)
                if sqlite3_step(deleteStmt) != SQLITE_DONE {
                    deleteSucceeded = false
                    break
                }
                sqlite3_reset(deleteStmt)
                sqlite3_clear_bindings(deleteStmt)
            }
            sqlite3_finalize(deleteStmt)
            guard deleteSucceeded,
                  sqlite3_exec(handle, "COMMIT", nil, nil, nil) == SQLITE_OK else {
                logger?.error("AlertsTableRelocator: bounded cleanup transaction failed: \(String(cString: sqlite3_errmsg(handle)), privacy: .public)")
                return false
            }
            committed = true
        }
    }

    private static func pragmaInt64(
        handle: OpaquePointer,
        sql: String
    ) -> Int64? {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(handle, sql, -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            sqlite3_finalize(stmt)
            return nil
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        return sqlite3_column_int64(stmt, 0)
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

}
