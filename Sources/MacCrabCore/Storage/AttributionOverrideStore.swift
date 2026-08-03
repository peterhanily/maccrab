// AttributionOverrideStore.swift
// MacCrabCore
//
// v1.9 PR-5 audit (B3 fix) — operator verdicts live in their own SQLite
// file rather than co-resident in `events.db`. Pre-fix the dashboard
// (running as the user) tried to UPSERT into a root-owned 0640
// `events.db`, hit SQLITE_READONLY on the prepare-fallback path, and
// silently swallowed the error — clicking the reattribute thumbs did
// nothing visible.
//
// Resolution: move the table out. The override "file" is owned by
// whoever runs the dashboard (the user); the daemon reads it
// read-only when computing stats. Either side may write
// independently. Single source of truth per `event_id` is preserved
// via `INSERT … ON CONFLICT(event_id) DO UPDATE`.
//
// The historical `attribution_overrides` table inside `events.db`
// (added by Migration v5) is left in place as harmless dead schema —
// removing it would require a migration v6 with no functional gain.

import Foundation
import CSQLCipher
import os.log

public enum AttributionOverrideStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)
    case queryFailed(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "AttributionOverrideStore: open failed: \(m)"
        case .prepareFailed(let m):       return "AttributionOverrideStore: prepare failed: \(m)"
        case .stepFailed(let m):          return "AttributionOverrideStore: step failed: \(m)"
        case .queryFailed(let m):         return "AttributionOverrideStore: query failed: \(m)"
        }
    }
}

public actor AttributionOverrideStore {

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private var insertStmt: OpaquePointer?
    private let databasePath: String
    private let storagePolicy: SQLitePersistentStorePolicy
    private var storageAdmission: SQLitePersistentStoreAdmission?
    private var sqlitePageSizeBytes: Int64
    private var isReadOnly = false

    private let logger = Logger(subsystem: "com.maccrab.storage", category: "attribution-overrides")

    // MARK: - Schema

    nonisolated static let schemaMigrations: [Migration] = [
        Migration(version: 1, name: "baseline_overrides", sql: []),
    ]

    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else { return }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw AttributionOverrideStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
        }
    }

    private static func openDatabase(
        at path: String,
        storagePolicy: SQLitePersistentStorePolicy
    ) throws -> (
        OpaquePointer,
        Bool,
        OpaquePointer?,
        SQLitePersistentStoreAdmission?,
        Int64,
        SQLiteControlledCheckpointController?
    ) {
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")

        // SQLiteOpenPathPolicy closes symlink traversal at open. The census
        // rejects non-regular/multiply-linked family members; protection from
        // a non-symlink replacement race relies on the production
        // owner-controlled support directory.
        _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        let existingDatabase = try SQLitePersistentStoreAdmission
            .mainFileExists(path)
        var admission: SQLitePersistentStoreAdmission? = try .init(
            databasePath: path,
            policy: storagePolicy,
            latchOperationalPressure: existingDatabase
        )
        var db: OpaquePointer?
        var isReadOnly = false
        var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        if !existingDatabase { flags |= SQLITE_OPEN_CREATE }
        var rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
        if rc != SQLITE_OK {
            if let h = db { sqlite3_close(h) }
            db = nil
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
            isReadOnly = true
            admission = nil
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let db { sqlite3_close(db) }
            throw AttributionOverrideStoreError.databaseOpenFailed(msg)
        }
        var checkpointController: SQLiteControlledCheckpointController?
        var returnHandleToCaller = false
        defer {
            if !returnHandleToCaller {
                checkpointController?.detach(from: handle)
                sqlite3_close(handle)
            }
        }
        if !isReadOnly {
            checkpointController = try .install(
                on: handle,
                thresholdPages: StoragePragmas.walAutocheckpointPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: path,
                        policy: storagePolicy
                    ),
                ]
            )
        }

        if !isReadOnly {
            do {
                try admission?.installPageLimit(on: handle)
            } catch let error as SQLitePersistentStoreAdmissionError
                where error.isOperationalPressure {
                // Existing oversized store opens for read/inspection in shed mode.
            }
        }
        let writerInitializationAllowed = !isReadOnly
            && !(admission?.growthBlocked ?? false)

        func admitSchemaWork(_ rawWork: SchemaStorageWork) throws {
            guard var current = admission else { return }
            defer { admission = current }
            let work = existingDatabase ? rawWork : SchemaStorageWork(
                boundedMetadataStatementCount:
                    rawWork.boundedMetadataStatementCount
                        + rawWork.rebuildStatementCount,
                rebuildStatementCount: 0
            )
            if work.rebuildStatementCount > 0 {
                try current.admitSchemaRebuild(
                    operationCount: work.rebuildStatementCount
                )
            }
            if work.boundedMetadataStatementCount > 0 {
                try current.admitWrite(
                    estimatedTransactionBytes:
                        work.boundedTransactionEstimateBytes,
                    on: handle
                )
            }
        }

        // Tiny store; conservative pragmas.
        // v1.12.6 Wave 9L: auto_vacuum = INCREMENTAL MUST be set
        // BEFORE journal_mode = WAL. SQLite silently refuses to flip
        // auto_vacuum once WAL setup has dirtied the DB header. Wave
        // 9B.1 fixed this across the five primary stores but missed
        // AttributionOverrideStore. Tiny-store impact is small but
        // the invariant is uniform — see StoragePragmas.swift comment.
        if writerInitializationAllowed {
            try admitSchemaWork(SchemaStorageWork(
                boundedMetadataStatementCount: 1,
                rebuildStatementCount: 0
            ))
            for sql in [
                "PRAGMA auto_vacuum = INCREMENTAL",
                "PRAGMA journal_mode = WAL",
                "PRAGMA synchronous = NORMAL",
                "PRAGMA cache_size = -2000",
                "PRAGMA temp_store = MEMORY",
            ] {
                try executeChecked(handle, sql)
            }
        }
        try executeChecked(handle, "PRAGMA busy_timeout = 5000")

        let schema = [
            """
            CREATE TABLE IF NOT EXISTS attribution_overrides (
                event_id TEXT PRIMARY KEY,
                machine_confidence TEXT,
                user_verdict TEXT NOT NULL,
                user_note TEXT,
                schema_version INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_overrides_verdict ON attribution_overrides(user_verdict)",
            "CREATE INDEX IF NOT EXISTS idx_overrides_updated ON attribution_overrides(updated_at)",
        ]
        if writerInitializationAllowed {
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: schema
                )
            )
            for sql in schema {
                try executeChecked(handle, sql)
            }
        }
        if writerInitializationAllowed {
            try SchemaMigrator.run(
                on: handle,
                migrations: Self.schemaMigrations,
                beforeStorageWork: { work in
                    try admitSchemaWork(work)
                }
            )
        }

        var stmt: OpaquePointer?
        let upsert = """
            INSERT INTO attribution_overrides (
                event_id, machine_confidence, user_verdict, user_note,
                schema_version, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(event_id) DO UPDATE SET
                user_verdict = excluded.user_verdict,
                user_note = excluded.user_note,
                machine_confidence = excluded.machine_confidence,
                schema_version = excluded.schema_version,
                updated_at = excluded.updated_at
            """
        if !writerInitializationAllowed {
            stmt = nil
        } else if sqlite3_prepare_v2(handle, upsert, -1, &stmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw AttributionOverrideStoreError.prepareFailed(msg)
        }
        var pageStmt: OpaquePointer?
        guard sqlite3_prepare_v2(
            handle,
            "PRAGMA page_size",
            -1,
            &pageStmt,
            nil
        ) == SQLITE_OK, let pageStmt,
              sqlite3_step(pageStmt) == SQLITE_ROW else {
            if let pageStmt { sqlite3_finalize(pageStmt) }
            throw AttributionOverrideStoreError.databaseOpenFailed(
                "could not read PRAGMA page_size"
            )
        }
        let pageSize = sqlite3_column_int64(pageStmt, 0)
        sqlite3_finalize(pageStmt)
        guard pageSize > 0,
              pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            throw AttributionOverrideStoreError.databaseOpenFailed(
                "invalid PRAGMA page_size=\(pageSize)"
            )
        }
        returnHandleToCaller = true
        return (
            handle,
            isReadOnly,
            stmt,
            admission,
            pageSize,
            checkpointController
        )
    }

    private static func executeChecked(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            let message = String(cString: sqlite3_errmsg(db))
            throw AttributionOverrideStoreError.stepFailed("\(sql): \(message)")
        }
    }

    // MARK: - Init

    /// Open the override store at the user's support directory by
    /// default (always writable). Daemon callers should pass their
    /// own `directory` so the store is co-located with the daemon's
    /// other state. Operators running both the daemon (root) and the
    /// dashboard (user) get TWO override files — one per writer.
    /// `eventCountWithMachineAttribution(in:)` in EventStore is the
    /// roll-up surface; AppState/StatusCommand merge stats across
    /// both override paths.
    public init(
        directory: String,
        storagePolicy suppliedPolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        let url = URL(fileURLWithPath: directory)
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true, attributes: nil
        )
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: url.path
        )
        let databasePath = url.appendingPathComponent("attribution_overrides.db").path
        self.databasePath = databasePath
        let policy = suppliedPolicy ?? Self.defaultStoragePolicy(for: databasePath)
        self.storagePolicy = policy
        // Verdicts and analyst notes are user-private evidence, not a
        // group-readable dashboard cache.
        let oldUmask = umask(0o077)
        defer { umask(oldUmask) }
        let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
            at: databasePath,
            storagePolicy: policy
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.storageAdmission = admission
        self.sqlitePageSizeBytes = pageSize
        self.checkpointController = controller
        if !ro {
            chmod(databasePath, 0o600)
            chmod(databasePath + "-wal", 0o600)
            chmod(databasePath + "-shm", 0o600)
        }
    }

    /// Test-only path init.
    public init(
        path: String,
        storagePolicy suppliedPolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        self.databasePath = path
        let policy = suppliedPolicy ?? Self.defaultStoragePolicy(for: path)
        self.storagePolicy = policy
        let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
            at: path,
            storagePolicy: policy
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.storageAdmission = admission
        self.sqlitePageSizeBytes = pageSize
        self.checkpointController = controller
    }

    private static func defaultStoragePolicy(for databasePath: String)
        -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: 32 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: 4 * 1_048_576,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent
        )
    }

    deinit {
        if let s = insertStmt { sqlite3_finalize(s) }
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
    }

    // MARK: - API

    /// UPSERT a verdict. Replaces on event_id collision; bumps
    /// updated_at. Single source of truth per event.
    public func record(_ override: AttributionOverride) throws {
        let values: [String?] = [
            override.eventId,
            override.machineConfidence,
            override.verdict.rawValue,
            override.userNote,
        ]
        var logical = Int64(7 * 16)
        for value in values {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                Int64(value?.utf8.count ?? 0)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical,
            Int64(override.eventId.utf8.count
                + override.verdict.rawValue.utf8.count + 3 * 16)
        )
        let newRowBytes = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 4
            )
        let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            newRowBytes,
            try existingOverrideMutationBytes(eventId: override.eventId)
        )
        try admitStorageWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeTransactionBytes(
                    rowMutationBytes: rowBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumTreePathPageTouches: 8
                )
        )
        guard !isReadOnly, let stmt = insertStmt else {
            throw AttributionOverrideStoreError.stepFailed("store is read-only")
        }
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, override.eventId, -1, TRANSIENT)
        if let mc = override.machineConfidence {
            sqlite3_bind_text(stmt, 2, mc, -1, TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, 2)
        }
        sqlite3_bind_text(stmt, 3, override.verdict.rawValue, -1, TRANSIENT)
        if let note = override.userNote {
            sqlite3_bind_text(stmt, 4, note, -1, TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, 4)
        }
        sqlite3_bind_int(stmt, 5, Int32(override.schemaVersion))
        sqlite3_bind_double(stmt, 6, override.createdAt.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 7, override.updatedAt.timeIntervalSince1970)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AttributionOverrideStoreError.stepFailed(msg)
        }
    }

    private func existingOverrideMutationBytes(eventId: String) throws -> Int64 {
        guard let db else { return 0 }
        let sql = """
            SELECT event_id, machine_confidence, user_verdict, user_note,
                   schema_version, created_at, updated_at
            FROM attribution_overrides WHERE event_id = ?1 LIMIT 1
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            sqlite3_finalize(statement)
            throw AttributionOverrideStoreError.stepFailed(
                "existing override estimate prepare failed"
            )
        }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(
            OpaquePointer(bitPattern: -1)!,
            to: sqlite3_destructor_type.self
        )
        sqlite3_bind_text(statement, 1, eventId, -1, transient)
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return 0 }
        guard step == SQLITE_ROW else {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw AttributionOverrideStoreError.stepFailed(
                "existing override estimate step failed"
            )
        }
        func bytes(_ column: Int32) -> Int64 {
            sqlite3_column_type(statement, column) == SQLITE_NULL
                ? 0 : Int64(sqlite3_column_bytes(statement, column))
        }
        var logical = Int64(7 * 16)
        for column in Int32(0)..<Int32(7) {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical,
            SQLitePersistentStoreAdmission.saturatingAdd(
                bytes(0), bytes(2)
            )
        )
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical, 3 * 16
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 4
            )
    }

    private func admitStorageWrite(
        estimatedTransactionBytes: Int64
    ) throws {
        guard var admission = storageAdmission else { return }
        let wasBlocked = admission.growthBlocked
        let writerSetupPending = !isReadOnly && insertStmt == nil
        do {
            try admission.admitWrite(
                estimatedTransactionBytes: estimatedTransactionBytes,
                on: db
            )
        } catch {
            storageAdmission = admission
            throw error
        }
        let recovered = wasBlocked && !admission.growthBlocked
        storageAdmission = admission
        if recovered || (writerSetupPending && !admission.growthBlocked) {
            try reopenAfterStorageRecovery()
        }
    }

    private func throwLatchedStoragePressureIfPresent(resultCode: Int32) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        if let pressure = admission.latchSQLitePressure(resultCode: resultCode, db: db) {
            throw pressure
        }
    }

    public func storageAdmissionSnapshot() -> SQLitePersistentStoreAdmissionSnapshot? {
        guard var admission = storageAdmission else { return nil }
        defer { storageAdmission = admission }
        return admission.snapshot()
    }

    private func reopenAfterStorageRecovery() throws {
        let (
            newDB,
            newReadOnly,
            newStatement,
            newAdmission,
            pageSize,
            newCheckpointController
        ) = try Self.openDatabase(
            at: databasePath,
            storagePolicy: storagePolicy
        )
        if let insertStmt { sqlite3_finalize(insertStmt) }
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
        db = newDB
        isReadOnly = newReadOnly
        insertStmt = newStatement
        storageAdmission = newAdmission
        sqlitePageSizeBytes = pageSize
        checkpointController = newCheckpointController
    }

    public func fetch(eventId: String) throws -> AttributionOverride? {
        guard let db else { return nil }
        let sql = """
            SELECT machine_confidence, user_verdict, user_note,
                   schema_version, created_at, updated_at
            FROM attribution_overrides
            WHERE event_id = ?1
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw AttributionOverrideStoreError.prepareFailed(msg)
        }
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, eventId, -1, TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        let mc: String? = sqlite3_column_type(stmt, 0) == SQLITE_NULL
            ? nil : String(cString: sqlite3_column_text(stmt, 0))
        let verdictRaw = String(cString: sqlite3_column_text(stmt, 1))
        let verdict = AttributionOverride.Verdict(rawValue: verdictRaw) ?? .unknown
        let note: String? = sqlite3_column_type(stmt, 2) == SQLITE_NULL
            ? nil : String(cString: sqlite3_column_text(stmt, 2))
        let schemaVersion = Int(sqlite3_column_int(stmt, 3))
        let createdAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
        let updatedAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 5))
        return AttributionOverride(
            eventId: eventId,
            machineConfidence: mc,
            verdict: verdict,
            userNote: note,
            createdAt: createdAt,
            updatedAt: updatedAt,
            schemaVersion: schemaVersion
        )
    }

    /// Per-verdict counts. Combine with EventStore's
    /// `eventCountWithMachineAttribution()` to produce a full
    /// `AttributionOverrideStats`.
    public func verdictCounts() throws -> (rated: Int, confirmed: Int, wrongTool: Int, noAgent: Int, unknown: Int) {
        guard let db else { return (0, 0, 0, 0, 0) }
        let sql = """
            SELECT user_verdict, COUNT(*)
            FROM attribution_overrides
            GROUP BY user_verdict
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw AttributionOverrideStoreError.prepareFailed(msg)
        }
        var rated = 0, confirmed = 0, wrongTool = 0, noAgent = 0, unknown = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let v = String(cString: sqlite3_column_text(stmt, 0))
            let c = Int(sqlite3_column_int64(stmt, 1))
            rated += c
            switch v {
            case AttributionOverride.Verdict.confirmed.rawValue: confirmed = c
            case AttributionOverride.Verdict.wrongTool.rawValue: wrongTool = c
            case AttributionOverride.Verdict.noAgent.rawValue:   noAgent = c
            case AttributionOverride.Verdict.unknown.rawValue:   unknown = c
            default: break
            }
        }
        return (rated, confirmed, wrongTool, noAgent, unknown)
    }

    /// Combine local verdict counts with a caller-supplied total to
    /// produce the canonical `AttributionOverrideStats`.
    public func stats(totalEventsWithMachineAttribution: Int) throws -> AttributionOverrideStats {
        let c = try verdictCounts()
        return AttributionOverrideStats(
            ratedCount: c.rated,
            confirmedCount: c.confirmed,
            wrongToolCount: c.wrongTool,
            noAgentCount: c.noAgent,
            unknownVerdictCount: c.unknown,
            totalEventsWithMachineAttribution: totalEventsWithMachineAttribution
        )
    }

    public func count() throws -> Int {
        guard let db else { return 0 }
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM attribution_overrides", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return 0
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }
}
