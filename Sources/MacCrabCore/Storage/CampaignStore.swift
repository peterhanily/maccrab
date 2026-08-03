// CampaignStore.swift
// MacCrabCore
//
// SQLite-backed persistent store for detected campaigns.
// Campaigns were previously kept in-memory only in CampaignDetector; this
// store survives restarts and lets the dashboard query campaigns
// independently of the detection actor.

import Foundation
import Darwin
import CSQLCipher
import os.log

// MARK: - Errors

public enum CampaignStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)
    case encodingFailed(String)
    case decodingFailed(String)
    /// v1.12.6 Wave 9N: distinguish SQLITE_FULL from generic step
    /// failures so callers can stop retrying on disk-pressured
    /// hosts. Mirrors EventStore.diskFull + AlertStore.diskFull.
    case diskFull(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "Campaign DB open failed: \(m)"
        case .prepareFailed(let m):      return "Campaign prepare failed: \(m)"
        case .stepFailed(let m):         return "Campaign step failed: \(m)"
        case .encodingFailed(let m):     return "Campaign encode failed: \(m)"
        case .decodingFailed(let m):     return "Campaign decode failed: \(m)"
        case .diskFull(let m):           return "Campaign DB disk full: \(m)"
        }
    }
}

// MARK: - CampaignStore

/// Persistent store for campaigns detected by `CampaignDetector`.
///
/// The store is decoupled from the detector: the detector emits `Record`s
/// (via a thin adapter in DaemonSetup), the store persists them, and the
/// dashboard queries the store. Swapping or stopping the detector does not
/// affect historical campaign records.
public actor CampaignStore {

    // MARK: - Nested types

    /// Persisted form of a detected campaign. Codable wrapper around
    /// `CampaignDetector.Campaign` — keeps the storage type decoupled from
    /// the in-memory detection actor.
    public struct Record: Codable, Sendable, Hashable, Identifiable {
        public let id: String
        public let type: String              // CampaignType.rawValue
        public let severity: Severity
        public let title: String
        public let description: String
        public let tactics: [String]
        public let timeSpanSeconds: Double
        public let detectedAt: Date
        public let alerts: [AlertRef]
        public var suppressed: Bool
        public var notes: String?

        // MARK: - v2 aggregate attribution (Wave 2C)
        //
        // Aggregates computed by `CampaignDetector` over the contributing
        // alerts at persist time. All optional so existing rows / JSON blobs
        // round-trip unchanged. The store binds nullable SQLite columns when
        // these are absent.

        /// Distinct user IDs across contributing alerts. String form mirrors
        /// `AlertRef.userId` (already string-typed for lateral-movement keying).
        public let affectedUsers: [String]?

        /// Distinct process executable paths across contributing alerts.
        public let affectedExecutables: [String]?

        /// Timestamp of the earliest contributing alert.
        public let firstSeen: Date?

        /// Timestamp of the latest contributing alert.
        public let lastSeen: Date?

        /// Max process-ancestor depth observed across contributing alerts.
        public let processTreeDepth: Int?

        /// Distinct MITRE ATT&CK technique IDs across contributing alerts
        /// (sibling of `tactics`).
        public let techniques: [String]?

        /// Distinct `ai_tool` values (claude_code, cursor, …) involved in the
        /// contributing alerts. nil for non-AI campaigns.
        public let aiTools: [String]?

        public init(
            id: String,
            type: String,
            severity: Severity,
            title: String,
            description: String,
            tactics: [String],
            timeSpanSeconds: Double,
            detectedAt: Date,
            alerts: [AlertRef] = [],
            suppressed: Bool = false,
            notes: String? = nil,
            affectedUsers: [String]? = nil,
            affectedExecutables: [String]? = nil,
            firstSeen: Date? = nil,
            lastSeen: Date? = nil,
            processTreeDepth: Int? = nil,
            techniques: [String]? = nil,
            aiTools: [String]? = nil
        ) {
            self.id = id
            self.type = type
            self.severity = severity
            self.title = title
            self.description = description
            self.tactics = tactics
            self.timeSpanSeconds = timeSpanSeconds
            self.detectedAt = detectedAt
            self.alerts = alerts
            self.suppressed = suppressed
            self.notes = notes
            self.affectedUsers = affectedUsers
            self.affectedExecutables = affectedExecutables
            self.firstSeen = firstSeen
            self.lastSeen = lastSeen
            self.processTreeDepth = processTreeDepth
            self.techniques = techniques
            self.aiTools = aiTools
        }
    }

    /// Lightweight reference to an alert that contributed to a campaign.
    public struct AlertRef: Codable, Sendable, Hashable {
        public let ruleId: String
        public let ruleTitle: String
        public let severity: Severity
        public let processPath: String?
        public let pid: Int?
        public let userId: String?
        public let timestamp: Date
        public let tactics: [String]

        public init(
            ruleId: String,
            ruleTitle: String,
            severity: Severity,
            processPath: String? = nil,
            pid: Int? = nil,
            userId: String? = nil,
            timestamp: Date,
            tactics: [String] = []
        ) {
            self.ruleId = ruleId
            self.ruleTitle = ruleTitle
            self.severity = severity
            self.processPath = processPath
            self.pid = pid
            self.userId = userId
            self.timestamp = timestamp
            self.tactics = tactics
        }
    }

    // MARK: - Schema migrations

    nonisolated static let schemaMigrations: [Migration] = [
        Migration(version: 1, name: "campaigns_baseline", sql: []),
        // v2 (v1.12.6 Wave 2C): aggregate attribution columns surfaced
        // by `CampaignDetector` over the contributing alerts at persist
        // time. Existing rows get NULL — readers fall back to raw_json
        // for backward-compat. New rows write both raw_json AND the
        // indexed columns so dashboards / MCP can filter without a
        // JSON_EXTRACT scan. `first_seen` is indexed because timeline
        // queries pivot on it for "what happened during the campaign
        // window" lookups.
        Migration(
            version: 2,
            name: "add_aggregate_attribution_columns",
            sql: [
                "ALTER TABLE campaigns ADD COLUMN affected_users TEXT",
                "ALTER TABLE campaigns ADD COLUMN affected_executables TEXT",
                "ALTER TABLE campaigns ADD COLUMN first_seen REAL",
                "ALTER TABLE campaigns ADD COLUMN last_seen REAL",
                "ALTER TABLE campaigns ADD COLUMN process_tree_depth INTEGER",
                "ALTER TABLE campaigns ADD COLUMN techniques TEXT",
                "ALTER TABLE campaigns ADD COLUMN ai_tools TEXT",
                "CREATE INDEX IF NOT EXISTS idx_campaigns_first_seen ON campaigns(first_seen)",
            ]
        ),
    ]

    // MARK: - State

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private let databasePath: String
    private var storagePolicy: SQLitePersistentStorePolicy?
    private var storageAdmission: SQLitePersistentStoreAdmission?
    private var sqlitePageSizeBytes: Int64
    private var maintenanceRowMutationHighWaterBytes: Int64? = nil
    private var maintenanceHighWaterScannedExistingRows = false
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var insertStmt: OpaquePointer?
    private var isReadOnly = false

    // MARK: - Init

    /// Throw `CampaignStoreError.databaseOpenFailed` if `path` exists and is a
    /// symbolic link. A missing file is always OK — SQLite will create it.
    /// This preflight provides a store-specific diagnostic. The authoritative
    /// symlink boundary is SQLiteOpenPathPolicy's NOFOLLOW open below.
    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return
        }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw CampaignStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
        }
    }

    private static func defaultStoragePolicy(
        for databasePath: String
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: 50 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent
        )
    }

    /// - Parameter forceReadOnly: When `true`, open with
    ///   `SQLITE_OPEN_READONLY` and skip the RW attempt. See
    ///   `EventStore.openDatabase` for the v1.12.6 Wave 9A background.
    private static func openDatabase(
        at path: String,
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
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

        // NOFOLLOW is enforced by SQLiteOpenPathPolicy at the actual open.
        // The family census adds regular-file/single-link checks; its
        // non-symlink race assumption is the shipping owner-controlled
        // support directory, not an arbitrary caller-writable parent.
        _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        let existingDatabase = try SQLitePersistentStoreAdmission
            .mainFileExists(path)
        let effectivePolicy = forceReadOnly
            ? nil : (storagePolicy ?? Self.defaultStoragePolicy(for: path))
        var admission = try effectivePolicy.map {
            try SQLitePersistentStoreAdmission(
                databasePath: path,
                policy: $0,
                latchOperationalPressure: existingDatabase
            )
        }
        var db: OpaquePointer?
        var isReadOnly = false
        var flags: Int32
        var rc: Int32
        if forceReadOnly {
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
            isReadOnly = true
        } else {
            flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            if !existingDatabase { flags |= SQLITE_OPEN_CREATE }
            rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
            if rc != SQLITE_OK {
                if let handle = db { sqlite3_close(handle) }
                db = nil
                flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
                rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
                isReadOnly = true
                admission = nil
            }
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let db { sqlite3_close(db) }
            throw CampaignStoreError.databaseOpenFailed(msg)
        }
        var checkpointController: SQLiteControlledCheckpointController?
        var returnHandleToCaller = false
        defer {
            if !returnHandleToCaller {
                checkpointController?.detach(from: handle)
                sqlite3_close(handle)
            }
        }
        if !isReadOnly, let effectivePolicy {
            checkpointController = try .install(
                on: handle,
                thresholdPages: StoragePragmas.walAutocheckpointPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: path,
                        policy: effectivePolicy
                    ),
                ]
            )
        }

        if !isReadOnly {
            do {
                try admission?.installPageLimit(on: handle)
            } catch let error as SQLitePersistentStoreAdmissionError
                where error.isOperationalPressure {
                // Shed-mode open: retention remains available, growth does not.
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

        if writerInitializationAllowed {
            try admitSchemaWork(SchemaStorageWork(
                boundedMetadataStatementCount: 1,
                rebuildStatementCount: 0
            ))
            // Wave 9B.1 (v1.12.6 RC2): auto_vacuum MUST come BEFORE journal_mode
            // — SQLite silently refuses to flip auto_vacuum after the WAL setup
            // dirties the DB header. Pre-9B.1 fresh campaigns.db landed at
            // mode 0 (NONE) silently.
            try Self.exec(handle, "PRAGMA auto_vacuum = INCREMENTAL")
            try Self.exec(handle, "PRAGMA journal_mode = WAL")
            try Self.exec(handle, "PRAGMA synchronous = NORMAL")
        }
        // v1.4.4 — see EventStore.swift for the busy_timeout rationale.
        try Self.exec(handle, "PRAGMA busy_timeout = 5000")
        try Self.exec(handle, "PRAGMA foreign_keys = ON")

        let schemaSQLs = [
            // v1.12.6 Wave 2C: fresh-install schema includes v2 aggregate
            // attribution columns directly. Migration v2 covers existing
            // installs via idempotent ADD COLUMN.
            """
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                detected_at REAL NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                tactics TEXT NOT NULL,
                time_span_seconds REAL NOT NULL,
                suppressed INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                raw_json TEXT NOT NULL,
                affected_users TEXT,
                affected_executables TEXT,
                first_seen REAL,
                last_seen REAL,
                process_tree_depth INTEGER,
                techniques TEXT,
                ai_tools TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_campaigns_detected_at ON campaigns(detected_at)",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_type ON campaigns(type)",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_severity ON campaigns(severity)",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_sup_det ON campaigns(suppressed, detected_at)",
        ]
        if writerInitializationAllowed {
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: schemaSQLs
                )
            )
            for sql in schemaSQLs {
                try Self.exec(handle, sql)
            }
        }

        if writerInitializationAllowed {
            // v1.12.0 RC27 (perf): consistency with EventStore /
            // AlertStore / SQLiteCausalGraphStore — skip per-init
            // quick_check on the boot path. Round-10 perf audit caught
            // this as the only store still doing PRAGMA quick_check
            // synchronously.
            try SchemaMigrator.run(
                on: handle,
                migrations: Self.schemaMigrations,
                skipQuickCheck: true,
                beforeStorageWork: { work in
                    try admitSchemaWork(work)
                }
            )
            // `first_seen` is introduced by v2. Keep its index behind the
            // migration so a v1 database can add the column before CREATE
            // INDEX, and re-resolve it on latest-version reopen for repair.
            let postMigrationIndex = "CREATE INDEX IF NOT EXISTS idx_campaigns_first_seen ON campaigns(first_seen)"
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: [postMigrationIndex]
                )
            )
            try Self.exec(handle, postMigrationIndex)
        }

        let insertSQL = """
            INSERT OR REPLACE INTO campaigns
              (id, detected_at, type, severity, title, tactics, time_span_seconds,
               suppressed, notes, raw_json,
               affected_users, affected_executables, first_seen, last_seen,
               process_tree_depth, techniques, ai_tools)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            """
        var insertStmt: OpaquePointer?
        if writerInitializationAllowed,
           sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw CampaignStoreError.prepareFailed(msg)
        }

        let pageSize = try Self.readPositivePageSize(handle)
        returnHandleToCaller = true
        return (
            handle,
            isReadOnly,
            insertStmt,
            admission,
            pageSize,
            checkpointController
        )
    }

    private static func readPositivePageSize(_ db: OpaquePointer) throws -> Int64 {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, nil) == SQLITE_OK,
              let stmt else {
            throw CampaignStoreError.databaseOpenFailed("could not read PRAGMA page_size")
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CampaignStoreError.databaseOpenFailed("PRAGMA page_size returned no row")
        }
        let pageSize = sqlite3_column_int64(stmt, 0)
        guard pageSize > 0,
              pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            throw CampaignStoreError.databaseOpenFailed("invalid PRAGMA page_size=\(pageSize)")
        }
        return pageSize
    }

    /// Execute SQL on a raw handle and surface the error via os.log on
    /// failure. See the EventStore.exec comment for the rationale.
    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            Logger(subsystem: "com.maccrab.storage", category: "campaign-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
            throw CampaignStoreError.stepFailed("\(sql): \(msg)")
        }
    }

    /// Open a CampaignStore at the default MacCrab data directory.
    ///
    /// v1.6.22: this used to open `events.db` and create the `campaigns`
    /// table inside that shared file — the third long-lived SQLite
    /// connection on the same file, accidentally inflating the per-handle
    /// memory cost (cache_size, busy_timeout buffer) by 50 %. Now opens its
    /// own `campaigns.db`. The previous `campaigns` table inside events.db
    /// is left in place; SQLite ignores it and the next size-cap-driven
    /// VACUUM reclaims the (small) space.
    ///
    /// - Parameters:
    ///   - directory: Filesystem directory the store should live in.
    ///   - forceReadOnly: When `true`, open with `SQLITE_OPEN_READONLY` and
    ///     skip chmod / umask management. See `EventStore.init` for the
    ///     v1.12.6 Wave 9A rationale (keep dashboard-side handles from
    ///     blocking the daemon's VACUUM).
    public init(
        directory: String = "/Library/Application Support/MacCrab",
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        let dir = URL(fileURLWithPath: directory)
        if !forceReadOnly {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
        }

        let databasePath = dir.appendingPathComponent("campaigns.db").path
        self.databasePath = databasePath
        let effectiveStoragePolicy = forceReadOnly
            ? nil
            : (storagePolicy ?? Self.defaultStoragePolicy(for: databasePath))
        self.storagePolicy = effectiveStoragePolicy
        // v1.21.5 (audit sec-storage-crypto): 0o027/0o640 — group read-only,
        // not group-write. See EventStore.init: a non-root admin process
        // must not be able to open campaigns.db read-write and rewrite
        // campaign state. Mutations route through the inbox IPC (root daemon).
        let oldUmask = forceReadOnly ? nil : umask(0o027)
        defer { if let oldUmask { umask(oldUmask) } }
        let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
            at: databasePath,
            forceReadOnly: forceReadOnly,
            storagePolicy: effectiveStoragePolicy
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.storageAdmission = admission
        self.sqlitePageSizeBytes = pageSize
        self.checkpointController = controller
        if !forceReadOnly {
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
        }
    }

    /// Open a CampaignStore at a custom path (useful for tests).
    public init(
        path: String,
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        self.databasePath = path
        let effectiveStoragePolicy = forceReadOnly
            ? nil
            : (storagePolicy ?? Self.defaultStoragePolicy(for: path))
        self.storagePolicy = effectiveStoragePolicy
        let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
            at: path,
            forceReadOnly: forceReadOnly,
            storagePolicy: effectiveStoragePolicy
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.storageAdmission = admission
        self.sqlitePageSizeBytes = pageSize
        self.checkpointController = controller
    }

    deinit {
        if let insertStmt { sqlite3_finalize(insertStmt) }
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
    }

    // MARK: - Insert

    /// Persist a campaign record. Overwrites any record with the same id.
    public func insert(_ r: Record) throws {
        guard let stmt = insertStmt else {
            // Shed-only opens intentionally have no prepared writer. Surface
            // the typed storage-admission cause instead of hiding it behind a
            // generic prepare error; this branch is off the normal hot path.
            if storageAdmission?.growthBlocked == true {
                try admitStorageWrite(estimatedTransactionBytes: 0)
            }
            throw CampaignStoreError.prepareFailed("insert statement not prepared")
        }

        let jsonData: Data
        do {
            jsonData = try encoder.encode(r)
        } catch {
            throw CampaignStoreError.encodingFailed(error.localizedDescription)
        }
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw CampaignStoreError.encodingFailed("could not UTF-8 encode JSON")
        }
        let affectedUsers = encodeStringArrayOrNil(r.affectedUsers)
        let affectedExecutables = encodeStringArrayOrNil(r.affectedExecutables)
        let techniques = encodeStringArrayOrNil(r.techniques)
        let aiTools = encodeStringArrayOrNil(r.aiTools)
        let tactics = r.tactics.joined(separator: ",")

        let tableStrings: [String?] = [
            r.id, r.type, r.severity.rawValue, r.title, tactics, r.notes,
            jsonString, affectedUsers, affectedExecutables, techniques, aiTools,
        ]
        var logical = Int64(17 * 16)
        for value in tableStrings {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                Int64(value?.utf8.count ?? 0)
            )
        }
        // PRIMARY KEY plus five secondary index representations.
        for value in [r.id, r.type, r.severity.rawValue] {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                Int64(value.utf8.count)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical, 6 * 16
        )
        let newRowBytes = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 7
            )
        let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            newRowBytes,
            try existingCampaignMutationBytes(id: r.id)
        )
        try admitStorageWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeTransactionBytes(
                    rowMutationBytes: rowBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumTreePathPageTouches: 18
                )
        )

        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)

        bindText(stmt, index: 1, value: r.id)
        sqlite3_bind_double(stmt, 2, r.detectedAt.timeIntervalSince1970)
        bindText(stmt, index: 3, value: r.type)
        bindText(stmt, index: 4, value: r.severity.rawValue)
        bindText(stmt, index: 5, value: r.title)
        bindText(stmt, index: 6, value: tactics)
        sqlite3_bind_double(stmt, 7, r.timeSpanSeconds)
        sqlite3_bind_int(stmt, 8, r.suppressed ? 1 : 0)
        bindTextOrNull(stmt, index: 9, value: r.notes)
        bindText(stmt, index: 10, value: jsonString)

        // v1.12.6 Wave 2C: aggregate attribution columns. JSON-encode the
        // string arrays; on encoder failure (unreachable for [String], but
        // we fail closed) bind NULL rather than blocking the campaign
        // persist — the raw_json blob still carries the full Record.
        bindTextOrNull(stmt, index: 11, value: affectedUsers)
        bindTextOrNull(stmt, index: 12, value: affectedExecutables)
        bindDoubleOrNull(stmt, index: 13, value: r.firstSeen?.timeIntervalSince1970)
        bindDoubleOrNull(stmt, index: 14, value: r.lastSeen?.timeIntervalSince1970)
        if let depth = r.processTreeDepth {
            sqlite3_bind_int(stmt, 15, Int32(depth))
        } else {
            sqlite3_bind_null(stmt, 15)
        }
        bindTextOrNull(stmt, index: 16, value: techniques)
        bindTextOrNull(stmt, index: 17, value: aiTools)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            // v1.12.6 Wave 9N: surface SQLite/VFS exhaustion distinctly
            // so disk-pressure isn't masked as a generic step failure.
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            if failure.primaryResultCode == SQLITE_FULL
                || failure.systemErrno == ENOSPC
                || failure.systemErrno == EDQUOT {
                throw CampaignStoreError.diskFull(msg)
            }
            throw CampaignStoreError.stepFailed(msg)
        }
        maintenanceRowMutationHighWaterBytes = max(
            maintenanceRowMutationHighWaterBytes ?? 0,
            rowBytes
        )
    }

    private func existingCampaignMutationBytes(id: String) throws -> Int64 {
        guard let db else { return 0 }
        let sql = """
            SELECT id, detected_at, type, severity, title, tactics,
                   time_span_seconds, suppressed, notes, raw_json,
                   affected_users, affected_executables, first_seen, last_seen,
                   process_tree_depth, techniques, ai_tools
            FROM campaigns WHERE id = ?1 LIMIT 1
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            sqlite3_finalize(statement)
            throw CampaignStoreError.prepareFailed("existing campaign estimate")
        }
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: id)
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return 0 }
        guard step == SQLITE_ROW else {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw CampaignStoreError.stepFailed("existing campaign estimate step")
        }
        func bytes(_ column: Int32) -> Int64 {
            sqlite3_column_type(statement, column) == SQLITE_NULL
                ? 0 : Int64(sqlite3_column_bytes(statement, column))
        }
        var logical = Int64(17 * 16)
        for column in Int32(0)..<Int32(17) {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        for column in [0, 2, 3] as [Int32] {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical, 6 * 16
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 7
            )
    }

    /// Encode a `[String]?` as a compact JSON array string for storage in
    /// a `TEXT` column. Returns nil when the input is nil or empty. On
    /// JSONEncoder failure logs the issue and returns nil so the column
    /// is bound NULL — the campaign persist still succeeds (raw_json is
    /// the source of truth for downstream readers).
    private func encodeStringArrayOrNil(_ values: [String]?) -> String? {
        guard let values, !values.isEmpty else { return nil }
        do {
            let data = try encoder.encode(values)
            return String(data: data, encoding: .utf8)
        } catch {
            Logger(subsystem: "com.maccrab.storage", category: "campaign-store")
                .warning("CampaignStore: JSON encode of string array failed (\(error.localizedDescription, privacy: .public)); binding NULL")
            return nil
        }
    }

    // MARK: - Query

    /// Fetch campaigns detected at or after `since`, newest first.
    public func list(
        since: Date = Date.distantPast,
        includeSuppressed: Bool = true,
        limit: Int = 100
    ) throws -> [Record] {
        var sql = "SELECT raw_json FROM campaigns WHERE detected_at >= ?1"
        if !includeSuppressed {
            sql += " AND suppressed = 0"
        }
        sql += " ORDER BY detected_at DESC LIMIT ?2"
        return try query(sql: sql, bindings: [
            (1, .double(since.timeIntervalSince1970)),
            (2, .int(Int32(limit))),
        ])
    }

    /// Fetch a single campaign by id.
    public func get(id: String) throws -> Record? {
        let sql = "SELECT raw_json FROM campaigns WHERE id = ?1 LIMIT 1"
        return try query(sql: sql, bindings: [(1, .text(id))]).first
    }

    /// Count rows.
    public func count() throws -> Int {
        let stmt = try prepare("SELECT COUNT(*) FROM campaigns")
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CampaignStoreError.stepFailed("count failed")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Update

    /// Mark a campaign suppressed. Updates the `suppressed` column AND the
    /// `raw_json` blob so future reads return a consistent view.
    public func setSuppressed(id: String, _ flag: Bool) throws {
        guard var record = try get(id: id) else { return }
        record.suppressed = flag
        try insert(record)
    }

    /// Attach / replace analyst notes on a campaign.
    public func setNotes(id: String, notes: String?) throws {
        guard var record = try get(id: id) else { return }
        record.notes = notes
        try insert(record)
    }

    // MARK: - Pruning

    /// Delete campaigns detected before `date`. Returns rows deleted.
    @discardableResult
    public func prune(olderThan date: Date) async throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            DELETE FROM campaigns WHERE rowid IN (
                SELECT rowid FROM campaigns WHERE detected_at < ?1
                ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            let stmt = try prepare(sql)
            sqlite3_bind_double(stmt, 1, date.timeIntervalSince1970)
            sqlite3_bind_int(stmt, 2, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw CampaignStoreError.stepFailed(msg)
            }
            let deleted = Int(sqlite3_changes(db))
            total += deleted
            if deleted == 0 { break }
            await Task.yield()
        }
        return total
    }

    /// v1.8.0: drop the oldest `count` campaigns by detected_at. Defense-in-
    /// depth size cap when campaigns.db exceeds `campaignsMaxSizeMB`. Tiny
    /// table in practice — this exists for parity with the events / alerts
    /// stores rather than because campaigns ever fill 50 MB on real workloads.
    @discardableResult
    public func pruneOldest(count: Int) async throws -> Int {
        guard count > 0 else { return 0 }
        let batch = maintenanceBatchRowLimit()
        let sql = """
            DELETE FROM campaigns WHERE id IN (
                SELECT id FROM campaigns ORDER BY detected_at ASC LIMIT ?1
            )
            """
        var remaining = count
        var total = 0
        while remaining > 0 {
            let thisBatch = min(batch, Int32(clamping: remaining))
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes:
                    maintenanceEstimate(rowCount: Int(thisBatch))
            )
            let stmt = try prepare(sql)
            sqlite3_bind_int(stmt, 1, thisBatch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw CampaignStoreError.stepFailed(msg)
            }
            let deleted = Int(sqlite3_changes(db))
            total += deleted
            remaining -= deleted
            if deleted == 0 { break }
            await Task.yield()
        }
        return total
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // Mirrors EventStore.incrementalVacuum. campaigns.db is the
    // smallest of the four stores in practice (tens of MB at worst),
    // so this is here for parity rather than because it's a hot path
    // — but the size-cap timer on a misconfigured host could still
    // benefit from the in-place truncate.
    @discardableResult
    public func incrementalVacuum(maxPages: Int) async throws -> Int {
        guard let db = db else { return 0 }
        guard StoragePragmas.readAutoVacuumMode(db) == 2 else { return 0 }
        let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: max(0, maxPages),
            reserveBytes: storageTransactionReserveBytes,
            pageSizeBytes: sqlitePageSizeBytes
        )
        guard plan.pages > 0 else { return 0 }
        guard walCheckpoint() else {
            throw CampaignStoreError.stepFailed(
                "incremental VACUUM refused because the pre-checkpoint did not fully drain"
            )
        }
        try admitStorageMaintenanceWrite(
            estimatedTransactionBytes: plan.estimatedTransactionBytes
        )
        do {
            let result = try StoragePragmas.runIncrementalVacuum(
                on: db,
                maxPages: plan.pages
            )
            guard walCheckpointTruncate() else {
                throw CampaignStoreError.stepFailed(
                    "incremental VACUUM completed but its WAL could not be fully drained/truncated"
                )
            }
            return result.pagesReclaimed
        } catch let error as StoragePragmas.IncrementalVacuumError {
            try throwLatchedStoragePressureIfPresent(
                details: error.sqliteFailureMetadata.publicDetails
            )
            throw error
        }
    }

    /// Best-effort VACUUM. campaigns.db is small enough that this
    /// almost never gates on disk space, but the size-cap timer
    /// callers want a consistent API across all four stores.
    public func vacuum() async throws {
        guard let db = db else { return }
        guard walCheckpoint() else {
            throw CampaignStoreError.stepFailed(
                "VACUUM refused because the pre-checkpoint did not fully drain"
            )
        }
        // One-shot auto_vacuum conversion (audit corr-storage): the pragma is
        // a silent no-op on a populated DB, so a campaigns.db created before
        // the INCREMENTAL default stays mode 0 (NONE) and incrementalVacuum()
        // never reclaims. Issuing it right before VACUUM converts the file on
        // this rewrite; idempotent once already mode 2.
        let autoVacuumRC = sqlite3_exec(
            db,
            "PRAGMA auto_vacuum = INCREMENTAL",
            nil,
            nil,
            nil
        )
        if autoVacuumRC != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: autoVacuumRC)
            throw CampaignStoreError.stepFailed("auto_vacuum conversion failed")
        }
        try admitStorageFullVacuum()
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = String(cString: sqlite3_errmsg(db))
            throw CampaignStoreError.stepFailed("VACUUM failed: \(msg)")
        }
        guard walCheckpointTruncate() else {
            throw CampaignStoreError.stepFailed(
                "VACUUM completed but its WAL could not be fully drained/truncated"
            )
        }
    }

    /// PASSIVE→RESTART checkpoint chain. Used by the size-cap path
    /// to drain the WAL before measuring on-disk footprint.
    @discardableResult
    public func walCheckpoint() -> Bool {
        guard let db = db else { return false }
        guard (try? admitStorageCheckpoint()) != nil else { return false }
        var passiveLog: Int32 = 0
        var passiveCkpt: Int32 = 0
        let rcPassive = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_PASSIVE),
            &passiveLog, &passiveCkpt
        )
        if rcPassive == SQLITE_OK, passiveLog == passiveCkpt { return true }
        guard rcPassive == SQLITE_OK else {
            if rcPassive != SQLITE_BUSY, rcPassive != SQLITE_LOCKED {
                _ = latchStoragePressureIfPresent(resultCode: rcPassive)
            }
            return false
        }

        guard (try? admitStorageCheckpoint()) != nil else { return false }

        var restartLog: Int32 = 0
        var restartCkpt: Int32 = 0
        let rcRestart = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_RESTART),
            &restartLog, &restartCkpt
        )
        if rcRestart != SQLITE_OK,
           rcRestart != SQLITE_BUSY,
           rcRestart != SQLITE_LOCKED {
            _ = latchStoragePressureIfPresent(resultCode: rcRestart)
        }
        return rcRestart == SQLITE_OK && restartLog == restartCkpt
    }

    @discardableResult
    public func walCheckpointTruncate() -> Bool {
        guard let db = db else { return false }
        guard (try? admitStorageCheckpoint()) != nil else { return false }
        var log: Int32 = 0
        var checkpointed: Int32 = 0
        let rc = sqlite3_wal_checkpoint_v2(
            db, nil, Int32(SQLITE_CHECKPOINT_TRUNCATE), &log, &checkpointed
        )
        if rc != SQLITE_OK, rc != SQLITE_BUSY, rc != SQLITE_LOCKED {
            _ = latchStoragePressureIfPresent(resultCode: rc)
        }
        return rc == SQLITE_OK && log == checkpointed
    }

    /// Read the file's `PRAGMA auto_vacuum` mode. Returns 0/1/2
    /// (NONE / FULL / INCREMENTAL); 0 on closed/error.
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }

    // MARK: - Private helpers

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

    private func admitStorageMaintenanceWrite(
        estimatedTransactionBytes: Int64
    ) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitMaintenanceWrite(
            estimatedTransactionBytes: estimatedTransactionBytes
        )
    }

    private func admitStorageCheckpoint() throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitCheckpoint()
    }

    private var storageTransactionReserveBytes: Int64 {
        storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.bytesPerMiB * 8
    }

    private func maintenanceRowMutationUpperBound() -> Int64 {
        if maintenanceHighWaterScannedExistingRows,
           let cached = maintenanceRowMutationHighWaterBytes {
            return max(
                cached,
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
            )
        }
        guard let db else { return storageTransactionReserveBytes }
        let columns = [
            "id", "detected_at", "type", "severity", "title", "tactics",
            "time_span_seconds", "suppressed", "notes", "raw_json",
            "affected_users", "affected_executables", "first_seen", "last_seen",
            "process_tree_depth", "techniques", "ai_tools",
        ]
        let indexed = ["id", "type", "severity"]
        func length(_ column: String) -> String {
            "COALESCE(length(CAST(\"\(column)\" AS BLOB)), 0)"
        }
        let fixed = columns.count * 16 + 6 * 16
        let expression = ([String(fixed)]
            + columns.map(length) + indexed.map(length))
            .joined(separator: " + ")
        var statement: OpaquePointer?
        var upper = max(
            maintenanceRowMutationHighWaterBytes ?? 0,
            SQLitePersistentStoreAdmission.conservativeRowMutationBytes
        )
        if sqlite3_prepare_v2(
            db,
            "SELECT COALESCE(MAX(\(expression)), 0) FROM campaigns",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement {
            defer { sqlite3_finalize(statement) }
            if sqlite3_step(statement) == SQLITE_ROW {
                upper = max(
                    upper,
                    SQLitePersistentStoreAdmission
                        .conservativeEncodedRowMutationBytes(
                            logicalRepresentationBytes: max(
                                0, sqlite3_column_int64(statement, 0)
                            ),
                            pageSizeBytes: sqlitePageSizeBytes,
                            maximumLeafPageTouches: 7
                        )
                )
            }
        } else {
            sqlite3_finalize(statement)
            upper = storageTransactionReserveBytes
        }
        maintenanceRowMutationHighWaterBytes = upper
        maintenanceHighWaterScannedExistingRows = true
        return upper
    }

    private func maintenanceBatchRowLimit() -> Int32 {
        let fixed = SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 18
        )
        return Int32(clamping: max(1,
            SQLitePersistentStoreAdmission.maximumRowsPerTransaction(
                reserveBytes: max(0, storageTransactionReserveBytes - fixed),
                bytesPerRow: maintenanceRowMutationUpperBound()
            )
        ))
    }

    private func maintenanceEstimate(rowCount: Int) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: SQLitePersistentStoreAdmission.saturatingMultiply(
                Int64(max(0, rowCount)),
                by: maintenanceRowMutationUpperBound()
            ),
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 18
        )
    }

    private func admitStorageFullVacuum() throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitFullVacuum()
    }

    private func throwLatchedStoragePressureIfPresent(resultCode: Int32) throws {
        if let pressure = latchStoragePressureIfPresent(resultCode: resultCode) {
            throw pressure
        }
    }

    @discardableResult
    private func latchStoragePressureIfPresent(
        resultCode: Int32
    ) -> SQLitePersistentStoreAdmissionError? {
        guard var admission = storageAdmission else { return nil }
        defer { storageAdmission = admission }
        return admission.latchSQLitePressure(resultCode: resultCode, db: db)
    }

    private func throwLatchedStoragePressureIfPresent(
        details: SQLiteFailureDetails
    ) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        if let pressure = admission.latchSQLitePressure(details: details) {
            throw pressure
        }
    }

    public func storageAdmissionSnapshot() -> SQLitePersistentStoreAdmissionSnapshot? {
        guard var admission = storageAdmission else { return nil }
        defer { storageAdmission = admission }
        return admission.snapshot()
    }

    public func updateStorageAdmission(
        _ policy: SQLitePersistentStorePolicy
    ) throws -> SQLitePersistentStoreAdmissionSnapshot? {
        guard !isReadOnly, let db else { return nil }
        guard var admission = storageAdmission else {
            var created = try SQLitePersistentStoreAdmission(
                databasePath: databasePath,
                policy: policy,
                latchOperationalPressure: true
            )
            try checkpointController?.updateFamily(
                schema: "main",
                configuration: SQLiteControlledCheckpointFamily(
                    databasePath: databasePath,
                    policy: policy
                )
            )
            do {
                try created.installPageLimit(on: db)
            } catch let error as SQLitePersistentStoreAdmissionError
                where error.isOperationalPressure {
                // Retained as a sticky pending ceiling.
            } catch {
                storagePolicy = policy
                storageAdmission = created
                throw error
            }
            storagePolicy = policy
            storageAdmission = created
            return created.snapshot()
        }
        let wasBlocked = admission.growthBlocked
        let writerSetupPending = !isReadOnly && insertStmt == nil
        let result: SQLitePersistentStoreAdmissionSnapshot
        do {
            result = try admission.updatePolicy(policy, on: db)
        } catch {
            storageAdmission = admission
            storagePolicy = policy
            try? checkpointController?.updateFamily(
                schema: "main",
                configuration: SQLiteControlledCheckpointFamily(
                    databasePath: databasePath,
                    policy: policy
                )
            )
            throw error
        }
        storageAdmission = admission
        storagePolicy = policy
        try checkpointController?.updateFamily(
            schema: "main",
            configuration: SQLiteControlledCheckpointFamily(
                databasePath: databasePath,
                policy: policy
            )
        )
        if (wasBlocked || writerSetupPending) && !admission.growthBlocked {
            try reopenAfterStorageRecovery()
            return storageAdmissionSnapshot()
        }
        return result
    }

    private func reopenAfterStorageRecovery() throws {
        guard let policy = storagePolicy else { return }
        let (
            newDB,
            newReadOnly,
            newStatement,
            newAdmission,
            pageSize,
            newCheckpointController
        ) = try Self.openDatabase(
            at: databasePath,
            forceReadOnly: false,
            storagePolicy: policy
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

    private enum BindingValue {
        case text(String)
        case double(Double)
        case int(Int32)
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw CampaignStoreError.prepareFailed(msg)
        }
        return stmt
    }

    private func bindText(_ stmt: OpaquePointer, index: Int32, value: String) {
        _ = value.withCString { cstr in
            sqlite3_bind_text(stmt, index, cstr, -1,
                              unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
    }

    private func bindTextOrNull(_ stmt: OpaquePointer, index: Int32, value: String?) {
        if let value {
            bindText(stmt, index: index, value: value)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    private func bindDoubleOrNull(_ stmt: OpaquePointer, index: Int32, value: Double?) {
        if let value {
            sqlite3_bind_double(stmt, index, value)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    private func query(sql: String, bindings: [(Int32, BindingValue)]) throws -> [Record] {
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }

        for (idx, value) in bindings {
            switch value {
            case .text(let s):   bindText(stmt, index: idx, value: s)
            case .double(let d): sqlite3_bind_double(stmt, idx, d)
            case .int(let i):    sqlite3_bind_int(stmt, idx, i)
            }
        }

        var results: [Record] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let cstr = sqlite3_column_text(stmt, 0) else { continue }
            let json = String(cString: cstr)
            guard let data = json.data(using: .utf8) else { continue }
            do {
                let record = try decoder.decode(Record.self, from: data)
                results.append(record)
            } catch {
                // Skip malformed rows rather than failing the whole query.
                continue
            }
        }
        return results
    }
}
