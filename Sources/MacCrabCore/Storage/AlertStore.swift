// AlertStore.swift
// MacCrabCore
//
// SQLite-backed alert store using the sqlite3 C API directly (no dependencies).
// Uses WAL journal mode for concurrent reads during writes.
// Thread-safe via Swift actor isolation.

import Foundation
import Darwin
import CSQLCipher
import os.log

// MARK: - AlertStoreError

/// Errors that can occur during alert store operations.
public enum AlertStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)
    case notFound(String)
    /// v1.12.6 Wave 9N: distinguish SQLITE_FULL from generic step
    /// failures so callers can stop retrying immediately on a
    /// disk-pressured host instead of hammering the busted insert.
    /// Mirrors EventStore.diskFull (added in v1.12.0 RC28).
    case diskFull(String, failure: SQLiteFailureDetails? = nil)
    case sqliteFailure(
        context: String,
        message: String,
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    )

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let msg):  return "Database open failed: \(msg)"
        case .prepareFailed(let msg):       return "Prepare failed: \(msg)"
        case .stepFailed(let msg):          return "Step failed: \(msg)"
        case .notFound(let id):             return "Alert not found: \(id)"
        case .diskFull(let msg, _):         return "Disk full: \(msg)"
        case let .sqliteFailure(context, message, rc, extended, systemErrno):
            return "SQLite \(context) failed (rc=\(rc), extended=\(extended), system_errno=\(systemErrno)): \(message)"
        }
    }
}

/// A reserve-bounded alert batch can commit a prefix before admission or SQLite
/// rejects a later chunk. Carry the exact durable prefix so AlertSink can commit
/// only the matching dedup reservations and still authorize post-commit work for
/// rows which really exist. The remaining suffix is in original insertion order.
public struct AlertBatchInsertFailure: Error, LocalizedError,
    SQLiteFailureReporting, @unchecked Sendable {
    public let committedAlerts: [Alert]
    public let uncommittedAlerts: [Alert]
    public let underlyingError: any Error

    public init(
        committedAlerts: [Alert],
        uncommittedAlerts: [Alert],
        underlyingError: any Error
    ) {
        self.committedAlerts = committedAlerts
        self.uncommittedAlerts = uncommittedAlerts
        self.underlyingError = underlyingError
    }

    public var errorDescription: String? {
        "Alert batch stopped after \(committedAlerts.count) committed row(s); "
            + "\(uncommittedAlerts.count) row(s) remain: "
            + underlyingError.localizedDescription
    }

    public var sqliteFailureDetails: SQLiteFailureDetails? {
        SQLiteFailureClassifier.details(from: underlyingError)
    }
}

// MARK: - AlertStore

/// A SQLite-backed store for detection alerts.
///
/// Alerts are produced by the rule engine when an event matches a detection
/// rule. Each alert references the originating event by ID and records
/// the rule metadata, severity, and optional MITRE ATT&CK mappings.
///
/// ## Schema
///
/// One table, `alerts`:
///
/// | Column                    | Type    | Notes                                              |
/// |---------------------------|---------|----------------------------------------------------|
/// | `id`                      | TEXT PK | Alert UUID                                         |
/// | `timestamp`               | REAL    | Unix seconds with fractional precision             |
/// | `rule_id`                 | TEXT    | e.g. `maccrab.persistence.launch-agent`            |
/// | `rule_title`              | TEXT    | Human-readable rule name                           |
/// | `severity`                | TEXT    | `critical`/`high`/`medium`/`low`/`informational`   |
/// | `event_id`                | TEXT    | FK into `EventStore.events.id`                     |
/// | `process_path`            | TEXT?   | Absolute executable path of the triggering process |
/// | `process_name`            | TEXT?   | Basename of `process_path`                         |
/// | `description`             | TEXT?   | Rule-authored or formatted alert summary           |
/// | `mitre_tactics`           | TEXT?   | Comma-separated ATT&CK tactic IDs                  |
/// | `mitre_techniques`        | TEXT?   | Comma-separated ATT&CK technique IDs               |
/// | `suppressed`              | INTEGER | 0 = visible, 1 = hidden by user (default 0)        |
/// | `llm_investigation_json`  | TEXT?   | Phase-4 agentic triage (v2 migration)              |
/// | `d3fend_techniques`       | TEXT?   | CSV of D3FEND defensive technique IDs (v3)         |
/// | `remediation_hint`        | TEXT?   | First-line remediation guidance (v3)               |
/// | `analyst_metadata_json`   | TEXT?   | SOC analyst workflow blob (v3)                     |
/// | `campaign_id`             | TEXT?   | Owning CampaignDetector grouping (v4)              |
/// | `user_id`                 | INTEGER?| UID of triggering process (v5, v1.12.6 Wave 2B)    |
/// | `user_name`               | TEXT?   | Username of triggering process owner (v5)          |
/// | `working_directory`       | TEXT?   | Triggering process CWD at event time (v5)          |
/// | `ai_tool`                 | TEXT?   | AI tool attribution (claude_code/cursor/...) (v5)  |
/// | `parent_executable`       | TEXT?   | First ancestor executable path (v5)                |
/// | `process_sha256`          | TEXT?   | SHA-256 of triggering process executable (v5)      |
/// | `host_name`               | TEXT?   | Host where alert was generated (v5)                |
///
/// Indexes cover the common query patterns: time-range, rule, severity,
/// the composite triage path `(timestamp, severity, suppressed)`, plus
/// v5 attribution pivots `user_id` and `(ai_tool, timestamp)`.
///
/// ## Concurrency
///
/// The store is a Swift actor; all reads and writes are serialized at the
/// actor level. SQLite itself uses `SQLITE_OPEN_FULLMUTEX` + WAL mode so
/// concurrent readers from other processes (e.g. `maccrabctl` and the
/// dashboard) do not block writers.
///
/// ## Read-only degradation
///
/// If the file can't be opened read-write (disk-full, SIP-protected path,
/// running unprivileged against the system DB), the store silently retries
/// read-only and sets `isReadOnly = true`. `suppress` / `unsuppress`
/// writes throw `SQLITE_READONLY` in that mode, which the CLI and dashboard
/// treat as non-fatal.
public actor AlertStore {

    // MARK: Properties

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private let databasePath: String
    private var storagePolicy: SQLitePersistentStorePolicy?
    private var storageAdmission: SQLitePersistentStoreAdmission?
    private var sqlitePageSizeBytes: Int64
    private var maintenanceRowMutationHighWaterBytes: Int64? = nil
    private var maintenanceHighWaterScannedExistingRows = false

    // MARK: Prepared statement cache

    private var insertStmt: OpaquePointer?

    /// Whether this store was opened in read-only mode.
    private var isReadOnly = false

    // MARK: - Schema migrations

    /// Ordered list of schema migrations applied on top of the baseline
    /// `CREATE TABLE IF NOT EXISTS alerts` statements in `openDatabase`.
    ///
    /// Each entry bumps `PRAGMA user_version` atomically. Fresh DBs run all
    /// migrations in order; existing DBs skip ones already applied.
    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "baseline",
            sql: []
        ),
        // v2: Phase 4 agentic triage — persist structured LLMInvestigation
        // JSON alongside the alert so the dashboard can show it after a
        // daemon restart. JSON blob column keeps the store flexible as
        // the schema evolves.
        Migration(
            version: 2,
            name: "add_llm_investigation_json",
            sql: [
                "ALTER TABLE alerts ADD COLUMN llm_investigation_json TEXT",
            ]
        ),
        // v3 (v1.11.0): persist the Alert "phantom" enrichments — D3FEND
        // chips, remediation hint, analyst metadata. Pre-v1.11.0 the V2
        // dashboard inspector read these from the in-memory Alert but
        // `if let / !isEmpty` gates hid them after a daemon restart
        // because they weren't persisted. Migration adds three columns;
        // the AnalystMetadata blob is a Codable JSON shape consistent
        // with the LLMInvestigation pattern.
        Migration(
            version: 3,
            name: "add_phantom_field_columns",
            sql: [
                "ALTER TABLE alerts ADD COLUMN d3fend_techniques TEXT",
                "ALTER TABLE alerts ADD COLUMN remediation_hint TEXT",
                "ALTER TABLE alerts ADD COLUMN analyst_metadata_json TEXT",
            ]
        ),
        // v4 (v1.11.0 RC2 ship-blocker fix): persist `Alert.campaignId`.
        // Pre-RC2 the v1.11.0 release added `AlertStore.suppress(campaignId:)`
        // and the MCP suppress_campaign tool used it, but the column was
        // never added to the schema and the field was never bound on
        // insert / restored on read — so every MCP campaign-suppress
        // call errored with "no such column: campaign_id" AND the
        // dashboard inbox-IPC fan-out (`for a in alerts where a.campaignId
        // == id`) silently no-op'd because campaignId was always nil
        // post-restart. Pre-existing v1.10.x bug (Alert.campaignId was
        // never persisted), but the v1.11.0 perf rewrite turned a
        // silent no-op into a hard SQL error. Index on the column so
        // the new UPDATE WHERE clause is O(matching rows) not O(table).
        Migration(
            version: 4,
            name: "add_campaign_id_column",
            sql: [
                "ALTER TABLE alerts ADD COLUMN campaign_id TEXT",
                "CREATE INDEX IF NOT EXISTS idx_alerts_campaign_id ON alerts(campaign_id)",
            ]
        ),
        // v5 (v1.12.6 Wave 2B): promote attribution fields from raw_json
        // / cross-DB join to indexed columns on the alert row itself.
        // Pre-v5 the dashboard "who/where/which AI?" pivots either had
        // to JOIN alerts.db → events.db on event_id (cross-DB join, no
        // FK enforcement, breaks when events drop out of the 24h hot
        // tier) or json_extract the LLM investigation blob. Both are
        // O(table-scan) and fail post-eviction.
        //
        // Source of truth: AlertSink populates these directly from the
        // triggering Event before insertion — single chokepoint, no
        // second insertion path introduced (preserves Pass 2 of
        // pre-release-audit.sh).
        //
        // Indexes:
        //   - idx_alerts_user_id: per-user alert lookups in fleet view.
        //   - idx_alerts_ai_tool_ts: AI-Guard timeline pivots
        //     ("show me alerts for ai_tool=claude_code last 7d").
        Migration(
            version: 5,
            name: "add_attribution_columns",
            sql: [
                "ALTER TABLE alerts ADD COLUMN user_id INTEGER",
                "ALTER TABLE alerts ADD COLUMN user_name TEXT",
                "ALTER TABLE alerts ADD COLUMN working_directory TEXT",
                "ALTER TABLE alerts ADD COLUMN ai_tool TEXT",
                "ALTER TABLE alerts ADD COLUMN parent_executable TEXT",
                "ALTER TABLE alerts ADD COLUMN process_sha256 TEXT",
                "ALTER TABLE alerts ADD COLUMN host_name TEXT",
                "CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_ai_tool_ts ON alerts(ai_tool, timestamp)",
            ]
        ),
        // v6 (v1.17.2): snapshot the triggering event(s) ONTO the alert.
        // Pre-v6 an alert kept only event_id; events.db prunes on a ~30 min
        // hot tier while alerts are retained ~365 days, so by the time an
        // operator opens an old alert the triggering event is long gone and
        // the dashboard could only do a lossy ±30 min time-window search
        // around the alert timestamp. This column stores a bounded JSON array
        // of the contributing event raw_json blobs (triggering event first,
        // plus contributing events for sequence/campaign alerts) captured at
        // alert-creation in AlertSink — the same single chokepoint the v5
        // attribution columns use. Bounded by EventSnapshot.maxEvents and the
        // existing 64 KB-per-event payload cap; expires with the alert row, so
        // no separate retention/prune is needed.
        Migration(
            version: 6,
            name: "add_triggering_events_snapshot",
            sql: [
                "ALTER TABLE alerts ADD COLUMN triggering_events_json TEXT",
            ]
        ),
        // v7 (Wave-3 P2): tie an alert to the durable agent session whose
        // activity tripped it (the alert rail of the session timeline).
        // Lifted from the triggering event's ai_tool_session_id in AlertSink.
        Migration(
            version: 7,
            name: "add_ai_tool_session_id",
            sql: [
                "ALTER TABLE alerts ADD COLUMN ai_tool_session_id TEXT",
                "CREATE INDEX IF NOT EXISTS idx_alerts_ai_session_ts ON alerts(ai_tool_session_id, timestamp) WHERE ai_tool_session_id IS NOT NULL",
            ]
        ),
    ]

    // MARK: Initialization

    /// Throw `AlertStoreError.databaseOpenFailed` if `path` exists and is a
    /// symbolic link. A missing file is always OK — SQLite will create it.
    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return // does not exist yet — safe
        }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw AlertStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
        }
    }

    private static func defaultStoragePolicy(
        for databasePath: String
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            maxFootprintBytes: 100 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent
        )
    }

    /// Opens a SQLite database, creates schema, and prepares statements before
    /// actor isolation begins. Returns all handles so init can assign directly.
    ///
    /// - Parameter forceReadOnly: When `true`, open with
    ///   `SQLITE_OPEN_READONLY` and skip the RW attempt. The dashboard
    ///   (MacCrabApp/V2LiveDataProvider) uses this to keep its long-lived
    ///   handle from holding shared/upgrade locks that would block the
    ///   daemon's `VACUUM` / `wal_checkpoint(TRUNCATE)`. See
    ///   `EventStore.openDatabase` for the v1.12.6 Wave 9A field background.
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
        // Preflight the DB path and its WAL/SHM/journal sidecars for clear
        // diagnostics and reject multiply-linked family members. The actual
        // SQLite open also uses NOFOLLOW through SQLiteOpenPathPolicy, closing
        // symlink races at the open boundary. Non-symlink replacement safety
        // relies on the shipping owner-controlled support directory.
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")

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
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            if let db { sqlite3_close(db) }
            throw AlertStoreError.sqliteFailure(
                context: "database open",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
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
            // v1.6.22: pragmas centralized in StoragePragmas.applyAlertStorePragmas.
            // Alerts table is much smaller than events; uses tighter 4 MB cache
            // + 16 MB mmap.
            do {
                try StoragePragmas.applyAlertStorePragmasChecked(to: handle)
            } catch let failure as StoragePragmas.ApplicationFailure {
                throw AlertStoreError.sqliteFailure(
                    context: failure.sql,
                    message: String(cString: sqlite3_errmsg(handle)),
                    resultCode: failure.metadata.resultCode,
                    extendedResultCode: failure.metadata.extendedResultCode,
                    systemErrno: failure.metadata.systemErrno
                )
            }
        }
        // v1.4.4 — see EventStore.swift for the busy_timeout rationale.
        try Self.exec(handle, "PRAGMA busy_timeout = 5000")
        try Self.exec(handle, "PRAGMA foreign_keys = ON")

        // Create schema. The CREATE TABLE statement reflects the *latest*
        // schema (v5 attribution columns inline) so a fresh install lands
        // with the full column set without needing the ALTER TABLE
        // migration path to run. Existing v1..v4 DBs get the new columns
        // via the v5 Migration entry below (idempotent ADD COLUMN).
        let schemaSQLs = [
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                rule_id TEXT NOT NULL, rule_title TEXT NOT NULL,
                severity TEXT NOT NULL, event_id TEXT NOT NULL,
                process_path TEXT, process_name TEXT, description TEXT,
                mitre_tactics TEXT, mitre_techniques TEXT,
                suppressed INTEGER DEFAULT 0,
                llm_investigation_json TEXT,
                d3fend_techniques TEXT,
                remediation_hint TEXT,
                analyst_metadata_json TEXT,
                campaign_id TEXT,
                user_id INTEGER,
                user_name TEXT,
                working_directory TEXT,
                ai_tool TEXT,
                parent_executable TEXT,
                process_sha256 TEXT,
                host_name TEXT,
                triggering_events_json TEXT,
                ai_tool_session_id TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts(event_id)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_ts_severity ON alerts(timestamp, severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_rule_ts ON alerts(rule_id, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_ts_sev_sup ON alerts(timestamp, severity, suppressed)",
        ]
        if writerInitializationAllowed {
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: schemaSQLs
                )
            )
            for sql in schemaSQLs { try Self.exec(handle, sql) }
        }

        // Apply versioned schema migrations on top of the baseline tables above.
        // v1 marks "baseline schema present"; later versions add columns for
        // campaign linkage, host context, analyst metadata, etc.
        // v1.12.0: skip the per-init quick_check — see EventStore for the
        // boot-path latency rationale. Callers can invoke `runQuickCheck()`
        // from a deferred Task once the store is up.
        if writerInitializationAllowed {
            try SchemaMigrator.run(
                on: handle,
                migrations: Self.schemaMigrations,
                skipQuickCheck: true,
                beforeStorageWork: { work in
                    try admitSchemaWork(work)
                }
            )
            // These indexes reference columns added by migrations v4/v5/v7.
            // Creating them in the pre-migration baseline makes a direct
            // legacy upgrade fail before ALTER TABLE can add those columns.
            // Re-resolve them after migration as both an ordering boundary and
            // a latest-version missing-index repair gate.
            let postMigrationIndexSQLs = [
                "CREATE INDEX IF NOT EXISTS idx_alerts_campaign_id ON alerts(campaign_id)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_ai_tool_ts ON alerts(ai_tool, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_ai_session_ts ON alerts(ai_tool_session_id, timestamp) WHERE ai_tool_session_id IS NOT NULL",
            ]
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: postMigrationIndexSQLs
                )
            )
            for sql in postMigrationIndexSQLs { try Self.exec(handle, sql) }
        }

        // Prepare insert statement
        let insertSQL = """
            INSERT OR REPLACE INTO alerts (
                id, timestamp, rule_id, rule_title, severity,
                event_id, process_path, process_name, description,
                mitre_tactics, mitre_techniques, suppressed,
                llm_investigation_json,
                d3fend_techniques, remediation_hint, analyst_metadata_json,
                campaign_id,
                user_id, user_name, working_directory,
                ai_tool, parent_executable, process_sha256, host_name,
                triggering_events_json, ai_tool_session_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)
            """
        var insertStmt: OpaquePointer?
        let prepareRC = !writerInitializationAllowed
            ? SQLITE_OK
            : sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil)
        if prepareRC != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            let failure = SQLiteFailureDetails(resultCode: prepareRC, db: handle)
            throw AlertStoreError.sqliteFailure(
                context: "prepare insert",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
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
            throw AlertStoreError.databaseOpenFailed("could not read PRAGMA page_size")
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw AlertStoreError.databaseOpenFailed("PRAGMA page_size returned no row")
        }
        let pageSize = sqlite3_column_int64(stmt, 0)
        guard pageSize > 0,
              pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            throw AlertStoreError.databaseOpenFailed("invalid PRAGMA page_size=\(pageSize)")
        }
        return pageSize
    }

    /// Execute a SQL statement on a raw handle (used during init before actor is live).
    /// Execute SQL on a raw handle and surface the error via os.log on
    /// failure. See the EventStore.exec comment for the rationale.
    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            Logger(subsystem: "com.maccrab.storage", category: "alert-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
            throw AlertStoreError.sqliteFailure(
                context: sql,
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }

    /// Creates an `AlertStore` backed by a SQLite database at the default location.
    ///
    /// The database is stored at `<directory>/alerts.db`. v1.8.0 split this
    /// out of the shared `events.db` file so alert history can have its own
    /// retention budget — a heavy event firehose can no longer evict alerts
    /// as collateral damage on storage prune. Existing v1.7-shape DBs are
    /// migrated by `AlertsTableRelocator` at daemon startup.
    ///
    /// - Parameters:
    ///   - directory: Filesystem directory the store should live in.
    ///   - forceReadOnly: When `true`, open with `SQLITE_OPEN_READONLY` and
    ///     skip chmod / umask management. The dashboard sets this to
    ///     guarantee its connection never holds locks that block the
    ///     daemon's `VACUUM`. Suppress / unsuppress / delete from the
    ///     dashboard route through the inbox file-IPC channel
    ///     (v1.10.1's fix) when SQLITE_READONLY surfaces — that fallback
    ///     was already in place; Wave 9A simply guarantees we take it.
    /// - Throws: `AlertStoreError` if the database cannot be opened or initialized.
    public init(
        directory: String = "/Library/Application Support/MacCrab",
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        let maccrabDir = URL(fileURLWithPath: directory)

        if !forceReadOnly {
            try FileManager.default.createDirectory(
                at: maccrabDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
            // rwxr-xr-x: non-root MacCrab.app needs to read alerts
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: maccrabDir.path
            )
        }

        let databasePath = maccrabDir.appendingPathComponent("alerts.db").path
        self.databasePath = databasePath
        let effectiveStoragePolicy = forceReadOnly
            ? nil
            : (storagePolicy ?? Self.defaultStoragePolicy(for: databasePath))
        self.storagePolicy = effectiveStoragePolicy
        // v1.21.5 (audit sec-storage-crypto): 0o027/0o640 (owner rw, group
        // read-only) — NOT the old 0o007/0o660. The default macOS user is
        // in the admin group (gid 80), so a group-WRITE bit let a non-root
        // admin process open alerts.db read-write and INSERT suppression
        // rows to silence the EDR with no escalation. Suppression now
        // routes through the privileged inbox IPC (dashboard + MCP), which
        // the root daemon applies; the dashboard only READS (group-read).
        // See EventStore.init for the full rationale.
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
        // Skip chmod when forceReadOnly: the dashboard is not the owner
        // and has no business touching the daemon-owned file's mode bits.
        if !forceReadOnly {
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
        }
    }

    /// Creates an `AlertStore` at a custom path (useful for testing).
    ///
    /// - Parameters:
    ///   - path: Full file system path for the SQLite database.
    ///   - forceReadOnly: See `init(directory:forceReadOnly:)`.
    /// - Throws: `AlertStoreError` if the database cannot be opened or initialized.
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


    /// Run SQLite `PRAGMA quick_check` on the open handle, deferred off
    /// the daemon boot path. See `EventStore.runQuickCheck` for the
    /// rationale — boot-time savings without sacrificing correctness
    /// (real corruption still surfaces immediately on actual queries).
    public func runQuickCheck() {
        guard let db = self.db else { return }
        do {
            try SchemaMigrator.quickCheck(on: db) { msg in
                Logger(subsystem: "com.maccrab.storage", category: "alert-store")
                    .info("quick_check: \(msg, privacy: .public)")
            }
        } catch {
            Logger(subsystem: "com.maccrab.storage", category: "alert-store")
                .warning("Deferred quick_check failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: - Insert

    /// Persists a single alert to the store.
    ///
    /// - Parameter alert: The alert to store.
    /// - Throws: `AlertStoreError` on database failure.
    public func insert(alert: Alert) throws {
        try insert(alert: alert) { rowBytes in
            try self.admitStorageWrite(
                estimatedTransactionBytes: self.alertTransactionEstimate(
                    rowMutationBytes: rowBytes
                )
            )
        }
    }

    private func insert(
        alert: Alert,
        beforeWrite: (Int64) throws -> Void
    ) throws {
        let newRowBytes: Int64
        do {
            newRowBytes = try Self.estimatedAlertMutationBytes(
                alert,
                pageSizeBytes: sqlitePageSizeBytes
            )
        } catch {
            throw AlertStoreError.stepFailed(
                "alert transaction estimate encode failed: \(error.localizedDescription)"
            )
        }
        let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            newRowBytes,
            try existingAlertMutationBytes(id: alert.id)
        )
        try beforeWrite(rowBytes)

        // beforeWrite performs storage admission and may recover by reopening
        // the database, which finalizes the old cached insert statement. Never
        // retain that pointer across the admission boundary.
        guard let stmt = insertStmt else {
            // admitStorageWrite already performs one full-estimate secondary
            // recovery when a fresh open races back into shed-only mode.
            throw AlertStoreError.prepareFailed(
                "Insert statement not prepared after storage admission"
            )
        }
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)

        // 1: id
        bindText(stmt, index: 1, value: alert.id)
        // 2: timestamp
        sqlite3_bind_double(stmt, 2, alert.timestamp.timeIntervalSince1970)
        // 3: rule_id
        bindText(stmt, index: 3, value: alert.ruleId)
        // 4: rule_title
        bindText(stmt, index: 4, value: alert.ruleTitle)
        // 5: severity
        bindText(stmt, index: 5, value: alert.severity.rawValue)
        // 6: event_id
        bindText(stmt, index: 6, value: alert.eventId)
        // 7: process_path
        bindTextOrNull(stmt, index: 7, value: alert.processPath)
        // 8: process_name
        bindTextOrNull(stmt, index: 8, value: alert.processName)
        // 9: description
        bindTextOrNull(stmt, index: 9, value: alert.description)
        // 10: mitre_tactics
        bindTextOrNull(stmt, index: 10, value: alert.mitreTactics)
        // 11: mitre_techniques
        bindTextOrNull(stmt, index: 11, value: alert.mitreTechniques)
        // 12: suppressed
        sqlite3_bind_int(stmt, 12, alert.suppressed ? 1 : 0)
        // 13: llm_investigation_json — serialized structured triage output
        if let inv = alert.llmInvestigation,
           let data = try? Self.investigationEncoder.encode(inv),
           let json = String(data: data, encoding: .utf8) {
            bindText(stmt, index: 13, value: json)
        } else {
            sqlite3_bind_null(stmt, 13)
        }
        // 14: d3fend_techniques — CSV of D3FEND defensive technique IDs
        // (schema v3, v1.11.0). Pre-v1.11.0 these existed on `Alert`
        // but were dropped on persist; the V2 inspector hid the chips
        // post-restart even though they'd been computed at alert time.
        if let d3fend = alert.d3fendTechniques, !d3fend.isEmpty {
            bindText(stmt, index: 14, value: d3fend.joined(separator: ","))
        } else {
            sqlite3_bind_null(stmt, 14)
        }
        // 15: remediation_hint — first-line guidance (schema v3, v1.11.0).
        bindTextOrNull(stmt, index: 15, value: alert.remediationHint)
        // 16: analyst_metadata_json — analyst workflow state (notes,
        // owner, status, ticket ref). Codable JSON blob (schema v3, v1.11.0).
        if let analyst = alert.analyst,
           let data = try? Self.investigationEncoder.encode(analyst),
           let json = String(data: data, encoding: .utf8) {
            bindText(stmt, index: 16, value: json)
        } else {
            sqlite3_bind_null(stmt, 16)
        }
        // 17: campaign_id — required so AlertStore.suppress(campaignId:)
        // and the inbox-IPC fan-out actually find rows post-restart
        // (schema v4, v1.11.0 RC2). Pre-fix this field was Codable on
        // Alert but never reached SQL.
        bindTextOrNull(stmt, index: 17, value: alert.campaignId)
        // 18-24: attribution columns (schema v5, v1.12.6 Wave 2B).
        // NULL when the alert was constructed without an Event (self-
        // defense, ES health, scheduled-report stubs) — AlertSink
        // populates these from `event.process.*` for event-bound paths.
        // bindTextNonEmptyOrNull normalises "" → NULL so query-time
        // `WHERE ai_tool IS NOT NULL` doesn't pick up sentinel empties.
        if let uid = alert.userId {
            sqlite3_bind_int64(stmt, 18, Int64(uid))
        } else {
            sqlite3_bind_null(stmt, 18)
        }
        bindTextNonEmptyOrNull(stmt, index: 19, value: alert.userName)
        bindTextNonEmptyOrNull(stmt, index: 20, value: alert.workingDirectory)
        bindTextNonEmptyOrNull(stmt, index: 21, value: alert.aiTool)
        bindTextNonEmptyOrNull(stmt, index: 22, value: alert.parentExecutable)
        bindTextNonEmptyOrNull(stmt, index: 23, value: alert.processSha256)
        bindTextNonEmptyOrNull(stmt, index: 24, value: alert.hostName)
        // 25: triggering-event snapshot (schema v6). NULL for alerts built
        // without contributing events. AlertSink fills this from the Event(s).
        bindTextNonEmptyOrNull(stmt, index: 25, value: alert.triggeringEventsJson)
        // 26: durable agent session id (schema v7). NULL unless the trigger
        // was AI-attributed; AlertSink lifts it from the event enrichment.
        bindTextNonEmptyOrNull(stmt, index: 26, value: alert.aiToolSessionId)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            // v1.12.6 Wave 9N: surface SQLite/VFS exhaustion distinctly,
            // matching EventStore's Resil-B1 pattern. The
            // alert path doesn't have a hot-loop retry, but callers
            // (AlertSink, suppression sync, etc.) should still see the
            // disk-pressure signal rather than a generic step failure.
            if failure.primaryResultCode == SQLITE_FULL
                || failure.systemErrno == ENOSPC
                || failure.systemErrno == EDQUOT {
                throw AlertStoreError.diskFull(msg, failure: failure)
            }
            throw AlertStoreError.sqliteFailure(
                context: "insert step",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
        maintenanceRowMutationHighWaterBytes = max(
            maintenanceRowMutationHighWaterBytes ?? 0,
            rowBytes
        )
    }

    static func estimatedAlertMutationBytes(
        _ alert: Alert,
        pageSizeBytes: Int64
    ) throws -> Int64 {
        // Encoding the full Codable alert is at least as large as its table
        // text representation: nested JSON strings are escaped in this outer
        // payload. Add each secondary-index text key separately because those
        // are additional durable b-tree copies.
        let encoded = try investigationEncoder.encode(alert)
        var logical = Int64(encoded.count + 26 * 16)
        let indexed: [String?] = [
            alert.id,
            alert.ruleId,
            alert.ruleId,
            alert.severity.rawValue,
            alert.severity.rawValue,
            alert.severity.rawValue,
            alert.eventId,
            alert.campaignId,
            alert.aiTool,
            alert.aiToolSessionId,
        ]
        for value in indexed {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                Int64(value?.utf8.count ?? 0) + 16
            )
        }
        // timestamp-only and user_id-only indexes have no text key above.
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical, 2 * 16
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: pageSizeBytes,
                maximumLeafPageTouches: 13
            )
    }

    /// `INSERT OR REPLACE` deletes the prior row and all of its index entries
    /// before inserting the new representation. Read the authoritative stored
    /// values so an old large row cannot hide outside the incoming estimate.
    private func existingAlertMutationBytes(id: String) throws -> Int64 {
        guard let db else { return 0 }
        let sql = """
            SELECT id, timestamp, rule_id, rule_title, severity, event_id,
                   process_path, process_name, description, mitre_tactics,
                   mitre_techniques, suppressed, llm_investigation_json,
                   d3fend_techniques, remediation_hint, analyst_metadata_json,
                   campaign_id, user_id, user_name, working_directory, ai_tool,
                   parent_executable, process_sha256, host_name,
                   triggering_events_json, ai_tool_session_id
            FROM alerts WHERE id = ?1 LIMIT 1
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            sqlite3_finalize(statement)
            throw AlertStoreError.prepareFailed("existing alert estimate")
        }
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: id)
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return 0 }
        guard step == SQLITE_ROW else {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw AlertStoreError.stepFailed("existing alert estimate step")
        }
        func bytes(_ column: Int32) -> Int64 {
            sqlite3_column_type(statement, column) == SQLITE_NULL
                ? 0 : Int64(sqlite3_column_bytes(statement, column))
        }
        var logical = Int64(26 * 16)
        for column in Int32(0)..<Int32(26) {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        // PK plus 11 explicit indexes. Numeric-only key portions are covered
        // by the fixed allowance; duplicated text keys are charged per b-tree.
        for column in [0, 2, 2, 4, 4, 4, 5, 16, 20, 25] as [Int32] {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical, 12 * 16
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 13
            )
    }

    private func alertTransactionEstimate(rowMutationBytes: Int64) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowMutationBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 32
        )
    }

    /// Persists alerts in reserve-bounded transactions. Alert ids use REPLACE,
    /// so retrying the caller array after a later chunk fails is idempotent.
    /// A failure after at least one commit is wrapped in
    /// ``AlertBatchInsertFailure`` with the exact durable prefix. A failure before
    /// any commit preserves the original error type for existing callers.
    ///
    /// - Parameter alerts: The alerts to store.
    /// - Throws: `AlertStoreError` on database failure.
    @discardableResult
    public func insert(alerts: [Alert]) throws -> [Alert] {
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.bytesPerMiB * 8
        var transactionOpen = false
        var rowEstimate: Int64 = 0
        var openTransactionAlerts: [Alert] = []
        var committedAlerts: [Alert] = []

        func commit() throws {
            guard transactionOpen else { return }
            try execute("COMMIT")
            committedAlerts.append(contentsOf: openTransactionAlerts)
            openTransactionAlerts.removeAll(keepingCapacity: true)
            transactionOpen = false
            rowEstimate = 0
        }
        do {
            for alert in alerts {
                try insert(alert: alert) { rowBytes in
                    let nextRows = SQLitePersistentStoreAdmission.saturatingAdd(
                        rowEstimate,
                        rowBytes
                    )
                    if transactionOpen,
                       alertTransactionEstimate(rowMutationBytes: nextRows) > reserve {
                        try commit()
                    }
                    if !transactionOpen {
                        try execute(
                            "BEGIN TRANSACTION",
                            estimatedTransactionBytes:
                                alertTransactionEstimate(
                                    rowMutationBytes: rowBytes
                                )
                        )
                        transactionOpen = true
                    }
                    rowEstimate = SQLitePersistentStoreAdmission.saturatingAdd(
                        rowEstimate,
                        rowBytes
                    )
                }
                openTransactionAlerts.append(alert)
            }
            try commit()
            return committedAlerts
        } catch {
            if transactionOpen { try? execute("ROLLBACK") }
            guard !committedAlerts.isEmpty else { throw error }
            throw AlertBatchInsertFailure(
                committedAlerts: committedAlerts,
                uncommittedAlerts: Array(alerts.dropFirst(committedAlerts.count)),
                underlyingError: error
            )
        }
    }

    // MARK: - Query

    /// Returns alerts from the store, optionally filtered by time range and severity.
    ///
    /// - Parameters:
    ///   - since: Only return alerts at or after this date.
    ///   - severity: If provided, only return alerts at this severity or higher.
    ///   - suppressed: If provided, filter by suppression status.
    ///   - limit: Maximum number of alerts to return (default 500).
    /// - Returns: An array of `Alert` values, most recent first.
    public func alerts(
        since: Date,
        severity: Severity? = nil,
        suppressed: Bool? = nil,
        limit: Int = 500
    ) throws -> [Alert] {
        var sql = "SELECT * FROM alerts WHERE timestamp >= ?1"
        var bindings: [(Int32, BindingValue)] = [
            (1, .double(since.timeIntervalSince1970))
        ]
        var nextIndex: Int32 = 2

        if let severity {
            let validSeverities = Severity.allCases.filter { $0 >= severity }
            let placeholders = validSeverities.enumerated().map { i, _ in
                "?\(nextIndex + Int32(i))"
            }.joined(separator: ", ")
            sql += " AND severity IN (\(placeholders))"
            for (i, sev) in validSeverities.enumerated() {
                bindings.append((nextIndex + Int32(i), .text(sev.rawValue)))
            }
            nextIndex += Int32(validSeverities.count)
        }

        if let suppressed {
            sql += " AND suppressed = ?\(nextIndex)"
            bindings.append((nextIndex, .int(suppressed ? 1 : 0)))
            nextIndex += 1
        }

        sql += " ORDER BY timestamp DESC LIMIT ?\(nextIndex)"
        bindings.append((nextIndex, .int(Int32(limit))))

        return try queryAlerts(sql: sql, bindings: bindings)
    }

    /// Exact-rule-id variant of `alerts(since:)`. v1.21.5: the generic query
    /// applies its row cap BEFORE any caller-side rule filter, so a
    /// low-volume rule's alerts (e.g. `maccrab.intent.bayesian-posterior`)
    /// could be crowded out of the 500-row window entirely on a busy box.
    /// Filtering at the SQL layer (parameterized equality, mirroring the
    /// `campaigns(before:)` rule_id-LIKE precedent) keeps the cap meaningful.
    ///
    /// - Parameters:
    ///   - since: Only return alerts at or after this date.
    ///   - ruleId: Exact `rule_id` to match.
    ///   - limit: Maximum number of alerts to return (default 500).
    /// - Returns: An array of `Alert` values, most recent first.
    public func alerts(since: Date, ruleId: String, limit: Int = 500) throws -> [Alert] {
        let sql = """
            SELECT * FROM alerts WHERE timestamp >= ?1 AND rule_id = ?2
            ORDER BY timestamp DESC LIMIT ?3
            """
        return try queryAlerts(sql: sql, bindings: [
            (1, .double(since.timeIntervalSince1970)),
            (2, .text(ruleId)),
            (3, .int(Int32(limit))),
        ])
    }

    /// Keyset-paginated variant. Returns at most `pageSize` alerts strictly
    /// older than `cursor` (or the newest page if `cursor == nil`), plus
    /// the cursor for the next page.
    ///
    /// Use this for "Load older" style UIs over Alerts: the list view holds
    /// the cursor for the oldest currently-visible row, and a button calls
    /// this with that cursor to append the next page. Stable under writes
    /// — new alerts arriving between fetches don't shift the window.
    ///
    /// `pageSize` is the requested batch size; the underlying SQL clamps
    /// to at most 1000 to keep a single page fast and bounded. Callers
    /// wanting bulk export should iterate.
    public func alerts(
        before cursor: PaginationCursor?,
        severity: Severity? = nil,
        suppressed: Bool? = nil,
        pageSize: Int = 100
    ) throws -> PagedResults<Alert> {
        let clamped = max(1, min(pageSize, 1000))

        var sql = "SELECT * FROM alerts WHERE 1=1"
        var bindings: [(Int32, BindingValue)] = []
        var nextIndex: Int32 = 1

        if let cursor {
            // Tuple comparison: (ts, id) strictly less than the cursor in
            // (timestamp DESC, id DESC) order.
            sql += " AND (timestamp < ?\(nextIndex) OR (timestamp = ?\(nextIndex + 1) AND id < ?\(nextIndex + 2)))"
            bindings.append((nextIndex, .double(cursor.timestamp.timeIntervalSince1970)))
            bindings.append((nextIndex + 1, .double(cursor.timestamp.timeIntervalSince1970)))
            bindings.append((nextIndex + 2, .text(cursor.id)))
            nextIndex += 3
        }

        if let severity {
            let validSeverities = Severity.allCases.filter { $0 >= severity }
            let placeholders = validSeverities.enumerated().map { i, _ in
                "?\(nextIndex + Int32(i))"
            }.joined(separator: ", ")
            sql += " AND severity IN (\(placeholders))"
            for (i, sev) in validSeverities.enumerated() {
                bindings.append((nextIndex + Int32(i), .text(sev.rawValue)))
            }
            nextIndex += Int32(validSeverities.count)
        }

        if let suppressed {
            sql += " AND suppressed = ?\(nextIndex)"
            bindings.append((nextIndex, .int(suppressed ? 1 : 0)))
            nextIndex += 1
        }

        sql += " ORDER BY timestamp DESC, id DESC LIMIT ?\(nextIndex)"
        bindings.append((nextIndex, .int(Int32(clamped))))

        let rows = try queryAlerts(sql: sql, bindings: bindings)

        // If we got a full page, hand back a cursor pointing at the last
        // row so the caller can fetch the next page. A short page means
        // we hit the end of the table — no more pages exist.
        let next: PaginationCursor?
        if rows.count == clamped, let last = rows.last {
            next = PaginationCursor(timestamp: last.timestamp, id: last.id)
        } else {
            next = nil
        }
        return PagedResults(items: rows, nextCursor: next)
    }

    /// Keyset-paginated variant for **campaign rows only** — the synthetic
    /// alerts whose `rule_id` starts with `maccrab.campaign.`. Filtering at
    /// the SQL layer (LIKE `'maccrab.campaign.%'`) replaces the legacy
    /// "fetch 1000 alerts then in-process .filter().prefix()" pattern, which
    /// silently dropped any campaign older than the most-recent 1000 alerts.
    ///
    /// Mirrors `alerts(before:)` for shape — same cursor contract, same
    /// `pageSize` clamp.
    public func campaigns(
        before cursor: PaginationCursor?,
        pageSize: Int = 100
    ) throws -> PagedResults<Alert> {
        let clamped = max(1, min(pageSize, 1000))

        var sql = "SELECT * FROM alerts WHERE rule_id LIKE 'maccrab.campaign.%'"
        var bindings: [(Int32, BindingValue)] = []
        var nextIndex: Int32 = 1

        if let cursor {
            sql += " AND (timestamp < ?\(nextIndex) OR (timestamp = ?\(nextIndex + 1) AND id < ?\(nextIndex + 2)))"
            bindings.append((nextIndex, .double(cursor.timestamp.timeIntervalSince1970)))
            bindings.append((nextIndex + 1, .double(cursor.timestamp.timeIntervalSince1970)))
            bindings.append((nextIndex + 2, .text(cursor.id)))
            nextIndex += 3
        }

        sql += " ORDER BY timestamp DESC, id DESC LIMIT ?\(nextIndex)"
        bindings.append((nextIndex, .int(Int32(clamped))))

        let rows = try queryAlerts(sql: sql, bindings: bindings)
        let next: PaginationCursor?
        if rows.count == clamped, let last = rows.last {
            next = PaginationCursor(timestamp: last.timestamp, id: last.id)
        } else {
            next = nil
        }
        return PagedResults(items: rows, nextCursor: next)
    }

    /// Substring search across the alert's user-visible text fields.
    ///
    /// Unlike `EventStore.search`, the alerts table has no FTS5 virtual
    /// table — it's small enough (typically <10K rows) that LIKE on five
    /// columns is fast. Pattern is parameterized so it can't escape the
    /// query; SQLite's LIKE operator only treats `%` and `_` as wildcards
    /// and we wrap the user's text with `%…%` for substring semantics. The
    /// caller doesn't need to escape the input.
    ///
    /// Results are most-recent-first (matches the dashboard ordering).
    public func search(text: String, limit: Int = 100) throws -> [Alert] {
        let clamped = max(1, min(limit, 1000))
        // Strip any embedded LIKE wildcards so a user typing literal `%` or
        // `_` doesn't get unexpected matches. We don't support glob syntax
        // here — search is plain substring.
        let cleaned = text
            .replacingOccurrences(of: "%", with: "")
            .replacingOccurrences(of: "_", with: "")
        let pattern = "%\(cleaned)%"

        let sql = """
            SELECT * FROM alerts
            WHERE rule_title LIKE ?1
               OR process_name LIKE ?2
               OR process_path LIKE ?3
               OR description LIKE ?4
               OR mitre_techniques LIKE ?5
            ORDER BY timestamp DESC, id DESC
            LIMIT ?6
            """
        return try queryAlerts(sql: sql, bindings: [
            (1, .text(pattern)),
            (2, .text(pattern)),
            (3, .text(pattern)),
            (4, .text(pattern)),
            (5, .text(pattern)),
            (6, .int(Int32(clamped))),
        ])
    }

    /// Returns alerts associated with a specific event.
    ///
    /// - Parameter eventId: The event's unique identifier.
    /// - Returns: Up to 1000 alerts that reference the given event.
    ///
    /// v1.11.0 (audit perf MEDIUM): added `LIMIT 1000`. Normally 1-3 rows
    /// per event, but a rule storm pinned to the same event_id (e.g.
    /// hundreds of behavioural-score variants firing on the same exec)
    /// previously returned the unbounded set. The cap is high enough
    /// that legitimate use cases never hit it.
    public func alerts(forEventId eventId: String) throws -> [Alert] {
        let sql = "SELECT * FROM alerts WHERE event_id = ?1 ORDER BY timestamp DESC LIMIT 1000"
        return try queryAlerts(sql: sql, bindings: [(1, .text(eventId))])
    }

    /// Wave-3 P2: alerts tripped by a given durable agent session, oldest
    /// first (timeline order). Backed by idx_alerts_ai_session_ts.
    public func alerts(forAgentSession sessionId: String, limit: Int = 1000) throws -> [Alert] {
        let sql = "SELECT * FROM alerts WHERE ai_tool_session_id = ?1 ORDER BY timestamp ASC LIMIT ?2"
        return try queryAlerts(sql: sql, bindings: [(1, .text(sessionId)), (2, .int(Int32(max(1, min(limit, 5000)))))])
    }

    /// Returns a single alert by its identifier.
    ///
    /// - Parameter id: The alert's unique ID.
    /// - Returns: The alert, or `nil` if not found.
    public func alert(id: String) throws -> Alert? {
        let sql = "SELECT * FROM alerts WHERE id = ?1 LIMIT 1"
        return try queryAlerts(sql: sql, bindings: [(1, .text(id))]).first
    }

    /// Returns the total number of alerts in the store.
    public func count() throws -> Int {
        let sql = "SELECT COUNT(*) FROM alerts"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_ROW else {
            throw AlertStoreError.stepFailed("Failed to count alerts")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// FF-04: SQL-side count of campaign rows (`rule_id LIKE
    /// 'maccrab.campaign.%'`, the same predicate as `campaigns(before:)`).
    ///
    /// `maccrabctl status` derived this by fetching the newest 500 alerts and
    /// filtering in-process, so it printed "0 campaign(s)" whenever the most
    /// recent 500 alerts happened to hold no campaign row — on a busy host that
    /// is the normal case, and it reinforced the same false empty state the
    /// `campaigns` subcommand was giving. A count must never be derived from a
    /// capped sample.
    public func campaignCount() throws -> Int {
        let sql = "SELECT COUNT(*) FROM alerts WHERE rule_id LIKE 'maccrab.campaign.%'"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed("Failed to count campaign alerts")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// v1.18: read-only count of UNSUPPRESSED alerts for a campaign — the
    /// pre-flight for the MCP `suppress_campaign` fan-out confirmation. Uses
    /// the IDENTICAL predicate as `suppress(campaignId:)` so the count and
    /// the subsequent UPDATE agree exactly.
    public func countByCampaign(campaignId id: String) throws -> Int {
        let sql = "SELECT COUNT(*) FROM alerts WHERE campaign_id = ?1 AND suppressed = 0"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed("Failed to count alerts by campaign")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// PERF-5: exact count of alerts since `since`, computed SQL-side (no row
    /// materialization). Replaces counting via `alerts(…, limit: 5000).count`,
    /// which silently UNDERCOUNTED once a busy host exceeded the 5000-row cap.
    public func openAlertCount(since: Date, includeSuppressed: Bool = false) throws -> Int {
        var sql = "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?1"
        if !includeSuppressed { sql += " AND suppressed = 0" }
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, since.timeIntervalSince1970)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed("Failed to count open alerts")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// PERF-3: per-(bucket, severity) unsuppressed counts over the window
    /// [endingAt - spanSeconds, endingAt), bucketed SQL-side so no alert rows
    /// cross into Swift. Buckets are "steps ago" from `endingAt` (bucket 0 = the
    /// most recent step), matching the dashboard's now-anchored histogram grid.
    /// Uses idx_alerts_ts_severity. Returns one (bucketsAgo, severityRaw, count)
    /// per occupied cell.
    public func severityHistogram(
        spanSeconds: TimeInterval, stepSeconds: TimeInterval, endingAt: Date
    ) throws -> [(bucketsAgo: Int, severity: String, count: Int)] {
        let endUnix = endingAt.timeIntervalSince1970
        let startUnix = endUnix - spanSeconds
        let sql = """
            SELECT CAST((?1 - timestamp) / ?2 AS INTEGER) AS bucketsAgo, severity, COUNT(*) AS c
            FROM alerts
            WHERE suppressed = 0 AND timestamp >= ?3 AND timestamp < ?1
            GROUP BY bucketsAgo, severity
            ORDER BY bucketsAgo ASC
            """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, endUnix)
        sqlite3_bind_double(stmt, 2, stepSeconds)
        sqlite3_bind_double(stmt, 3, startUnix)
        var out: [(bucketsAgo: Int, severity: String, count: Int)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let bucketsAgo = Int(sqlite3_column_int64(stmt, 0))
            guard let sevC = sqlite3_column_text(stmt, 1) else { continue }
            out.append((bucketsAgo, String(cString: sevC), Int(sqlite3_column_int64(stmt, 2))))
        }
        return out
    }

    /// Marks an alert as suppressed.
    ///
    /// - Parameter id: The alert's unique identifier.
    /// - Throws: `AlertStoreError` on database failure.
    public func suppress(alertId id: String) throws {
        try admitStorageWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
        )
        let sql = "UPDATE alerts SET suppressed = 1 WHERE id = ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
    }

    /// Suppress every alert that belongs to a given campaign in a single
    /// SQL statement. Returns the number of rows updated.
    ///
    /// v1.11.0 (audit perf HIGH): pre-fix the MCP `suppress_campaign`
    /// handler pulled up to 10K alerts then issued a serial `suppress`
    /// per match. With 5K matching alerts × 6ms / write that wedged the
    /// handler for ~30s. Single SQL `UPDATE WHERE campaign_id = ?` is
    /// O(matched rows) at the page level, with a single COMMIT.
    @discardableResult
    public func suppress(campaignId id: String) throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            UPDATE alerts SET suppressed = 1 WHERE rowid IN (
                SELECT rowid FROM alerts
                WHERE campaign_id = ?1 AND suppressed = 0
                ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            try admitStorageWrite(estimatedTransactionBytes: estimate)
            let stmt = try prepare(sql)
            bindText(stmt, index: 1, value: id)
            sqlite3_bind_int(stmt, 2, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw AlertStoreError.stepFailed(msg)
            }
            let changed = db.map { Int(sqlite3_changes($0)) } ?? 0
            total += changed
            if changed == 0 { break }
        }
        return total
    }

    /// Reverse of `suppress(campaignId:)` — lift suppression on every alert
    /// tagged with this campaign id. Used by the dashboard's campaign-restore
    /// flow so suppress/restore is symmetric. Returns rows changed.
    @discardableResult
    public func unsuppress(campaignId id: String) throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            UPDATE alerts SET suppressed = 0 WHERE rowid IN (
                SELECT rowid FROM alerts
                WHERE campaign_id = ?1 AND suppressed = 1
                ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            try admitStorageWrite(estimatedTransactionBytes: estimate)
            let stmt = try prepare(sql)
            bindText(stmt, index: 1, value: id)
            sqlite3_bind_int(stmt, 2, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw AlertStoreError.stepFailed(msg)
            }
            let changed = db.map { Int(sqlite3_changes($0)) } ?? 0
            total += changed
            if changed == 0 { break }
        }
        return total
    }

    /// v1.11.0 (audit perf HIGH): SQL-side AI-Guard alert filter.
    /// Pre-fix the MCP `get_ai_alerts` handler pulled 10K alerts then
    /// substring-matched 8 keywords across rule_id + title in Swift.
    ///
    /// **v1.11.0 RC2 ship-blocker fix:** the original RC1 SQL used
    /// only rule_id prefixes (`ai_%`, `credential_fence_%`,
    /// `injection_%`, `mcp_%`, `prompt_%`, etc.). Swift-emitted
    /// alerts (rule_id starts with `maccrab.ai-guard.`) matched, but
    /// every YAML-authored AI safety / credential rule has a UUID
    /// rule_id (`d1a2b3c4-…`) — no prefix match — so the new SQL
    /// returned NOTHING for the bulk of AI rules that the v1.10.x
    /// Swift filter (which scanned rule_title for "AI" / "Credential
    /// Fence" / "Boundary" / "Injection" / "MCP" / "Prompt") would
    /// have caught. RC2 adds rule_title LIKE clauses to recover the
    /// title-keyword path. Both rule_id AND rule_title must be
    /// indexed for this not to scan the whole table; the existing
    /// idx_alerts_rule_id covers the prefix path; rule_title is
    /// scanned LIKE-pattern (worst-case linear, but bounded by the
    /// timestamp + suppressed predicate first).
    public func aiAlerts(since: Date, limit: Int) throws -> [Alert] {
        let sql = """
            SELECT * FROM alerts
             WHERE timestamp >= ?1
               AND suppressed = 0
               AND (rule_id LIKE 'ai_%'
                 OR rule_id LIKE 'maccrab.ai-guard.%'
                 OR rule_id LIKE 'maccrab.mcp.%'
                 OR rule_id LIKE 'credential_fence_%'
                 OR rule_id LIKE 'boundary_%'
                 OR rule_id LIKE 'injection_%'
                 OR rule_id LIKE 'mcp_%'
                 OR rule_id LIKE 'prompt_%'
                 OR rule_id LIKE 'agent_%'
                 OR rule_title LIKE 'AI %'
                 OR rule_title LIKE '%Credential Fence%'
                 OR rule_title LIKE '%Boundary Violation%'
                 OR rule_title LIKE '%Prompt Injection%'
                 OR rule_title LIKE '%MCP%'
                 OR rule_title LIKE '%Agent %'
                 OR rule_title LIKE '%AI Coding Tool%')
             ORDER BY timestamp DESC
             LIMIT ?2
            """
        return try queryAlerts(sql: sql, bindings: [
            (1, .double(since.timeIntervalSince1970)),
            (2, .int(Int32(limit))),
        ])
    }

    /// Unsuppress a previously suppressed alert.
    public func unsuppress(alertId id: String) throws {
        try admitStorageWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
        )
        let sql = "UPDATE alerts SET suppressed = 0 WHERE id = ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
    }

    /// Permanently delete a single alert by id. Used by the History
    /// tab's "Delete" action when an operator wants to wipe a
    /// suppressed-or-resolved alert from the record entirely
    /// (e.g. accidentally captured PII in the alert body). Audit
    /// trail of the deletion lives in `dashboard_audit.log`.
    @discardableResult
    public func delete(alertId id: String) throws -> Bool {
        try admitStorageMaintenanceWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
        )
        let sql = "DELETE FROM alerts WHERE id = ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
        return Int(sqlite3_changes(db)) > 0
    }

    /// List `(id, ruleId)` pairs for alerts currently marked suppressed.
    /// Used by the feedback-loop sweeper in DaemonTimers to plumb UI
    /// dismissals back into the deduplicator's FP-rate tracking.
    public func listSuppressed(limit: Int = 500) throws -> [(id: String, ruleId: String)] {
        let sql = "SELECT id, rule_id FROM alerts WHERE suppressed = 1 ORDER BY timestamp DESC LIMIT ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(limit))
        var out: [(id: String, ruleId: String)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = columnTextOrNil(stmt, index: 0) ?? ""
            let rid = columnTextOrNil(stmt, index: 1) ?? ""
            guard !id.isEmpty, !rid.isEmpty else { continue }
            out.append((id, rid))
        }
        return out
    }

    // MARK: - Pruning

    /// Deletes alerts older than the specified date for data retention.
    ///
    /// Deletes in batches of 100,000 rows and yields between batches so that
    /// concurrent alert inserts are not blocked for extended periods.
    ///
    /// - Parameter date: Alerts with timestamps before this date will be deleted.
    /// - Returns: The total number of alerts deleted across all batches.
    @discardableResult
    public func prune(olderThan date: Date) async throws -> Int {
        let batchSize = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batchSize))
        let timestamp = date.timeIntervalSince1970
        var totalDeleted = 0

        let sql = """
            DELETE FROM alerts WHERE rowid IN (
                SELECT rowid FROM alerts WHERE timestamp < ?1
                ORDER BY rowid LIMIT ?2
            )
            """

        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            let stmt = try prepare(sql)
            sqlite3_bind_double(stmt, 1, timestamp)
            sqlite3_bind_int(stmt, 2, batchSize)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw AlertStoreError.stepFailed(msg)
            }
            let rowsDeleted = Int(sqlite3_changes(db))
            totalDeleted += rowsDeleted
            if rowsDeleted == 0 { break }
            await Task.yield()
        }

        return totalDeleted
    }

    /// v1.8.0: drop the oldest `count` alerts by timestamp. Defense-in-
    /// depth size cap when alerts.db exceeds `alertsMaxSizeMB` despite
    /// time-based retention. Mirrors EventStore.pruneOldest.
    @discardableResult
    public func pruneOldest(count: Int) async throws -> Int {
        guard count > 0 else { return 0 }
        let batchSize: Int32 = min(
            maintenanceBatchRowLimit(),
            Int32(clamping: count)
        )
        var remaining = count
        var totalDeleted = 0

        let sql = """
            DELETE FROM alerts WHERE rowid IN (
                SELECT rowid FROM alerts ORDER BY timestamp ASC LIMIT ?1
            )
            """

        while remaining > 0 {
            let thisBatch = min(batchSize, Int32(clamping: remaining))
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
                throw AlertStoreError.stepFailed(msg)
            }
            let rowsDeleted = Int(sqlite3_changes(db))
            totalDeleted += rowsDeleted
            remaining -= rowsDeleted
            if rowsDeleted == 0 { break }
            await Task.yield()
        }

        return totalDeleted
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // Mirrors EventStore.incrementalVacuum. AlertStore is configured
    // with `auto_vacuum = INCREMENTAL` on fresh DBs (see
    // StoragePragmas.applyAlertStorePragmas), so this is the safe
    // path on low-disk hosts where a full VACUUM can't preserve the configured
    // floor plus the shared gate's 2× whole-main-file scratch allowance.
    //
    // Returns pages physically removed from the file. Zero on a
    // legacy alerts.db still in auto_vacuum mode 0 (NONE) — a file
    // created before applyAlertStorePragmas set INCREMENTAL, which
    // the pragma alone cannot flip on a populated DB. `vacuum()`
    // below now performs the one-shot conversion on its next run,
    // so the mode-0 window closes the first time a full VACUUM runs
    // (read-only DBs return 0 with no error).
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
            throw AlertStoreError.stepFailed(
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
                throw AlertStoreError.stepFailed(
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

    /// Best-effort VACUUM. Mirrors EventStore.vacuum — only the
    /// size-cap enforcer calls this, after pre-flighting free disk
    /// space. Required as the second leg of the Wave 9B low-disk
    /// fallback (incremental_vacuum is preferred but the AlertStore
    /// caller still wants the option to fall through to full VACUUM
    /// once disk frees up).
    public func vacuum() async throws {
        guard let db = db else { return }
        guard walCheckpoint() else {
            throw AlertStoreError.stepFailed(
                "VACUUM refused because the pre-checkpoint did not fully drain"
            )
        }
        // One-shot auto_vacuum conversion (audit corr-storage): setting the
        // pragma just before VACUUM rewrites a legacy mode-0 (NONE) alerts.db
        // into INCREMENTAL, so incrementalVacuum() (the low-disk reclaim path)
        // stops being a permanent no-op on upgraded installs. Idempotent once
        // the file is already mode 2. See StoragePragmas ordering note.
        let autoVacuumRC = sqlite3_exec(
            db,
            "PRAGMA auto_vacuum = INCREMENTAL",
            nil,
            nil,
            nil
        )
        if autoVacuumRC != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: autoVacuumRC)
            throw AlertStoreError.stepFailed("auto_vacuum conversion failed")
        }
        try admitStorageFullVacuum()
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = String(cString: sqlite3_errmsg(db))
            throw AlertStoreError.stepFailed("VACUUM failed: \(msg)")
        }
        guard walCheckpointTruncate() else {
            throw AlertStoreError.stepFailed(
                "VACUUM completed but its WAL could not be fully drained/truncated"
            )
        }
    }

    /// PASSIVE→RESTART checkpoint chain. Same shape as
    /// EventStore.walCheckpoint; alerts.db has a smaller cache and
    /// rarely accumulates a large WAL but the size-cap path still
    /// needs a drained WAL before measuring on-disk size.
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

    // MARK: - Private Helpers

    /// A sum type for binding values to prepared statements.
    private enum BindingValue {
        case text(String)
        case double(Double)
        case int(Int32)
        case null
    }

    /// Executes a SQL statement that does not return rows.
    private func execute(
        _ sql: String,
        maintenance: Bool = false,
        estimatedTransactionBytes: Int64? = nil
    ) throws {
        if sql.trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased().hasPrefix("BEGIN") {
            guard let estimatedTransactionBytes else {
                throw AlertStoreError.stepFailed(
                    "BEGIN requires an explicit bounded transaction estimate"
                )
            }
            if maintenance {
                try admitStorageMaintenanceWrite(
                    estimatedTransactionBytes: estimatedTransactionBytes
                )
            } else {
                try admitStorageWrite(
                    estimatedTransactionBytes: estimatedTransactionBytes
                )
            }
        }
        var errmsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
        if rc != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
            sqlite3_free(errmsg)
            throw AlertStoreError.stepFailed(msg)
        }
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
            if !isReadOnly, insertStmt == nil {
                guard var secondary = storageAdmission else { return }
                do {
                    try secondary.admitWrite(
                        estimatedTransactionBytes: estimatedTransactionBytes,
                        on: db
                    )
                } catch {
                    storageAdmission = secondary
                    throw error
                }
                storageAdmission = secondary
                if !secondary.growthBlocked {
                    try reopenAfterStorageRecovery()
                }
                if insertStmt == nil, let failure = storageAdmission?.latchedFailure {
                    throw failure
                }
            }
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
            "id", "timestamp", "rule_id", "rule_title", "severity", "event_id",
            "process_path", "process_name", "description", "mitre_tactics",
            "mitre_techniques", "suppressed", "llm_investigation_json",
            "d3fend_techniques", "remediation_hint", "analyst_metadata_json",
            "campaign_id", "user_id", "user_name", "working_directory",
            "ai_tool", "parent_executable", "process_sha256", "host_name",
            "triggering_events_json", "ai_tool_session_id",
        ]
        let indexed = [
            "id", "rule_id", "rule_id", "severity", "severity", "severity",
            "event_id", "campaign_id", "ai_tool", "ai_tool_session_id",
        ]
        func length(_ column: String) -> String {
            "COALESCE(length(CAST(\"\(column)\" AS BLOB)), 0)"
        }
        let fixed = columns.count * 16 + 12 * 16
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
            "SELECT COALESCE(MAX(\(expression)), 0) FROM alerts",
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
                            maximumLeafPageTouches: 13
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
            maximumTreePathPageTouches: 32
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
            maximumTreePathPageTouches: 32
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
            newPageSizeBytes,
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
        sqlitePageSizeBytes = newPageSizeBytes
        checkpointController = newCheckpointController
    }

    /// Prepares a SQL statement.
    private func prepare(_ sql: String) throws -> OpaquePointer {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.prepareFailed(msg)
        }
        return stmt
    }

    /// Binds a non-nil text value to a prepared statement parameter.
    private func bindText(_ stmt: OpaquePointer, index: Int32, value: String) {
        _ = value.withCString { cstr in
            sqlite3_bind_text(stmt, index, cstr, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
    }

    /// Binds a text value or NULL to a prepared statement parameter.
    private func bindTextOrNull(_ stmt: OpaquePointer, index: Int32, value: String?) {
        if let value {
            bindText(stmt, index: index, value: value)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    /// Binds a text value or NULL, treating empty strings as NULL.
    /// Used by attribution columns (schema v5) so query-time
    /// `WHERE ai_tool IS NOT NULL` predicates don't pick up empty
    /// sentinel strings emitted by upstream callers that haven't
    /// gated on `!isEmpty` themselves.
    private func bindTextNonEmptyOrNull(_ stmt: OpaquePointer, index: Int32, value: String?) {
        if let value, !value.isEmpty {
            bindText(stmt, index: index, value: value)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    /// Reads a text column or returns `nil` if the column is NULL.
    private func columnTextOrNil(_ stmt: OpaquePointer, index: Int32) -> String? {
        guard let cstr = sqlite3_column_text(stmt, index) else { return nil }
        return String(cString: cstr)
    }

    /// Runs a SELECT query and decodes each row into an `Alert`.
    private func queryAlerts(
        sql: String,
        bindings: [(Int32, BindingValue)]
    ) throws -> [Alert] {
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }

        for (index, value) in bindings {
            switch value {
            case .text(let s):
                bindText(stmt, index: index, value: s)
            case .double(let d):
                sqlite3_bind_double(stmt, index, d)
            case .int(let i):
                sqlite3_bind_int(stmt, index, i)
            case .null:
                sqlite3_bind_null(stmt, index)
            }
        }

        var results: [Alert] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            // Columns by index match the CREATE TABLE order:
            // 0: id, 1: timestamp, 2: rule_id, 3: rule_title, 4: severity,
            // 5: event_id, 6: process_path, 7: process_name, 8: description,
            // 9: mitre_tactics, 10: mitre_techniques, 11: suppressed,
            // 12: llm_investigation_json (v2), 13: d3fend_techniques (v3),
            // 14: remediation_hint (v3), 15: analyst_metadata_json (v3),
            // 16: campaign_id (v4), 17: user_id (v5), 18: user_name (v5),
            // 19: working_directory (v5), 20: ai_tool (v5),
            // 21: parent_executable (v5), 22: process_sha256 (v5),
            // 23: host_name (v5).

            guard let id = columnTextOrNil(stmt, index: 0),
                  let ruleId = columnTextOrNil(stmt, index: 2),
                  let ruleTitle = columnTextOrNil(stmt, index: 3),
                  let severityRaw = columnTextOrNil(stmt, index: 4),
                  let severity = Severity(rawValue: severityRaw),
                  let eventId = columnTextOrNil(stmt, index: 5)
            else {
                continue
            }

            let timestamp = sqlite3_column_double(stmt, 1)
            let suppressedInt = sqlite3_column_int(stmt, 11)

            // Column 12: llm_investigation_json (added in schema v2).
            // Decodes to LLMInvestigation or nil. Malformed JSON is
            // silently dropped rather than failing the whole row.
            var investigation: LLMInvestigation? = nil
            if let json = columnTextOrNil(stmt, index: 12),
               let data = json.data(using: .utf8) {
                investigation = try? Self.investigationDecoder.decode(
                    LLMInvestigation.self, from: data
                )
            }

            // Columns 13/14/15: phantom-field enrichments (schema v3,
            // v1.11.0). Each is independently nullable — a row written
            // pre-v3 has all three NULL and the V2 inspector continues
            // to hide the corresponding sections via its existing
            // `if let / !isEmpty` gates.
            let d3fend: [String]? = {
                guard let csv = columnTextOrNil(stmt, index: 13), !csv.isEmpty else { return nil }
                return csv.split(separator: ",").map { String($0) }
            }()
            let remediation = columnTextOrNil(stmt, index: 14)
            var analyst: AnalystMetadata? = nil
            if let json = columnTextOrNil(stmt, index: 15),
               let data = json.data(using: .utf8) {
                analyst = try? Self.investigationDecoder.decode(
                    AnalystMetadata.self, from: data
                )
            }

            // Column 16: campaign_id (added in schema v4, v1.11.0 RC2).
            // NULL for pre-v4 rows; v4+ rows reflect the originating
            // CampaignDetector grouping. Required so the dashboard's
            // suppress-campaign fan-out and AlertStore.suppress(campaignId:)
            // actually identify contributing rows.
            let campaignId = columnTextOrNil(stmt, index: 16)

            // Columns 17-23: attribution promotion (schema v5,
            // v1.12.6 Wave 2B). Each is independently nullable —
            // pre-v5 rows have all seven NULL. user_id is INTEGER;
            // SQLite reports SQLITE_NULL via sqlite3_column_type,
            // distinguishing nil from a legitimate uid==0 (root).
            let userId: UInt32? = {
                guard sqlite3_column_type(stmt, 17) != SQLITE_NULL else { return nil }
                return UInt32(sqlite3_column_int64(stmt, 17))
            }()
            let userName = columnTextOrNil(stmt, index: 18)
            let workingDirectory = columnTextOrNil(stmt, index: 19)
            let aiTool = columnTextOrNil(stmt, index: 20)
            let parentExecutable = columnTextOrNil(stmt, index: 21)
            let processSha256 = columnTextOrNil(stmt, index: 22)
            let hostName = columnTextOrNil(stmt, index: 23)
            // Column 24: triggering-events snapshot (schema v6). NULL for
            // pre-v6 rows and for alerts created without contributing events.
            let triggeringEventsJson = columnTextOrNil(stmt, index: 24)
            // Column 25: durable agent session id (schema v7). NULL for
            // pre-v7 rows and non-AI-attributed alerts.
            let aiToolSessionId = columnTextOrNil(stmt, index: 25)

            let alert = Alert(
                id: id,
                timestamp: Date(timeIntervalSince1970: timestamp),
                ruleId: ruleId,
                ruleTitle: ruleTitle,
                severity: severity,
                eventId: eventId,
                processPath: columnTextOrNil(stmt, index: 6),
                processName: columnTextOrNil(stmt, index: 7),
                description: columnTextOrNil(stmt, index: 8),
                mitreTactics: columnTextOrNil(stmt, index: 9),
                mitreTechniques: columnTextOrNil(stmt, index: 10),
                suppressed: suppressedInt != 0,
                campaignId: campaignId,
                analyst: analyst,
                d3fendTechniques: d3fend,
                remediationHint: remediation,
                llmInvestigation: investigation,
                userId: userId,
                userName: userName,
                workingDirectory: workingDirectory,
                aiTool: aiTool,
                parentExecutable: parentExecutable,
                processSha256: processSha256,
                hostName: hostName,
                triggeringEventsJson: triggeringEventsJson,
                aiToolSessionId: aiToolSessionId
            )
            results.append(alert)
        }
        return results
    }

    // MARK: - Investigation update

    /// Attach an LLMInvestigation to an existing alert record.
    /// Called by the daemon after agentic triage completes.
    public func updateInvestigation(alertId: String, investigation: LLMInvestigation) throws {
        guard let data = try? Self.investigationEncoder.encode(investigation),
              let json = String(data: data, encoding: .utf8) else {
            throw AlertStoreError.stepFailed("investigation encode failed")
        }
        let logical = SQLitePersistentStoreAdmission.saturatingAdd(
            Int64(data.count),
            Int64(alertId.utf8.count)
        )
        let rowBytes = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 2
            )
        try admitStorageWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeTransactionBytes(
                    rowMutationBytes: rowBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumTreePathPageTouches: 6
                )
        )
        let sql = "UPDATE alerts SET llm_investigation_json = ?1 WHERE id = ?2"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: json)
        bindText(stmt, index: 2, value: alertId)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
        // UPDATE success does not mean a row existed. Treat a zero-row update
        // as a real failure so callers cannot report a completed LLM triage
        // whose result was silently discarded (the rc.4 pre-insert race).
        guard let db, sqlite3_changes(db) == 1 else {
            throw AlertStoreError.notFound(alertId)
        }
    }

    // MARK: - Encoders for LLMInvestigation

    nonisolated static let investigationEncoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    nonisolated static let investigationDecoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
