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
/// Two lifetime-coupled tables, `alerts` and slim `alert_evidence`:
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
/// `alert_evidence` stores only `(alert_id, event_id, timestamp, raw_json)`.
/// Its composite primary key supports lookup/idempotency and its foreign key
/// cascades on alert deletion. It deliberately does not repeat EventStore's
/// projected search columns or secondary indexes.
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
    private var evidenceMaintenanceRowMutationHighWaterBytes: Int64? = nil
    private var evidenceMaintenanceHighWaterScannedExistingRows = false

    /// Exact logical ownership plus a conservative physical-page upper bound.
    /// A full COUNT/SUM + DBSTAT pass seeds (or explicitly refreshes) this cache;
    /// ordinary capture then updates it in O(rows inserted/deleted), avoiding a
    /// whole-table scan on every alert. Until the next DBSTAT refresh, allocated
    /// growth is charged by the same conservative mutation estimate admitted for
    /// SQLite, so stale physical accounting can only overstate usage.
    private struct EvidenceAccountingCache {
        var rowCount: Int
        var logicalBytes: Int64
        var observedAllocatedBytes: Int64
        var conservativeAllocatedBytes: Int64
        var allocatedBytesExact: Bool
        var mutationGeneration: UInt64
    }
    private struct EvidenceDeletionImpact {
        let rows: Int
        let logicalBytes: Int64
        let maximumLogicalRowBytes: Int64

        static let zero = EvidenceDeletionImpact(
            rows: 0,
            logicalBytes: 0,
            maximumLogicalRowBytes: 0
        )
    }
    private struct CascadeAlertDeletionItem {
        let id: String
        let evidence: EvidenceDeletionImpact
        let rowMutationBytes: Int64
    }
    private var evidenceAccountingCache: EvidenceAccountingCache?
    private var evidenceAccountingFullRefreshes: UInt64 = 0

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
        // v8: alert context has the same owner and lifetime as its alert, so it
        // belongs in alerts.db. The legacy events.db.alert_evidence table had 25
        // projected columns plus raw_json and two extra indexes; rc.5 measured
        // 98 MB of that duplicated shape inside the event-store budget. The new
        // WITHOUT ROWID table stores only identity, ordering, and the lossless
        // payload. Its composite primary key is simultaneously the alert lookup,
        // idempotency, and cascade index — no secondary indexes are needed.
        Migration(
            version: 8,
            name: "add_alert_owned_evidence",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS alert_evidence (
                    alert_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY (alert_id, event_id),
                    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
                ) WITHOUT ROWID
                """,
            ]
        ),
        // v9: persist whether the exact capture-time journal window was
        // complete. A direct trigger may still be present when surrounding
        // context contains a poison/corrupt record or selection fails; without
        // this row, an empty/partial evidence set would look falsely complete.
        Migration(
            version: 9,
            name: "add_alert_evidence_context_status",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS alert_evidence_context (
                    alert_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'complete', 'incomplete', 'capture_failed')
                    ),
                    source_mutation_generation INTEGER NOT NULL CHECK (
                        source_mutation_generation >= 0
                    ),
                    poison_record_count INTEGER NOT NULL CHECK (
                        poison_record_count >= 0
                    ),
                    corrupt_record_count INTEGER NOT NULL CHECK (
                        corrupt_record_count >= 0
                    ),
                    CHECK (
                        status != 'complete'
                        OR (
                            source_mutation_generation > 0
                            AND poison_record_count = 0
                            AND corrupt_record_count = 0
                        )
                    ),
                    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
                ) WITHOUT ROWID
                """,
                """
                CREATE TRIGGER IF NOT EXISTS alerts_initialize_evidence_context
                AFTER INSERT ON alerts
                BEGIN
                    INSERT OR IGNORE INTO alert_evidence_context (
                        alert_id, status, source_mutation_generation,
                        poison_record_count, corrupt_record_count
                    ) VALUES (NEW.id, 'pending', 0, 0, 0);
                END
                """,
            ]
        ),
        // v10: an incomplete bit without a reason is not actionable and can
        // falsely hide inherited rc.12 loss or exact-query resource limiting.
        // Add reason counters in place (no unbounded table rewrite), then
        // enforce the complete/incomplete equations on every future write.
        Migration(
            version: 10,
            name: "reason_alert_evidence_context_gaps",
            sql: [
                "ALTER TABLE alert_evidence_context ADD COLUMN inherited_loss_count INTEGER NOT NULL DEFAULT 0 CHECK (inherited_loss_count >= 0)",
                "ALTER TABLE alert_evidence_context ADD COLUMN resource_limit_count INTEGER NOT NULL DEFAULT 0 CHECK (resource_limit_count >= 0)",
                "ALTER TABLE alert_evidence_context ADD COLUMN journal_admission_gap_count INTEGER NOT NULL DEFAULT 0 CHECK (journal_admission_gap_count >= 0)",
                """
                CREATE TRIGGER IF NOT EXISTS alert_evidence_context_validate_insert
                BEFORE INSERT ON alert_evidence_context
                WHEN (
                    NEW.status = 'complete' AND (
                        NEW.source_mutation_generation <= 0
                        OR NEW.poison_record_count != 0
                        OR NEW.corrupt_record_count != 0
                        OR NEW.inherited_loss_count != 0
                        OR NEW.resource_limit_count != 0
                        OR NEW.journal_admission_gap_count != 0
                    )
                ) OR (
                    NEW.status = 'incomplete'
                    AND NEW.poison_record_count = 0
                    AND NEW.corrupt_record_count = 0
                    AND NEW.inherited_loss_count = 0
                    AND NEW.resource_limit_count = 0
                    AND NEW.journal_admission_gap_count = 0
                )
                BEGIN
                    SELECT RAISE(ABORT, 'invalid alert evidence context status equation');
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS alert_evidence_context_validate_update
                BEFORE UPDATE ON alert_evidence_context
                WHEN (
                    NEW.status = 'complete' AND (
                        NEW.source_mutation_generation <= 0
                        OR NEW.poison_record_count != 0
                        OR NEW.corrupt_record_count != 0
                        OR NEW.inherited_loss_count != 0
                        OR NEW.resource_limit_count != 0
                        OR NEW.journal_admission_gap_count != 0
                    )
                ) OR (
                    NEW.status = 'incomplete'
                    AND NEW.poison_record_count = 0
                    AND NEW.corrupt_record_count = 0
                    AND NEW.inherited_loss_count = 0
                    AND NEW.resource_limit_count = 0
                    AND NEW.journal_admission_gap_count = 0
                )
                BEGIN
                    SELECT RAISE(ABORT, 'invalid alert evidence context status equation');
                END
                """,
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

    /// The alerts and evidence knobs are separate ownership budgets, but both
    /// tables share one SQLite family. The hard family ceiling therefore is the
    /// exact saturating sum; DB + WAL + SHM are admitted together by
    /// SQLitePersistentStoreAdmission.
    public nonisolated static func combinedFamilyCapBytes(
        alertsMaxSizeMiB: Int,
        evidenceMaxSizeMiB: Int
    ) -> Int64 {
        SQLitePersistentStoreAdmission.saturatingAdd(
            SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: alertsMaxSizeMiB
            ),
            SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: evidenceMaxSizeMiB
            )
        )
    }

    private static func defaultStoragePolicy(
        for databasePath: String
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            // Defaults mirror DaemonConfig's 100 MiB alerts + 100 MiB evidence
            // ownership budgets. Daemon startup supplies the configured sum.
            maxFootprintBytes: combinedFamilyCapBytes(
                alertsMaxSizeMiB: 100,
                evidenceMaxSizeMiB: 100
            ),
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
            """
            CREATE TABLE IF NOT EXISTS alert_evidence (
                alert_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (alert_id, event_id),
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            ) WITHOUT ROWID
            """,
            """
            CREATE TABLE IF NOT EXISTS alert_evidence_context (
                alert_id TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (
                    status IN ('pending', 'complete', 'incomplete', 'capture_failed')
                ),
                source_mutation_generation INTEGER NOT NULL CHECK (
                    source_mutation_generation >= 0
                ),
                poison_record_count INTEGER NOT NULL CHECK (
                    poison_record_count >= 0
                ),
                corrupt_record_count INTEGER NOT NULL CHECK (
                    corrupt_record_count >= 0
                ),
                CHECK (
                    status != 'complete'
                    OR (
                        source_mutation_generation > 0
                        AND poison_record_count = 0
                        AND corrupt_record_count = 0
                    )
                ),
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            ) WITHOUT ROWID
            """,
            """
            CREATE TRIGGER IF NOT EXISTS alerts_initialize_evidence_context
            AFTER INSERT ON alerts
            BEGIN
                INSERT OR IGNORE INTO alert_evidence_context (
                    alert_id, status, source_mutation_generation,
                    poison_record_count, corrupt_record_count
                ) VALUES (NEW.id, 'pending', 0, 0, 0);
            END
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
            INSERT INTO alerts (
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
            ON CONFLICT(id) DO UPDATE SET
                timestamp = excluded.timestamp,
                rule_id = excluded.rule_id,
                rule_title = excluded.rule_title,
                severity = excluded.severity,
                event_id = excluded.event_id,
                process_path = excluded.process_path,
                process_name = excluded.process_name,
                description = excluded.description,
                mitre_tactics = excluded.mitre_tactics,
                mitre_techniques = excluded.mitre_techniques,
                suppressed = excluded.suppressed,
                llm_investigation_json = excluded.llm_investigation_json,
                d3fend_techniques = excluded.d3fend_techniques,
                remediation_hint = excluded.remediation_hint,
                analyst_metadata_json = excluded.analyst_metadata_json,
                campaign_id = excluded.campaign_id,
                user_id = excluded.user_id,
                user_name = excluded.user_name,
                working_directory = excluded.working_directory,
                ai_tool = excluded.ai_tool,
                parent_executable = excluded.parent_executable,
                process_sha256 = excluded.process_sha256,
                host_name = excluded.host_name,
                triggering_events_json = excluded.triggering_events_json,
                ai_tool_session_id = excluded.ai_tool_session_id
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
        var transactionOpen = false
        do {
            try insert(alert: alert) { rowBytes in
                // The AFTER INSERT trigger writes `.pending` in this same
                // bounded transaction. `rowBytes` includes that context-row
                // mutation, so storage admission cannot approve the alert while
                // omitting its durable completeness truth from the estimate.
                try self.execute(
                    "BEGIN TRANSACTION",
                    estimatedTransactionBytes: self.alertTransactionEstimate(
                        rowMutationBytes: rowBytes
                    )
                )
                transactionOpen = true
            }
            try execute("COMMIT")
            transactionOpen = false
        } catch {
            if transactionOpen { try? execute("ROLLBACK") }
            throw error
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
        let alertRowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            newRowBytes,
            try existingAlertMutationBytes(id: alert.id)
        )
        let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            alertRowBytes,
            pendingEvidenceContextMutationBytes(alertId: alert.id)
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
        // The insert trigger handles genuinely new rows. This explicit
        // idempotent step also repairs an updated pre-v9 alert whose INSERT ...
        // ON CONFLICT took the UPDATE branch and therefore did not fire it.
        // Every caller opens a bounded transaction before entering this helper,
        // so alert + pending context commit or roll back together.
        try ensurePendingEvidenceContext(alertId: alert.id)
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

    /// The idempotent UPSERT rewrites the prior row and its changed index
    /// entries. Read the authoritative stored values so an old large row
    /// cannot hide outside the incoming estimate. UPSERT (not REPLACE) is
    /// required now that alert_evidence has ON DELETE CASCADE: REPLACE's
    /// implicit delete would erase a valid snapshot on a harmless retry.
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

    private func pendingEvidenceContextMutationBytes(alertId: String) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeEncodedRowMutationBytes(
            logicalRepresentationBytes: Int64(alertId.utf8.count + 128),
            pageSizeBytes: sqlitePageSizeBytes,
            maximumLeafPageTouches: 2
        )
    }

    private func ensurePendingEvidenceContext(alertId: String) throws {
        let statement = try prepare(
            """
            INSERT OR IGNORE INTO alert_evidence_context (
                alert_id, status, source_mutation_generation,
                poison_record_count, corrupt_record_count,
                inherited_loss_count, resource_limit_count,
                journal_admission_gap_count
            ) VALUES (?1, 'pending', 0, 0, 0, 0, 0, 0)
            """
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: alertId)
        let rc = sqlite3_step(statement)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let message = db.map { String(cString: sqlite3_errmsg($0)) }
                ?? "unknown error"
            throw AlertStoreError.stepFailed(
                "pending alert evidence context insert failed: \(message)"
            )
        }
    }

    /// Persists alerts in reserve-bounded transactions. Alert ids use an UPSERT,
    /// so retrying the caller array after a later chunk fails is idempotent
    /// without triggering the evidence foreign-key cascade.
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
        return try deleteAlertsCascadeAware(ids: [id]) > 0
    }

    // MARK: - Alert-owned evidence (schema v8)

    /// Persist fail-closed completeness metadata for the exact journal window.
    /// Upserts are monotonic: a retry can advance the source generation and
    /// counts, but it can never turn a previously observed gap into complete.
    public func recordEvidenceContext(
        _ record: AlertEvidenceContextRecord
    ) throws {
        guard !record.alertId.isEmpty else {
            throw AlertStoreError.stepFailed(
                "alert evidence context requires an alert id"
            )
        }
        guard try tableExists("alert_evidence_context") else {
            throw AlertStoreError.stepFailed(
                "alert evidence context schema is unavailable"
            )
        }
        try admitStorageWrite(
            estimatedTransactionBytes:
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
        )
        let sql = """
            INSERT INTO alert_evidence_context (
                alert_id, status, source_mutation_generation,
                poison_record_count, corrupt_record_count,
                inherited_loss_count, resource_limit_count,
                journal_admission_gap_count
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(alert_id) DO UPDATE SET
                status = CASE
                    WHEN alert_evidence_context.status = 'capture_failed'
                      OR excluded.status = 'capture_failed'
                    THEN 'capture_failed'
                    WHEN alert_evidence_context.status = 'incomplete'
                      OR excluded.status = 'incomplete'
                    THEN 'incomplete'
                    WHEN excluded.status = 'pending'
                    THEN alert_evidence_context.status
                    ELSE 'complete'
                END,
                source_mutation_generation = MAX(
                    alert_evidence_context.source_mutation_generation,
                    excluded.source_mutation_generation
                ),
                poison_record_count = MAX(
                    alert_evidence_context.poison_record_count,
                    excluded.poison_record_count
                ),
                corrupt_record_count = MAX(
                    alert_evidence_context.corrupt_record_count,
                    excluded.corrupt_record_count
                ),
                inherited_loss_count = MAX(
                    alert_evidence_context.inherited_loss_count,
                    excluded.inherited_loss_count
                ),
                journal_admission_gap_count = MAX(
                    alert_evidence_context.journal_admission_gap_count,
                    excluded.journal_admission_gap_count
                ),
                resource_limit_count = MAX(
                    alert_evidence_context.resource_limit_count,
                    excluded.resource_limit_count,
                    CASE
                        WHEN alert_evidence_context.status = 'incomplete'
                          AND alert_evidence_context.poison_record_count = 0
                          AND alert_evidence_context.corrupt_record_count = 0
                          AND alert_evidence_context.inherited_loss_count = 0
                          AND alert_evidence_context.resource_limit_count = 0
                          AND alert_evidence_context.journal_admission_gap_count = 0
                        THEN 1 ELSE 0
                    END
                )
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: record.alertId)
        bindText(statement, index: 2, value: record.status.rawValue)
        sqlite3_bind_int64(
            statement,
            3,
            Int64(clamping: record.sourceMutationGeneration)
        )
        sqlite3_bind_int64(
            statement,
            4,
            Int64(clamping: record.poisonRecordCount)
        )
        sqlite3_bind_int64(
            statement,
            5,
            Int64(clamping: record.corruptRecordCount)
        )
        sqlite3_bind_int64(
            statement,
            6,
            Int64(clamping: record.inheritedLossCount)
        )
        sqlite3_bind_int64(
            statement,
            7,
            Int64(clamping: record.resourceLimitedCount)
        )
        sqlite3_bind_int64(
            statement,
            8,
            Int64(clamping: record.journalAdmissionGapCount)
        )
        let rc = sqlite3_step(statement)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let message = db.map { String(cString: sqlite3_errmsg($0)) }
                ?? "unknown error"
            throw AlertStoreError.stepFailed(
                "alert evidence context insert failed: \(message)"
            )
        }
    }

    public func evidenceContext(
        alertId: String
    ) throws -> AlertEvidenceContextRecord? {
        guard try tableExists("alert_evidence_context") else { return nil }
        let statement = try prepare(
            "SELECT status, source_mutation_generation, poison_record_count, corrupt_record_count, inherited_loss_count, resource_limit_count, journal_admission_gap_count FROM alert_evidence_context WHERE alert_id = ?1"
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: alertId)
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW,
              let statusBytes = sqlite3_column_text(statement, 0),
              let status = AlertEvidenceContextRecord.Status(
                rawValue: String(cString: statusBytes)
              ) else {
            throw AlertStoreError.stepFailed(
                "alert evidence context read failed"
            )
        }
        let generation = max(0, sqlite3_column_int64(statement, 1))
        let poison = Int(sqlite3_column_int64(statement, 2))
        let corrupt = Int(sqlite3_column_int64(statement, 3))
        let inherited = Int(sqlite3_column_int64(statement, 4))
        var resource = Int(sqlite3_column_int64(statement, 5))
        let journalAdmissionGap = Int(sqlite3_column_int64(statement, 6))
        if status == .incomplete, poison == 0, corrupt == 0,
           inherited == 0, resource == 0, journalAdmissionGap == 0 {
            // A v9 row may predate the reason columns. Surface that inherited
            // anonymous incomplete bit as explicit representation/resource
            // debt without rewriting the whole table during migration.
            resource = 1
        }
        return AlertEvidenceContextRecord(
            alertId: alertId,
            status: status,
            sourceMutationGeneration: UInt64(generation),
            poisonRecordCount: poison,
            corruptRecordCount: corrupt,
            inheritedLossCount: inherited,
            resourceLimitedCount: resource,
            journalAdmissionGapCount: journalAdmissionGap
        )
    }

    /// Durable work left in the atomic post-alert capture state. Unlike the
    /// sink's in-memory queue depth this survives crash/restart and includes
    /// jobs shed before they could enter that queue.
    public func pendingEvidenceContextCount() throws -> Int {
        try evidenceContextCounts().pending
    }

    public func evidenceContextCounts() throws -> AlertEvidenceContextCounts {
        guard try tableExists("alert_evidence_context") else {
            throw AlertStoreError.stepFailed(
                "alert evidence context schema is unavailable"
            )
        }
        let statement = try prepare(
            """
            SELECT
                COUNT(*),
                SUM(CASE WHEN c.status = 'pending' THEN 1 ELSE 0 END),
                SUM(CASE WHEN c.status = 'complete' THEN 1 ELSE 0 END),
                SUM(CASE WHEN c.status = 'incomplete' THEN 1 ELSE 0 END),
                SUM(CASE WHEN c.status = 'capture_failed' THEN 1 ELSE 0 END),
                SUM(CASE WHEN c.alert_id IS NULL THEN 1 ELSE 0 END),
                COALESCE(SUM(c.poison_record_count), 0),
                COALESCE(SUM(c.corrupt_record_count), 0),
                COALESCE(SUM(c.inherited_loss_count), 0),
                COALESCE(SUM(c.journal_admission_gap_count), 0),
                COALESCE(SUM(
                    c.resource_limit_count
                    + CASE
                        WHEN c.status = 'incomplete'
                          AND c.poison_record_count = 0
                          AND c.corrupt_record_count = 0
                          AND c.inherited_loss_count = 0
                          AND c.resource_limit_count = 0
                          AND c.journal_admission_gap_count = 0
                        THEN 1 ELSE 0
                      END
                ), 0)
            FROM alerts AS a
            LEFT JOIN alert_evidence_context AS c ON c.alert_id = a.id
            """
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed(
                "alert evidence context status count failed"
            )
        }
        return AlertEvidenceContextCounts(
            alertRows: Int(sqlite3_column_int64(statement, 0)),
            pending: Int(sqlite3_column_int64(statement, 1)),
            complete: Int(sqlite3_column_int64(statement, 2)),
            incomplete: Int(sqlite3_column_int64(statement, 3)),
            captureFailed: Int(sqlite3_column_int64(statement, 4)),
            legacyUnverified: Int(sqlite3_column_int64(statement, 5)),
            poisonRecords: Int(sqlite3_column_int64(statement, 6)),
            corruptRecords: Int(sqlite3_column_int64(statement, 7)),
            inheritedLossRecords: Int(sqlite3_column_int64(statement, 8)),
            resourceLimitedRecords: Int(sqlite3_column_int64(statement, 10)),
            journalAdmissionGapRecords: Int(
                sqlite3_column_int64(statement, 9)
            )
        )
    }

    /// Capture a bounded evidence snapshot after its parent alert has committed.
    /// The alert insert is intentionally a separate transaction: a best-effort
    /// context failure must never roll back the detection itself.
    ///
    /// Candidate payloads are validated as real Events with matching ids before
    /// storage. The table-level `(alert_id, event_id)` key makes retries
    /// idempotent; the fixed per-alert ceiling applies across existing + new
    /// rows, not merely to this call's input array.
    @discardableResult
    public func captureEvidence(
        alertId: String,
        candidates: [AlertEvidenceCandidate],
        maxBytes: Int64
    ) async throws -> AlertEvidenceCaptureResult {
        guard maxBytes > 0, !candidates.isEmpty else {
            return AlertEvidenceCaptureResult(
                insertedRows: 0,
                duplicateRows: 0,
                prunedRows: 0
            )
        }
        guard try tableExists("alert_evidence") else {
            throw AlertStoreError.stepFailed(
                "alert-owned evidence schema is unavailable"
            )
        }
        guard let parentTimestamp = try alertTimestamp(id: alertId) else {
            throw AlertStoreError.stepFailed(
                "alert evidence parent does not exist"
            )
        }
        // `alerts.timestamp` is persisted as Unix seconds. Converting that
        // Double back to Date and then subtracting in Date's reference-date
        // epoch can move the value by one ULP. At either inclusive boundary
        // that used to reject a legitimate trigger or an event exactly one
        // lookback old. Compare in the database's Unix-seconds coordinate so
        // the validation agrees with EventStore's source-window selection.
        let parentTimestampSeconds = parentTimestamp.timeIntervalSince1970
        let lowerTimestampSeconds = parentTimestampSeconds
            - AlertEvidencePolicy.lookbackSeconds
        // Seed exact accounting once per store-open. Subsequent captures update
        // logical ownership and a conservative allocated-page upper bound in
        // O(inserted rows); they do not rescan the complete evidence table.
        _ = try evidenceBudgetSnapshot(maxBytes: maxBytes)

        let decoder = JSONDecoder()
        var seenInput: Set<String> = []
        var valid: [AlertEvidenceCandidate] = []
        for candidate in candidates {
            let byteCount = candidate.rawJSON.lengthOfBytes(using: .utf8)
            guard byteCount > 0,
                  byteCount <= AlertEvidencePolicy.maximumRawPayloadBytes,
                  seenInput.insert(candidate.eventId).inserted,
                  let data = candidate.rawJSON.data(using: .utf8),
                  let event = try? decoder.decode(Event.self, from: data) else {
                continue
            }
            let eventTimestampSeconds = event.timestamp.timeIntervalSince1970
            guard parentTimestampSeconds.isFinite,
                  lowerTimestampSeconds.isFinite,
                  eventTimestampSeconds.isFinite,
                  eventTimestampSeconds <= parentTimestampSeconds,
                  eventTimestampSeconds >= lowerTimestampSeconds,
                  event.id.uuidString.caseInsensitiveCompare(candidate.eventId)
                    == .orderedSame else {
                continue
            }
            valid.append(AlertEvidenceCandidate(
                eventId: event.id.uuidString,
                timestamp: event.timestamp,
                rawJSON: candidate.rawJSON
            ))
        }
        valid.sort {
            if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
            return $0.eventId < $1.eventId
        }
        guard !valid.isEmpty else {
            return AlertEvidenceCaptureResult(
                insertedRows: 0,
                duplicateRows: 0,
                prunedRows: 0
            )
        }

        let existingIDs = try evidenceEventIDs(alertId: alertId)
        let duplicates = valid.filter { existingIDs.contains($0.eventId) }.count
        let remaining = max(
            0,
            AlertEvidencePolicy.maximumEventsPerAlert - existingIDs.count
        )
        let pending = Array(
            valid.lazy
                .filter { !existingIDs.contains($0.eventId) }
                .prefix(remaining)
        )
        guard !pending.isEmpty else {
            let pruned = try await pruneAlertEvidenceToBudget(maxBytes: maxBytes)
            return AlertEvidenceCaptureResult(
                insertedRows: 0,
                duplicateRows: duplicates,
                prunedRows: pruned
            )
        }

        struct PlannedRow {
            let candidate: AlertEvidenceCandidate
            let mutationBytes: Int64
        }
        let planned = pending.map { candidate in
            PlannedRow(
                candidate: candidate,
                mutationBytes: evidenceRowMutationEstimate(candidate)
            )
        }
        let reserve = storageTransactionReserveBytes
        var chunks: [[PlannedRow]] = []
        var current: [PlannedRow] = []
        var currentBytes: Int64 = 0
        for row in planned {
            let nextBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                currentBytes, row.mutationBytes
            )
            if !current.isEmpty,
               evidenceTransactionEstimate(rowMutationBytes: nextBytes) > reserve {
                chunks.append(current)
                current = []
                currentBytes = 0
            }
            let singleEstimate = evidenceTransactionEstimate(
                rowMutationBytes: row.mutationBytes
            )
            guard singleEstimate <= reserve else {
                throw SQLitePersistentStoreAdmissionError
                    .transactionEstimateExceedsReserve(
                        estimatedBytes: singleEstimate,
                        reserveBytes: reserve
                    )
            }
            current.append(row)
            currentBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                currentBytes, row.mutationBytes
            )
        }
        if !current.isEmpty { chunks.append(current) }

        let insertSQL = """
            INSERT OR IGNORE INTO alert_evidence (
                alert_id, event_id, timestamp, raw_json
            ) VALUES (?1, ?2, ?3, ?4)
            """
        var inserted = 0
        for chunk in chunks {
            let rowBytes = chunk.reduce(Int64(0)) {
                SQLitePersistentStoreAdmission.saturatingAdd(
                    $0, $1.mutationBytes
                )
            }
            var transactionOpen = false
            var insertedLogicalBytes: Int64 = 0
            var insertedAllocatedUpperBound: Int64 = 0
            var insertedMaximumRowMutationBytes: Int64 = 0
            var insertedInChunk = 0
            do {
                try execute(
                    "BEGIN TRANSACTION",
                    estimatedTransactionBytes: evidenceTransactionEstimate(
                        rowMutationBytes: rowBytes
                    )
                )
                transactionOpen = true
                for row in chunk {
                    let statement = try prepare(insertSQL)
                    bindText(statement, index: 1, value: alertId)
                    bindText(statement, index: 2, value: row.candidate.eventId)
                    sqlite3_bind_double(
                        statement, 3,
                        row.candidate.timestamp.timeIntervalSince1970
                    )
                    bindText(
                        statement, index: 4,
                        value: row.candidate.rawJSON
                    )
                    let rc = sqlite3_step(statement)
                    sqlite3_finalize(statement)
                    guard rc == SQLITE_DONE else {
                        try throwLatchedStoragePressureIfPresent(resultCode: rc)
                        let message = db.map { String(cString: sqlite3_errmsg($0)) }
                            ?? "unknown error"
                        throw AlertStoreError.stepFailed(
                            "alert evidence insert failed: \(message)"
                        )
                    }
                    if sqlite3_changes(db) > 0 {
                        insertedInChunk += 1
                        insertedLogicalBytes = SQLitePersistentStoreAdmission
                            .saturatingAdd(
                                insertedLogicalBytes,
                                evidenceLogicalBytes(
                                    alertId: alertId,
                                    candidate: row.candidate
                                )
                            )
                        insertedAllocatedUpperBound =
                            SQLitePersistentStoreAdmission.saturatingAdd(
                                insertedAllocatedUpperBound,
                                row.mutationBytes
                            )
                        insertedMaximumRowMutationBytes = max(
                            insertedMaximumRowMutationBytes,
                            row.mutationBytes
                        )
                    }
                }
                try execute("COMMIT")
                transactionOpen = false
                inserted += insertedInChunk
                recordEvidenceInsertion(
                    rows: insertedInChunk,
                    logicalBytes: insertedLogicalBytes,
                    allocatedUpperBoundBytes: insertedAllocatedUpperBound,
                    maximumRowMutationBytes:
                        insertedMaximumRowMutationBytes
                )
            } catch {
                if transactionOpen { try? execute("ROLLBACK") }
                throw error
            }
        }

        // Newest context displaces oldest context when the evidence ownership
        // budget is full. The combined alerts.db family ceiling was already
        // enforced before every insert transaction; this sub-cap decides which
        // of those admitted pages belong to evidence rather than alert rows.
        let pruned = try await pruneAlertEvidenceToBudget(maxBytes: maxBytes)
        return AlertEvidenceCaptureResult(
            insertedRows: inserted,
            duplicateRows: duplicates,
            prunedRows: pruned
        )
    }

    /// Read new schema-v8 evidence in chronological order. A read-only handle
    /// on a pre-v8 database returns an empty array so callers can fall back to
    /// the preserved legacy events.db table.
    public func evidenceFor(alertId: String) throws -> [Event] {
        guard try tableExists("alert_evidence") else { return [] }
        let statement = try prepare(
            "SELECT raw_json FROM alert_evidence WHERE alert_id = ?1 ORDER BY timestamp ASC, event_id ASC"
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: alertId)
        let decoder = JSONDecoder()
        var events: [Event] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else {
                throw AlertStoreError.stepFailed(
                    "alert evidence read failed"
                )
            }
            let byteCount = Int(sqlite3_column_bytes(statement, 0))
            guard byteCount > 0,
                  byteCount <= AlertEvidencePolicy.maximumRawPayloadBytes,
                  let bytes = sqlite3_column_text(statement, 0),
                  let data = String(cString: bytes).data(using: .utf8),
                  let event = try? decoder.decode(Event.self, from: data) else {
                continue
            }
            events.append(event)
        }
        return events
    }

    /// Current ownership accounting for the slim evidence table. The first call
    /// after open performs one exact COUNT/SUM + DBSTAT pass. Later calls are O(1)
    /// and return exact logical counters plus a conservative physical upper bound
    /// until an explicit refresh or an over-budget slow path re-measures DBSTAT.
    public func evidenceBudgetSnapshot(
        maxBytes: Int64
    ) throws -> AlertEvidenceBudgetSnapshot {
        if evidenceAccountingCache == nil {
            try refreshEvidenceAccounting()
        }
        return cachedEvidenceBudgetSnapshot(maxBytes: maxBytes)
    }

    /// Force a full ownership refresh. Periodic maintenance/diagnostics should
    /// use this when they need exact DBSTAT page ownership; the capture hot path
    /// deliberately uses `evidenceBudgetSnapshot` and remains scan-free.
    public func refreshEvidenceBudgetSnapshot(
        maxBytes: Int64
    ) throws -> AlertEvidenceBudgetSnapshot {
        try refreshEvidenceAccounting()
        return cachedEvidenceBudgetSnapshot(maxBytes: maxBytes)
    }

    private func refreshEvidenceAccounting() throws {
        guard try tableExists("alert_evidence") else {
            evidenceAccountingCache = EvidenceAccountingCache(
                rowCount: 0,
                logicalBytes: 0,
                observedAllocatedBytes: 0,
                conservativeAllocatedBytes: 0,
                allocatedBytesExact: true,
                mutationGeneration:
                    evidenceAccountingCache?.mutationGeneration ?? 0
            )
            if evidenceAccountingFullRefreshes < .max {
                evidenceAccountingFullRefreshes += 1
            }
            return
        }
        let logicalStatement = try prepare(
            """
            SELECT COUNT(*), COALESCE(SUM(
                LENGTH(CAST(alert_id AS BLOB))
              + LENGTH(CAST(event_id AS BLOB))
              + 8
              + LENGTH(CAST(raw_json AS BLOB))
            ), 0)
            FROM alert_evidence
            """
        )
        defer { sqlite3_finalize(logicalStatement) }
        guard sqlite3_step(logicalStatement) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed(
                "alert evidence logical-size query failed"
            )
        }
        let rowCount = Int(sqlite3_column_int64(logicalStatement, 0))
        let logicalBytes = sqlite3_column_int64(logicalStatement, 1)
        let allocatedBytes = try allocatedBytes(
            table: "alert_evidence",
            includeIndexes: true
        )
        evidenceAccountingCache = EvidenceAccountingCache(
            rowCount: rowCount,
            logicalBytes: logicalBytes,
            observedAllocatedBytes: allocatedBytes,
            conservativeAllocatedBytes: allocatedBytes,
            allocatedBytesExact: true,
            mutationGeneration:
                evidenceAccountingCache?.mutationGeneration ?? 0
        )
        if evidenceAccountingFullRefreshes < .max {
            evidenceAccountingFullRefreshes += 1
        }
    }

    private func cachedEvidenceBudgetSnapshot(
        maxBytes: Int64
    ) -> AlertEvidenceBudgetSnapshot {
        let cache = evidenceAccountingCache ?? EvidenceAccountingCache(
            rowCount: 0,
            logicalBytes: 0,
            observedAllocatedBytes: 0,
            conservativeAllocatedBytes: 0,
            allocatedBytesExact: true,
            mutationGeneration: 0
        )
        return AlertEvidenceBudgetSnapshot(
            rowCount: cache.rowCount,
            logicalBytes: cache.logicalBytes,
            allocatedBytes: cache.observedAllocatedBytes,
            chargedBytes: max(
                cache.logicalBytes,
                cache.conservativeAllocatedBytes
            ),
            maxBytes: max(0, maxBytes),
            allocatedBytesExact: cache.allocatedBytesExact,
            mutationGeneration: cache.mutationGeneration,
            fullRefreshesTotal: evidenceAccountingFullRefreshes
        )
    }

    /// SQLite pages owned by alerts plus its explicit/automatic indexes, but
    /// not alert_evidence. Used to enforce the alert-row budget independently
    /// from the evidence-row budget inside their shared family.
    public func alertsAllocatedBytes() throws -> Int64 {
        try allocatedBytes(table: "alerts", includeIndexes: true)
    }

    /// Repair an adversarial/legacy over-per-alert shape. Normal capture never
    /// creates it, but maintenance must not trust that invariant blindly.
    @discardableResult
    public func pruneAlertEvidencePerAlertCap(
        _ perAlertMax: Int = AlertEvidencePolicy.maximumEventsPerAlert
    ) async throws -> Int {
        guard perAlertMax >= 0,
              try tableExists("alert_evidence") else { return 0 }
        _ = try evidenceBudgetSnapshot(maxBytes: .max)
        let batch = evidenceMaintenanceBatchRowLimit()
        var deletedTotal = 0
        while true {
            let selection = """
                SELECT alert_id, event_id,
                       \(Self.evidenceLogicalSQL) AS logical_bytes
                FROM (
                    SELECT alert_id, event_id, timestamp, raw_json,
                           ROW_NUMBER() OVER (
                               PARTITION BY alert_id
                               ORDER BY timestamp DESC, event_id DESC
                           ) AS rank
                    FROM alert_evidence
                ) ranked
                WHERE rank > ?1
                LIMIT ?2
                """
            let impact = try evidenceDeletionImpact(
                selecting: selection
            ) { statement in
                sqlite3_bind_int(
                    statement, 1, Int32(clamping: perAlertMax)
                )
                sqlite3_bind_int(statement, 2, batch)
            }
            guard impact.rows > 0 else { break }
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: evidenceMaintenanceEstimate(
                    rowCount: impact.rows
                )
            )
            let statement = try prepare(
                """
                DELETE FROM alert_evidence
                WHERE (alert_id, event_id) IN (
                    SELECT alert_id, event_id FROM (
                        SELECT alert_id, event_id,
                               ROW_NUMBER() OVER (
                                   PARTITION BY alert_id
                                   ORDER BY timestamp DESC, event_id DESC
                               ) AS rank
                        FROM alert_evidence
                    ) ranked
                    WHERE rank > ?1
                    LIMIT ?2
                )
                """
            )
            sqlite3_bind_int(statement, 1, Int32(clamping: perAlertMax))
            sqlite3_bind_int(statement, 2, batch)
            let rc = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                throw AlertStoreError.stepFailed(
                    "alert evidence per-alert prune failed"
                )
            }
            let deleted = Int(sqlite3_changes(db))
            deletedTotal += deleted
            if deleted == impact.rows {
                recordEvidenceDeletion(
                    rows: deleted,
                    logicalBytes: impact.logicalBytes
                )
            } else {
                try refreshEvidenceAccounting()
            }
            if deleted == 0 { break }
            await Task.yield()
        }
        return deletedTotal
    }

    /// Evict oldest context until both logical ownership and SQLite table-page
    /// ownership fit the evidence sub-budget. Free pages may remain in the
    /// alerts.db family until incremental vacuum; the independent combined
    /// family admission continues to count those DB/WAL/SHM bytes exactly.
    @discardableResult
    public func pruneAlertEvidenceToBudget(
        maxBytes: Int64
    ) async throws -> Int {
        guard maxBytes >= 0,
              try tableExists("alert_evidence") else { return 0 }
        _ = try evidenceBudgetSnapshot(maxBytes: maxBytes)
        let batch = evidenceMaintenanceBatchRowLimit()
        var deletedTotal = 0
        for _ in 0..<4096 {
            var snapshot = try evidenceBudgetSnapshot(maxBytes: maxBytes)
            if snapshot.overBudget, !snapshot.allocatedBytesExact {
                // Conservative insert charging may intentionally overstate page
                // ownership. Pay for DBSTAT only on this cold over-budget edge,
                // then prune solely when the exact boundary still fails.
                try refreshEvidenceAllocatedAccounting()
                snapshot = try evidenceBudgetSnapshot(maxBytes: maxBytes)
            }
            guard snapshot.overBudget, snapshot.rowCount > 0 else { break }
            let selection = """
                SELECT alert_id, event_id,
                       \(Self.evidenceLogicalSQL) AS logical_bytes
                FROM alert_evidence
                ORDER BY timestamp ASC, alert_id ASC, event_id ASC
                LIMIT ?1
                """
            let impact = try evidenceDeletionImpact(
                selecting: selection
            ) { statement in
                sqlite3_bind_int(statement, 1, batch)
            }
            guard impact.rows > 0 else { break }
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: evidenceMaintenanceEstimate(
                    rowCount: impact.rows
                )
            )
            let statement = try prepare(
                """
                DELETE FROM alert_evidence
                WHERE (alert_id, event_id) IN (
                    SELECT alert_id, event_id
                    FROM alert_evidence
                    ORDER BY timestamp ASC, alert_id ASC, event_id ASC
                    LIMIT ?1
                )
                """
            )
            sqlite3_bind_int(statement, 1, batch)
            let rc = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                throw AlertStoreError.stepFailed(
                    "alert evidence size prune failed"
                )
            }
            let deleted = Int(sqlite3_changes(db))
            deletedTotal += deleted
            if deleted == impact.rows {
                recordEvidenceDeletion(
                    rows: deleted,
                    logicalBytes: impact.logicalBytes
                )
                // DELETE page release is not derivable from row bytes. This is
                // a cap-maintenance slow path, so re-measure allocation once per
                // reserve-bounded batch instead of once per alert capture.
                try refreshEvidenceAllocatedAccounting()
            } else {
                try refreshEvidenceAccounting()
            }
            if deleted == 0 { break }
            await Task.yield()
        }
        return deletedTotal
    }

    @discardableResult
    public func enforceAlertEvidenceBudget(
        maxBytes: Int64,
        perAlertMax: Int = AlertEvidencePolicy.maximumEventsPerAlert
    ) async throws -> (perAlert: Int, bySize: Int) {
        // Scheduled maintenance is the deliberate exact-accounting boundary;
        // ordinary capture remains incremental between these cold passes.
        try refreshEvidenceAccounting()
        let perAlert = try await pruneAlertEvidencePerAlertCap(perAlertMax)
        let bySize = try await pruneAlertEvidenceToBudget(maxBytes: maxBytes)
        return (perAlert, bySize)
    }

    /// List `(id, ruleId)` pairs for administrative suppression reporting.
    /// Suppression is policy state, not a TP/FP verdict, and this query must not
    /// feed runtime severity or response authority.
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

    // MARK: - Cascade-aware alert deletion planning

    private func alertIDsForRetention(
        before timestamp: Double,
        limit: Int
    ) throws -> [String] {
        guard limit > 0 else { return [] }
        let statement = try prepare(
            "SELECT id FROM alerts WHERE timestamp < ?1 ORDER BY rowid LIMIT ?2"
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, timestamp)
        sqlite3_bind_int(statement, 2, Int32(clamping: limit))
        return try textColumnRows(statement, context: "retention id selection")
    }

    private func oldestAlertIDs(limit: Int) throws -> [String] {
        guard limit > 0 else { return [] }
        let statement = try prepare(
            "SELECT id FROM alerts ORDER BY timestamp ASC, rowid ASC LIMIT ?1"
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int(statement, 1, Int32(clamping: limit))
        return try textColumnRows(statement, context: "oldest alert selection")
    }

    private func textColumnRows(
        _ statement: OpaquePointer,
        context: String
    ) throws -> [String] {
        var values: [String] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { return values }
            guard step == SQLITE_ROW else {
                throw AlertStoreError.stepFailed("\(context) failed")
            }
            if let value = columnTextOrNil(statement, index: 0) {
                values.append(value)
            }
        }
    }

    private func evidenceImpact(alertId: String) throws -> EvidenceDeletionImpact {
        try evidenceDeletionImpact(
            selecting: """
                SELECT alert_id, event_id,
                       \(Self.evidenceLogicalSQL) AS logical_bytes
                FROM alert_evidence
                WHERE alert_id = ?1
                """
        ) { statement in
            bindText(statement, index: 1, value: alertId)
        }
    }

    private func evidenceCascadeMutationBytes(
        _ impact: EvidenceDeletionImpact
    ) -> Int64 {
        guard impact.rows > 0 else { return 0 }
        let perRow = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: impact.maximumLogicalRowBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 2
            )
        return SQLitePersistentStoreAdmission.saturatingMultiply(
            Int64(impact.rows),
            by: perRow
        )
    }

    private func cascadeTransactionEstimate(
        rowMutationBytes: Int64
    ) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowMutationBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 40
        )
    }

    /// If an adversarial parent exceeds the normal 50-row invariant, its one-
    /// statement FK cascade may not fit the reserve. Drain children through
    /// independently admitted batches before deleting the childless parent.
    private func deleteEvidenceReserveBounded(alertId: String) throws {
        let batch = evidenceMaintenanceBatchRowLimit()
        for _ in 0..<4096 {
            let selection = """
                SELECT alert_id, event_id,
                       \(Self.evidenceLogicalSQL) AS logical_bytes
                FROM alert_evidence
                WHERE alert_id = ?1
                ORDER BY timestamp ASC, event_id ASC
                LIMIT ?2
                """
            let impact = try evidenceDeletionImpact(
                selecting: selection
            ) { statement in
                bindText(statement, index: 1, value: alertId)
                sqlite3_bind_int(statement, 2, batch)
            }
            guard impact.rows > 0 else { return }
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: evidenceMaintenanceEstimate(
                    rowCount: impact.rows
                )
            )
            let statement = try prepare(
                """
                DELETE FROM alert_evidence
                WHERE (alert_id, event_id) IN (
                    SELECT alert_id, event_id
                    FROM alert_evidence
                    WHERE alert_id = ?1
                    ORDER BY timestamp ASC, event_id ASC
                    LIMIT ?2
                )
                """
            )
            bindText(statement, index: 1, value: alertId)
            sqlite3_bind_int(statement, 2, batch)
            let rc = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                throw AlertStoreError.stepFailed(
                    "reserve-bounded alert evidence delete failed"
                )
            }
            let deleted = Int(sqlite3_changes(db))
            guard deleted > 0 else { return }
            if deleted == impact.rows {
                recordEvidenceDeletion(
                    rows: deleted,
                    logicalBytes: impact.logicalBytes
                )
            } else {
                try refreshEvidenceAccounting()
            }
        }
        throw AlertStoreError.stepFailed(
            "reserve-bounded alert evidence delete exceeded iteration limit"
        )
    }

    private func executeCascadeDelete(
        _ items: [CascadeAlertDeletionItem]
    ) throws -> Int {
        guard !items.isEmpty else { return 0 }
        let rowBytes = items.reduce(Int64(0)) {
            SQLitePersistentStoreAdmission.saturatingAdd(
                $0, $1.rowMutationBytes
            )
        }
        try admitStorageMaintenanceWrite(
            estimatedTransactionBytes: cascadeTransactionEstimate(
                rowMutationBytes: rowBytes
            )
        )
        let placeholders = (1...items.count)
            .map { "?\($0)" }
            .joined(separator: ",")
        let statement = try prepare(
            "DELETE FROM alerts WHERE id IN (\(placeholders))"
        )
        for (index, item) in items.enumerated() {
            bindText(
                statement,
                index: Int32(index + 1),
                value: item.id
            )
        }
        let rc = sqlite3_step(statement)
        sqlite3_finalize(statement)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let message = db.map { String(cString: sqlite3_errmsg($0)) }
                ?? "unknown error"
            throw AlertStoreError.stepFailed(
                "cascade-aware alert delete failed: \(message)"
            )
        }
        let deleted = Int(sqlite3_changes(db))
        if deleted == items.count {
            let evidenceRows = items.reduce(0) { $0 + $1.evidence.rows }
            let evidenceLogical = items.reduce(Int64(0)) {
                SQLitePersistentStoreAdmission.saturatingAdd(
                    $0, $1.evidence.logicalBytes
                )
            }
            recordEvidenceDeletion(
                rows: evidenceRows,
                logicalBytes: evidenceLogical
            )
        } else if items.contains(where: { $0.evidence.rows > 0 }) {
            try refreshEvidenceAccounting()
        }
        return deleted
    }

    private func deleteAlertsCascadeAware(ids: [String]) throws -> Int {
        guard !ids.isEmpty else { return 0 }
        let reserve = storageTransactionReserveBytes
        let parentRowBytes = maintenanceRowMutationUpperBound()
        var chunk: [CascadeAlertDeletionItem] = []
        var chunkRowBytes: Int64 = 0
        var totalDeleted = 0

        func flushChunk() throws {
            guard !chunk.isEmpty else { return }
            totalDeleted += try executeCascadeDelete(chunk)
            chunk.removeAll(keepingCapacity: true)
            chunkRowBytes = 0
        }

        for id in ids {
            var impact = try evidenceImpact(alertId: id)
            var itemBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                parentRowBytes,
                evidenceCascadeMutationBytes(impact)
            )
            if cascadeTransactionEstimate(rowMutationBytes: itemBytes) > reserve {
                try flushChunk()
                try deleteEvidenceReserveBounded(alertId: id)
                impact = try evidenceImpact(alertId: id)
                itemBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                    parentRowBytes,
                    evidenceCascadeMutationBytes(impact)
                )
            }
            let itemEstimate = cascadeTransactionEstimate(
                rowMutationBytes: itemBytes
            )
            guard itemEstimate <= reserve else {
                throw SQLitePersistentStoreAdmissionError
                    .transactionEstimateExceedsReserve(
                        estimatedBytes: itemEstimate,
                        reserveBytes: reserve
                    )
            }
            let prospective = SQLitePersistentStoreAdmission.saturatingAdd(
                chunkRowBytes,
                itemBytes
            )
            if !chunk.isEmpty,
               cascadeTransactionEstimate(rowMutationBytes: prospective) > reserve {
                try flushChunk()
            }
            chunk.append(CascadeAlertDeletionItem(
                id: id,
                evidence: impact,
                rowMutationBytes: itemBytes
            ))
            chunkRowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                chunkRowBytes,
                itemBytes
            )
        }
        try flushChunk()
        return totalDeleted
    }

    // MARK: - Pruning

    /// Deletes alerts older than the specified date for data retention.
    ///
    /// Plans at most 256 parents at a time, then splits them again by the exact
    /// parent + FK-evidence mutation estimate so every transaction fits the
    /// configured reserve. Yields between candidate windows.
    ///
    /// - Parameter date: Alerts with timestamps before this date will be deleted.
    /// - Returns: The total number of alerts deleted across all batches.
    @discardableResult
    public func prune(olderThan date: Date) async throws -> Int {
        let timestamp = date.timeIntervalSince1970
        var totalDeleted = 0
        let candidateLimit = min(256, Int(maintenanceBatchRowLimit()))

        while true {
            let ids = try alertIDsForRetention(
                before: timestamp,
                limit: candidateLimit
            )
            guard !ids.isEmpty else { break }
            let rowsDeleted = try deleteAlertsCascadeAware(ids: ids)
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
        var remaining = count
        var totalDeleted = 0

        while remaining > 0 {
            let ids = try oldestAlertIDs(
                limit: min(
                    remaining,
                    min(256, Int(maintenanceBatchRowLimit()))
                )
            )
            guard !ids.isEmpty else { break }
            let rowsDeleted = try deleteAlertsCascadeAware(ids: ids)
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

    private func tableExists(_ name: String) throws -> Bool {
        let statement = try prepare(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1"
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: name)
        let step = sqlite3_step(statement)
        if step == SQLITE_ROW { return true }
        if step == SQLITE_DONE { return false }
        throw AlertStoreError.stepFailed("schema lookup failed for \(name)")
    }

    private func evidenceEventIDs(alertId: String) throws -> Set<String> {
        let statement = try prepare(
            "SELECT event_id FROM alert_evidence WHERE alert_id = ?1 LIMIT ?2"
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: alertId)
        sqlite3_bind_int(
            statement, 2,
            Int32(AlertEvidencePolicy.maximumEventsPerAlert + 1)
        )
        var ids: Set<String> = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else {
                throw AlertStoreError.stepFailed(
                    "alert evidence identity query failed"
                )
            }
            if let value = columnTextOrNil(statement, index: 0) {
                ids.insert(value)
            }
        }
        return ids
    }

    private func alertTimestamp(id: String) throws -> Date? {
        let statement = try prepare(
            "SELECT timestamp FROM alerts WHERE id = ?1 LIMIT 1"
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: id)
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return nil }
        guard step == SQLITE_ROW else {
            throw AlertStoreError.stepFailed(
                "alert evidence parent lookup failed"
            )
        }
        return Date(
            timeIntervalSince1970: sqlite3_column_double(statement, 0)
        )
    }

    private static let evidenceLogicalSQL = """
        LENGTH(CAST(alert_id AS BLOB))
        + LENGTH(CAST(event_id AS BLOB))
        + 8
        + LENGTH(CAST(raw_json AS BLOB))
        """

    private func evidenceDeletionImpact(
        selecting selectionSQL: String,
        bind: (OpaquePointer) -> Void = { _ in }
    ) throws -> EvidenceDeletionImpact {
        let statement = try prepare(
            """
            SELECT COUNT(*),
                   COALESCE(SUM(logical_bytes), 0),
                   COALESCE(MAX(logical_bytes), 0)
            FROM (
                \(selectionSQL)
            ) selected_evidence
            """
        )
        defer { sqlite3_finalize(statement) }
        bind(statement)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed(
                "alert evidence deletion accounting query failed"
            )
        }
        return EvidenceDeletionImpact(
            rows: Int(clamping: sqlite3_column_int64(statement, 0)),
            logicalBytes: max(0, sqlite3_column_int64(statement, 1)),
            maximumLogicalRowBytes: max(0, sqlite3_column_int64(statement, 2))
        )
    }

    private func refreshEvidenceAllocatedAccounting() throws {
        guard var cache = evidenceAccountingCache else {
            try refreshEvidenceAccounting()
            return
        }
        let allocated = try allocatedBytes(
            table: "alert_evidence",
            includeIndexes: true
        )
        cache.observedAllocatedBytes = allocated
        cache.conservativeAllocatedBytes = allocated
        cache.allocatedBytesExact = true
        evidenceAccountingCache = cache
        if evidenceAccountingFullRefreshes < .max {
            evidenceAccountingFullRefreshes += 1
        }
    }

    /// DBSTAT page ownership. This is deliberately fail-closed: if the SQLite
    /// build cannot account for table pages, evidence capture logs a failure
    /// after preserving the parent alert rather than pretending the sub-budget
    /// is healthy.
    private func allocatedBytes(
        table: String,
        includeIndexes: Bool
    ) throws -> Int64 {
        let sql: String
        if includeIndexes {
            sql = """
                SELECT COALESCE(SUM(pgsize), 0)
                FROM dbstat
                WHERE name = ?1
                   OR name IN (
                       SELECT name FROM sqlite_master
                       WHERE type = 'index' AND tbl_name = ?1
                   )
                """
        } else {
            sql = "SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?1"
        }
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: table)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw AlertStoreError.stepFailed(
                "dbstat ownership query failed for \(table)"
            )
        }
        return max(0, sqlite3_column_int64(statement, 0))
    }

    private func evidenceRowMutationEstimate(
        _ candidate: AlertEvidenceCandidate
    ) -> Int64 {
        let logical = Int64(
            candidate.eventId.utf8.count
                + candidate.rawJSON.utf8.count
                + 8
                + 4 * 16
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                // One WITHOUT ROWID b-tree; two leaf touches covers a split.
                maximumLeafPageTouches: 2
            )
    }

    private func evidenceLogicalBytes(
        alertId: String,
        candidate: AlertEvidenceCandidate
    ) -> Int64 {
        SQLitePersistentStoreAdmission.saturatingAdd(
            Int64(alertId.utf8.count + candidate.eventId.utf8.count + 8),
            Int64(candidate.rawJSON.utf8.count)
        )
    }

    private func advanceEvidenceMutationGeneration(
        _ cache: inout EvidenceAccountingCache
    ) {
        if cache.mutationGeneration < .max {
            cache.mutationGeneration += 1
        }
    }

    private func recordEvidenceInsertion(
        rows: Int,
        logicalBytes: Int64,
        allocatedUpperBoundBytes: Int64,
        maximumRowMutationBytes: Int64
    ) {
        guard rows > 0, var cache = evidenceAccountingCache else { return }
        cache.rowCount = Int(clamping: SQLitePersistentStoreAdmission
            .saturatingAdd(Int64(cache.rowCount), Int64(rows)))
        cache.logicalBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            cache.logicalBytes,
            max(0, logicalBytes)
        )
        cache.conservativeAllocatedBytes = SQLitePersistentStoreAdmission
            .saturatingAdd(
                cache.conservativeAllocatedBytes,
                max(0, allocatedUpperBoundBytes)
            )
        cache.allocatedBytesExact = false
        advanceEvidenceMutationGeneration(&cache)
        evidenceAccountingCache = cache
        evidenceMaintenanceRowMutationHighWaterBytes = max(
            evidenceMaintenanceRowMutationHighWaterBytes ?? 0,
            maximumRowMutationBytes
        )
    }

    private func recordEvidenceDeletion(rows: Int, logicalBytes: Int64) {
        guard rows > 0, var cache = evidenceAccountingCache else { return }
        cache.rowCount = max(0, cache.rowCount - rows)
        cache.logicalBytes = max(0, cache.logicalBytes - max(0, logicalBytes))
        // DELETE can free table pages but does not prove how SQLite reassigned
        // them. Keep the prior upper bound until one cold-path DBSTAT refresh.
        cache.allocatedBytesExact = false
        advanceEvidenceMutationGeneration(&cache)
        evidenceAccountingCache = cache
    }

    private func evidenceTransactionEstimate(
        rowMutationBytes: Int64
    ) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowMutationBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 8
        )
    }

    private func evidenceMaintenanceRowMutationUpperBound() -> Int64 {
        if evidenceMaintenanceHighWaterScannedExistingRows,
           let cached = evidenceMaintenanceRowMutationHighWaterBytes {
            return max(
                cached,
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
            )
        }
        var statement: OpaquePointer?
        let sql = """
            SELECT COALESCE(MAX(
                LENGTH(CAST(alert_id AS BLOB))
              + LENGTH(CAST(event_id AS BLOB))
              + LENGTH(CAST(raw_json AS BLOB))
              + 8 + 64
            ), 0)
            FROM alert_evidence
            """
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            sqlite3_finalize(statement)
            return storageTransactionReserveBytes
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            return storageTransactionReserveBytes
        }
        let logical = max(
            Int64(128),
            sqlite3_column_int64(statement, 0)
        )
        let upper = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 2
            )
        evidenceMaintenanceRowMutationHighWaterBytes = max(
            evidenceMaintenanceRowMutationHighWaterBytes ?? 0,
            upper
        )
        evidenceMaintenanceHighWaterScannedExistingRows = true
        return max(
            upper,
            SQLitePersistentStoreAdmission.conservativeRowMutationBytes
        )
    }

    private func evidenceMaintenanceBatchRowLimit() -> Int32 {
        let fixed = SQLitePersistentStoreAdmission
            .transactionFixedOverheadBytes(
                pageSizeBytes: sqlitePageSizeBytes,
                maximumTreePathPageTouches: 8
            )
        return Int32(clamping: max(
            1,
            min(
                1_000,
                SQLitePersistentStoreAdmission.maximumRowsPerTransaction(
                    reserveBytes: max(
                        0, storageTransactionReserveBytes - fixed
                    ),
                    bytesPerRow: evidenceMaintenanceRowMutationUpperBound()
                )
            )
        ))
    }

    private func evidenceMaintenanceEstimate(rowCount: Int) -> Int64 {
        evidenceTransactionEstimate(
            rowMutationBytes: SQLitePersistentStoreAdmission
                .saturatingMultiply(
                    Int64(max(0, rowCount)),
                    by: evidenceMaintenanceRowMutationUpperBound()
                )
        )
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

            // Opening the replacement connection and preparing its writer can
            // grow or reshape the SQLite family. Prove the same full ordinary
            // transaction again against that post-open footprint before the
            // caller is allowed to BEGIN.
            try revalidateStorageWriteAfterReopen(
                estimatedTransactionBytes: estimatedTransactionBytes
            )

            // Space can disappear between the successful probe and the fresh
            // open. A shed-only reopen has no insert statement. Retry the open
            // once, then revalidate the same full estimate a second time; a
            // cached pre-reopen snapshot is never accepted as proof.
            if !isReadOnly, insertStmt == nil {
                try reopenAfterStorageRecovery()
                try revalidateStorageWriteAfterReopen(
                    estimatedTransactionBytes: estimatedTransactionBytes
                )
                if insertStmt == nil,
                   let failure = storageAdmission?.latchedFailure {
                    throw failure
                }
            }
        }
    }

    private func revalidateStorageWriteAfterReopen(
        estimatedTransactionBytes: Int64
    ) throws {
        guard var admission = storageAdmission else { return }
        do {
            try admission.admitWrite(
                estimatedTransactionBytes: estimatedTransactionBytes,
                on: db
            )
        } catch {
            storageAdmission = admission
            throw error
        }
        storageAdmission = admission
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

    /// Proves that an ordinary alert write can enter its bounded transaction
    /// without actually mutating the database. Maintenance admission is
    /// intentionally unable to clear a sticky pressure latch, so startup
    /// recovery must run this normal gate after reclaim and reacquire the
    /// cached writer statement before any producer is allowed to ingest.
    @discardableResult
    public func reprobeStorageAdmissionForWrite() throws
        -> SQLitePersistentStoreAdmissionSnapshot {
        guard !isReadOnly, db != nil else {
            throw AlertStoreError.stepFailed(
                "alert storage admission reprobe requires a writable database"
            )
        }
        guard storageAdmission != nil else {
            throw AlertStoreError.stepFailed(
                "alert storage admission reprobe requires an active policy"
            )
        }

        // Use the complete configured transaction reserve. This is the same
        // upper bound all ordinary writes must fit, and exercises the normal
        // recovery/reopen path without issuing BEGIN or INSERT.
        try admitStorageWrite(
            estimatedTransactionBytes: storageTransactionReserveBytes
        )

        guard insertStmt != nil else {
            throw AlertStoreError.stepFailed(
                "alert storage admission recovered without a writer statement"
            )
        }
        guard let snapshot = storageAdmissionSnapshot(),
              snapshot.footprintBytes != nil,
              snapshot.freeSpaceBytes != nil,
              snapshot.latchedFailure == nil,
              !snapshot.pageLimitPending else {
            throw AlertStoreError.stepFailed(
                "alert storage admission remained blocked after normal reprobe"
            )
        }
        return snapshot
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
        evidenceAccountingCache = nil
        maintenanceRowMutationHighWaterBytes = nil
        maintenanceHighWaterScannedExistingRows = false
        evidenceMaintenanceRowMutationHighWaterBytes = nil
        evidenceMaintenanceHighWaterScannedExistingRows = false
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
