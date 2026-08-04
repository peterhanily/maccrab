// EventStore.swift
// MacCrabCore
//
// SQLite-backed event store using the sqlite3 C API directly (no dependencies).
// Uses WAL journal mode for concurrent reads during writes.
// Thread-safe via Swift actor isolation.

import Foundation
import Darwin
import CSQLCipher
import os.log

// MARK: - EventStoreError

/// Errors that can occur during event store operations.
public enum EventStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)
    case encodingFailed(String)
    case decodingFailed(String)
    /// v1.12.0 RC28: distinguish disk-full from generic step failures
    /// so the daemon's insert path can degrade gracefully instead of
    /// silently dropping events under storage exhaustion.
    case diskFull(String, failure: SQLiteFailureDetails? = nil)
    /// v1.21.5-rc.3 (#13): SQLITE_BUSY / SQLITE_LOCKED — a TRANSIENT lock
    /// contention (typically a reader/writer contending the WAL beyond the 5s
    /// busy_timeout). Distinct from `stepFailed` so a batched writer can RETRY
    /// instead of dropping the batch (retrying a transient lock succeeds once the
    /// contention clears; retrying a permanent failure does not).
    case busy(String, failure: SQLiteFailureDetails? = nil)
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
        case .diskFull(let msg, _):         return "Disk full: \(msg)"
        case .busy(let msg, _):             return "Database busy (transient): \(msg)"
        case let .sqliteFailure(context, message, rc, extended, systemErrno):
            return "SQLite \(context) failed (rc=\(rc), extended=\(extended), system_errno=\(systemErrno)): \(message)"
        case .encodingFailed(let msg):      return "Encoding failed: \(msg)"
        case .decodingFailed(let msg):      return "Decoding failed: \(msg)"
        }
    }
}

public struct EventBatchInsertResult: Sendable, Equatable {
    public let inputCount: Int
    public let persistedCount: Int
    public let filteredCount: Int
    public let committedTransactionCount: Int

    public init(
        inputCount: Int,
        persistedCount: Int,
        filteredCount: Int,
        committedTransactionCount: Int
    ) {
        self.inputCount = inputCount
        self.persistedCount = persistedCount
        self.filteredCount = filteredCount
        self.committedTransactionCount = committedTransactionCount
    }
}

/// A reserve-chunked batch can commit a prefix before a later chunk fails.
/// The exact uncommitted, insert-filter-passing suffix is carried so callers
/// never retry or count the already-durable prefix as shed.
public struct EventBatchInsertFailure: Error, LocalizedError,
    SQLiteFailureReporting, @unchecked Sendable {
    public let progress: EventBatchInsertResult
    public let uncommittedEvents: [Event]
    public let underlyingError: any Error
    /// True when corruption recovery quarantined the database that contained
    /// any previously committed chunks. In that case `progress.persistedCount`
    /// is reset to zero and `uncommittedEvents` contains every filter-passing
    /// candidate, because the old prefix is no longer in the active store.
    public let activeDatabaseWasReplaced: Bool
    /// A replacement database was opened and prepared successfully, so a
    /// bounded caller may retry `uncommittedEvents` immediately.
    public let replacementReadyForRetry: Bool

    public init(
        progress: EventBatchInsertResult,
        uncommittedEvents: [Event],
        underlyingError: any Error,
        activeDatabaseWasReplaced: Bool = false,
        replacementReadyForRetry: Bool = false
    ) {
        self.progress = progress
        self.uncommittedEvents = uncommittedEvents
        self.underlyingError = underlyingError
        self.activeDatabaseWasReplaced = activeDatabaseWasReplaced
        self.replacementReadyForRetry = replacementReadyForRetry
    }

    public var errorDescription: String? {
        "Event batch stopped after \(progress.persistedCount) persisted row(s); \(uncommittedEvents.count) row(s) remain: \(underlyingError.localizedDescription)"
    }

    /// Preserve SQLite's primary/extended/VFS classification through the
    /// partial-progress envelope. Recovery and telemetry callers must never
    /// lose BUSY/FULL/corruption identity merely because earlier chunks
    /// committed successfully.
    public var sqliteFailureDetails: SQLiteFailureDetails? {
        SQLiteFailureClassifier.details(from: underlyingError)
    }
}

// MARK: - EventStore

/// A SQLite-backed store for security events.
///
/// The store writes events into a structured schema with individual columns
/// for commonly-queried fields, while also storing the full JSON representation
/// in `raw_json` for lossless retrieval. An FTS5 virtual table enables
/// full-text search across process names, paths, command lines, and other
/// string fields.
public actor EventStore {

    // MARK: Properties

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private let databasePath: String
    private var storagePolicy: SQLitePersistentStorePolicy?
    private var storageAdmission: SQLitePersistentStoreAdmission?
    /// Authoritative PRAGMA page_size captured at each open/reopen. Transaction
    /// estimates use this value rather than assuming the usual 4 KiB so legacy
    /// databases with larger pages remain safely bounded.
    private var sqlitePageSizeBytes: Int64
    /// Lazily scanned high-water estimate for maintenance rewrites/deletes.
    /// New writes can raise it; deletes deliberately do not lower it.
    private var maintenanceRowMutationHighWaterBytes: Int64? = nil
    private var maintenanceHighWaterScannedExistingRows = false
    private var committedBatchInsertTransactions: UInt64 = 0
    /// Incremented when corruption quarantine removes the active DB family.
    /// Batch progress is meaningful only within one generation.
    private var activeDatabaseGeneration: UInt64 = 0
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    // MARK: Payload size cap (v1.12.6)

    /// Hard cap on per-event raw_json bytes after encoding. Events exceeding
    /// this are truncated at the per-arg level before re-encoding; the
    /// `payload.truncated` enrichment is set to record the truncation.
    ///
    /// Field-measured background: median exec raw_json is ~700B; P99 is under
    /// 16KB. The cap sits well above the long tail but well below the
    /// 1 MB outliers we've seen (e.g. base64-encoded appcast.xml passed via
    /// `python3 -c '...'`). Keeps the DB / FTS5 index / dashboard from
    /// being blinded by a single misbehaving caller.
    internal static let maxRawJsonBytes: Int = 65_536

    /// Threshold above which a single `process.args` entry gets replaced with
    /// a `<truncated:N bytes>` marker. Chosen to match the
    /// UnifiedLogCollector message cap convention so per-arg behaviour is
    /// predictable across collectors.
    internal static let argTruncationThreshold: Int = 4_096

    /// Hard cap on the bytes bound into the indexed `process_commandline`
    /// column (audit corr-storage). `raw_json` is bounded by
    /// `maxRawJsonBytes`, but the command line is bound to its OWN column and
    /// tokenized into the `events_fts` index independently of raw_json, so an
    /// oversized argv (e.g. an inline base64 payload) blows up both the column
    /// and the FTS index — defeating the raw_json cap for the exact vector it
    /// cites. 16 KB comfortably fits any real command line (P99 raw_json is
    /// <16 KB and the command line is only part of that) while bounding the
    /// pathological case. Applied to the stored + indexed copy only; the full
    /// (still per-arg-truncated) command line remains in raw_json.
    internal static let maxIndexedCommandLineBytes: Int = 16_384

    /// Truncate `s` so its UTF-8 encoding is at most `maxBytes`, cutting on a
    /// Character boundary (never mid-scalar) and appending a byte-count marker
    /// when truncation occurs. The common case (short command line) returns the
    /// input untouched after a single O(n) length check.
    static func boundIndexedText(_ s: String, maxBytes: Int) -> String {
        let utf8Count = s.utf8.count
        if utf8Count <= maxBytes { return s }
        let marker = "…<truncated:\(utf8Count) bytes>"
        let budget = max(0, maxBytes - marker.utf8.count)
        var kept = 0
        var end = s.startIndex
        var idx = s.startIndex
        while idx < s.endIndex {
            let n = String(s[idx]).utf8.count
            if kept + n > budget { break }
            kept += n
            idx = s.index(after: idx)
            end = idx
        }
        return String(s[s.startIndex..<end]) + marker
    }

    /// Number of events whose raw_json was truncated to fit `maxRawJsonBytes`.
    /// Snapshot via `payloadTruncatedTotal()`. Surfaced into
    /// `heartbeat_rich.json` as `payload_truncated_total` (Wave 9K,
    /// v1.12.6) so operators see the cap firing rate without
    /// scraping the daemon log.
    private var payloadTruncatedCount: Int = 0

    // MARK: Prepared statement cache

    private var insertStmt: OpaquePointer?

    /// Whether this store was opened in read-only mode (fallback for non-owner access).
    private var isReadOnly = false

    /// v1.8.0 Layer 1: pre-insert filter. Nil = no filtering (legacy behavior).
    /// Set after init via `setInsertFilter` so `init(path:)` test paths can
    /// bypass filtering. The daemon's bootstrap installs the default filter
    /// + any operator-extended patterns.
    private var insertFilter: EventInsertFilter?

    // MARK: - Schema migrations

    /// Ordered list of schema migrations applied on top of the baseline
    /// `CREATE TABLE IF NOT EXISTS events` statements in `openDatabase`.
    ///
    /// Each entry bumps `PRAGMA user_version` atomically. Fresh DBs run all
    /// migrations in order; existing DBs skip ones already applied.
    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "baseline",
            sql: []
        ),
        // v1.7.2: promote MCP attribution from raw_json to indexed
        // columns. v1.7.0 carried these in `event.enrichments` only;
        // the dashboard's MCPActivityView pre-v1.7.2 had to
        // json_extract over raw_json to filter by server. Now they're
        // top-level indexed columns with their own composite index.
        Migration(
            version: 2,
            name: "add_mcp_attribution_columns",
            sql: [
                "ALTER TABLE events ADD COLUMN mcp_server_name TEXT",
                "ALTER TABLE events ADD COLUMN mcp_server_category TEXT",
                "ALTER TABLE events ADD COLUMN ai_tool_session_id TEXT",
                "CREATE INDEX IF NOT EXISTS idx_events_mcp_server ON events(timestamp, mcp_server_name)",
            ]
        ),
        // v1.8.0: tiered retention model. The `events` table becomes a
        // 24-hour hot tier; older rows get aggregated into
        // `event_aggregates` (≤30 day rollup) and the events LEADING UP TO an
        // alert get copied into `alert_evidence` (kept forever, bounded by
        // alert count). Capture is synchronous at alert-fire time, so it is
        // BACKWARD-looking — the ~windowSeconds of already-persisted events
        // before the alert; events after the alert have not happened yet.
        // (audit corr-storage: earlier "±60s"/"~120s" framing overstated a
        // forward window that is always empty at capture time.)
        //
        // Replaces the size-cap-and-VACUUM dance at DaemonTimers.swift —
        // pre-fix that approach silently let the file grow to 1.8 GB+ on
        // busy machines because per-tick VACUUM kept failing or being
        // skipped. The tier model is bounded by design: events table
        // never holds more than ~24h, aggregates are <5 MB, evidence
        // grows as alerts × ~windowSeconds of preceding events.
        Migration(
            version: 3,
            name: "add_tiered_retention_tables",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS alert_evidence (
                    alert_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    process_pid INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    process_commandline TEXT,
                    process_ppid INTEGER,
                    process_signer TEXT,
                    process_team_id TEXT,
                    process_signing_id TEXT,
                    file_path TEXT,
                    file_action TEXT,
                    network_dest_ip TEXT,
                    network_dest_port INTEGER,
                    tcc_service TEXT,
                    tcc_client TEXT,
                    raw_json TEXT NOT NULL,
                    mcp_server_name TEXT,
                    mcp_server_category TEXT,
                    ai_tool_session_id TEXT,
                    PRIMARY KEY (alert_id, id)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_evidence_alert_ts ON alert_evidence(alert_id, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_evidence_event ON alert_evidence(id)",
                """
                CREATE TABLE IF NOT EXISTS event_aggregates (
                    day TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    process_signer TEXT NOT NULL DEFAULT '',
                    process_path TEXT NOT NULL DEFAULT '',
                    count INTEGER NOT NULL,
                    PRIMARY KEY (day, event_category, process_signer, process_path)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_aggregates_day ON event_aggregates(day)",
                "CREATE INDEX IF NOT EXISTS idx_aggregates_day_category ON event_aggregates(day, event_category)",
            ]
        ),
        // v1.9 Agent Traces (PR-1): additive columns for AI-agent attribution
        // surfaced via W3C TRACEPARENT propagation and lineage walks. Columns
        // are nullable; absence means "no agent trace was bound to this event."
        // The partial index covers only rows with an attached trace_id, which
        // is a tiny fraction of total events on a typical machine — keeping
        // the index size proportional to agent activity.
        //
        // `machine_agent_confidence` is immutable after the row is written;
        // user reattribute verdicts (PR-4) live in a separate
        // `attribution_overlay` table so the original attribution is always
        // auditable.
        Migration(
            version: 4,
            name: "add_agent_trace_columns",
            sql: [
                "ALTER TABLE events ADD COLUMN agent_trace_id TEXT",
                "ALTER TABLE events ADD COLUMN agent_span_id TEXT",
                "ALTER TABLE events ADD COLUMN agent_tool TEXT",
                "ALTER TABLE events ADD COLUMN machine_agent_confidence TEXT",
                "ALTER TABLE events ADD COLUMN agent_evidence_json TEXT",
                "CREATE INDEX IF NOT EXISTS idx_events_trace ON events(agent_trace_id) WHERE agent_trace_id IS NOT NULL",
            ]
        ),
        // v1.9 Agent Traces (PR-4): operator-recorded verdict overlay on
        // top of an event's machine-emitted attribution. Co-located with
        // events.db so retention coupling can run inside a single
        // transaction (Pass 12 invariant: every override row has a
        // matching event row). Single PRIMARY KEY column means a second
        // verdict for the same event REPLACES the first — single source
        // of truth per event, simpler quality metric.
        Migration(
            version: 5,
            name: "add_attribution_overrides_table",
            sql: [
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
        ),
        // v1.12.6 Wave 2A: promote user / architecture / notarization /
        // ai_tool / parent / session fields from raw_json into indexed
        // columns. Pre-fix, rules predicating on `User`, `Architecture`,
        // `NotarizationStatus`, etc. silently fell through to
        // `event.enrichments[fieldName]` (never populated for these keys
        // -- e.g. NotarizationChecker writes `notarization.status`, not
        // `NotarizationStatus`). Result: rosetta_binary_from_downloads,
        // notarization_absent_non_system, and the rosetta / notarized-
        // dropper sequence rules never fired in production.
        //
        // Migration is ADDITIVE: pre-v6 rows keep NULL for the new
        // columns, and RuleEngine falls back to raw_json extraction
        // for those rows so historical events remain matchable.
        Migration(
            version: 6,
            name: "promote_raw_json_to_indexed_columns",
            sql: [
                "ALTER TABLE events ADD COLUMN user_id INTEGER",
                "ALTER TABLE events ADD COLUMN user_name TEXT",
                "ALTER TABLE events ADD COLUMN group_id INTEGER",
                "ALTER TABLE events ADD COLUMN working_directory TEXT",
                "ALTER TABLE events ADD COLUMN responsible_pid INTEGER",
                "ALTER TABLE events ADD COLUMN architecture TEXT",
                "ALTER TABLE events ADD COLUMN is_platform_binary INTEGER",
                "ALTER TABLE events ADD COLUMN is_notarized INTEGER",
                "ALTER TABLE events ADD COLUMN process_sha256 TEXT",
                "ALTER TABLE events ADD COLUMN parent_name TEXT",
                "ALTER TABLE events ADD COLUMN parent_executable TEXT",
                "ALTER TABLE events ADD COLUMN parent_signer_type TEXT",
                "ALTER TABLE events ADD COLUMN ai_tool TEXT",
                "ALTER TABLE events ADD COLUMN ai_tool_child INTEGER",
                "ALTER TABLE events ADD COLUMN session_launch_source TEXT",
                "ALTER TABLE events ADD COLUMN tcc_decision TEXT",
                "CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_ai_tool_ts ON events(ai_tool, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_events_parent_exe_ts ON events(parent_executable, timestamp)",
            ]
        ),
        // v1.21.5 PERF: index hygiene on `events`, the highest-insert-rate table
        // in the product — every index on it is a B-tree write per row.
        //
        // Drops two indexes that were strict prefixes of wider ones and so were
        // pure insert cost with no possible read benefit (see the baseline schema
        // in `openDatabase` for the prefix argument).
        //
        // Adds the index the dashboard's paged Events query actually needs.
        // `EventStore.events(before:category:severity:)` — re-run every 5 s by the
        // V2 Events workspace — builds
        //     WHERE event_category = ? AND severity IN (…) ORDER BY timestamp DESC
        // and the only composite available led with `timestamp`, so the planner
        // fell back to idx_events_category. That index has 3 distinct values, so
        // it visited ~1/3 of the table and temp-sorted those wide rows to return
        // 100. Leading with the equality column bounds the scan to rows that can
        // actually match; the residual ORDER BY sort is then over a handful of
        // rows instead of thousands.
        //
        // `DROP INDEX IF EXISTS` is idempotent, which matters here: SchemaMigrator
        // re-applies EVERY migration on EVERY open (see its v1.7.6 co-resident-
        // store fix), so a non-idempotent DROP would be a bug. These are safe.
        Migration(
            version: 7,
            name: "prune_redundant_event_indexes",
            sql: [
                "DROP INDEX IF EXISTS idx_events_process_path",
                "DROP INDEX IF EXISTS idx_events_ts_severity",
                "CREATE INDEX IF NOT EXISTS idx_events_cat_sev_ts ON events(event_category, severity, timestamp)",
            ]
        ),
    ]

    // MARK: Initialization

    /// Throw `EventStoreError.databaseOpenFailed` if `path` exists and is a
    /// symbolic link. A missing file is always OK — SQLite will create it.
    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return // does not exist yet — safe
        }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw EventStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
        }
    }

    private static func defaultStoragePolicy(
        for databasePath: String
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            // DaemonConfig's legacy 420 MiB envelope reserves 100 MiB for
            // alert-owned evidence after the schema-v8 file split.
            maxFootprintBytes: 320 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy
                .eventTransactionReserveBytes,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent
        )
    }

    /// Opens a SQLite database before actor isolation begins.
    /// Returns (db handle, isReadOnly) so init can assign to stored properties.
    ///
    /// - Parameter forceReadOnly: When `true`, skip the RW open attempt and
    ///   open with `SQLITE_OPEN_READONLY` directly. Used by the dashboard
    ///   (MacCrabApp/V2LiveDataProvider) to ensure its long-lived connection
    ///   never holds the shared/upgrade lock that blocks the daemon's
    ///   `VACUUM` and `wal_checkpoint(TRUNCATE)` operations.
    ///   (v1.12.6 RC2, Wave 9A — see lsof field background in v1.12.6 RC1
    ///   recovery notes.)
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

        // Admission is deliberately evaluated before SQLite can create or
        // mutate any family member. Explicit read-only consumers skip it and
        // never install the mutating max_page_count PRAGMA.
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
            // Explicit RO open — no RW attempt. The dashboard never writes
            // to this store (mutations route through the inbox file-IPC
            // channel per v1.10.1), so we skip the RW open and the lock
            // it would imply.
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
            throw EventStoreError.sqliteFailure(
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
                thresholdPages: StoragePragmas.eventWalAutocheckpointPages,
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
                // Existing oversized databases open in shed mode so bounded
                // retention can reclaim them. No schema/growth writes run.
            }
        }

        let writerInitializationAllowed = !isReadOnly
            && !(admission?.growthBlocked ?? false)

        func admitSchemaWork(_ rawWork: SchemaStorageWork) throws {
            guard var current = admission else { return }
            defer { admission = current }
            // A brand-new file has no user rows for CREATE INDEX to scan; treat
            // all bootstrap/migration DDL as bounded metadata. Existing stores
            // route every missing CREATE/DROP INDEX through the rebuild gate.
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
            // v1.6.22: pragmas centralized in StoragePragmas.applyEventStorePragmas.
            // Cut from 64 MB cache + 256 MB mmap (v1.6.21) to 16 MB + 64 MB after
            // 2.76 GB resident observation on a test host with 2 long-lived
            // connections to events.db (EventStore + AlertStore).
            do {
                try StoragePragmas.applyEventStorePragmasChecked(to: handle)
            } catch let failure as StoragePragmas.ApplicationFailure {
                throw EventStoreError.sqliteFailure(
                    context: failure.sql,
                    message: String(cString: sqlite3_errmsg(handle)),
                    resultCode: failure.metadata.resultCode,
                    extendedResultCode: failure.metadata.extendedResultCode,
                    systemErrno: failure.metadata.systemErrno
                )
            }
        }
        // v1.4.4: `busy_timeout = 5000` tells SQLite to retry a busy-lock
        // for up to 5 seconds instead of failing immediately with
        // SQLITE_BUSY. Default is 0 (no retry). Fixes the class of
        // transient "database is locked" errors v1.4.3's fail-loud
        // banner surfaced — WAL autocheckpoint briefly holds the write
        // lock, and without a timeout the next insert fails.
        try Self.exec(handle, "PRAGMA busy_timeout = 5000")
        try Self.exec(handle, "PRAGMA foreign_keys = ON")

        // Create schema
        let schemaSQLs = [
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                event_category TEXT NOT NULL, event_type TEXT NOT NULL,
                event_action TEXT NOT NULL, severity TEXT NOT NULL,
                process_pid INTEGER, process_name TEXT, process_path TEXT,
                process_commandline TEXT, process_ppid INTEGER,
                process_signer TEXT, process_team_id TEXT, process_signing_id TEXT,
                file_path TEXT, file_action TEXT,
                network_dest_ip TEXT, network_dest_port INTEGER,
                tcc_service TEXT, tcc_client TEXT, raw_json TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            // v1.21.5 PERF: idx_events_process_path (process_path) and
            // idx_events_ts_severity (timestamp, severity) are no longer created.
            // Each is a STRICT PREFIX of a wider index that already exists
            // (idx_events_process_ts = (process_path, timestamp);
            // idx_events_ts_sev_cat = (timestamp, severity, event_category)), so
            // neither could ever be the planner's best choice for any query the
            // wider index doesn't serve — while both cost a B-tree write on every
            // insert, at ~220 inserts/s on a developer host. Migration v7 drops
            // them from existing databases; see `schemaMigrations`.
            "CREATE INDEX IF NOT EXISTS idx_events_ts_category ON events(timestamp, event_category)",
            "CREATE INDEX IF NOT EXISTS idx_events_process_ts ON events(process_path, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_ts_sev_cat ON events(timestamp, severity, event_category)",
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                process_name, process_path, process_commandline,
                file_path, network_dest_ip, tcc_service, tcc_client,
                content=events, content_rowid=rowid
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES (new.rowid, new.process_name, new.process_path, new.process_commandline,
                    new.file_path, new.network_dest_ip, new.tcc_service, new.tcc_client);
            END
            """,
            // events_au AFTER UPDATE (audit corr-storage): keep the external-
            // content FTS index in sync when an existing event row is UPDATED
            // directly. Normal event insertion treats duplicate immutable ids
            // as no-ops, but maintenance or future SQL UPDATE surfaces must not
            // orphan old FTS postings. This trigger removes the stale postings
            // (via the FTS5 'delete' command with old.* values, which does not
            // depend on the content row) and re-adds the fresh ones. The prune
            // paths delete FTS rows explicitly (while the content row is still
            // present) and are unaffected — no AFTER DELETE trigger exists, so
            // there is no double-delete.
            """
            CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
                INSERT INTO events_fts(events_fts, rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES ('delete', old.rowid, old.process_name, old.process_path, old.process_commandline,
                    old.file_path, old.network_dest_ip, old.tcc_service, old.tcc_client);
                INSERT INTO events_fts(rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES (new.rowid, new.process_name, new.process_path, new.process_commandline,
                    new.file_path, new.network_dest_ip, new.tcc_service, new.tcc_client);
            END
            """,
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

        // v1.21.4 Tier-A perf: defer FTS5 index merging off the hot insert
        // path. FTS5's default `automerge=4` runs an incremental b-tree
        // segment merge once ~4 segments accumulate at a level — fired on the
        // per-insert flush path (the profile sampled `fts5StorageSync →
        // fts5IndexMergeLevel` there). Raising automerge to 16 defers that
        // incremental merge until 4× as many segments pile up, so the write
        // path pays the merge cost far less often; the `crisismerge` safety
        // valve (default 16, the max allowed segments per level) still bounds
        // worst-case segment growth so hunt queries can never degrade
        // unboundedly. The index is compacted off-path by an explicit
        // ('merge', N) crank driven from the background size-cap sweep (see
        // `mergeFTS(pages:)` + DaemonTimers.runAdaptiveRollupSweep).
        //
        // DETECTION-SAFE: `events_fts` is read ONLY by `search()` (threat
        // hunting) — the detection engine never queries it. `automerge` /
        // `merge` change only the index's physical segment layout on disk,
        // never which rowids a MATCH returns, so this alters hunt latency,
        // never any detection outcome. The value persists in FTS5's `%_config`
        // shadow table; we (re)assert it on each read-write open so existing
        // DBs pick up the new value. Skipped on read-only opens (the
        // dashboard's connection), which cannot write the shadow table.
        //
        // Best-effort: a bare `sqlite3_exec` (not `Self.exec`) so a refused
        // write stays silent — this is a non-load-bearing perf tuning, and if
        // it can't be applied (e.g. a user-uid CLI opened the root daemon's DB
        // RW) the index just keeps the correct default automerge=4. Distinct
        // from the load-bearing schema statements above, whose failures log.
        if writerInitializationAllowed {
            if (try? admission?.admitWrite(
                estimatedTransactionBytes:
                    SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
                on: handle
            )) != nil {
                sqlite3_exec(handle, "INSERT INTO events_fts(events_fts, rank) VALUES('automerge', 16)", nil, nil, nil)
            }
        }

        // Apply versioned schema migrations on top of the baseline tables above.
        // v1 marks "baseline schema present"; later versions add columns for
        // enrichment fields (file/process hashes, session context, etc).
        //
        // Migration failures are load-bearing. In particular, callers need
        // the typed SQLite codes to distinguish explicit corruption from
        // BUSY/LOCKED/PERM/READONLY/IOERR without parsing a message. Swallowing
        // one here would let daemon recovery make the wrong evidence decision.
        if writerInitializationAllowed {
            // v1.12.0: skip the per-init quick_check — it's a 1–2 s PRAGMA
            // on a large events.db. A deferred task runs it after startup.
            try SchemaMigrator.run(
                on: handle,
                migrations: Self.schemaMigrations,
                skipQuickCheck: true,
                beforeStorageWork: { work in
                    try admitSchemaWork(work)
                }
            )
            // Wave-3 P1. This index references the v2 ai_tool_session_id
            // column, so it must be installed AFTER migrations; placing it in
            // the baseline list made a fresh DB depend on swallowed errors.
            let aiSessionIndex = "CREATE INDEX IF NOT EXISTS idx_events_ai_session ON events(ai_tool_session_id, timestamp) WHERE ai_tool_session_id IS NOT NULL"
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: [aiSessionIndex]
                )
            )
            try Self.exec(handle, aiSessionIndex)
        }

        // Prepare insert statement.
        // v1.7.2 schema v2: 3 new indexed MCP attribution columns
        // (mcp_server_name, mcp_server_category, ai_tool_session_id).
        // Pulled from `event.enrichments` at insert time. Nullable —
        // events without MCP attribution leave them nil.
        // v1.9 PR-5 hotfix (audit B1): added five agent_* columns for
        // the v4 schema migration. Pre-fix the migration added the
        // columns but the INSERT never bound them, so every event
        // wrote NULL into the new fields and the partial index was
        // permanently empty. TraceCorrelator.flatten() writes these
        // keys into `event.enrichments`; we project them into columns
        // here so SQL-side queries (`WHERE agent_trace_id = ?`,
        // `WHERE agent_tool = 'claude_code'`) actually work.
        // v1.12.6 Wave 2A: 16 new columns promoted from raw_json (params
        // 30..=45). Order kept stable so re-prepares across schema bumps
        // are append-only. NULL/0 for fields that aren't present on a
        // given event category (e.g. tcc_decision is only set for TCC
        // events; ai_tool only when a TraceCorrelator binding exists).
        // Event ids identify immutable evidence. A duplicate is an idempotent
        // no-op, not a rewrite: this avoids both evidence mutation and a hidden
        // old-value FTS delete/new-value insert whose storage work cannot be
        // derived from the incoming event. Direct SQL UPDATEs remain covered by
        // `events_au`, which keeps the external-content FTS index coherent.
        let insertSQL = """
            INSERT OR IGNORE INTO events (
                id, timestamp, event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json,
                mcp_server_name, mcp_server_category, ai_tool_session_id,
                agent_trace_id, agent_span_id, agent_tool,
                machine_agent_confidence, agent_evidence_json,
                user_id, user_name, group_id, working_directory,
                responsible_pid, architecture, is_platform_binary,
                is_notarized, process_sha256, parent_name, parent_executable,
                parent_signer_type, ai_tool, ai_tool_child,
                session_launch_source, tcc_decision
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41,?42,?43,?44,?45)
            """
        var insertStmt: OpaquePointer?
        let prepareRC = !writerInitializationAllowed
            ? SQLITE_OK
            : sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil)
        if prepareRC != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            let failure = SQLiteFailureDetails(resultCode: prepareRC, db: handle)
            throw EventStoreError.sqliteFailure(
                context: "prepare insert",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }

        let pageSize = try Self.readPositivePragma(
            handle,
            name: "page_size"
        )
        guard pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            throw EventStoreError.databaseOpenFailed(
                "unsupported SQLite page_size \(pageSize)"
            )
        }

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

    private static func readPositivePragma(
        _ db: OpaquePointer,
        name: String
    ) throws -> Int64 {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            throw EventStoreError.databaseOpenFailed(
                "could not read PRAGMA \(name)"
            )
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw EventStoreError.databaseOpenFailed(
                "PRAGMA \(name) returned no row"
            )
        }
        let value = sqlite3_column_int64(stmt, 0)
        guard value > 0 else {
            throw EventStoreError.databaseOpenFailed(
                "invalid PRAGMA \(name)=\(value)"
            )
        }
        return value
    }

    /// Execute a SQL statement on a raw handle (used during init before actor is live).
    /// Execute SQL on a raw handle and surface the error to os.log when it
    /// fails. PRAGMAs used to be silently ignored; a failed `journal_mode =
    /// WAL` (corrupt DB, disk-full, read-only filesystem) would leave the
    /// store in a quieter fallback mode with no visible signal. `.public`
    /// interpolation keeps the diagnostic useful under `sudo log show`
    /// (values here are SQL strings and SQLite return codes, never user
    /// secrets).
    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
            throw EventStoreError.sqliteFailure(
                context: sql,
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }

    /// Creates an `EventStore` backed by a SQLite database at the default location.
    ///
    /// The database is stored at `~/Library/Application Support/MacCrab/events.db`.
    /// The directory is created if it does not already exist.
    ///
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
    public init(
        directory: String = "/Library/Application Support/MacCrab",
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil
    ) throws {
        let maccrabDir = URL(fileURLWithPath: directory)

        // Skip dir-create + chmod when forceReadOnly — dashboard is not the
        // owner of these paths and shouldn't mutate them.
        if !forceReadOnly {
            try FileManager.default.createDirectory(
                at: maccrabDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: maccrabDir.path
            )
        }

        let databasePath = maccrabDir.appendingPathComponent("events.db").path
        self.databasePath = databasePath
        let effectiveStoragePolicy = forceReadOnly
            ? nil
            : (storagePolicy ?? Self.defaultStoragePolicy(for: databasePath))
        self.storagePolicy = effectiveStoragePolicy

        // v1.21.5 (audit sec-storage-crypto): umask 0o027 ⇒ new SQLite
        // WAL/SHM files are created 0o640 (owner rw, group read-only).
        // The evidence DBs are root-owned; the console-user dashboard/CLI
        // READ them (group-read) but must NOT write them directly. The
        // default macOS account is in the admin group (gid 80), so the
        // old group-WRITE bit (0o660) let any non-root admin process open
        // events.db read-write and DELETE the rows recording its own
        // activity (anti-forensics) with no sudo / escalation. All
        // legitimate mutations now route through the privileged inbox IPC
        // (the daemon applies them as root); 0o640 keeps group-read for
        // display while closing the direct-write tamper path.
        // (Skip umask + chmod entirely when forceReadOnly — see Wave 9A.)
        if forceReadOnly {
            let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
                at: databasePath,
                forceReadOnly: true,
                storagePolicy: nil
            )
            self.db = handle
            self.isReadOnly = ro
            self.insertStmt = stmt
            self.storageAdmission = admission
            self.sqlitePageSizeBytes = pageSize
            self.checkpointController = controller
        } else {
            let oldUmask = umask(0o027)
            defer { umask(oldUmask) }
            let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
                at: databasePath,
                forceReadOnly: false,
                storagePolicy: effectiveStoragePolicy
            )
            self.db = handle
            self.isReadOnly = ro
            self.insertStmt = stmt
            self.storageAdmission = admission
            self.sqlitePageSizeBytes = pageSize
            self.checkpointController = controller
            // Re-clamp existing files (incl. any created 0o660 by an older
            // build) to 0o640: owner rw, group read-only, no other.
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
        }
    }

    /// Creates an `EventStore` at a custom path (useful for testing).
    ///
    /// - Parameter path: Full file system path for the SQLite database.
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
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

    /// Persists a single event to the store.
    ///
    /// The event is serialised to JSON for the `raw_json` column, and
    /// commonly-queried fields are extracted into their own columns.
    ///
    /// - Parameter event: The event to store.
    /// - Throws: `EventStoreError` on serialisation or database failure.
    /// Install (or replace) the pre-insert filter. Called by daemon bootstrap
    /// after the support dir is resolved + DaemonConfig parsed. Tests can call
    /// this to dial a specific filter into a temp store.
    public func setInsertFilter(_ filter: EventInsertFilter?) {
        self.insertFilter = filter
    }

    /// Run SQLite `PRAGMA quick_check` on the open handle, deferred
    /// off the daemon boot path. EventStore.init now constructs with
    /// `skipQuickCheck: true` — call this from a background Task once
    /// boot completes. Logs structural-corruption findings; does not
    /// throw, since the daemon has no recovery path from corruption
    /// at this layer anyway (real corruption surfaces as SQLITE_CORRUPT
    /// on actual queries and the daemon's existing error handlers take
    /// over from there).
    public func runQuickCheck() {
        guard let db = self.db else { return }
        do {
            try SchemaMigrator.quickCheck(on: db) { msg in
                Logger(subsystem: "com.maccrab.storage", category: "event-store")
                    .info("quick_check: \(msg, privacy: .public)")
            }
        } catch {
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .warning("Deferred quick_check failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Snapshot the filter's drop counter. Wired into the daemon's heartbeat
    /// so the dashboard can surface "X events dropped at insert filter today"
    /// — operators tuning their filter list need to see the impact.
    public func insertFilterCounters() -> (dropped: Int, passed: Int)? {
        return insertFilter?.counters.snapshot()
    }

    /// Snapshot the running total of events whose raw_json was truncated
    /// to fit `maxRawJsonBytes`. Exposed so the daemon heartbeat can surface
    /// `maccrab_eventstore_payload_truncated_total` to scrapers and the
    /// dashboard. Monotonic for the lifetime of the actor.
    public func payloadTruncatedTotal() -> Int {
        return payloadTruncatedCount
    }

    public func insert(event: Event) throws {
        _ = try insert(event: event, applyInsertFilter: true) { rowMutationBytes in
            try self.admitStorageWrite(
                estimatedTransactionBytes: self.eventTransactionEstimate(
                    rowMutationBytes: rowMutationBytes
                )
            )
        }
    }

    /// Prepare the complete persisted representation before asking the caller
    /// to admit the write. Batch insertion uses the callback to close the
    /// current transaction before adding a row that would exceed its reserve.
    private func insert(
        event: Event,
        applyInsertFilter: Bool,
        beforeWrite: (Int64) throws -> Void
    ) throws -> Bool {
        // v1.8.0 Layer 1: drop noise events at insert. Cheaper than letting
        // them hit SQLite + FTS5 + indexes. Self-monitoring (daemon watches
        // its own log/DB) was 17% of volume on field-measured hardware.
        if applyInsertFilter,
           let filter = insertFilter,
           filter.shouldDrop(event: event) {
            return false
        }
        // Sanitize the command line to redact secrets (passwords, tokens, API keys)
        // before persisting to the database.
        let sanitizedCommandLine = CommandSanitizer.sanitize(event.process.commandLine)

        // Audit P-CPU-117: this is the largest steady-state allocation
        // source on a busy host. Short-circuit when sanitization is a
        // no-op — most events don't contain secrets in their commandline
        // and don't need the ProcessInfo + Event struct rebuild + their
        // associated array allocations. Each sanitized arg is also a
        // fresh String, so the per-arg comparison is cheap.
        let sanitizedArgs: [String]?
        if sanitizedCommandLine == event.process.commandLine {
            // Quick win: if the commandline didn't change, the args
            // almost certainly didn't either. Skip the per-arg pass.
            // CommandSanitizer is regex-based on the full string; the
            // per-arg pass would catch only edge cases where args have
            // secrets the joined commandline doesn't.
            sanitizedArgs = nil
        } else {
            sanitizedArgs = event.process.args.map { CommandSanitizer.sanitize($0) }
        }

        // Reuse the original event if nothing was sanitized — skips
        // ProcessInfo + Event struct copies + ruleMatches/ancestors
        // array reference rebuilds. ~half the allocations on a quiet
        // host.
        let sanitizedEvent: Event
        if let args = sanitizedArgs {
            let sanitizedProcess = ProcessInfo(
                pid: event.process.pid,
                ppid: event.process.ppid,
                rpid: event.process.rpid,
                name: event.process.name,
                executable: event.process.executable,
                commandLine: sanitizedCommandLine,
                args: args,
                workingDirectory: event.process.workingDirectory,
                userId: event.process.userId,
                userName: event.process.userName,
                groupId: event.process.groupId,
                startTime: event.process.startTime,
                exitCode: event.process.exitCode,
                codeSignature: event.process.codeSignature,
                ancestors: event.process.ancestors,
                architecture: event.process.architecture,
                isPlatformBinary: event.process.isPlatformBinary
            )
            sanitizedEvent = Event(
                id: event.id,
                timestamp: event.timestamp,
                eventCategory: event.eventCategory,
                eventType: event.eventType,
                eventAction: event.eventAction,
                process: sanitizedProcess,
                file: event.file,
                network: event.network,
                tcc: event.tcc,
                enrichments: event.enrichments,
                severity: event.severity,
                ruleMatches: event.ruleMatches
            )
        } else {
            sanitizedEvent = event
        }

        // v1.12.6: bound raw_json at insert. A single misbehaving caller
        // (e.g. `python3 -c '...' <base64-payload>`) can otherwise drop a
        // ~1MB row into events.db and crowd out detection signal. Encode
        // once; if oversized, apply structured per-arg truncation +
        // enrichment markers; only as a final fail-open fallback do we
        // truncate the raw string itself.
        let jsonString: String
        do {
            let initialData = try encoder.encode(sanitizedEvent)
            if initialData.count <= Self.maxRawJsonBytes {
                guard let s = String(data: initialData, encoding: .utf8) else {
                    throw EventStoreError.encodingFailed("Failed to convert JSON data to string")
                }
                jsonString = s
            } else {
                let truncated = truncatePayload(
                    sanitizedEvent: sanitizedEvent,
                    originalBytes: initialData.count
                )
                jsonString = truncated.string
                payloadTruncatedCount &+= 1
            }
        } catch let error as EventStoreError {
            throw error
        } catch {
            throw EventStoreError.encodingFailed(error.localizedDescription)
        }

        let indexedCommandLine = Self.boundIndexedText(
            sanitizedCommandLine,
            maxBytes: Self.maxIndexedCommandLineBytes
        )
        let mutationBytes = Self.estimatedEventMutationBytes(
            event: event,
            indexedCommandLine: indexedCommandLine,
            rawJSON: jsonString,
            pageSizeBytes: sqlitePageSizeBytes
        )
        try beforeWrite(mutationBytes)

        // Storage admission can synchronously recover a sticky pressure latch
        // by calling reopenAfterStorageRecovery(). That path finalizes the old
        // cached statement and replaces the SQLite handle. Acquire the statement
        // only after admission so no local pointer can outlive that reopen.
        guard let stmt = insertStmt else {
            // admitStorageWrite performs one bounded, full-estimate secondary
            // recovery if a reopen races back into shed-only mode. Reaching this
            // guard therefore means no authoritative writer could be restored.
            throw EventStoreError.prepareFailed(
                "Insert statement not prepared after storage admission"
            )
        }
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)

        // 1: id (UUID -> String)
        bindText(stmt, index: 1, value: event.id.uuidString)
        // 2: timestamp (Unix epoch seconds)
        sqlite3_bind_double(stmt, 2, event.timestamp.timeIntervalSince1970)
        // 3: event_category
        bindText(stmt, index: 3, value: event.eventCategory.rawValue)
        // 4: event_type
        bindText(stmt, index: 4, value: event.eventType.rawValue)
        // 5: event_action
        bindText(stmt, index: 5, value: event.eventAction)
        // 6: severity
        bindText(stmt, index: 6, value: event.severity.rawValue)
        // 7: process_pid
        sqlite3_bind_int(stmt, 7, event.process.pid)
        // 8: process_name
        bindText(stmt, index: 8, value: event.process.name)
        // 9: process_path (executable)
        bindText(stmt, index: 9, value: event.process.executable)
        // 10: process_commandline (sanitized, length-bounded). Bounded
        // independently of raw_json because this column feeds the events_fts
        // index directly — an oversized argv would otherwise blow up the FTS
        // index unbounded. See maxIndexedCommandLineBytes.
        bindText(stmt, index: 10, value: indexedCommandLine)
        // 11: process_ppid
        sqlite3_bind_int(stmt, 11, event.process.ppid)
        // 12: process_signer
        bindTextOrNull(stmt, index: 12, value: event.process.codeSignature?.signerType.rawValue)
        // 13: process_team_id
        bindTextOrNull(stmt, index: 13, value: event.process.codeSignature?.teamId)
        // 14: process_signing_id
        bindTextOrNull(stmt, index: 14, value: event.process.codeSignature?.signingId)
        // 15: file_path
        bindTextOrNull(stmt, index: 15, value: event.file?.path)
        // 16: file_action
        bindTextOrNull(stmt, index: 16, value: event.file?.action.rawValue)
        // 17: network_dest_ip
        bindTextOrNull(stmt, index: 17, value: event.network?.destinationIp)
        // 18: network_dest_port
        if let port = event.network?.destinationPort {
            sqlite3_bind_int(stmt, 18, Int32(port))
        } else {
            sqlite3_bind_null(stmt, 18)
        }
        // 19: tcc_service
        bindTextOrNull(stmt, index: 19, value: event.tcc?.service)
        // 20: tcc_client
        bindTextOrNull(stmt, index: 20, value: event.tcc?.client)
        // 21: raw_json (sanitized)
        bindText(stmt, index: 21, value: jsonString)
        // v1.7.2 schema v2: indexed MCP attribution columns.
        // 22: mcp_server_name
        bindTextOrNull(stmt, index: 22, value: event.enrichments["mcp_server_name"])
        // 23: mcp_server_category
        bindTextOrNull(stmt, index: 23, value: event.enrichments["mcp_server_category"])
        // 24: ai_tool_session_id
        bindTextOrNull(stmt, index: 24, value: event.enrichments["ai_tool_session_id"])
        // v1.9 schema v4: agent trace correlation columns. Keys live in
        // `event.enrichments` written by `TraceCorrelator.flatten()`;
        // we project them into indexed columns so SQL-side queries
        // (`WHERE agent_trace_id = ?`, `agent_tool = ?`,
        // `machine_agent_confidence = ?`) and the partial index
        // `idx_events_trace` actually populate.
        // 25: agent_trace_id
        bindTextOrNull(stmt, index: 25, value: event.enrichments[TraceCorrelator.EnrichmentKey.traceId])
        // 26: agent_span_id
        bindTextOrNull(stmt, index: 26, value: event.enrichments[TraceCorrelator.EnrichmentKey.spanId])
        // 27: agent_tool
        bindTextOrNull(stmt, index: 27, value: event.enrichments[TraceCorrelator.EnrichmentKey.agentTool])
        // 28: machine_agent_confidence
        bindTextOrNull(stmt, index: 28, value: event.enrichments[TraceCorrelator.EnrichmentKey.confidence])
        // 29: agent_evidence_json
        bindTextOrNull(stmt, index: 29, value: event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson])
        // v1.12.6 Wave 2A schema v6: promoted process / signature /
        // session / ai-tool fields. Empty Strings are bound as NULL so
        // `IS NULL` filters work in SQL; "" would otherwise non-match
        // for `field IS NOT NULL`. Bool fields use SQLite 0/1 INTEGER.
        // 30: user_id (UInt32 -> Int64 to avoid Int32 overflow)
        sqlite3_bind_int64(stmt, 30, Int64(event.process.userId))
        // 31: user_name -- empty -> NULL (often empty in capture stream)
        bindTextOrNull(stmt, index: 31, value: event.process.userName.isEmpty ? nil : event.process.userName)
        // 32: group_id
        sqlite3_bind_int64(stmt, 32, Int64(event.process.groupId))
        // 33: working_directory -- empty -> NULL
        bindTextOrNull(stmt, index: 33, value: event.process.workingDirectory.isEmpty ? nil : event.process.workingDirectory)
        // 34: responsible_pid (Int32, never negative in practice but
        // bind raw value — historical events have rpid==pid placeholder)
        sqlite3_bind_int(stmt, 34, event.process.rpid)
        // 35: architecture (Optional<String>) -- nil already maps to NULL
        bindTextOrNull(stmt, index: 35, value: event.process.architecture)
        // 36: is_platform_binary -- 0/1 not "true"/"false"
        sqlite3_bind_int(stmt, 36, event.process.isPlatformBinary ? 1 : 0)
        // 37: is_notarized -- only when codeSignature is present.
        // NULL means "unknown" (no signature info), 0 means "explicitly
        // not notarized", 1 means "notarized". Sigma rules predicate
        // on the 3-state via the NotarizationStatus resolver alias.
        if let sig = event.process.codeSignature {
            sqlite3_bind_int(stmt, 37, sig.isNotarized ? 1 : 0)
        } else {
            sqlite3_bind_null(stmt, 37)
        }
        // 38: process_sha256 -- only when ProcessHasher attached hashes
        bindTextOrNull(stmt, index: 38, value: event.process.hashes?.sha256)
        // 39: parent_name -- first ancestor or NULL when ancestors empty
        bindTextOrNull(stmt, index: 39, value: event.process.ancestors.first?.name)
        // 40: parent_executable -- ditto
        bindTextOrNull(stmt, index: 40, value: event.process.ancestors.first?.executable)
        // 41: parent_signer_type -- set by EventEnricher when parent
        // process signature lookup succeeds; nil otherwise.
        bindTextOrNull(stmt, index: 41, value: event.enrichments["ParentSignerType"])
        // 42: ai_tool -- reads either canonical key. AIProcessTracker
        // (EventLoop.swift:89,97) writes "ai_tool"; TraceCorrelator
        // (the legacy EnrichmentKey.agentTool constant) writes
        // "agent_tool". Either should populate the indexed column.
        // v1.12.6 RC2 fix: pre-RC1 only read EnrichmentKey.agentTool
        // so the column was 100% NULL in production despite
        // "claude_code"/"cursor"/etc. being live in raw_json under
        // the "ai_tool" key. Rules can match either Sigma alias
        // against this column (AITool, AiTool both resolve here).
        let aiTool = event.enrichments["ai_tool"]
            ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        bindTextOrNull(stmt, index: 42, value: aiTool)
        // 43: ai_tool_child -- 1 when MCPAttributor / AgentLineage
        // marks this process as a descendant of an AI tool; otherwise
        // NULL (not "0", so historical rows still register as unknown).
        if let aiChild = event.enrichments["ai_tool_child"] {
            sqlite3_bind_int(stmt, 43, aiChild == "true" ? 1 : 0)
        } else {
            sqlite3_bind_null(stmt, 43)
        }
        // 44: session_launch_source -- LaunchSource raw value ("ssh",
        // "terminal", "launchd", ...) from SessionEnricher; nil when
        // the enricher hasn't classified the parent chain yet. The
        // "telemetry_gap" sentinel (LaunchSource.telemetryGap) is the
        // honest-degradation value written when attribution was UNRESOLVED
        // because a kernel telemetry gap was active for the event's window
        // (EventEnricher.telemetryGapSession) — distinct from a silent NULL.
        bindTextOrNull(stmt, index: 44, value: event.process.session?.launchSource?.rawValue)
        // 45: tcc_decision -- "granted" / "denied". TCCInfo.allowed
        // (Bool) flattened to a string so the Sigma rule can compare
        // against rule literals without engine-side Bool plumbing.
        if let allowed = event.tcc?.allowed {
            bindText(stmt, index: 45, value: allowed ? "granted" : "denied")
        } else {
            sqlite3_bind_null(stmt, 45)
        }

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            // v1.12.0 RC28 audit fix (Resil-B1): surface SQLITE_FULL
            // distinctly so EventLoop can stop trying to insert (no
            // point hammering a full disk) instead of treating it as
            // a transient step failure. The vendored Unix VFS reports
            // ENOSPC writes as primary SQLITE_FULL; other VFS paths may
            // retain ENOSPC/EDQUOT in sqlite3_system_errno().
            if failure.primaryResultCode == SQLITE_FULL
                || failure.systemErrno == ENOSPC
                || failure.systemErrno == EDQUOT {
                throw EventStoreError.diskFull(msg, failure: failure)
            }
            // #13: transient lock contention (past the 5s busy_timeout) — the
            // batched writer retries rather than dropping the batch.
            if rc == SQLITE_BUSY || rc == SQLITE_LOCKED {
                throw EventStoreError.busy(msg, failure: failure)
            }
            // C-04: a mid-run corruption code triggers a bounded, rate-limited
            // close→quarantine→reopen so ingestion recovers instead of failing
            // forever. We still throw this event's failure (the row is lost);
            // the *next* insert lands in the freshly-reopened DB. (When reached
            // from the batch `insert(events:)`, the enclosing transaction's
            // ROLLBACK runs on the reopened handle as a harmless no-op.)
            if failure.isExplicitCorruption {
                attemptCorruptionSelfHeal(failure: failure, reason: msg)
            }
            throw EventStoreError.sqliteFailure(
                context: "insert step",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
        if sqlite3_changes(db) > 0 {
            maintenanceRowMutationHighWaterBytes = max(
                maintenanceRowMutationHighWaterBytes ?? 0,
                mutationBytes
            )
        }
        return true
    }

    /// Derive the transaction estimate from exactly what the insert binds.
    /// `raw_json` is capped at 64 KiB and the independently indexed command
    /// line at 16 KiB, but every other projected string is counted at its real
    /// UTF-8 length so an adversarial path/enrichment can only make admission
    /// stricter. Table bytes and every secondary-index key are counted once;
    /// FTS input is counted four times for token/posting expansion. The shared
    /// estimator doubles that durable representation for WAL/page-image writes
    /// and charges up to 20 random leaf pages per row at the authoritative DB
    /// page size (events table + PK + 13 live indexes + three FTS5 backing
    /// b-trees, with two pages of margin). Interior tree/header slack is charged once per transaction by
    /// `eventTransactionEstimate`, so batching does not pay it once per event.
    static func estimatedEventMutationBytes(
        event: Event,
        indexedCommandLine: String,
        rawJSON: String,
        pageSizeBytes: Int64
    ) -> Int64 {
        func bytes(_ value: String?) -> Int64 {
            guard let value else { return 0 }
            return Int64(value.utf8.count)
        }
        func add(_ total: inout Int64, _ value: Int64) {
            total = SQLitePersistentStoreAdmission.saturatingAdd(total, value)
        }
        func addStrings(_ total: inout Int64, _ values: [String?]) {
            for value in values { add(&total, bytes(value)) }
        }

        let aiTool = event.enrichments["ai_tool"]
            ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        let tccDecision = event.tcc.map { $0.allowed ? "granted" : "denied" }

        // Row payload: every text column bound by insert(event:). Numeric/null
        // columns receive a fixed-width allowance below.
        var logical: Int64 = 45 * 16
        addStrings(&logical, [
            event.id.uuidString,
            event.eventCategory.rawValue,
            event.eventType.rawValue,
            event.eventAction,
            event.severity.rawValue,
            event.process.name,
            event.process.executable,
            indexedCommandLine,
            event.process.codeSignature?.signerType.rawValue,
            event.process.codeSignature?.teamId,
            event.process.codeSignature?.signingId,
            event.file?.path,
            event.file?.action.rawValue,
            event.network?.destinationIp,
            event.tcc?.service,
            event.tcc?.client,
            rawJSON,
            event.enrichments["mcp_server_name"],
            event.enrichments["mcp_server_category"],
            event.enrichments["ai_tool_session_id"],
            event.enrichments[TraceCorrelator.EnrichmentKey.traceId],
            event.enrichments[TraceCorrelator.EnrichmentKey.spanId],
            event.enrichments[TraceCorrelator.EnrichmentKey.agentTool],
            event.enrichments[TraceCorrelator.EnrichmentKey.confidence],
            event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson],
            event.process.userName.isEmpty ? nil : event.process.userName,
            event.process.workingDirectory.isEmpty ? nil : event.process.workingDirectory,
            event.process.architecture,
            event.process.hashes?.sha256,
            event.process.ancestors.first?.name,
            event.process.ancestors.first?.executable,
            event.enrichments["ParentSignerType"],
            aiTool,
            event.process.session?.launchSource?.rawValue,
            tccDecision,
        ])

        // Secondary indexes. Duplicates are intentional: they are separate
        // durable b-tree keys. Fixed numeric timestamp/rowid portions receive
        // 16 bytes per listed key.
        let indexedStrings: [String?] = [
            event.id.uuidString,                         // PRIMARY KEY
            event.eventCategory.rawValue,               // category + composites
            event.eventCategory.rawValue,
            event.eventCategory.rawValue,
            event.eventCategory.rawValue,
            event.severity.rawValue,                    // severity + composites
            event.severity.rawValue,
            event.severity.rawValue,
            event.process.executable,                   // process/timestamp
            event.enrichments["mcp_server_name"],
            event.enrichments[TraceCorrelator.EnrichmentKey.traceId],
            event.enrichments["ai_tool_session_id"],
            event.process.userName.isEmpty ? nil : String(event.process.userId),
            aiTool,
            event.process.ancestors.first?.executable,
        ]
        addStrings(&logical, indexedStrings)
        add(&logical, Int64(indexedStrings.count) * 16)

        // FTS5 can materialize a token dictionary plus postings/doclist data.
        // Count four copies here; the shared WAL multiplier below makes this
        // an eightfold allowance for the source text.
        var ftsBytes: Int64 = 0
        addStrings(&ftsBytes, [
            event.process.name,
            event.process.executable,
            indexedCommandLine,
            event.file?.path,
            event.network?.destinationIp,
            event.tcc?.service,
            event.tcc?.client,
        ])
        add(
            &logical,
            SQLitePersistentStoreAdmission.saturatingMultiply(ftsBytes, by: 4)
        )

        return SQLitePersistentStoreAdmission.conservativeEncodedRowMutationBytes(
            logicalRepresentationBytes: logical,
            pageSizeBytes: pageSizeBytes,
            maximumLeafPageTouches: 20
        )
    }

    // MARK: - Payload truncation (v1.12.6)

    /// Result of the payload truncation pipeline.
    private struct TruncatedPayload {
        let event: Event
        let string: String
    }

    /// Apply structured truncation to an oversized event payload so the
    /// SQLite write fits inside `maxRawJsonBytes`. Returns a re-encoded
    /// JSON string plus the mutated `Event` so callers can observe the
    /// truncation markers (used in tests).
    ///
    /// Pipeline (cheapest → most aggressive):
    ///   1. Replace each `process.args` entry over `argTruncationThreshold`
    ///      bytes with `"<truncated:N bytes>"`. Drops the dominant 1MB
    ///      base64-arg case to a marker.
    ///   2. If still oversized, also collapse `process.commandLine` to a
    ///      marker (recovers events whose mass lives in the joined string
    ///      rather than per-arg).
    ///   3. As a last-resort fail-open, replace oversized `enrichments`
    ///      values with markers and RE-ENCODE (largest-first, stop as soon
    ///      as it fits). The result is always valid, decodable JSON — never
    ///      a byte-sliced string — so `queryEvents()` can still surface the
    ///      row instead of silently dropping it on a decode error.
    ///
    /// Always sets `payload.truncated = "true"` and
    /// `payload.original_bytes = "<N>"` on the resulting event so the FTS
    /// index, dashboard, and analytics consumers see the cap was hit.
    private func truncatePayload(
        sanitizedEvent: Event,
        originalBytes: Int
    ) -> TruncatedPayload {
        let log = Logger(subsystem: "com.maccrab.storage", category: "event-store")
        var mutated = sanitizedEvent
        mutated.enrichments["payload.truncated"] = "true"
        mutated.enrichments["payload.original_bytes"] = String(originalBytes)

        // Pass 1: per-arg truncation.
        let originalArgs = sanitizedEvent.process.args
        let truncatedArgs: [String] = originalArgs.map { arg in
            let argBytes = arg.utf8.count
            if argBytes > Self.argTruncationThreshold {
                return "<truncated:\(argBytes) bytes>"
            }
            return arg
        }

        let argsChanged = zip(originalArgs, truncatedArgs).contains { $0 != $1 }
        if argsChanged {
            mutated = withProcess(
                event: mutated,
                rebuiltProcess: rebuildProcess(
                    sanitizedEvent.process,
                    commandLine: sanitizedEvent.process.commandLine,
                    args: truncatedArgs
                )
            )
        }

        if let encoded = try? encoder.encode(mutated),
           encoded.count <= Self.maxRawJsonBytes,
           let s = String(data: encoded, encoding: .utf8) {
            return TruncatedPayload(event: mutated, string: s)
        }

        // Pass 2: also collapse the joined commandLine.
        let originalCmd = sanitizedEvent.process.commandLine
        let cmdBytes = originalCmd.utf8.count
        let collapsedCmd = "<truncated:\(cmdBytes) bytes>"
        mutated = withProcess(
            event: mutated,
            rebuiltProcess: rebuildProcess(
                sanitizedEvent.process,
                commandLine: collapsedCmd,
                args: truncatedArgs
            )
        )

        if let encoded = try? encoder.encode(mutated),
           encoded.count <= Self.maxRawJsonBytes,
           let s = String(data: encoded, encoding: .utf8) {
            return TruncatedPayload(event: mutated, string: s)
        }

        // Pass 3 (fail-open): structured enrichment truncation + re-encode.
        //
        // The earlier implementation byte-SLICED the encoded JSON string and
        // appended a tail marker. That produced SYNTACTICALLY INVALID JSON:
        // `queryEvents()` decodes raw_json into an `Event` and `catch { continue }`s
        // on failure, so every sliced row — and its truncation signal — was
        // silently dropped on READ, becoming permanently invisible to the
        // dashboard/analytics (a live audit found such rows in events.db).
        //
        // After Pass 1+2 collapsed `args` and `commandLine`, the residual mass
        // lives in oversized ENRICHMENT values (captured file content, agent
        // evidence, env blocks). Replace those with markers, cheapest-first
        // (largest value first, stop as soon as it fits), and re-encode:
        // `JSONEncoder` always emits valid JSON, so the row stays decodable and
        // the `payload.truncated` / `payload.original_bytes` markers survive.
        var stripped = mutated
        let bigEnrichmentKeys = stripped.enrichments
            .filter { $0.value.utf8.count > Self.argTruncationThreshold }
            .sorted { $0.value.utf8.count > $1.value.utf8.count }
            .map(\.key)
        for key in bigEnrichmentKeys {
            let n = stripped.enrichments[key]?.utf8.count ?? 0
            stripped.enrichments[key] = "<truncated:\(n) bytes>"
            if let encoded = try? encoder.encode(stripped),
               encoded.count <= Self.maxRawJsonBytes,
               let s = String(data: encoded, encoding: .utf8) {
                log.warning("Payload truncation fell through to enrichment-strip path for event \(sanitizedEvent.id.uuidString, privacy: .public) (\(originalBytes) bytes)")
                return TruncatedPayload(event: stripped, string: s)
            }
        }

        // Residual mass is in some other field (pathological). The stripped
        // event is still VALID, decodable JSON and now far smaller than the
        // original — store it even if marginally over the soft cap. A valid
        // oversized row beats an invalid truncated one that reads as nothing.
        if let encoded = try? encoder.encode(stripped),
           let s = String(data: encoded, encoding: .utf8) {
            log.warning("Payload truncation fell through to fail-open path for event \(sanitizedEvent.id.uuidString, privacy: .public) (\(originalBytes) bytes, residual \(encoded.count))")
            return TruncatedPayload(event: stripped, string: s)
        }

        // Unreachable: `stripped` derives from an Event that already encoded
        // above. Keep a VALID minimal stub rather than risk an invalid row.
        return TruncatedPayload(event: stripped, string: "{\"payload\":\"unencodable\"}")
    }

    /// Rebuild a `ProcessInfo` with new `commandLine` and `args` fields,
    /// preserving every other field. Used by the truncation pipeline so
    /// downstream enrichments (codeSignature, ancestors, hashes, etc.)
    /// survive the per-arg rewrite.
    private func rebuildProcess(
        _ source: ProcessInfo,
        commandLine: String,
        args: [String]
    ) -> ProcessInfo {
        return ProcessInfo(
            pid: source.pid,
            ppid: source.ppid,
            rpid: source.rpid,
            name: source.name,
            executable: source.executable,
            commandLine: commandLine,
            args: args,
            workingDirectory: source.workingDirectory,
            userId: source.userId,
            userName: source.userName,
            groupId: source.groupId,
            startTime: source.startTime,
            exitCode: source.exitCode,
            codeSignature: source.codeSignature,
            ancestors: source.ancestors,
            architecture: source.architecture,
            isPlatformBinary: source.isPlatformBinary,
            hashes: source.hashes,
            session: source.session,
            envVars: source.envVars
        )
    }

    /// Rebuild an `Event` swapping in a different `ProcessInfo`. Preserves
    /// id/timestamp/category/type/action and copies enrichments + severity
    /// + ruleMatches through.
    private func withProcess(event: Event, rebuiltProcess: ProcessInfo) -> Event {
        return Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: rebuiltProcess,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: event.severity,
            ruleMatches: event.ruleMatches
        )
    }

    /// Persists a batch in reserve-bounded transactions. A very large caller
    /// array (the daemon buffer is independently capped at 20K) can no longer
    /// grow one WAL transaction without limit. Each chunk commits before the
    /// next fresh disk probe; immutable event-id duplicate no-ops make retry
    /// after a later chunk failure idempotent, though the whole input array is intentionally no
    /// longer one atomic unit. On failure, `EventBatchInsertFailure` carries
    /// the exact committed count and filter-passing suffix.
    ///
    /// - Parameter events: The events to store.
    /// - Throws: `EventBatchInsertFailure` on serialisation/database failure.
    @discardableResult
    public func insert(events: [Event]) throws -> EventBatchInsertResult {
        let startingGeneration = activeDatabaseGeneration
        var candidates: [Event] = []
        candidates.reserveCapacity(events.count)
        var filteredCount = 0
        for event in events {
            if let filter = insertFilter, filter.shouldDrop(event: event) {
                filteredCount += 1
            } else {
                candidates.append(event)
            }
        }

        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        var transactionOpen = false
        var rowMutationEstimate: Int64 = 0
        var rowsInOpenTransaction = 0
        var committedRows = 0
        var committedTransactions = 0

        func commitOpenTransaction() throws {
            guard transactionOpen else { return }
            try execute("COMMIT")
            committedBatchInsertTransactions &+= 1
            committedTransactions += 1
            committedRows += rowsInOpenTransaction
            transactionOpen = false
            rowMutationEstimate = 0
            rowsInOpenTransaction = 0
        }

        do {
            for event in candidates {
                _ = try insert(
                    event: event,
                    applyInsertFilter: false
                ) { rowBytes in
                    let nextRows = SQLitePersistentStoreAdmission
                        .saturatingAdd(rowMutationEstimate, rowBytes)
                    let nextEstimate = eventTransactionEstimate(
                        rowMutationBytes: nextRows
                    )
                    if transactionOpen, nextEstimate > reserve {
                        try commitOpenTransaction()
                    }
                    if !transactionOpen {
                        let firstEstimate = eventTransactionEstimate(
                            rowMutationBytes: rowBytes
                        )
                        try execute(
                            "BEGIN TRANSACTION",
                            estimatedTransactionBytes: firstEstimate
                        )
                        transactionOpen = true
                    }
                    rowMutationEstimate = SQLitePersistentStoreAdmission
                        .saturatingAdd(rowMutationEstimate, rowBytes)
                }
                rowsInOpenTransaction += 1
            }
            try commitOpenTransaction()
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: committedRows,
                filteredCount: filteredCount,
                committedTransactionCount: committedTransactions
            )
        } catch {
            if transactionOpen { try? execute("ROLLBACK") }
            let databaseWasReplaced = activeDatabaseGeneration
                != startingGeneration
            let durableRows = databaseWasReplaced ? 0 : committedRows
            let durableTransactions = databaseWasReplaced
                ? 0 : committedTransactions
            let progress = EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: durableRows,
                filteredCount: filteredCount,
                committedTransactionCount: durableTransactions
            )
            throw EventBatchInsertFailure(
                progress: progress,
                uncommittedEvents: databaseWasReplaced
                    ? candidates
                    : Array(candidates.dropFirst(committedRows)),
                underlyingError: error,
                activeDatabaseWasReplaced: databaseWasReplaced,
                replacementReadyForRetry: databaseWasReplaced
                    && db != nil && insertStmt != nil && !isReadOnly
            )
        }
    }

    private func eventTransactionEstimate(
        rowMutationBytes: Int64
    ) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowMutationBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 48
        )
    }

    /// Deterministic regression surface for verifying that the reserve guard
    /// still batches ordinary events instead of degenerating to per-row commits.
    func batchInsertTransactionCount() -> UInt64 {
        committedBatchInsertTransactions
    }

    // MARK: - Query

    /// Returns events from the store, optionally filtered by time range, category,
    /// and severity.
    ///
    /// - Parameters:
    ///   - since: Only return events at or after this date.
    ///   - category: If provided, filter to this category only.
    ///   - severity: If provided, filter to this severity or higher.
    ///   - limit: Maximum number of events to return (default 1000).
    /// - Returns: An array of `Event` values decoded from the `raw_json` column.
    public func events(
        since: Date,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        limit: Int = 1000
    ) throws -> [Event] {
        var sql = "SELECT raw_json FROM events WHERE timestamp >= ?1"
        var bindings: [(Int32, BindingValue)] = [
            (1, .double(since.timeIntervalSince1970))
        ]
        var nextIndex: Int32 = 2

        if let category {
            sql += " AND event_category = ?\(nextIndex)"
            bindings.append((nextIndex, .text(category.rawValue)))
            nextIndex += 1
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

        sql += " ORDER BY timestamp DESC LIMIT ?\(nextIndex)"
        bindings.append((nextIndex, .int(Int32(limit))))

        return try queryEvents(sql: sql, bindings: bindings)
    }

    /// Wave-3 P1: all events stamped with a given durable agent session
    /// id, in chronological order — the queryable per-session timeline
    /// (proc/file/net rails today). Backed by idx_events_ai_session.
    public func eventsForAgentSession(_ sessionId: String, limit: Int = 2000) throws -> [Event] {
        let sql = "SELECT raw_json FROM events WHERE ai_tool_session_id = ?1 ORDER BY timestamp ASC LIMIT ?2"
        let bindings: [(Int32, BindingValue)] = [
            (1, .text(sessionId)),
            (2, .int(Int32(max(1, min(limit, 10000))))),
        ]
        return try queryEvents(sql: sql, bindings: bindings)
    }

    /// Phase-5 injection-evidence weld: events for a session bounded to a tight
    /// time window [since, until], chronological. Pushes the "prior N seconds"
    /// retro-scan window into SQL (idx_events_ai_session covers
    /// (ai_tool_session_id, timestamp)) so a busy session that has emitted more
    /// than the plain `limit` of events can't push the recent window out of a
    /// LIMIT-capped ASC scan. `since`/`until` are compared against the same
    /// epoch-seconds `timestamp` column the index is keyed on.
    public func eventsForAgentSession(_ sessionId: String, since: Date, until: Date, limit: Int = 2000) throws -> [Event] {
        let sql = """
            SELECT raw_json FROM events
            WHERE ai_tool_session_id = ?1 AND timestamp >= ?2 AND timestamp <= ?3
            ORDER BY timestamp ASC LIMIT ?4
            """
        let bindings: [(Int32, BindingValue)] = [
            (1, .text(sessionId)),
            (2, .double(since.timeIntervalSince1970)),
            (3, .double(until.timeIntervalSince1970)),
            (4, .int(Int32(max(1, min(limit, 10000))))),
        ]
        return try queryEvents(sql: sql, bindings: bindings)
    }

    /// Wave-3 P2b: the most-recent durable session id associated with a
    /// process pid. Used MCP-side to attribute a mutation (whose only
    /// correlation handle is the caller's ppid) back to an agent session —
    /// a medium-confidence join (pids recycle; the MCP host pid may differ
    /// from the kernel-work AI-tool root), so callers should label it as
    /// ppid-correlated, not trace-confirmed.
    public func agentSessionForPid(_ pid: Int32) throws -> String? {
        let sql = "SELECT ai_tool_session_id FROM events WHERE process_pid = ?1 AND ai_tool_session_id IS NOT NULL ORDER BY timestamp DESC LIMIT 1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, pid)
        guard sqlite3_step(stmt) == SQLITE_ROW, let c = sqlite3_column_text(stmt, 0) else { return nil }
        return String(cString: c)
    }

    /// One-line summary per durable agent session, derived from the
    /// stamped events (no separate registry table needed for this slice).
    /// Most-recently-active first. Backed by idx_events_ai_session.
    public struct AgentSessionSummary: Sendable, Hashable {
        public let sessionId: String
        public let tool: String?
        public let projectDir: String?
        public let firstSeen: Date
        public let lastSeen: Date
        public let eventCount: Int
    }

    /// Wave-3 P1b: enumerate agent sessions for list_agent_sessions.
    public func agentSessions(limit: Int = 100) throws -> [AgentSessionSummary] {
        let sql = """
            SELECT ai_tool_session_id, MAX(ai_tool), MAX(working_directory),
                   MIN(timestamp), MAX(timestamp), COUNT(*)
            FROM events
            WHERE ai_tool_session_id IS NOT NULL
            GROUP BY ai_tool_session_id
            ORDER BY MAX(timestamp) DESC
            LIMIT ?1
            """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(max(1, min(limit, 1000))))
        var out: [AgentSessionSummary] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let sidC = sqlite3_column_text(stmt, 0) else { continue }
            let tool = sqlite3_column_text(stmt, 1).map { String(cString: $0) }
            let proj = sqlite3_column_text(stmt, 2).map { String(cString: $0) }
            out.append(AgentSessionSummary(
                sessionId: String(cString: sidC),
                tool: tool,
                projectDir: proj,
                firstSeen: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 3)),
                lastSeen: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4)),
                eventCount: Int(sqlite3_column_int64(stmt, 5))
            ))
        }
        return out
    }

    /// Keyset-paginated variant of `events(...)`. Returns at most
    /// `pageSize` events strictly older than `cursor` (or the newest page
    /// if `cursor == nil`), plus the cursor for the next page.
    ///
    /// Same use case as `AlertStore.alerts(before:)`: backs the "Load older"
    /// UI in the Events tab. Constant-time index seek regardless of page
    /// depth (no OFFSET scan), stable under inserts.
    public func events(
        before cursor: PaginationCursor?,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        pageSize: Int = 100
    ) throws -> PagedResults<Event> {
        let clamped = max(1, min(pageSize, 1000))

        var sql = "SELECT raw_json FROM events WHERE 1=1"
        var bindings: [(Int32, BindingValue)] = []
        var nextIndex: Int32 = 1

        if let cursor {
            sql += " AND (timestamp < ?\(nextIndex) OR (timestamp = ?\(nextIndex + 1) AND id < ?\(nextIndex + 2)))"
            bindings.append((nextIndex, .double(cursor.timestamp.timeIntervalSince1970)))
            bindings.append((nextIndex + 1, .double(cursor.timestamp.timeIntervalSince1970)))
            bindings.append((nextIndex + 2, .text(cursor.id)))
            nextIndex += 3
        }

        if let category {
            sql += " AND event_category = ?\(nextIndex)"
            bindings.append((nextIndex, .text(category.rawValue)))
            nextIndex += 1
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

        sql += " ORDER BY timestamp DESC, id DESC LIMIT ?\(nextIndex)"
        bindings.append((nextIndex, .int(Int32(clamped))))

        let rows = try queryEvents(sql: sql, bindings: bindings)

        let next: PaginationCursor?
        if rows.count == clamped, let last = rows.last {
            next = PaginationCursor(
                timestamp: last.timestamp,
                id: last.id.uuidString
            )
        } else {
            next = nil
        }
        return PagedResults(items: rows, nextCursor: next)
    }

    /// Performs a full-text search across indexed event fields.
    ///
    /// Uses the FTS5 virtual table to search process names, paths, command
    /// lines, file paths, network destinations, and TCC fields.
    ///
    /// - Parameters:
    ///   - text: The search query (FTS5 syntax supported).
    ///   - limit: Maximum number of results (default 100).
    /// - Returns: Matching events ordered by relevance.
    public func search(
        text: String,
        since: Date = .distantPast,
        until: Date = .distantFuture,
        limit: Int = 100
    ) throws -> [Event] {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }

        let escaped = trimmed.replacingOccurrences(of: "\"", with: "\"\"")
        let phraseQuery = "\"\(escaped)\""
        let sinceTs = since.timeIntervalSince1970
        let untilTs = until.timeIntervalSince1970

        // Strategy 1 — FTS5 MATCH with a quoted-phrase query, bounded
        // by [since, until]. Pre-fix `search` had neither bound; an
        // "Investigate in Events" navigation from an alert timestamped
        // 30 days ago surfaced any matching event ever.  Now: every
        // strategy applies the same `timestamp BETWEEN since AND until`
        // predicate, which lets callers narrow to a tight window
        // around an alert's firing time.
        let ftsSQL = """
            SELECT e.raw_json
            FROM events e
            JOIN events_fts fts ON e.rowid = fts.rowid
            WHERE events_fts MATCH ?1
              AND e.timestamp >= ?2
              AND e.timestamp <= ?3
            ORDER BY e.timestamp DESC
            LIMIT ?4
            """

        if let rows = try? queryEvents(sql: ftsSQL, bindings: [
            (1, .text(phraseQuery)),
            (2, .double(sinceTs)),
            (3, .double(untilTs)),
            (4, .int(Int32(limit)))
        ]), !rows.isEmpty {
            return rows
        }

        if !trimmed.contains(where: { !$0.isLetter && !$0.isNumber }) {
            if let rows = try? queryEvents(sql: ftsSQL, bindings: [
                (1, .text(trimmed)),
                (2, .double(sinceTs)),
                (3, .double(untilTs)),
                (4, .int(Int32(limit)))
            ]), !rows.isEmpty {
                return rows
            }
        }

        let likePattern = "%" + trimmed.replacingOccurrences(of: "%", with: "\\%")
                                       .replacingOccurrences(of: "_", with: "\\_") + "%"
        let likeSQL = """
            SELECT raw_json FROM events
            WHERE timestamp >= ?2 AND timestamp <= ?3
              AND (process_path LIKE ?1 ESCAPE '\\'
                OR process_name LIKE ?1 ESCAPE '\\'
                OR process_commandline LIKE ?1 ESCAPE '\\'
                OR file_path LIKE ?1 ESCAPE '\\'
                OR network_dest_ip LIKE ?1 ESCAPE '\\'
                OR tcc_service LIKE ?1 ESCAPE '\\'
                OR tcc_client LIKE ?1 ESCAPE '\\')
            ORDER BY timestamp DESC
            LIMIT ?4
            """
        return try queryEvents(sql: likeSQL, bindings: [
            (1, .text(likePattern)),
            (2, .double(sinceTs)),
            (3, .double(untilTs)),
            (4, .int(Int32(limit)))
        ])
    }

    /// Returns a single event by its identifier.
    ///
    /// - Parameter id: The event's unique UUID.
    /// - Returns: The event, or `nil` if not found.
    public func event(id: UUID) throws -> Event? {
        let sql = "SELECT raw_json FROM events WHERE id = ?1 LIMIT 1"
        let results = try queryEvents(sql: sql, bindings: [(1, .text(id.uuidString))])
        return results.first
    }

    /// Returns event counts grouped by `event_category`, restricted to
    /// rows newer than `since`. Used by the heartbeat writer to feed the
    /// rebuilt ES Health panel's per-event-type breakdown. Cheap because
    /// it walks the existing `idx_events_ts_category` composite index.
    public func eventCountsByCategory(since: Date) throws -> [String: Int] {
        let sql = "SELECT event_category, COUNT(*) FROM events WHERE timestamp >= ?1 GROUP BY event_category"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, since.timeIntervalSince1970)
        var out: [String: Int] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let cstr = sqlite3_column_text(stmt, 0) else { continue }
            let category = String(cString: cstr)
            let n = Int(sqlite3_column_int64(stmt, 1))
            if n > 0 { out[category] = n }
        }
        return out
    }

    /// v1.21.6 (PERF-04): retained wall-clock span per `event_category`, in
    /// seconds (MAX(timestamp) - MIN(timestamp) over the rows still on disk).
    ///
    /// Exists because the CONFIGURED hot tier and the DELIVERED one had diverged
    /// by three orders of magnitude with nothing surfacing it: on the field host
    /// `file` retained 0.5 minutes against a configured 30, while `process`
    /// retained 17.8 — the Layer-3 row-count fallback evicting the fodder
    /// categories to keep the footprint under cap. Any sequence rule, graph rule
    /// or hunt that needs file history beyond ~30 s was silently blind.
    ///
    /// Cheap: MIN/MAX + GROUP BY over the covering `idx_events_cat_sev_ts` /
    /// `idx_events_ts_category` indexes, called at the 30 s heartbeat cadence,
    /// never on the insert path.
    public func retainedSpanSecondsByCategory() throws -> [String: Int] {
        let sql = "SELECT event_category, MIN(timestamp), MAX(timestamp) FROM events GROUP BY event_category"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        var out: [String: Int] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let cstr = sqlite3_column_text(stmt, 0) else { continue }
            let category = String(cString: cstr)
            let span = sqlite3_column_double(stmt, 2) - sqlite3_column_double(stmt, 1)
            out[category] = Int(max(0, span))
        }
        return out
    }

    /// Returns the total number of events in the store.
    public func count() throws -> Int {
        let sql = "SELECT COUNT(*) FROM events"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_ROW else {
            throw EventStoreError.stepFailed("Failed to count events")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Pruning

    private struct AggregateRollupFailure: Error {
        let underlying: any Error
    }

    /// Keep aggregate accounting, FTS deletion, and source deletion in one
    /// transaction. If trend aggregation alone fails, roll the whole attempt
    /// back and retry an atomic FTS+source delete so disk-cap convergence still
    /// outranks best-effort trend data without double-counting on a later run.
    private func deleteEventBatchAtomically(
        aggregateSQL: String?,
        ftsSQL: String,
        eventsSQL: String,
        estimatedTransactionBytes: Int64,
        bind: (OpaquePointer) -> Void
    ) throws -> Int {
        func run(aggregate: String?) throws -> Int {
            try execute(
                "BEGIN IMMEDIATE TRANSACTION",
                maintenance: true,
                estimatedTransactionBytes: estimatedTransactionBytes
            )
            var committed = false
            do {
                if let aggregate {
                    do {
                        let statement = try prepare(aggregate)
                        bind(statement)
                        let rc = sqlite3_step(statement)
                        sqlite3_finalize(statement)
                        guard rc == SQLITE_DONE else {
                            try throwLatchedStoragePressureIfPresent(
                                resultCode: rc
                            )
                            throw EventStoreError.stepFailed(
                                "event aggregate step failed"
                            )
                        }
                    } catch {
                        throw AggregateRollupFailure(underlying: error)
                    }
                }

                let fts = try prepare(ftsSQL)
                bind(fts)
                let ftsRC = sqlite3_step(fts)
                sqlite3_finalize(fts)
                guard ftsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: ftsRC)
                    throw EventStoreError.stepFailed("event FTS delete failed")
                }

                let events = try prepare(eventsSQL)
                bind(events)
                let eventsRC = sqlite3_step(events)
                sqlite3_finalize(events)
                guard eventsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(
                        resultCode: eventsRC
                    )
                    throw EventStoreError.stepFailed("event delete failed")
                }
                let deleted = Int(sqlite3_changes(db))
                try execute("COMMIT")
                committed = true
                return deleted
            } catch {
                if !committed { try? execute("ROLLBACK") }
                throw error
            }
        }

        if aggregateSQL != nil {
            do {
                return try run(aggregate: aggregateSQL)
            } catch let failure as AggregateRollupFailure {
                Logger(subsystem: "com.maccrab.storage", category: "event-store")
                    .warning("Layer-3 roll-up failed and was rolled back; retrying the FTS+event delete atomically without trend data: \(failure.underlying.localizedDescription, privacy: .public)")
            }
        }
        return try run(aggregate: nil)
    }

    /// Deletes events older than the specified date for data retention.
    ///
    /// Deletes in batches of 100,000 rows and yields between batches so that
    /// concurrent event inserts are not blocked for extended periods. At high
    /// event volumes a single bulk delete can take hours; batching keeps each
    /// individual write lock short.
    ///
    /// Also removes corresponding FTS entries to keep the search index consistent.
    ///
    /// - Parameter date: Events with timestamps before this date will be deleted.
    /// - Parameters:
    ///   - protectedCategory: If supplied with `floorCutoff`, rows in this
    ///     category that are newer than `floorCutoff` are SPARED even though
    ///     they are older than `date` — the per-category retention floor. Lets
    ///     a tightened size-cap cutoff roll up the file firehose without
    ///     evicting the low-volume process/exec channel out from under its
    ///     floor. Nil (default) = category-blind, unchanged behavior.
    ///   - floorCutoff: The floor boundary for `protectedCategory` (see above).
    /// - Returns: The total number of events deleted across all batches.
    @discardableResult
    public func prune(
        olderThan date: Date,
        protecting protectedCategory: EventCategory? = nil,
        newerThan floorCutoff: Date? = nil,
        // v1.21.4 (audit): set true when the CALLER already holds an open write
        // transaction (rollUpAndPrune). Inside a transaction we must NOT suspend
        // (Task.yield) — the actor would reenter and a concurrent insert(events:)
        // would issue a nested BEGIN, which SQLite rejects, silently losing that
        // insert's whole batch. We also skip incremental_vacuum (illegal inside a
        // transaction); the caller vacuums after COMMIT.
        withinTransaction: Bool = false
    ) async throws -> Int {
        guard !withinTransaction else {
            throw EventStoreError.stepFailed(
                "prune within an unbounded caller transaction is disabled; use reserve-bounded batches"
            )
        }
        let batchSize = maintenanceBatchRowLimit(mutationsPerCandidate: 2)
        let batchEstimate = maintenanceEstimate(
            rowCount: Int(batchSize),
            mutationsPerCandidate: 2
        )
        let timestamp = date.timeIntervalSince1970
        var totalDeleted = 0

        // Base predicate: older than the retention cutoff. When a protected
        // category + floor are supplied, spare protected-category rows still
        // newer than the floor (bound to ?3/?4).
        let hasFloor = protectedCategory != nil && floorCutoff != nil
        let selector = hasFloor
            ? "timestamp < ?1 AND (event_category <> ?3 OR timestamp < ?4)"
            : "timestamp < ?1"

        // Batch: delete FTS entries for the next batch of stale events, then delete
        // the events themselves. Repeat until no rows remain older than `date`.
        //
        // Using a rowid IN (SELECT rowid … LIMIT N) subquery avoids the need for
        // the SQLITE_ENABLE_UPDATE_DELETE_LIMIT compile-time flag, which may not
        // be set in the system SQLite.
        let deleteFTS = """
            DELETE FROM events_fts WHERE rowid IN (
                SELECT rowid FROM events WHERE \(selector)
                ORDER BY rowid LIMIT ?2
            )
            """
        let deleteEvents = """
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events WHERE \(selector)
                ORDER BY rowid LIMIT ?2
            )
            """

        func bindSelector(_ stmt: OpaquePointer) {
            sqlite3_bind_double(stmt, 1, timestamp)
            sqlite3_bind_int(stmt, 2, batchSize)
            if let protectedCategory, let floorCutoff {
                bindText(stmt, index: 3, value: protectedCategory.rawValue)
                sqlite3_bind_double(stmt, 4, floorCutoff.timeIntervalSince1970)
            }
        }

        while true {
            let rowsDeleted = try deleteEventBatchAtomically(
                aggregateSQL: nil,
                ftsSQL: deleteFTS,
                eventsSQL: deleteEvents,
                estimatedTransactionBytes: batchEstimate,
                bind: bindSelector
            )
            totalDeleted += rowsDeleted

            // No more rows in this batch — pruning is complete.
            if rowsDeleted == 0 { break }

            // Yield to the actor's cooperative executor so concurrent inserts and
            // queries are not starved between batches — but NEVER while a caller
            // holds an open transaction (see withinTransaction: a suspension here
            // lets a reentrant insert issue a nested BEGIN and lose its batch).
            await Task.yield()
        }

        // v1.10.0 perf: incremental_vacuum reclaims pages freed by the
        // prune above. Without this, events.db file grows monotonically
        // even when the row count is bounded — heavy-event machines
        // that keep 30 days of data accumulate freelist pages until a
        // full VACUUM runs (rare). incremental_vacuum is non-blocking
        // and operates on the already-released pages from this prune.
        // Cap to 5K pages (~20 MB) per call so we don't stall the
        // actor on a freshly-pruned giant DB.
        // incremental_vacuum is illegal inside a transaction — skip it when the
        // caller holds one (rollUpAndPrune runs it after COMMIT instead).
        if totalDeleted > 0, let db {
            let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
                requestedPages: Int.max,
                reserveBytes: storageTransactionReserveBytes,
                pageSizeBytes: sqlitePageSizeBytes
            )
            guard plan.pages > 0 else { return totalDeleted }
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: plan.estimatedTransactionBytes
            )
            let rc = sqlite3_exec(
                db,
                "PRAGMA incremental_vacuum(\(plan.pages))",
                nil,
                nil,
                nil
            )
            if rc != SQLITE_OK {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
            }
        }

        return totalDeleted
    }

    /// Delete the oldest `count` events (by timestamp). Used by the
    /// size-cap enforcer when the DB file exceeds `maxDatabaseSizeMB`
    /// despite retention-based pruning — e.g. a 30-day retention on a
    /// heavy-event machine. Prunes events and their FTS rows together.
    ///
    /// Batching matches `prune(olderThan:)` so a single 1M-event
    /// prune doesn't hold the write lock too long.
    ///
    /// ## Per-category floor (v1.21.4)
    ///
    /// When `protectedCategory` + `floorCutoff` are supplied the eviction
    /// becomes **category-aware**: rows that are NOT the protected category
    /// (plus protected-category rows already older than `floorCutoff`) are
    /// evicted first, oldest-first. This spares the low-volume — but
    /// high-value — process/exec channel from a cheap file-write flood that
    /// would otherwise collapse the whole window and take exec rows with it.
    ///
    /// **Soft-floor safety valve.** If the eligible (non-protected/aged) rows
    /// are exhausted before `count` is met — i.e. the protected process rows
    /// within the floor ALONE are keeping the DB over cap — the loop falls
    /// back to unconditional oldest-first (even on protected rows) for the
    /// remaining count. Without the separate hard floor below, this guarantees
    /// `pruneOldest` removes `count` rows (or the whole table), no matter how
    /// large the protected category gets.
    ///
    /// `hardFloorCutoff` is different: when supplied, no category newer than
    /// that timestamp is eligible in either phase and the method may return
    /// fewer rows than requested. This is the store primitive used when the
    /// daemon must prefer honest storage shedding/degraded state over silently
    /// deleting the entire recent forensic/correlation window to make a
    /// configured byte target appear feasible.
    @discardableResult
    public func pruneOldest(
        count: Int,
        protecting protectedCategory: EventCategory? = nil,
        newerThan floorCutoff: Date? = nil,
        preservingAllNewerThan hardFloorCutoff: Date? = nil
    ) async throws -> Int {
        guard count > 0 else { return 0 }
        let batchSize: Int32 = min(
            maintenanceBatchRowLimit(mutationsPerCandidate: 3),
            Int32(clamping: count)
        )
        var remaining = count
        var totalDeleted = 0

        // Phase 1 — category-aware eviction. "Eligible" = any row NOT in the
        // protected category, OR a protected-category row already older than
        // the floor. Oldest-first within that eligible set. Protected rows
        // newer than the floor are spared here. Delete FTS first so the rowid
        // subquery sees a stable event set, then the events (same pattern as
        // prune(olderThan:)).
        if let protectedCategory, let floorCutoff {
            let floorTs = floorCutoff.timeIntervalSince1970
            // v1.21.6 (audit DL-04). The eligible set used to be "everything
            // that is not the protected category", which made the SCARCE,
            // high-signal channels the FIRST rows evicted while the protected
            // firehose was spared entirely. Layer 3 asks for at least 10,000
            // rows (DaemonTimers.runAdaptiveRollupSweep) and network/auth/tcc
            // together hold only a few hundred, so Phase 1 drained them to ZERO
            // on every sweep before the valve below touched a single protected
            // row — the exact inverse of forensic value. Field-observed: this
            // host's events.db held only `process` and `file` rows, with no
            // network, authentication or tcc rows on disk at all, so `hunt` and
            // `get_events` could not answer the outbound-connection / DNS /
            // permission-grant questions a responder asks first.
            //
            // Fix: INSIDE the floor window only the bulk channels are fodder;
            // network (which also carries DNS), authentication and tcc get the
            // same freshness guarantee the protected category already gets.
            // Anything ALREADY older than the floor stays fully eligible
            // regardless of category, so the cap still converges and the
            // soft-floor valve in Phase 2 is untouched.
            //
            // NOT the auditor's suggested inversion (protect network/dns/tcc,
            // evict process first): process/exec is the substrate for lineage,
            // sequence rules and campaign correlation, and the v1.21.4 floor
            // exists precisely because a file-write flood collapsing it was a
            // detection outage. Both channels are protected; only `file` and
            // `registry` are fodder inside the window.
            //
            // Kept as ONE interpolated predicate so the FTS delete, the events
            // delete, and the Layer-3 roll-up can never drift apart. Shape is
            // unchanged (leading `timestamp` term, no expression in ORDER BY),
            // so idx_events_ts_category still drives an ordered top-N scan
            // rather than a full sort of the eligible set.
            let hardFloorPredicate = hardFloorCutoff == nil
                ? ""
                : " AND timestamp < ?4"
            let eligibleWhere = """
                (timestamp < ?2
                   OR (event_category <> ?1
                       AND event_category NOT IN ('network', 'authentication', 'tcc')))
                \(hardFloorPredicate)
                """
            let deleteEligibleFTS = """
                DELETE FROM events_fts WHERE rowid IN (
                    SELECT rowid FROM events
                    WHERE \(eligibleWhere)
                    ORDER BY timestamp ASC LIMIT ?3
                )
                """
            let deleteEligibleEvents = """
                DELETE FROM events WHERE rowid IN (
                    SELECT rowid FROM events
                    WHERE \(eligibleWhere)
                    ORDER BY timestamp ASC LIMIT ?3
                )
                """
            // v1.21.6 (audit DL-05): roll each batch up BEFORE deleting it.
            // Layer 3 does nearly all the pruning on a busy host (field log,
            // one sweep: Layer 2 = 140 rows, Layer 3 = 42,595 rows) and it used
            // to issue DELETEs with no INSERT at all — only rollUpAndPrune
            // aggregated. So the advertised `aggregateDays: 90` day-history
            // silently lost whole days: 500K-1M events/day through mid-July,
            // then 255,154 on 7/22, 11,798 on 7/25, 658 on 7/26, NOTHING on
            // 7/27, 156 on 7/28. Nothing warned — event_aggregates still
            // existed and still answered queries, so the dashboard's long-
            // horizon trend simply drew a flat line that looked like calm.
            //
            // Same upsert as rollUpAndPrune and the SAME `eligibleWhere`
            // predicate + LIMIT as the DELETEs below, so the rows counted are
            // exactly the rows removed.
            let aggregateEligible = """
                INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
                SELECT
                    strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                    event_category,
                    COALESCE(process_signer, ''),
                    COALESCE(process_path, ''),
                    COUNT(*) AS c
                FROM events WHERE rowid IN (
                    SELECT rowid FROM events
                    WHERE \(eligibleWhere)
                    ORDER BY timestamp ASC LIMIT ?3
                )
                GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
                ON CONFLICT(day, event_category, process_signer, process_path)
                DO UPDATE SET count = count + excluded.count
            """
            while remaining > 0 {
                let thisBatch = min(batchSize, Int32(clamping: remaining))
                let estimate = maintenanceEstimate(
                    rowCount: Int(thisBatch),
                    mutationsPerCandidate: 3
                )
                let deleted = try deleteEventBatchAtomically(
                    aggregateSQL: aggregateEligible,
                    ftsSQL: deleteEligibleFTS,
                    eventsSQL: deleteEligibleEvents,
                    estimatedTransactionBytes: estimate
                ) { statement in
                    bindText(
                        statement,
                        index: 1,
                        value: protectedCategory.rawValue
                    )
                    sqlite3_bind_double(statement, 2, floorTs)
                    sqlite3_bind_int(statement, 3, thisBatch)
                    if let hardFloorCutoff {
                        sqlite3_bind_double(
                            statement, 4,
                            hardFloorCutoff.timeIntervalSince1970
                        )
                    }
                }
                if deleted == 0 { break }  // no more eligible rows — engage valve below
                totalDeleted += deleted
                remaining -= deleted
                await Task.yield()
            }
            // Soft-floor valve: fall through to the plain oldest-first loop
            // below with the (possibly reduced) `remaining`, which can now
            // touch protected rows. When the floor was fully honored above,
            // `remaining == 0` and the loop is a no-op.
        }

        // Phase 2 — plain oldest-first. The whole job when no floor is
        // configured; the safety-valve tail otherwise.
        let hardFloorWhere = hardFloorCutoff == nil
            ? ""
            : " WHERE timestamp < ?2"
        let deleteFTS = """
            DELETE FROM events_fts WHERE rowid IN (
                SELECT rowid FROM events\(hardFloorWhere)
                ORDER BY timestamp ASC LIMIT ?1
            )
            """
        let deleteEvents = """
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events\(hardFloorWhere)
                ORDER BY timestamp ASC LIMIT ?1
            )
            """
        // v1.21.6 (audit DL-05): same roll-up-before-delete as Phase 1. This
        // loop is BOTH the whole job when no floor is configured AND the
        // soft-floor valve tail, so leaving it un-aggregated would keep losing
        // history on exactly the hosts where the valve engages most.
        let aggregateOldest = """
            INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
            SELECT
                strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                event_category,
                COALESCE(process_signer, ''),
                COALESCE(process_path, ''),
                COUNT(*) AS c
            FROM events WHERE rowid IN (
                SELECT rowid FROM events\(hardFloorWhere)
                ORDER BY timestamp ASC LIMIT ?1
            )
            GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
            ON CONFLICT(day, event_category, process_signer, process_path)
            DO UPDATE SET count = count + excluded.count
            """

        while remaining > 0 {
            let thisBatch = min(batchSize, Int32(clamping: remaining))
            let estimate = maintenanceEstimate(
                rowCount: Int(thisBatch),
                mutationsPerCandidate: 3
            )
            let deleted = try deleteEventBatchAtomically(
                aggregateSQL: aggregateOldest,
                ftsSQL: deleteFTS,
                eventsSQL: deleteEvents,
                estimatedTransactionBytes: estimate
            ) { statement in
                sqlite3_bind_int(statement, 1, thisBatch)
                if let hardFloorCutoff {
                    sqlite3_bind_double(
                        statement, 2,
                        hardFloorCutoff.timeIntervalSince1970
                    )
                }
            }
            if deleted == 0 { break }  // table empty
            totalDeleted += deleted
            remaining -= deleted
            await Task.yield()
        }
        return totalDeleted
    }

    // MARK: - Tiered retention (v1.8.0)

    /// One row of the `event_aggregates` rollup table. Replaces the full event
    /// payload for traffic older than the 24h hot tier — keeps just the
    /// information needed for trend charts and "show me events from path X
    /// over the last week" summaries.
    public struct AggregateRow: Sendable, Codable, Equatable {
        public let day: String              // ISO date "2026-04-15"
        public let category: EventCategory
        public let processSigner: String    // empty string if unsigned/unknown
        public let processPath: String      // empty string for non-process events
        public let count: Int
    }

    /// Read aggregated event counts for any window, optionally narrowed to a
    /// category. Used by the Overview trends widget and the SIEM-style time
    /// histogram in v1.8 — both want "how many process exec / file / network
    /// events per day in the last 7d?" without paying the cost of scanning
    /// the hot tier.
    public func aggregates(
        sinceDay: String,
        category: EventCategory? = nil
    ) throws -> [AggregateRow] {
        var sql = "SELECT day, event_category, process_signer, process_path, count FROM event_aggregates WHERE day >= ?1"
        var bindings: [(Int32, BindingValue)] = [(1, .text(sinceDay))]
        var nextIndex: Int32 = 2
        if let category {
            sql += " AND event_category = ?\(nextIndex)"
            bindings.append((nextIndex, .text(category.rawValue)))
            nextIndex += 1
        }
        sql += " ORDER BY day DESC, count DESC"

        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        for (idx, val) in bindings {
            switch val {
            case .text(let s): bindText(stmt, index: idx, value: s)
            case .double(let d): sqlite3_bind_double(stmt, idx, d)
            case .int(let i): sqlite3_bind_int(stmt, idx, i)
            case .null: sqlite3_bind_null(stmt, idx)
            }
        }
        // Inline the column→String reader. EventStore doesn't have a
        // shared helper like AlertStore's `columnTextOrNil`; sqlite3
        // returns nil if the column is NULL.
        func readText(_ s: OpaquePointer, _ idx: Int32) -> String? {
            guard let cstr = sqlite3_column_text(s, idx) else { return nil }
            return String(cString: cstr)
        }
        var rows: [AggregateRow] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let dayStr = readText(stmt, 0),
                  let catStr = readText(stmt, 1),
                  let cat = EventCategory(rawValue: catStr)
            else { continue }
            let signer = readText(stmt, 2) ?? ""
            let path = readText(stmt, 3) ?? ""
            let count = Int(sqlite3_column_int64(stmt, 4))
            rows.append(AggregateRow(
                day: dayStr, category: cat,
                processSigner: signer, processPath: path,
                count: count
            ))
        }
        return rows
    }

    /// Number of aggregate rows. Cheap; used by tests + the Overview widget
    /// to decide whether to render an empty state.
    public func aggregateCount() throws -> Int {
        let stmt = try prepare("SELECT COUNT(*) FROM event_aggregates")
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// v1.8.0: SQL-side histogram bin counts.
    ///
    /// Pre-fix, the dashboard's Events-tab histogram was built from the
    /// 500-row in-memory event cache. On a high-volume machine (264
    /// events/sec measured) those 500 events span ~2 seconds, so every
    /// bin collapsed into one regardless of window size — the chart was
    /// effectively broken since Phase 2c shipped.
    ///
    /// This query bins counts directly on the SQL side: GROUP BY a
    /// truncated-to-bucket-step timestamp expression. Indexed on the
    /// `timestamp` column so even a 24h window over 1.2 GB events.db
    /// scans only the relevant range.
    ///
    /// Returns one (bucketDate, count) per occupied bin, sorted ascending
    /// by time. Caller is expected to backfill 0-count bins for empty
    /// portions of the window.
    public func histogramBins(
        spanSeconds: TimeInterval,
        stepSeconds: Int,
        endingAt: Date = Date(),
        category: EventCategory? = nil
    ) throws -> [(Date, Int)] {
        guard stepSeconds > 0, spanSeconds > 0 else { return [] }
        let lo = endingAt.timeIntervalSince1970 - spanSeconds
        let hi = endingAt.timeIntervalSince1970

        // CAST(timestamp/step AS INTEGER) * step floors the timestamp to
        // the nearest bucket boundary. SQLite handles REAL math natively.
        var sql = """
            SELECT CAST(timestamp / ?1 AS INTEGER) * ?1 AS bucket, COUNT(*) AS c
            FROM events
            WHERE timestamp BETWEEN ?2 AND ?3
            """
        if category != nil {
            sql += " AND event_category = ?4"
        }
        sql += " GROUP BY bucket ORDER BY bucket ASC"

        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, Double(stepSeconds))
        sqlite3_bind_double(stmt, 2, lo)
        sqlite3_bind_double(stmt, 3, hi)
        if let cat = category {
            bindText(stmt, index: 4, value: cat.rawValue)
        }

        var results: [(Date, Int)] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let bucket = sqlite3_column_double(stmt, 0)
            let count = Int(sqlite3_column_int64(stmt, 1))
            results.append((Date(timeIntervalSince1970: bucket), count))
        }
        return results
    }

    /// Select a bounded, deterministic set of already-persisted events leading
    /// up to an alert. This is a read-only source operation: new evidence is
    /// owned and written by AlertStore in alerts.db.
    ///
    /// The inner ordering chooses the strongest/closest candidates; the outer
    /// ordering returns the selected set chronologically for incident review.
    /// Both caller-controlled bounds are clamped to the fixed policy ceiling.
    /// Oversized or malformed legacy payloads are omitted rather than copied
    /// into the new evidence tier.
    public func alertEvidenceCandidates(
        alertTimestamp: Date,
        windowSeconds: TimeInterval = AlertEvidencePolicy.lookbackSeconds,
        maxRows: Int = AlertEvidencePolicy.maximumEventsPerAlert
    ) throws -> [AlertEvidenceCandidate] {
        let requestedRows = min(
            AlertEvidencePolicy.maximumEventsPerAlert,
            max(0, maxRows)
        )
        guard requestedRows > 0 else { return [] }
        let boundedWindow = min(
            AlertEvidencePolicy.lookbackSeconds,
            max(0, windowSeconds)
        )
        let alertTs = alertTimestamp.timeIntervalSince1970
        let lowerTs = alertTs - boundedWindow
        let sql = """
            SELECT id, timestamp, raw_json
            FROM (
                SELECT id, timestamp, raw_json
                FROM events
                WHERE timestamp BETWEEN ?1 AND ?2
                  AND LENGTH(CAST(raw_json AS BLOB)) <= ?3
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    ABS(timestamp - ?2) ASC,
                    timestamp DESC,
                    id ASC
                LIMIT ?4
            ) selected
            ORDER BY timestamp ASC, id ASC
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, lowerTs)
        sqlite3_bind_double(statement, 2, alertTs)
        sqlite3_bind_int(
            statement, 3,
            Int32(clamping: AlertEvidencePolicy.maximumRawPayloadBytes)
        )
        sqlite3_bind_int(statement, 4, Int32(clamping: requestedRows))

        var candidates: [AlertEvidenceCandidate] = []
        while true {
            let step = sqlite3_step(statement)
            if step == SQLITE_DONE { break }
            guard step == SQLITE_ROW else {
                try throwLatchedStoragePressureIfPresent(resultCode: step)
                throw EventStoreError.stepFailed(
                    "alert evidence candidate selection failed"
                )
            }
            guard let idBytes = sqlite3_column_text(statement, 0),
                  let rawBytes = sqlite3_column_text(statement, 2) else {
                continue
            }
            let rawCount = Int(sqlite3_column_bytes(statement, 2))
            guard rawCount > 0,
                  rawCount <= AlertEvidencePolicy.maximumRawPayloadBytes else {
                continue
            }
            candidates.append(AlertEvidenceCandidate(
                eventId: String(cString: idBytes),
                timestamp: Date(
                    timeIntervalSince1970: sqlite3_column_double(statement, 1)
                ),
                rawJSON: String(cString: rawBytes)
            ))
        }
        return candidates
    }

    /// LEGACY COMPATIBILITY WRITE ONLY. New production alert capture must use
    /// `alertEvidenceCandidates` followed by `AlertStore.captureEvidence`.
    /// Existing events.db evidence remains readable and receives retention /
    /// explicit-delete cleanup, but no shipping call site may grow this table.
    ///
    /// Capture a snapshot of the `windowSeconds` of events immediately
    /// PRECEDING the alert into legacy `events.db.alert_evidence`. Idempotent —
    /// re-running for the same `alertId` is safe (PRIMARY KEY on
    /// (alert_id, id) silently dedupes).
    ///
    /// Called synchronously from the alert-firing path so the dashboard's alert
    /// detail view can show "what led up to this?" even after the hot-tier
    /// retention drops the surrounding events.
    ///
    /// BACKWARD-looking by construction (audit corr-storage): because capture
    /// runs at fire time, only events already persisted at/before the alert
    /// timestamp exist, so the window is `[alertTimestamp - windowSeconds,
    /// alertTimestamp]`. There is no forward half to populate — the prior
    /// "±windowSeconds" framing described a range that is always empty at
    /// capture time. (A caller wanting post-alert context would have to
    /// schedule a deferred second capture; none does today.)
    ///
    /// v1.8.0-rc6: capped at `maxRows` (default 50) to keep the evidence table
    /// bounded on high-volume hosts. Pre-cap, a 264 events/sec machine could
    /// drop ~30K rows per alert into evidence, and 1.6K alerts pushed the
    /// table past 800K rows / 2.4 GB on the field test host. Selection prefers
    /// higher-severity rows so the cap doesn't drop the most informative
    /// context — same-severity rows tie-break by closeness to the alert
    /// timestamp.
    @available(*, deprecated, message: "Legacy test/compatibility write; new capture belongs to AlertStore")
    func recordAlertEvidence(
        alertId: String,
        alertTimestamp: Date,
        windowSeconds: TimeInterval = 30,
        maxRows: Int = 50
    ) throws {
        let requestedRows = max(1, maxRows)
        let alertTs = alertTimestamp.timeIntervalSince1970
        let lo = alertTs - windowSeconds
        // Backward-only: the upper bound is the alert timestamp itself. A
        // forward bound (alertTs + windowSeconds) never matched anything —
        // those events do not exist yet when this runs at fire time — so it is
        // dropped to make the contract honest and the SQL intent explicit.
        let hi = alertTs
        let sql = """
            INSERT OR IGNORE INTO alert_evidence (
                alert_id, id, timestamp,
                event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json,
                mcp_server_name, mcp_server_category, ai_tool_session_id
            )
            SELECT
                ?1, id, timestamp,
                event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json,
                mcp_server_name, mcp_server_category, ai_tool_session_id
            FROM events
            WHERE timestamp BETWEEN ?2 AND ?3
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                ABS(timestamp - ?4) ASC
            LIMIT ?5 OFFSET ?6
            """
        var offset = 0
        while offset < requestedRows {
            let plan = try alertEvidenceBatchPlan(
                alertId: alertId,
                lowerTimestamp: lo,
                upperTimestamp: hi,
                alertTimestamp: alertTs,
                offset: offset,
                maximumRows: requestedRows - offset
            )
            guard plan.rowCount > 0 else { break }
            let thisBatch = plan.rowCount
            try admitStorageWrite(
                estimatedTransactionBytes: plan.estimatedTransactionBytes
            )
            let stmt = try prepare(sql)
            bindText(stmt, index: 1, value: alertId)
            sqlite3_bind_double(stmt, 2, lo)
            sqlite3_bind_double(stmt, 3, hi)
            sqlite3_bind_double(stmt, 4, alertTs)
            sqlite3_bind_int(stmt, 5, Int32(clamping: thisBatch))
            sqlite3_bind_int(stmt, 6, Int32(clamping: offset))
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
                throw EventStoreError.stepFailed("recordAlertEvidence failed: \(msg)")
            }
            maintenanceRowMutationHighWaterBytes = max(
                maintenanceRowMutationHighWaterBytes ?? 0,
                plan.maximumRowMutationBytes
            )
            offset += thisBatch
        }
    }

    /// Read the exact source rows selected by the following INSERT...SELECT and
    /// choose the largest prefix that fits the reserve. This closes the old
    /// 64-KiB non-raw assumption: legacy/adversarial projected columns are
    /// charged at their actual stored byte lengths before any evidence write.
    private func alertEvidenceBatchPlan(
        alertId: String,
        lowerTimestamp: Double,
        upperTimestamp: Double,
        alertTimestamp: Double,
        offset: Int,
        maximumRows: Int
    ) throws -> (
        rowCount: Int,
        estimatedTransactionBytes: Int64,
        maximumRowMutationBytes: Int64
    ) {
        let sql = """
            SELECT id, timestamp, event_category, event_type, event_action,
                   severity, process_pid, process_name, process_path,
                   process_commandline, process_ppid, process_signer,
                   process_team_id, process_signing_id, file_path, file_action,
                   network_dest_ip, network_dest_port, tcc_service, tcc_client,
                   raw_json, mcp_server_name, mcp_server_category,
                   ai_tool_session_id
            FROM events
            WHERE timestamp BETWEEN ?1 AND ?2
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
                END,
                ABS(timestamp - ?3) ASC
            LIMIT ?4 OFFSET ?5
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, lowerTimestamp)
        sqlite3_bind_double(statement, 2, upperTimestamp)
        sqlite3_bind_double(statement, 3, alertTimestamp)
        sqlite3_bind_int(statement, 4, Int32(clamping: max(0, maximumRows)))
        sqlite3_bind_int(statement, 5, Int32(clamping: max(0, offset)))

        let fixed = SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 16
        )
        var rowBytes: Int64 = 0
        var maximumRowMutationBytes: Int64 = 0
        var count = 0
        var step = sqlite3_step(statement)
        while step == SQLITE_ROW {
            func bytes(_ column: Int32) -> Int64 {
                sqlite3_column_type(statement, column) == SQLITE_NULL
                    ? 0 : Int64(sqlite3_column_bytes(statement, column))
            }
            var logical = Int64(25 * 16 + 3 * 16)
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    Int64(clamping: alertId.utf8.count), by: 3
                )
            )
            for column in Int32(0)..<Int32(24) {
                logical = SQLitePersistentStoreAdmission.saturatingAdd(
                    logical, bytes(column)
                )
            }
            // id is copied into the composite PK and event-id index.
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    bytes(0), by: 2
                )
            )
            let candidate = SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: logical,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumLeafPageTouches: 4
                )
            let nextRows = SQLitePersistentStoreAdmission.saturatingAdd(
                rowBytes, candidate
            )
            let nextTransaction = SQLitePersistentStoreAdmission.saturatingAdd(
                fixed, nextRows
            )
            if nextTransaction > storageTransactionReserveBytes {
                if count == 0 {
                    throw SQLitePersistentStoreAdmissionError
                        .transactionEstimateExceedsReserve(
                            estimatedBytes: nextTransaction,
                            reserveBytes: storageTransactionReserveBytes
                        )
                }
                break
            }
            rowBytes = nextRows
            maximumRowMutationBytes = max(maximumRowMutationBytes, candidate)
            count += 1
            step = sqlite3_step(statement)
        }
        if step != SQLITE_DONE && step != SQLITE_ROW {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw EventStoreError.stepFailed("alert evidence estimate step failed")
        }
        return (
            count,
            SQLitePersistentStoreAdmission.saturatingAdd(fixed, rowBytes),
            maximumRowMutationBytes
        )
    }

    /// v1.8.0-rc6: trim alert_evidence to at most `perAlertMax` rows per
    /// alert. Selection prefers higher-severity + closer-to-alert rows.
    /// Used by the rollup sweep to bound an existing oversize evidence
    /// table — recordAlertEvidence above caps writes going forward, but
    /// existing rows from earlier releases need cleanup.
    @discardableResult
    public func pruneAlertEvidenceCap(perAlertMax: Int) async throws -> Int {
        guard perAlertMax > 0 else { return 0 }
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        // Window function (SQLite 3.25+) ranks rows within each alert; we
        // delete those that fall outside the cap. macOS 13 ships SQLite
        // 3.39+, so this is safe.
        let sql = """
            DELETE FROM alert_evidence
            WHERE rowid IN (
                SELECT rowid FROM (
                    SELECT rowid,
                           ROW_NUMBER() OVER (
                               PARTITION BY alert_id
                               ORDER BY
                                   CASE severity
                                       WHEN 'critical' THEN 0
                                       WHEN 'high' THEN 1
                                       WHEN 'medium' THEN 2
                                       WHEN 'low' THEN 3
                                       ELSE 4
                                   END,
                                   timestamp ASC
                           ) AS rn
                    FROM alert_evidence
                )
                WHERE rn > ?1
                LIMIT ?2
            )
            """
        var total = 0
        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            let stmt = try prepare(sql)
            sqlite3_bind_int(stmt, 1, Int32(clamping: perAlertMax))
            sqlite3_bind_int(stmt, 2, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
                throw EventStoreError.stepFailed("pruneAlertEvidenceCap failed: \(msg)")
            }
            let deleted = Int(sqlite3_changes(db))
            total += deleted
            if deleted == 0 { break }
            await Task.yield()
        }
        return total
    }

    /// v1.8.0-rc6: drop alert_evidence rows older than `cutoff`. Aligns
    /// evidence retention with the parent alerts.db retention, so an
    /// orphaned evidence row whose alert was already pruned doesn't
    /// outlive the alert.
    @discardableResult
    public func pruneAlertEvidence(olderThan cutoff: Date) async throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            DELETE FROM alert_evidence WHERE rowid IN (
                SELECT rowid FROM alert_evidence
                WHERE timestamp < ?1 ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            let stmt = try prepare(sql)
            sqlite3_bind_double(stmt, 1, cutoff.timeIntervalSince1970)
            sqlite3_bind_int(stmt, 2, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
                throw EventStoreError.stepFailed("pruneAlertEvidence failed: \(msg)")
            }
            let deleted = Int(sqlite3_changes(db))
            total += deleted
            if deleted == 0 { break }
            await Task.yield()
        }
        return total
    }

    /// v1.17.5 (RC H2): bound the alert_evidence table by TOTAL payload size.
    /// Age + per-alert-cap pruning leave total size ungoverned, so on a busy
    /// host the table outgrew the events cap (field-observed 194 MB inside the
    /// 365-day window). Evicts the OLDEST rows across all alerts until the
    /// raw_json payload total is <= maxBytes. Returns rows deleted.
    @discardableResult
    public func pruneAlertEvidenceBySize(maxBytes: Int64, batchSize: Int = 2000) async throws -> Int {
        guard maxBytes > 0 else { return 0 }
        let batch = min(
            max(1, batchSize),
            Int(maintenanceBatchRowLimit())
        )
        let estimate = maintenanceEstimate(rowCount: batch)
        // `maxBytes` is a PHYSICAL footprint budget. The raw_json text is only
        // part of each row's on-disk cost (25 columns + 3 indexes), so the prior
        // SUM(LENGTH(raw_json)) cap let the physical table grow ~1.7x past the
        // budget — which kept events.db permanently over its size cap and
        // re-triggered the hourly full VACUUM on every maintenance tick (v1.18
        // audit). Bound the physical footprint instead. DELETE doesn't reclaim
        // pages until VACUUM (so dbstat can't drive the delete loop), so we derive
        // the physical/logical multiplier from dbstat once, scale the raw_json
        // budget by it, and loop on raw_json (which shrinks per delete). The
        // post-sweep VACUUM in the maintenance path reclaims the freed pages.
        func rawJsonBytes() throws -> Int64 {
            let stmt = try prepare("SELECT COALESCE(SUM(LENGTH(raw_json)), 0) FROM alert_evidence")
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
            return sqlite3_column_int64(stmt, 0)
        }
        // Physical page bytes of the table + its indexes via DBSTAT_VTAB. nil if
        // dbstat isn't compiled into this SQLite build (→ conservative fallback).
        func physicalBytes() -> Int64? {
            let sql = """
                SELECT COALESCE(SUM(pgsize), 0) FROM dbstat
                WHERE name = 'alert_evidence'
                   OR name IN (SELECT name FROM sqlite_master
                               WHERE type = 'index' AND tbl_name = 'alert_evidence')
                """
            guard let stmt = try? prepare(sql) else { return nil }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
            let bytes = sqlite3_column_int64(stmt, 0)
            return bytes > 0 ? bytes : nil
        }
        let logical = try rawJsonBytes()
        guard logical > 0 else { return 0 }
        // Scale the raw_json budget by the physical/logical ratio — but only when
        // the table is large enough that b-tree + index overhead is real signal,
        // not sub-page rounding on a tiny table (which would over-prune). dbstat
        // absent → a conservative fixed estimate so production still bounds size.
        let multiplier: Double
        switch physicalBytes() {
        case .some(let phys) where phys > 1_048_576:
            multiplier = max(1.0, Double(phys) / Double(logical))   // large table: measured ratio
        case .some:
            multiplier = 1.0                                        // small table: raw_json ≈ footprint
        case .none:
            multiplier = 1.8                                        // dbstat unavailable: conservative
        }
        let rawJsonBudget = Int64(Double(maxBytes) / multiplier)
        var total = logical
        guard total > rawJsonBudget else { return 0 }
        var deleted = 0
        // Delete oldest rows in batches until under the (scaled) budget. Bounded
        // to 4096 iterations so a pathological table can't wedge the sweep.
        for _ in 0..<4096 {
            if total <= rawJsonBudget { break }
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            let stmt = try prepare(
                "DELETE FROM alert_evidence WHERE rowid IN (SELECT rowid FROM alert_evidence ORDER BY timestamp ASC LIMIT \(batch))")
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
                throw EventStoreError.stepFailed("pruneAlertEvidenceBySize failed: \(msg)")
            }
            let n = Int(sqlite3_changes(db))
            deleted += n
            if n == 0 { break }
            total = try rawJsonBytes()
        }
        return deleted
    }

    /// Exact ownership of the preserved pre-schema-v8 evidence tier.
    ///
    /// New evidence is never written here, but an upgrade may retain up to a
    /// year of existing rows. Daemon storage admission uses this cold-path
    /// measurement to grant only the transition reserve those rows need. The
    /// DBSTAT query deliberately throws when page ownership cannot be proven;
    /// callers then retain the full configured reserve rather than stranding a
    /// live events database below an unknowable floor.
    public func legacyAlertEvidenceBudgetSnapshot(
        maxBytes: Int64
    ) throws -> AlertEvidenceBudgetSnapshot {
        let exists = try prepare(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_evidence' LIMIT 1"
        )
        defer { sqlite3_finalize(exists) }
        let existenceStep = sqlite3_step(exists)
        if existenceStep == SQLITE_DONE {
            return AlertEvidenceBudgetSnapshot(
                rowCount: 0,
                logicalBytes: 0,
                allocatedBytes: 0,
                chargedBytes: 0,
                maxBytes: max(0, maxBytes)
            )
        }
        guard existenceStep == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "legacy alert evidence schema lookup failed"
            )
        }

        let logical = try prepare(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(raw_json AS BLOB))), 0) FROM alert_evidence"
        )
        defer { sqlite3_finalize(logical) }
        guard sqlite3_step(logical) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "legacy alert evidence logical-size query failed"
            )
        }
        let rowCount = Int(sqlite3_column_int64(logical, 0))
        let logicalBytes = max(0, sqlite3_column_int64(logical, 1))
        guard rowCount > 0 else {
            return AlertEvidenceBudgetSnapshot(
                rowCount: 0,
                logicalBytes: 0,
                allocatedBytes: 0,
                chargedBytes: 0,
                maxBytes: max(0, maxBytes)
            )
        }

        let allocated = try prepare(
            """
            SELECT COALESCE(SUM(pgsize), 0) FROM dbstat
            WHERE name = 'alert_evidence'
               OR name IN (
                   SELECT name FROM sqlite_master
                   WHERE type = 'index' AND tbl_name = 'alert_evidence'
               )
            """
        )
        defer { sqlite3_finalize(allocated) }
        guard sqlite3_step(allocated) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "legacy alert evidence DBSTAT ownership query failed"
            )
        }
        let allocatedBytes = max(0, sqlite3_column_int64(allocated, 0))
        return AlertEvidenceBudgetSnapshot(
            rowCount: rowCount,
            logicalBytes: logicalBytes,
            allocatedBytes: allocatedBytes,
            chargedBytes: max(logicalBytes, allocatedBytes),
            maxBytes: max(0, maxBytes)
        )
    }

    /// Authoritative cold-path proof for a legacy-evidence reserve change.
    ///
    /// The evidence table's DBSTAT ownership determines the *candidate*
    /// reserve, but never proves that events.db can actually adopt the lower
    /// hard ceiling. Before publishing a shrink, callers also need a fresh
    /// family footprint after a fully drained checkpoint. A pinned reader is
    /// reported through `walCheckpointDrained == false`; freelist pages remain
    /// charged in both `pageCount` and the physical family measurement until
    /// maintenance has really reclaimed them.
    public func legacyAlertEvidenceTransitionMeasurement(
        maxBytes: Int64
    ) throws -> LegacyAlertEvidenceTransitionMeasurement {
        guard db != nil else {
            throw EventStoreError.stepFailed(
                "legacy alert-evidence transition probe requires an open database"
            )
        }

        // Checkpoint first, then stat the complete family. The checkpoint is
        // deliberately non-destructive: failure/pinning leaves the previous
        // reserve applied and exposes a pending candidate to the operator.
        let checkpointDrained = walCheckpoint()
        let evidence = try legacyAlertEvidenceBudgetSnapshot(maxBytes: maxBytes)
        let family = try SQLitePersistentStoreAdmission.measureFamily(
            databasePath
        )
        let pageSize = try strictPragmaInt64("PRAGMA page_size")
        let pageCount = try strictPragmaInt64("PRAGMA page_count")
        let freelistCount = try strictPragmaInt64("PRAGMA freelist_count")
        guard pageSize > 0, pageCount >= 0, freelistCount >= 0,
              freelistCount <= pageCount else {
            throw EventStoreError.stepFailed(
                "legacy alert-evidence transition page accounting is invalid"
            )
        }
        return LegacyAlertEvidenceTransitionMeasurement(
            evidence: evidence,
            familyFootprintBytes: family,
            walCheckpointDrained: checkpointDrained,
            pageSizeBytes: pageSize,
            pageCount: pageCount,
            freelistCount: freelistCount
        )
    }

    private func strictPragmaInt64(_ sql: String) throws -> Int64 {
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "SQLite transition accounting pragma failed"
            )
        }
        return sqlite3_column_int64(statement, 0)
    }

    /// Read events captured for `alertId` by `recordAlertEvidence`. Returns
    /// the ~windowSeconds of preceding activity that the alert detail view
    /// renders. Empty if the alert pre-dates v1.8 evidence capture.
    public func evidenceFor(alertId: String) throws -> [Event] {
        let sql = "SELECT raw_json FROM alert_evidence WHERE alert_id = ?1 ORDER BY timestamp ASC"
        return try queryEvents(sql: sql, bindings: [(1, .text(alertId))])
    }

    /// Delete all `alert_evidence` rows copied for `alertId`. Returns the row
    /// count removed.
    ///
    /// Companion to `AlertStore.delete(alertId:)` (audit corr-storage):
    /// `recordAlertEvidence` copies the surrounding events into events.db's
    /// `alert_evidence`, but deleting the alert row only touches alerts.db —
    /// the evidence copy (which can hold the very PII the operator is trying to
    /// wipe) survives until the retention sweep. The caller that owns BOTH
    /// stores (the delete-alert path) must invoke this alongside
    /// `AlertStore.delete` so the wipe is complete. Idempotent — a no-match is
    /// a successful 0.
    @discardableResult
    public func deleteEvidence(alertId: String) throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            DELETE FROM alert_evidence WHERE rowid IN (
                SELECT rowid FROM alert_evidence
                WHERE alert_id = ?1 ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            let stmt = try prepare(sql)
            bindText(stmt, index: 1, value: alertId)
            sqlite3_bind_int(stmt, 2, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
                throw EventStoreError.stepFailed("deleteEvidence failed: \(msg)")
            }
            let deleted = Int(sqlite3_changes(db))
            total += deleted
            if deleted == 0 { break }
        }
        return total
    }

    /// The 24h roll-up sweep that replaces the legacy size-cap-and-VACUUM
    /// dance. Runs from the daemon's 6h timer.
    ///
    /// Three steps in a single SQL transaction so a crash mid-sweep can
    /// either retry cleanly or finish on next tick:
    ///
    ///   1. Update `event_aggregates` with daily counts grouped by
    ///      (day, category, signer, path) for events older than `cutoff`.
    ///      `INSERT … ON CONFLICT DO UPDATE` makes re-runs idempotent.
    ///   2. (alert evidence is captured eagerly at alert-firing time, not
    ///      here — this method assumes evidence is already in place. It
    ///      would be wasted work to scan the whole hot tier here.)
    ///   3. Delete the rolled-up events from the hot table + drop their
    ///      FTS5 entries.
    ///
    /// Also: drops `event_aggregates` rows older than 30 days, keeping
    /// the rollup table tiny indefinitely.
    ///
    /// Returns the number of events deleted from the hot tier.
    ///
    /// `aggregateRetentionDays` controls the trim cutoff for the
    /// `event_aggregates` table (Step 3 below). v1.8.0 made this
    /// configurable from `StorageConfig.aggregateDays` — pre-v1.8 it was
    /// hardcoded at 30 days.
    ///
    /// v1.21.4: `protectedCategory` + `floorCutoff` extend the per-category
    /// retention floor to the time-based rollup. When supplied, protected-
    /// category rows newer than `floorCutoff` are excluded from BOTH the
    /// aggregation and the delete (the same predicate), so they stay as raw
    /// rows and are NOT double-counted — a later sweep whose cutoff has aged
    /// past the floor rolls them up normally. Keeps aggregate/delete
    /// symmetric under the floor.
    @discardableResult
    public func rollUpAndPrune(
        olderThan cutoff: Date,
        aggregateRetentionDays: Int = 30,
        protecting protectedCategory: EventCategory? = nil,
        newerThan floorCutoff: Date? = nil
    ) async throws -> Int {
        guard let db = db else { return 0 }
        // Each chunk is independently atomic: aggregate + FTS delete + event
        // delete either all commit or all roll back. The old implementation
        // wrapped every eligible row on the host in one transaction, allowing
        // an arbitrarily large WAL despite the nominal reserve. A default
        // 32 MiB event reserve and three conservative row mutations yields 42
        // source rows per transaction, followed by a fresh family/free probe.
        let batch = maintenanceBatchRowLimit(mutationsPerCandidate: 3)
        let transactionEstimate = maintenanceEstimate(
            rowCount: Int(batch),
            mutationsPerCandidate: 3
        )
        let hasFloor = protectedCategory != nil && floorCutoff != nil
        let floorPredicate = hasFloor
            ? " AND (event_category <> ?2 OR timestamp < ?3)"
            : ""
        let selector = """
            SELECT rowid FROM events
            WHERE timestamp < ?1\(floorPredicate)
            ORDER BY rowid LIMIT ?4
            """
        let aggregateSQL = """
            INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
            SELECT
                strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                event_category,
                COALESCE(process_signer, ''),
                COALESCE(process_path, ''),
                COUNT(*) AS c
            FROM events WHERE rowid IN (\(selector))
            GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
            ON CONFLICT(day, event_category, process_signer, process_path)
            DO UPDATE SET count = count + excluded.count
            """
        let deleteFTS = "DELETE FROM events_fts WHERE rowid IN (\(selector))"
        let deleteEvents = "DELETE FROM events WHERE rowid IN (\(selector))"

        func bindChunk(_ stmt: OpaquePointer) {
            sqlite3_bind_double(stmt, 1, cutoff.timeIntervalSince1970)
            if let protectedCategory, let floorCutoff {
                bindText(stmt, index: 2, value: protectedCategory.rawValue)
                sqlite3_bind_double(stmt, 3, floorCutoff.timeIntervalSince1970)
            }
            sqlite3_bind_int(stmt, 4, batch)
        }

        var deleted = 0
        while true {
            try execute(
                "BEGIN IMMEDIATE TRANSACTION",
                maintenance: true,
                estimatedTransactionBytes: transactionEstimate
            )
            var committed = false
            do {
                let aggregate = try prepare(aggregateSQL)
                bindChunk(aggregate)
                let aggregateRC = sqlite3_step(aggregate)
                sqlite3_finalize(aggregate)
                guard aggregateRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: aggregateRC)
                    throw EventStoreError.stepFailed(
                        "rollUp aggregate failed: \(String(cString: sqlite3_errmsg(db)))"
                    )
                }

                let fts = try prepare(deleteFTS)
                bindChunk(fts)
                let ftsRC = sqlite3_step(fts)
                sqlite3_finalize(fts)
                guard ftsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: ftsRC)
                    throw EventStoreError.stepFailed(
                        "rollUp FTS prune failed: \(String(cString: sqlite3_errmsg(db)))"
                    )
                }

                let events = try prepare(deleteEvents)
                bindChunk(events)
                let eventsRC = sqlite3_step(events)
                sqlite3_finalize(events)
                guard eventsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: eventsRC)
                    throw EventStoreError.stepFailed(
                        "rollUp event prune failed: \(String(cString: sqlite3_errmsg(db)))"
                    )
                }
                let thisBatch = Int(sqlite3_changes(db))
                try execute("COMMIT")
                committed = true
                deleted += thisBatch
                if thisBatch == 0 { break }
            } catch {
                if !committed { try? execute("ROLLBACK") }
                throw error
            }
            await Task.yield()
        }

        if deleted > 0 {
            let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
                requestedPages: Int.max,
                reserveBytes: storageTransactionReserveBytes,
                pageSizeBytes: sqlitePageSizeBytes
            )
            guard plan.pages > 0 else { return deleted }
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: plan.estimatedTransactionBytes
            )
            let rc = sqlite3_exec(
                db,
                "PRAGMA incremental_vacuum(\(plan.pages))",
                nil,
                nil,
                nil
            )
            if rc != SQLITE_OK {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
            }
        }

        // Step 3: trim aggregates older than `aggregateRetentionDays`.
        // Independent + idempotent — runs outside the main transaction so it
        // doesn't block on Step 2's long delete batch. A crash here just
        // leaves stale aggregates that the next sweep cleans up.
        let aggDays = max(1, aggregateRetentionDays)
        let cutoffDay = Self.isoDay(Date().addingTimeInterval(-Double(aggDays) * 86400))
        let trimBatch = maintenanceBatchRowLimit()
        let trimEstimate = maintenanceEstimate(rowCount: Int(trimBatch))
        let trimSQL = """
            DELETE FROM event_aggregates WHERE rowid IN (
                SELECT rowid FROM event_aggregates
                WHERE day < ?1 ORDER BY rowid LIMIT ?2
            )
            """
        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: trimEstimate
            )
            let trimStmt = try prepare(trimSQL)
            bindText(trimStmt, index: 1, value: cutoffDay)
            sqlite3_bind_int(trimStmt, 2, trimBatch)
            let trimRC = sqlite3_step(trimStmt)
            sqlite3_finalize(trimStmt)
            if trimRC != SQLITE_DONE {
                try throwLatchedStoragePressureIfPresent(resultCode: trimRC)
                throw EventStoreError.stepFailed("aggregate retention trim failed")
            }
            if sqlite3_changes(db) == 0 { break }
            await Task.yield()
        }

        return deleted
    }

    /// ISO date string ("2026-04-15") for `date` in UTC. Matches the
    /// `strftime('%Y-%m-%d', timestamp, 'unixepoch')` format used in the
    /// aggregate roll-up so day strings sort + compare as text.
    private static func isoDay(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }

    /// Run `VACUUM` to reclaim free pages into on-disk file size.
    /// SQLite's `DELETE` marks pages free but doesn't shrink the
    /// file; without this call, the size-cap enforcer prunes rows
    /// but the `.db` file stays the same size. Costly (rewrites the
    /// whole DB) AND requires ~= DB size of temp scratch space,
    /// so only called after a size-driven prune when
    /// `checkpointAndVacuum()` has confirmed there's enough free
    /// disk to do it safely.
    ///
    /// **WAL discipline**: the function checkpoints the WAL before
    /// and after VACUUM. Older SQLite (≤3.43, the macOS-bundled
    /// libsqlite3 we used pre-CSQLCipher migration) auto-checkpointed
    /// inside VACUUM, making the pattern caller-checkpoint-free.
    /// SQLite ≥3.53 (vendored via SQLCipher 4.16.0) no longer
    /// guarantees this — VACUUM can return SQLITE_OK without
    /// touching the WAL, leaving post-VACUUM file sizes identical
    /// to pre-VACUUM and silently breaking the size-cap shrink
    /// contract. Pre-checkpoint guarantees VACUUM operates on a
    /// drained main DB; post-checkpoint truncates the WAL that
    /// VACUUM itself produced so the on-disk footprint reflects the
    /// rebuilt DB.
    public func vacuum() async throws {
        guard let db = db else { return }
        guard walCheckpoint() else {
            throw EventStoreError.busy(
                "VACUUM refused because the pre-checkpoint did not fully drain"
            )
        }
        // One-shot auto_vacuum conversion (audit corr-storage): `PRAGMA
        // auto_vacuum = INCREMENTAL` is a SILENT no-op on an already-populated
        // DB — the mode only changes on the next VACUUM. Fresh installs get
        // mode 2 from applyEventStorePragmas (the pragma DOES take on an empty
        // header), but a DB that existed before that shipped stays in mode 0
        // (NONE) forever, so incrementalVacuum() — the low-disk reclaim path —
        // is permanently a no-op. Setting the pragma here means this full
        // VACUUM (already disk-pre-flighted by the size-cap caller) also
        // converts the file to INCREMENTAL, so subsequent low-disk sweeps can
        // reclaim in place. Idempotent + harmless once already mode 2.
        let autoVacuumRC = sqlite3_exec(
            db,
            "PRAGMA auto_vacuum = INCREMENTAL",
            nil,
            nil,
            nil
        )
        if autoVacuumRC != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: autoVacuumRC)
            throw EventStoreError.stepFailed("auto_vacuum conversion failed")
        }
        // Re-probe at the exact whole-file rewrite boundary. Caller preflights
        // are advisory and may race another disk consumer.
        try admitStorageFullVacuum()
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.stepFailed("VACUUM failed: \(msg)")
        }
        guard walCheckpointTruncate() else {
            throw EventStoreError.busy(
                "VACUUM completed but its WAL could not be fully drained/truncated"
            )
        }
    }

    /// Checkpoint the WAL into the main DB file. Uses the non-
    /// blocking PASSIVE mode first; if that doesn't fully drain the
    /// WAL, escalates to RESTART which briefly parks new writers
    /// but doesn't require zero readers (unlike TRUNCATE).
    ///
    /// After a successful RESTART checkpoint, the main `.db` file
    /// carries every row that's been committed, and a subsequent
    /// VACUUM will produce a shrunken file that the Settings UI
    /// actually shows as "Current size".
    ///
    /// Returns `true` iff the checkpoint drained the WAL (pages
    /// moved from `.db-wal` to `.db`). Returns `false` on partial
    /// or no progress; the caller should still be able to VACUUM
    /// but the shrink may be smaller than expected.
    @discardableResult
    public func walCheckpoint() -> Bool {
        guard let db = db else { return false }
        guard (try? admitStorageCheckpoint()) != nil else { return false }
        // PASSIVE: never blocks. Returns immediately; may leave
        // pages in the WAL if readers are active.
        var passiveLog: Int32 = 0
        var passiveCkpt: Int32 = 0
        let rcPassive = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_PASSIVE),
            &passiveLog, &passiveCkpt
        )
        let passiveDrained = (rcPassive == SQLITE_OK && passiveLog == passiveCkpt)
        if passiveDrained { return true }
        guard rcPassive == SQLITE_OK else {
            if rcPassive != SQLITE_BUSY, rcPassive != SQLITE_LOCKED {
                _ = latchStoragePressureIfPresent(resultCode: rcPassive)
            }
            return false
        }

        // PASSIVE may have grown main and consumed free blocks. Re-probe before
        // the blocking attempt; a pre-PASSIVE observation is stale here.
        guard (try? admitStorageCheckpoint()) != nil else { return false }

        // RESTART: parks new writers very briefly; forces all
        // readers to start from the new WAL file (existing ones
        // finish their current transactions first). Safer than
        // TRUNCATE (which requires truly zero readers).
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

    /// TRUNCATE checkpoint — drains the WAL into the main DB AND shrinks the
    /// `-wal` sidecar back to zero bytes. `walCheckpoint()` above (PASSIVE→
    /// RESTART) drains the WAL *content* but leaves the *file* pinned at its
    /// high-water mark; under `journalSizeLimitBytes` (64 MB) that means
    /// events.db-wal can sit at up to 64 MB indefinitely — invisible to a
    /// file-only size check yet real resident footprint.
    ///
    /// v1.21.4 (#23): with `eventWalAutocheckpointPages` raised to 16 MB the
    /// healthy high-water mark is ~16 MB, so the background size-cap sweep
    /// runs this each pass to reclaim it back to zero — footprint-neutral in
    /// steady state, matching the trace/tracegraph stores' `walCheckpointTruncate`
    /// discipline (DaemonTimers). Best-effort: TRUNCATE degrades to RESTART-
    /// like progress under an active reader, which is still fine.
    @discardableResult
    public func walCheckpointTruncate() -> Bool {
        guard let db = db else { return false }
        guard (try? admitStorageCheckpoint()) != nil else { return false }
        var log: Int32 = 0
        var ckpt: Int32 = 0
        let rc = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_TRUNCATE),
            &log, &ckpt
        )
        if rc != SQLITE_OK, rc != SQLITE_BUSY, rc != SQLITE_LOCKED {
            _ = latchStoragePressureIfPresent(resultCode: rc)
        }
        return rc == SQLITE_OK && log == ckpt
    }

    // MARK: - Disabled off-actor full VACUUM compatibility entry point

    /// Retained only so older maintenance callers fail with a specific error.
    /// A detached connection cannot prevent the ingestion actor from committing
    /// between the final free-space probe and acquisition of SQLite's VACUUM
    /// writer lock. Full VACUUM must run through the owning actor's `vacuum()`
    /// method, which serializes checkpoint -> admission -> rewrite.
    public static func vacuumOnDedicatedConnection(
        at path: String,
        storagePolicy suppliedPolicy: SQLitePersistentStorePolicy? = nil
    ) async throws {
        _ = path
        _ = suppliedPolicy
        // Fail closed: a detached connection cannot prevent the ingestion
        // actor from committing between its final stat and acquisition of the
        // VACUUM writer lock. Call `vacuum()` on the owning EventStore actor so
        // checkpoint -> headroom gate -> rewrite is one serialized operation.
        throw EventStoreError.stepFailed(
            "concurrent dedicated VACUUM is disabled; use EventStore.vacuum() on the owning actor"
        )
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // Reclaim freelist pages from the end of the file in place — no
    // scratch disk required. Drives the low-disk fallback in
    // `enforceDatabaseSizeCap` when a full VACUUM would need more
    // headroom than the volume has.
    //
    // Returns the number of pages physically removed from the file
    // (delta in `PRAGMA freelist_count`). Zero means either:
    //   - The DB isn't in `auto_vacuum = INCREMENTAL` mode (pre-v1.10
    //     EventStore DBs that never had the one-shot conversion run),
    //   - The freelist was already empty,
    //   - Or `maxPages == 0`.
    //
    // The caller can divide by `Int64(maxPages) * Int64(pageSize)` to
    // estimate the file-size reduction, but the size-cap enforcer
    // reads the on-disk footprint directly via `statvfs` so it gets
    // exact numbers including the WAL/SHM sidecars.
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
        // The shared incremental-vacuum primitive cannot safely checkpoint:
        // it has no path/floor/family probes. Drain through this actor's fresh
        // whole-sidecar gate, then re-probe ordinary maintenance headroom.
        guard walCheckpoint() else {
            throw EventStoreError.stepFailed(
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
                throw EventStoreError.stepFailed(
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

    /// Read the file's `PRAGMA auto_vacuum` mode at runtime. Returns
    /// 0/1/2 (NONE / FULL / INCREMENTAL); 0 on closed/error. The
    /// size-cap enforcer reads this so it can log when the DB is not
    /// in INCREMENTAL mode — incrementalVacuum is a no-op in that
    /// case, and the operator may want to schedule a one-shot
    /// `maccrabctl maintenance vacuum` to convert.
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }

    // MARK: - FTS5 index merge (v1.21.4 Tier-A perf)
    //
    // Companion to the `automerge=16` deferral set in `openDatabase`. With
    // per-insert automerge deferred to the crisismerge threshold (16), the
    // `events_fts` index accumulates more small b-tree segments between
    // compactions than the old default (4) allowed. This runs an explicit, BOUNDED incremental
    // merge OFF the hot write path — driven from the background size-cap sweep
    // — so hunt-query (`search()`) latency stays healthy without the insert
    // path paying the merge cost.
    //
    // `pages` bounds the work: FTS5's `('merge', N)` command runs a merge
    // until at least N leaf pages have been written to the database (or the
    // index is fully merged), then stops. A bounded budget keeps the actor
    // responsive; when there is nothing to merge the command is a cheap no-op.
    //
    // DETECTION-SAFE: `events_fts` is read ONLY by `search()` (threat
    // hunting), never by the detection engine. A merge changes only the
    // index's physical segment layout, never which rows a MATCH returns.
    // No-op on a read-only store (the dashboard has no business rewriting the
    // owner's index).
    @discardableResult
    public func mergeFTS(pages: Int = 1000) async -> Bool {
        guard let db = db, !isReadOnly else { return false }
        let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: max(1, pages),
            reserveBytes: storageTransactionReserveBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            fixedTreePageTouches: 16,
            // Vendored FTS5 performs merge work in 64-leaf-page quanta.
            overshootPages: 64
        )
        guard plan.pages > 0 else { return false }
        guard (try? admitStorageMaintenanceWrite(
            estimatedTransactionBytes: plan.estimatedTransactionBytes
        )) != nil else { return false }
        let sql = "INSERT INTO events_fts(events_fts, rank) VALUES('merge', \(plan.pages))"
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            _ = latchStoragePressureIfPresent(resultCode: rc)
            return false
        }
        return true
    }

    /// Full FTS5 `optimize` — merges EVERY events_fts segment into one and drops
    /// the delete markers left behind by pruned events. Unlike the bounded
    /// `mergeFTS` (`'merge', N`), which does a fixed slice of work per call and
    /// falls behind on a churned DB, `optimize` runs to completion in one pass.
    /// On a badly-fragmented index (measured on-device: ~104K segments / 400 MB
    /// backing an events table that had been pruned to near-empty) it frees the
    /// index's pages to the freelist so a subsequent incremental_vacuum / VACUUM
    /// can return them to the OS — the events_fts index was otherwise a permanent
    /// floor that kept the DB over its size cap (and its mmap inflated RSS). Cost
    /// scales with how out-of-date the index is: a near-no-op when already compact,
    /// a few seconds when heavily fragmented. Run OFF the hot path (the background
    /// size-cap sweep), gated on the DB being over target.
    ///
    /// DETECTION-SAFE: `events_fts` is read ONLY by `search()`/hunt, never by the
    /// detection engine; optimize changes only the index's physical layout, never
    /// which rows a MATCH returns. No-op on a read-only store.
    /// Timestamp of the last full `optimize` attempt, or nil if none has run
    /// since this store was opened — so a restart always permits one pass.
    /// Actor-isolated; deliberately not persisted.
    private var lastFullFTSOptimizeAt: Date?

    /// Minimum spacing between full FTS `optimize` passes. See optimizeFTS.
    private static let minFullFTSOptimizeInterval: TimeInterval = 6 * 3600

    @discardableResult
    public func optimizeFTS() async -> Bool {
        guard let db = db, !isReadOnly else { return false }
        // Rate-limit the FULL optimize. It is unbounded by construction (it
        // merges every segment in a single statement) and it runs on the
        // ACTOR's ingestion connection, so its entire duration is head-of-line
        // blocking for `insert(event:)`: while stalled, BatchedEventWriter
        // cannot drain and backpressure propagates toward the ES client message
        // queue — the path that ends in kernel-dropped ES messages and real
        // detection blind spots.
        //
        // The caller (the tier-rollup sweep, DaemonTimers) invokes this on
        // EVERY over-cap sweep, and the sweep cadence is operator-tunable down
        // to single-digit minutes via `storage.events_size_cap_interval_minutes`
        // (default 60), so a host sitting over cap on a low cadence pays the
        // full compaction again and again. One pass per interval is enough to
        // knock the index off the freelist floor that keeps the DB over cap —
        // the on-device case this optimize was added for collapsed ~104K
        // segments to 3 in a single pass — and the BOUNDED `mergeFTS` still
        // runs every sweep in between, so fragmentation does not accumulate
        // unchecked while this backs off.
        let now = Date()
        if let last = lastFullFTSOptimizeAt,
           now.timeIntervalSince(last) < Self.minFullFTSOptimizeInterval {
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .debug("optimizeFTS skipped: last full optimize was \(Int(now.timeIntervalSince(last)))s ago (min interval \(Int(Self.minFullFTSOptimizeInterval))s); bounded mergeFTS still runs each sweep")
            return false
        }
        // Full optimize rewrites all FTS segments and scales with the existing
        // store. It therefore uses whole-store schema/rebuild headroom rather
        // than pretending to fit the ordinary bounded row transaction reserve.
        guard (try? admitStorageSchemaRebuild()) != nil else { return false }
        // Stamp BEFORE the exec so a slow or repeatedly-failing optimize cannot
        // be re-attempted on every subsequent sweep.
        lastFullFTSOptimizeAt = now
        let rc = sqlite3_exec(
            db,
            "INSERT INTO events_fts(events_fts) VALUES('optimize')",
            nil,
            nil,
            nil
        )
        if rc != SQLITE_OK {
            _ = latchStoragePressureIfPresent(resultCode: rc)
            return false
        }
        return true
    }

    // MARK: - Reentrancy guard for size-cap enforcement
    //
    // The hourly size-cap timer, a user-invoked "Prune now", and a
    // CLI `maccrabctl prune --to-cap` can all end up here. Without a
    // guard, two invocations serialize behind the actor but each
    // runs a full prune + VACUUM pass — wasteful at best, unhelpful
    // at worst (second pass re-scans an already-pruned DB). The
    // guard returns `nil` from `beginSizeCapPrune()` when another
    // pass is already in flight.

    private var _isPruningForSizeCap = false

    /// Acquire the size-cap pruning exclusion. Returns `nil` if
    /// another pass is already active. Callers that receive `nil`
    /// should simply log and return.
    public func beginSizeCapPrune() -> Bool {
        if _isPruningForSizeCap { return false }
        _isPruningForSizeCap = true
        return true
    }

    /// Release the size-cap pruning exclusion. Must be called from
    /// a `defer` block so it runs even on throws.
    public func endSizeCapPrune() {
        _isPruningForSizeCap = false
    }

    // MARK: - Mid-run corruption self-heal (C-04)
    //
    // Init-time recovery (DaemonSetup.recoverEventStore) handles a store that
    // is already corrupt at open. This path handles a store that corrupts
    // *while the daemon is live* — a `SQLITE_CORRUPT` / `SQLITE_NOTADB` on an
    // insert step. Without it, every subsequent insert throws forever and
    // ingestion is silently dead until the next daemon restart.
    //
    // The self-heal is: close → quarantine the corrupt files aside → reopen a
    // fresh DB. It is *bounded* (at most `selfHealMaxAttempts` for the process
    // lifetime) and *rate-limited* (`selfHealMinInterval` between attempts) so
    // a persistently-failing device can't thrash open/close/backup in a hot
    // loop. Backups reuse the shared `CorruptDBBackup` naming + retention, so
    // they stay bounded exactly like the init-time quarantine.

    /// Attempts so far this process. Bounded so a device that keeps corrupting
    /// (failing hardware) doesn't churn forever — after the cap we stop trying
    /// and inserts simply keep failing (surfaced via StorageErrorTracker).
    private var selfHealCount = 0
    private var lastSelfHealAt = Date.distantPast
    private static let selfHealMaxAttempts = 3
    private static let selfHealMinInterval: TimeInterval = 300  // 5 minutes

    /// SQLite primary result code for a step failure that indicates on-disk
    /// corruption (as opposed to a transient lock / disk-full). Extended codes
    /// (e.g. `SQLITE_CORRUPT_VTAB`) share the low byte with their primary code.
    static func isCorruptionResultCode(_ rc: Int32) -> Bool {
        SQLiteFailureClassifier.isExplicitCorruption(
            resultCode: rc,
            extendedResultCode: rc
        )
    }

    /// Close the current connection, quarantine the corrupt DB (+ sidecars)
    /// aside, and reopen a fresh one. Returns `true` if the store is usable
    /// again afterwards. Bounded + rate-limited (see above). No-op (returns
    /// `false`) on a read-only store — the dashboard has no business rewriting
    /// the owner's DB.
    ///
    /// `now:` is injectable for tests; production callers use the default.
    @discardableResult
    func attemptCorruptionSelfHeal(
        failure: SQLiteFailureDetails,
        reason: String,
        now: Date = Date()
    ) -> Bool {
        let log = Logger(subsystem: "com.maccrab.storage", category: "event-store")
        // This guard belongs at the mutating boundary, not only at the caller.
        // A future recovery caller cannot accidentally quarantine on BUSY,
        // LOCKED, PERM, READONLY, IOERR, FULL, or a misleading error string.
        guard failure.isExplicitCorruption else { return false }
        guard !isReadOnly else { return false }
        guard selfHealCount < Self.selfHealMaxAttempts else {
            log.error("EventStore: corruption self-heal cap (\(Self.selfHealMaxAttempts, privacy: .public)) reached — not reopening. reason=\(reason, privacy: .public)")
            return false
        }
        guard now.timeIntervalSince(lastSelfHealAt) >= Self.selfHealMinInterval else {
            // Rate-limited: a burst of corrupt steps must not thrash the file.
            return false
        }
        lastSelfHealAt = now
        selfHealCount += 1
        log.error("EventStore: mid-run corruption detected (reason=\(reason, privacy: .public)); quarantining DB and reopening (attempt \(self.selfHealCount, privacy: .public)/\(Self.selfHealMaxAttempts, privacy: .public)).")

        // Close: finalize the cached insert statement, then close the handle.
        // insertStmt is the only long-lived statement on this connection
        // (queries prepare + finalize locally), so a v1 close succeeds cleanly.
        if let insertStmt { sqlite3_finalize(insertStmt) }
        insertStmt = nil
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
        checkpointController = nil
        db = nil

        // Quarantine the corrupt files aside (bounded retention). This *moves*
        // events.db* out of the way, so the reopen below starts from a clean
        // slate. `moveItem`/`removeItem` act on the final path component and
        // never follow a symlinked leaf; `openDatabase` re-checks the symlink
        // guard on the privileged path before it recreates the file.
        let dir = (databasePath as NSString).deletingLastPathComponent
        let base = (databasePath as NSString).lastPathComponent
        do {
            try CorruptDBBackup.quarantineAtomically(directory: dir, base: base)
            // Any chunks committed before this corruption event now live only
            // in the quarantined family, not the active store. Advance the
            // generation before reopening (including if reopen later fails).
            activeDatabaseGeneration &+= 1
        } catch {
            log.error("EventStore: corruption quarantine FAILED: \(error.localizedDescription, privacy: .public). Original DB family was rolled back; refusing to create a fresh store.")
            return false
        }

        // Reopen from the (now-empty) path. openDatabase re-applies pragmas +
        // schema + re-prepares the insert statement.
        do {
            // v1.21.5 (audit sec-storage-crypto): recreate the fresh DB with
            // the same 0o027/0o640 (group read-only, not group-write) as the
            // primary init — a self-heal must not silently re-loosen perms.
            let oldUmask = umask(0o027)
            defer { umask(oldUmask) }
            let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
                at: databasePath,
                forceReadOnly: false,
                storagePolicy: storagePolicy
            )
            db = handle
            isReadOnly = ro
            insertStmt = stmt
            storageAdmission = admission
            sqlitePageSizeBytes = pageSize
            checkpointController = controller
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
            log.notice("EventStore: reopened fresh DB after corruption self-heal.")
            return true
        } catch {
            log.error("EventStore: reopen after corruption self-heal FAILED: \(error.localizedDescription, privacy: .public). Inserts will keep failing until restart.")
            return false
        }
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
                throw EventStoreError.stepFailed(
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
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
            sqlite3_free(errmsg)
            // #13: BEGIN/COMMIT can return SQLITE_BUSY/LOCKED under WAL contention
            // (past busy_timeout) — transient, retryable. Surface it distinctly.
            if rc == SQLITE_BUSY || rc == SQLITE_LOCKED {
                throw EventStoreError.busy(msg, failure: failure)
            }
            throw EventStoreError.sqliteFailure(
                context: sql,
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }

    /// Exact DB+WAL+SHM+journal admission immediately before growth writes. The
    /// controller is a value so copy it out and always write it back, including
    /// on a thrown probe, preserving the sticky pressure latch.
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
            // Space can disappear between the successful probe and the fresh
            // open. A shed-only reopen has no insert statement. Retry admission
            // once with the SAME full transaction estimate; a successful retry
            // reopens again and the caller acquires only the new statement.
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

    /// Retention/reclaim writes are the bounded route back under the ceiling.
    private func admitStorageMaintenanceWrite(
        estimatedTransactionBytes: Int64
    ) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitMaintenanceWrite(
            estimatedTransactionBytes: estimatedTransactionBytes
        )
    }

    /// A checkpoint can copy the complete WAL into main while leaving the WAL
    /// allocated. It therefore has a whole-sidecar gate, not the small ordinary
    /// maintenance transaction gate.
    private func admitStorageCheckpoint() throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitCheckpoint()
    }

    private var storageTransactionReserveBytes: Int64 {
        storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
    }

    private func maintenanceRowMutationUpperBound() -> Int64 {
        if maintenanceHighWaterScannedExistingRows,
           let cached = maintenanceRowMutationHighWaterBytes {
            return max(
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
                cached
            )
        }
        guard let db else { return storageTransactionReserveBytes }

        func maximumLogicalBytes(
            table: String,
            columns: [String],
            duplicatedIndexColumns: [String],
            indexRepresentationCount: Int64,
            ftsColumns: [String] = []
        ) -> Int64? {
            func length(_ column: String) -> String {
                "COALESCE(length(CAST(\"\(column)\" AS BLOB)), 0)"
            }
            var terms = columns.map(length)
            terms.append(contentsOf: duplicatedIndexColumns.map(length))
            terms.append(contentsOf: ftsColumns.map {
                "4 * \(length($0))"
            })
            let fixed = SQLitePersistentStoreAdmission.saturatingAdd(
                Int64(columns.count * 16),
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    indexRepresentationCount, by: 16
                )
            )
            let expression = ([String(fixed)] + terms)
                .joined(separator: " + ")
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(
                db,
                "SELECT COALESCE(MAX(\(expression)), 0) FROM \"\(table)\"",
                -1,
                &statement,
                nil
            ) == SQLITE_OK, let statement else {
                sqlite3_finalize(statement)
                return nil
            }
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
            return max(0, sqlite3_column_int64(statement, 0))
        }

        let eventColumns = [
            "id", "timestamp", "event_category", "event_type", "event_action",
            "severity", "process_pid", "process_name", "process_path",
            "process_commandline", "process_ppid", "process_signer",
            "process_team_id", "process_signing_id", "file_path", "file_action",
            "network_dest_ip", "network_dest_port", "tcc_service", "tcc_client",
            "raw_json", "mcp_server_name", "mcp_server_category",
            "ai_tool_session_id", "agent_trace_id", "agent_span_id", "agent_tool",
            "machine_agent_confidence", "agent_evidence_json", "user_id",
            "user_name", "group_id", "working_directory", "responsible_pid",
            "architecture", "is_platform_binary", "is_notarized",
            "process_sha256", "parent_name", "parent_executable",
            "parent_signer_type", "ai_tool", "ai_tool_child",
            "session_launch_source", "tcc_decision",
        ]
        let eventIndexes = [
            "id", "event_category", "event_category", "event_category",
            "event_category", "severity", "severity", "severity",
            "process_path", "mcp_server_name", "agent_trace_id",
            "ai_tool_session_id", "user_id", "ai_tool", "parent_executable",
        ]
        let eventFTS = [
            "process_name", "process_path", "process_commandline", "file_path",
            "network_dest_ip", "tcc_service", "tcc_client",
        ]
        let evidenceColumns = [
            "alert_id", "id", "timestamp", "event_category", "event_type",
            "event_action", "severity", "process_pid", "process_name",
            "process_path", "process_commandline", "process_ppid",
            "process_signer", "process_team_id", "process_signing_id",
            "file_path", "file_action", "network_dest_ip", "network_dest_port",
            "tcc_service", "tcc_client", "raw_json", "mcp_server_name",
            "mcp_server_category", "ai_tool_session_id",
        ]
        let candidates: [Int64?] = [
            maximumLogicalBytes(
                table: "events",
                columns: eventColumns,
                duplicatedIndexColumns: eventIndexes,
                indexRepresentationCount: 14,
                ftsColumns: eventFTS
            ),
            maximumLogicalBytes(
                table: "alert_evidence",
                columns: evidenceColumns,
                duplicatedIndexColumns: ["alert_id", "alert_id", "id", "id"],
                indexRepresentationCount: 3
            ),
            maximumLogicalBytes(
                table: "event_aggregates",
                columns: ["day", "event_category", "process_signer", "process_path", "count"],
                duplicatedIndexColumns: [
                    "day", "day", "day", "event_category", "event_category",
                    "process_signer", "process_path",
                ],
                indexRepresentationCount: 3
            ),
            maximumLogicalBytes(
                table: "attribution_overrides",
                columns: [
                    "event_id", "machine_confidence", "user_verdict", "user_note",
                    "schema_version", "created_at", "updated_at",
                ],
                duplicatedIndexColumns: ["event_id", "user_verdict"],
                indexRepresentationCount: 3
            ),
        ]
        var upper = max(
            SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
            maintenanceRowMutationHighWaterBytes ?? 0
        )
        for logical in candidates.compactMap({ $0 }) {
            upper = max(
                upper,
                SQLitePersistentStoreAdmission
                    .conservativeEncodedRowMutationBytes(
                        logicalRepresentationBytes: logical,
                        pageSizeBytes: sqlitePageSizeBytes,
                        maximumLeafPageTouches: 20
                    )
            )
        }
        maintenanceRowMutationHighWaterBytes = upper
        maintenanceHighWaterScannedExistingRows = true
        return upper
    }

    private func maintenanceBatchRowLimit(
        mutationsPerCandidate: Int = 1
    ) -> Int32 {
        let fixed = SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 48
        )
        let bytesPerCandidate = SQLitePersistentStoreAdmission
            .saturatingMultiply(
                maintenanceRowMutationUpperBound(),
                by: Int64(max(1, mutationsPerCandidate))
            )
        let available = max(0, storageTransactionReserveBytes - fixed)
        let rows = SQLitePersistentStoreAdmission.maximumRowsPerTransaction(
            reserveBytes: available,
            bytesPerRow: bytesPerCandidate
        )
        return Int32(clamping: max(1, rows))
    }

    private func maintenanceEstimate(
        rowCount: Int,
        mutationsPerCandidate: Int = 1
    ) -> Int64 {
        let rowBytes = SQLitePersistentStoreAdmission.saturatingMultiply(
            maintenanceRowMutationUpperBound(),
            by: Int64(max(1, mutationsPerCandidate))
        )
        return SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: SQLitePersistentStoreAdmission.saturatingMultiply(
                Int64(max(0, rowCount)), by: rowBytes
            ),
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 48
        )
    }

    private func admitStorageSchemaRebuild(operationCount: Int = 1) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitSchemaRebuild(operationCount: operationCount)
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
            throw EventStoreError.prepareFailed(msg)
        }
        return stmt
    }

    /// Binds a non-nil text value to a prepared statement parameter.
    ///
    /// Uses `SQLITE_TRANSIENT` so SQLite copies the string immediately,
    /// making it safe even though the C string pointer is only valid inside
    /// the `withCString` closure.
    private func bindText(_ stmt: OpaquePointer, index: Int32, value: String) {
        _ = value.withCString { cstr in
            sqlite3_bind_text(stmt, index, cstr, -1,
                              unsafeBitCast(-1, to: sqlite3_destructor_type.self))
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

    /// Runs a SELECT query that returns `raw_json` as the first column and
    /// decodes each row into an `Event`.
    private func queryEvents(
        sql: String,
        bindings: [(Int32, BindingValue)]
    ) throws -> [Event] {
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

        var results: [Event] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let cstr = sqlite3_column_text(stmt, 0) else { continue }
            let jsonString = String(cString: cstr)
            guard let jsonData = jsonString.data(using: .utf8) else { continue }
            do {
                let event = try decoder.decode(Event.self, from: jsonData)
                results.append(event)
            } catch {
                // Skip malformed rows rather than failing the entire query.
                continue
            }
        }
        return results
    }

    // MARK: - v1.9 PR-4: attribution_overrides

    /// Insert or replace an operator verdict for an event. Idempotent on
    /// `(eventId)`: a second call REPLACES the prior verdict and bumps
    /// `updated_at`. Documents Plan v3 review #10's "single source of
    /// truth per event" contract.
    public func recordAttributionOverride(_ override: AttributionOverride) throws {
        let logicalBytes = [
            override.eventId,
            override.machineConfidence,
            override.verdict.rawValue,
            override.userNote,
        ].reduce(Int64(64)) { total, value in
            SQLitePersistentStoreAdmission.saturatingAdd(
                total,
                Int64(value?.utf8.count ?? 0)
            )
        }
        let indexedLogicalBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            logicalBytes,
            Int64(override.eventId.utf8.count
                + override.verdict.rawValue.utf8.count + 3 * 16)
        )
        let newRowBytes = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: indexedLogicalBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 4
            )
        let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            newRowBytes,
            try existingAttributionOverrideMutationBytes(
                eventId: override.eventId
            )
        )
        try admitStorageWrite(
            estimatedTransactionBytes: SQLitePersistentStoreAdmission
                .conservativeTransactionBytes(
                    rowMutationBytes: rowBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumTreePathPageTouches: 8
                )
        )
        guard let db else {
            throw EventStoreError.databaseOpenFailed("db not open")
        }
        let sql = """
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
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.prepareFailed(msg)
        }
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
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.stepFailed(msg)
        }
        maintenanceRowMutationHighWaterBytes = max(
            maintenanceRowMutationHighWaterBytes ?? 0,
            rowBytes
        )
    }

    private func existingAttributionOverrideMutationBytes(
        eventId: String
    ) throws -> Int64 {
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
            throw EventStoreError.prepareFailed(
                "existing attribution override estimate"
            )
        }
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: eventId)
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return 0 }
        guard step == SQLITE_ROW else {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw EventStoreError.stepFailed(
                "existing attribution override estimate step"
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

    /// Look up the operator verdict for a given event, or nil if none.
    public func attributionOverride(for eventId: String) throws -> AttributionOverride? {
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
            throw EventStoreError.prepareFailed(msg)
        }
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, eventId, -1, TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        let mc: String? = sqlite3_column_type(stmt, 0) == SQLITE_NULL
            ? nil
            : String(cString: sqlite3_column_text(stmt, 0))
        let verdictRaw = String(cString: sqlite3_column_text(stmt, 1))
        // Tolerant decode: unknown future verdicts surface as `.unknown`.
        let verdict = AttributionOverride.Verdict(rawValue: verdictRaw) ?? .unknown
        let note: String? = sqlite3_column_type(stmt, 2) == SQLITE_NULL
            ? nil
            : String(cString: sqlite3_column_text(stmt, 2))
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

    /// Compute aggregate stats. Plan v3 review #11: the metric only makes
    /// sense in the "rated" frame; callers must use
    /// `formattedAccuracyLine` to print it.
    public func attributionOverrideStats() throws -> AttributionOverrideStats {
        guard let db else {
            return AttributionOverrideStats(
                ratedCount: 0, confirmedCount: 0,
                wrongToolCount: 0, noAgentCount: 0, unknownVerdictCount: 0,
                totalEventsWithMachineAttribution: 0
            )
        }
        // Per-verdict counts
        let sql1 = """
            SELECT user_verdict, COUNT(*)
            FROM attribution_overrides
            GROUP BY user_verdict
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql1, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.prepareFailed(msg)
        }
        var rated = 0, confirmed = 0, wrongTool = 0, noAgent = 0, unknownVerdict = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let verdict = String(cString: sqlite3_column_text(stmt, 0))
            let count = Int(sqlite3_column_int64(stmt, 1))
            rated += count
            switch verdict {
            case AttributionOverride.Verdict.confirmed.rawValue: confirmed = count
            case AttributionOverride.Verdict.wrongTool.rawValue: wrongTool = count
            case AttributionOverride.Verdict.noAgent.rawValue:   noAgent = count
            case AttributionOverride.Verdict.unknown.rawValue:   unknownVerdict = count
            default: break
            }
        }

        // Total events that received any machine attribution.
        var totalStmt: OpaquePointer?
        defer { if let s = totalStmt { sqlite3_finalize(s) } }
        let sql2 = "SELECT COUNT(*) FROM events WHERE agent_trace_id IS NOT NULL OR agent_tool IS NOT NULL"
        var total = 0
        if sqlite3_prepare_v2(db, sql2, -1, &totalStmt, nil) == SQLITE_OK,
           sqlite3_step(totalStmt) == SQLITE_ROW {
            total = Int(sqlite3_column_int64(totalStmt, 0))
        }

        return AttributionOverrideStats(
            ratedCount: rated,
            confirmedCount: confirmed,
            wrongToolCount: wrongTool,
            noAgentCount: noAgent,
            unknownVerdictCount: unknownVerdict,
            totalEventsWithMachineAttribution: total
        )
    }

    /// v1.9 PR-5 audit (B3): roll-up surface used by AttributionOverrideStore
    /// to compute `AttributionOverrideStats`. This is a read-only query
    /// — works under the dashboard's read-only fallback path on a
    /// root-owned `events.db`. Counts events that received any machine
    /// attribution (either via TRACEPARENT or lineage).
    public func eventCountWithMachineAttribution() throws -> Int {
        guard let db else { return 0 }
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        let sql = "SELECT COUNT(*) FROM events WHERE agent_trace_id IS NOT NULL OR agent_tool IS NOT NULL"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return 0
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Sweep override rows whose `event_id` no longer points at a row in
    /// `events`. Pass 12 invariant: every override row has a matching
    /// event row, so this is called from the existing retention sweep.
    /// Returns the number of orphaned rows removed.
    @discardableResult
    public func purgeOrphanedAttributionOverrides() throws -> Int {
        guard let db else { return 0 }
        // NOTE: a NOT IN subquery is fine here because the overrides
        // table is small (operator-rated events only) and this runs
        // alongside the rest of the retention sweep. If overrides ever
        // grow large enough for this to matter, switch to a LEFT JOIN
        // delete pattern.
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            DELETE FROM attribution_overrides WHERE rowid IN (
                SELECT rowid FROM attribution_overrides
                WHERE event_id NOT IN (SELECT id FROM events)
                ORDER BY rowid LIMIT ?1
            )
            """
        var changes = 0
        while true {
            try admitStorageMaintenanceWrite(
                estimatedTransactionBytes: estimate
            )
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
                  let stmt else {
                let msg = String(cString: sqlite3_errmsg(db))
                throw EventStoreError.prepareFailed(msg)
            }
            sqlite3_bind_int(stmt, 1, batch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                let msg = String(cString: sqlite3_errmsg(db))
                throw EventStoreError.stepFailed("purge attribution overrides failed: \(msg)")
            }
            let deleted = Int(sqlite3_changes(db))
            changes += deleted
            if deleted == 0 { break }
        }
        return changes
    }
}
