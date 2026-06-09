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
    case diskFull(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let msg):  return "Database open failed: \(msg)"
        case .prepareFailed(let msg):       return "Prepare failed: \(msg)"
        case .stepFailed(let msg):          return "Step failed: \(msg)"
        case .diskFull(let msg):            return "Disk full: \(msg)"
        case .encodingFailed(let msg):      return "Encoding failed: \(msg)"
        case .decodingFailed(let msg):      return "Decoding failed: \(msg)"
        }
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
    private let databasePath: String
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
        // `event_aggregates` (≤30 day rollup) and any alert-anchored ±60s
        // window of events gets copied into `alert_evidence` (kept
        // forever, bounded by alert count).
        //
        // Replaces the size-cap-and-VACUUM dance at DaemonTimers.swift —
        // pre-fix that approach silently let the file grow to 1.8 GB+ on
        // busy machines because per-tick VACUUM kept failing or being
        // skipped. The tier model is bounded by design: events table
        // never holds more than ~24h, aggregates are <5 MB, evidence
        // grows as alerts × ~120s of events.
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
    private static func openDatabase(at path: String, forceReadOnly: Bool = false) throws -> (OpaquePointer, Bool, OpaquePointer?) {
        // Reject symlinks on the DB path and its WAL/SHM/journal sidecars.
        // `sqlite3_open_v2` follows symlinks, so a privileged attacker who can
        // swap the DB file for a symlink could redirect writes to an arbitrary
        // target. `lstat` (attributesOfItem) does NOT follow.
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")

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
            rc = sqlite3_open_v2(path, &db, flags, nil)
            isReadOnly = true
        } else {
            flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
            rc = sqlite3_open_v2(path, &db, flags, nil)
            if rc != SQLITE_OK {
                if let handle = db { sqlite3_close(handle) }
                db = nil
                flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
                rc = sqlite3_open_v2(path, &db, flags, nil)
                isReadOnly = true
            }
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let db { sqlite3_close(db) }
            throw EventStoreError.databaseOpenFailed(msg)
        }

        if !isReadOnly {
            // v1.6.22: pragmas centralized in StoragePragmas.applyEventStorePragmas.
            // Cut from 64 MB cache + 256 MB mmap (v1.6.21) to 16 MB + 64 MB after
            // 2.76 GB resident observation on a test host with 2 long-lived
            // connections to events.db (EventStore + AlertStore).
            StoragePragmas.applyEventStorePragmas(to: handle)
        }
        // v1.4.4: `busy_timeout = 5000` tells SQLite to retry a busy-lock
        // for up to 5 seconds instead of failing immediately with
        // SQLITE_BUSY. Default is 0 (no retry). Fixes the class of
        // transient "database is locked" errors v1.4.3's fail-loud
        // banner surfaced — WAL autocheckpoint briefly holds the write
        // lock, and without a timeout the next insert fails.
        Self.exec(handle, "PRAGMA busy_timeout = 5000")
        Self.exec(handle, "PRAGMA foreign_keys = ON")

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
            // Wave-3 P1: query an agent session's events in time order. Partial
            // index keeps it cheap — only AI-correlated rows are indexed.
            "CREATE INDEX IF NOT EXISTS idx_events_ai_session ON events(ai_tool_session_id, timestamp) WHERE ai_tool_session_id IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category)",
            "CREATE INDEX IF NOT EXISTS idx_events_process_path ON events(process_path)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_events_ts_severity ON events(timestamp, severity)",
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
        ]
        for sql in schemaSQLs { Self.exec(handle, sql) }

        // Apply versioned schema migrations on top of the baseline tables above.
        // v1 marks "baseline schema present"; later versions add columns for
        // enrichment fields (file/process hashes, session context, etc).
        //
        // v1.8.0 hardening: catch + log instead of throw. SQLite can return
        // SQLITE_OK from sqlite3_open_v2 with READWRITE flags against a
        // file the OS will later refuse writes on (root-owned 0640 +
        // user-uid open succeeds at the open syscall but EACCESs at the
        // first WRITE). Pre-fix, this surfaced as a fatal error in any
        // user-uid CLI tool that touched the root daemon's DB. Now we
        // log and continue — the store is still readable, which is what
        // the CLI actually needs for status / events / hunt.
        if !isReadOnly {
            do {
                // v1.12.0: skip the per-init quick_check — it's a 1–2 s
                // PRAGMA on the 962 MB events.db with FTS5 indexes and
                // accounts for most of the perceived cold-start cost on
                // the daemon's boot path. Callers re-invoke
                // `runQuickCheck()` from a deferred Task once the store
                // is up.
                try SchemaMigrator.run(
                    on: handle,
                    migrations: Self.schemaMigrations,
                    skipQuickCheck: true
                )
            } catch {
                Logger(subsystem: "com.maccrab.storage", category: "event-store")
                    .warning("Schema migration skipped (likely opened RW but DB is effectively read-only for this uid): \(error.localizedDescription, privacy: .public)")
            }
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
        let insertSQL = """
            INSERT OR REPLACE INTO events (
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
        if sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw EventStoreError.prepareFailed(msg)
        }

        return (handle, isReadOnly, insertStmt)
    }

    /// Execute a SQL statement on a raw handle (used during init before actor is live).
    /// Execute SQL on a raw handle and surface the error to os.log when it
    /// fails. PRAGMAs used to be silently ignored; a failed `journal_mode =
    /// WAL` (corrupt DB, disk-full, read-only filesystem) would leave the
    /// store in a quieter fallback mode with no visible signal. `.public`
    /// interpolation keeps the diagnostic useful under `sudo log show`
    /// (values here are SQL strings and SQLite return codes, never user
    /// secrets).
    private static func exec(_ db: OpaquePointer, _ sql: String) {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
        }
    }

    /// Creates an `EventStore` backed by a SQLite database at the default location.
    ///
    /// The database is stored at `~/Library/Application Support/MacCrab/events.db`.
    /// The directory is created if it does not already exist.
    ///
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
    public init(directory: String = "/Library/Application Support/MacCrab", forceReadOnly: Bool = false) throws {
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

        self.databasePath = maccrabDir.appendingPathComponent("events.db").path

        // umask 0o007 ⇒ new SQLite WAL/SHM files get created 0o660. The
        // dashboard runs as the admin-group user and needs write access
        // (suppress, mutate). 0o640 (the v1.3.8 → v1.10.0 default) gave
        // group-read only, which made bulk-suppress fail with
        // "database is read only". 0o660 keeps non-admin users locked
        // out while letting the dashboard mutate without an XPC broker.
        // (Skip umask + chmod entirely when forceReadOnly — see Wave 9A.)
        if forceReadOnly {
            let (handle, ro, stmt) = try Self.openDatabase(at: databasePath, forceReadOnly: true)
            self.db = handle
            self.isReadOnly = ro
            self.insertStmt = stmt
        } else {
            let oldUmask = umask(0o007)
            let (handle, ro, stmt) = try Self.openDatabase(at: databasePath, forceReadOnly: false)
            umask(oldUmask)
            self.db = handle
            self.isReadOnly = ro
            self.insertStmt = stmt
            // Re-clamp existing files from prior installs that were created
            // under the older 0o640 default.
            chmod(databasePath, 0o660)
            chmod(databasePath + "-wal", 0o660)
            chmod(databasePath + "-shm", 0o660)
        }
    }

    /// Creates an `EventStore` at a custom path (useful for testing).
    ///
    /// - Parameter path: Full file system path for the SQLite database.
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
    public init(path: String, forceReadOnly: Bool = false) throws {
        self.databasePath = path
        let (handle, ro, stmt) = try Self.openDatabase(at: path, forceReadOnly: forceReadOnly)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
    }

    deinit {
        if let insertStmt { sqlite3_finalize(insertStmt) }
        if let db { sqlite3_close(db) }
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
        // v1.8.0 Layer 1: drop noise events at insert. Cheaper than letting
        // them hit SQLite + FTS5 + indexes. Self-monitoring (daemon watches
        // its own log/DB) was 17% of volume on field-measured hardware.
        if let filter = insertFilter, filter.shouldDrop(event: event) {
            return
        }
        guard let stmt = insertStmt else {
            throw EventStoreError.prepareFailed("Insert statement not prepared")
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
        // 10: process_commandline (sanitized)
        bindText(stmt, index: 10, value: sanitizedCommandLine)
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
        // the enricher hasn't classified the parent chain yet.
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
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            // v1.12.0 RC28 audit fix (Resil-B1): surface SQLITE_FULL
            // distinctly so EventLoop can stop trying to insert (no
            // point hammering a full disk) instead of treating it as
            // a transient step failure. SQLite errors here can also
            // be SQLITE_IOERR_NOSPC (extended code 0x0D0A) which has
            // the same semantic.
            if rc == SQLITE_FULL || (rc & 0xFF) == SQLITE_FULL || rc == 0x0D0A {
                throw EventStoreError.diskFull(msg)
            }
            throw EventStoreError.stepFailed(msg)
        }
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
    ///   3. As a last-resort fail-open, truncate the raw JSON string
    ///      itself to `maxRawJsonBytes - margin` and append a tail
    ///      marker. The row will no longer JSON-parse cleanly — downstream
    ///      decoders are expected to read the truncation enrichments
    ///      first and skip raw_json reconstruction.
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

        // Pass 3 (fail-open): brute-force truncate the JSON string. We
        // never block insert — better to land a partially-readable row
        // than to lose the event and the truncation signal entirely.
        let tail = "<...truncated>"
        let margin = tail.utf8.count + 16
        let target = max(0, Self.maxRawJsonBytes - margin)
        let rawString: String
        if let data = try? encoder.encode(mutated),
           let s = String(data: data, encoding: .utf8) {
            rawString = s
        } else {
            // Should be unreachable — mutated is built from sanitizedEvent
            // which encoded successfully above. Fall back to a stub.
            rawString = "{\"payload\":\"unencodable\"}"
        }
        // Slice on UTF-8 byte boundary — may land mid-codepoint, so walk
        // back a few bytes until we hit valid UTF-8. Bounded by `margin`.
        let utf8Bytes = Array(rawString.utf8)
        var sliceEnd = min(target, utf8Bytes.count)
        var truncated = ""
        while sliceEnd > 0 {
            if let s = String(data: Data(utf8Bytes.prefix(sliceEnd)), encoding: .utf8) {
                truncated = s
                break
            }
            sliceEnd -= 1
        }
        truncated.append(tail)

        log.warning("Payload truncation fell through to fail-open path for event \(sanitizedEvent.id.uuidString, privacy: .public) (\(originalBytes) bytes)")
        return TruncatedPayload(event: mutated, string: truncated)
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

    /// Persists a batch of events inside a single transaction.
    ///
    /// - Parameter events: The events to store.
    /// - Throws: `EventStoreError` on serialisation or database failure.
    public func insert(events: [Event]) throws {
        try execute("BEGIN TRANSACTION")
        do {
            for event in events {
                try insert(event: event)
            }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
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
    /// - Returns: The total number of events deleted across all batches.
    @discardableResult
    public func prune(olderThan date: Date) async throws -> Int {
        let batchSize: Int32 = 100_000
        let timestamp = date.timeIntervalSince1970
        var totalDeleted = 0

        // Batch: delete FTS entries for the next batch of stale events, then delete
        // the events themselves. Repeat until no rows remain older than `date`.
        //
        // Using a rowid IN (SELECT rowid … LIMIT N) subquery avoids the need for
        // the SQLITE_ENABLE_UPDATE_DELETE_LIMIT compile-time flag, which may not
        // be set in the system SQLite.
        let deleteFTS = """
            DELETE FROM events_fts WHERE rowid IN (
                SELECT rowid FROM events WHERE timestamp < ?1
                ORDER BY rowid LIMIT ?2
            )
            """
        let deleteEvents = """
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events WHERE timestamp < ?1
                ORDER BY rowid LIMIT ?2
            )
            """

        while true {
            // FTS batch
            let ftsStmt = try prepare(deleteFTS)
            sqlite3_bind_double(ftsStmt, 1, timestamp)
            sqlite3_bind_int(ftsStmt, 2, batchSize)
            let rc1 = sqlite3_step(ftsStmt)
            sqlite3_finalize(ftsStmt)
            guard rc1 == SQLITE_DONE else {
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw EventStoreError.stepFailed("FTS prune failed: \(msg)")
            }

            // Events batch
            let evtStmt = try prepare(deleteEvents)
            sqlite3_bind_double(evtStmt, 1, timestamp)
            sqlite3_bind_int(evtStmt, 2, batchSize)
            let rc2 = sqlite3_step(evtStmt)
            sqlite3_finalize(evtStmt)
            guard rc2 == SQLITE_DONE else {
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw EventStoreError.stepFailed("Event prune failed: \(msg)")
            }

            let rowsDeleted = Int(sqlite3_changes(db))
            totalDeleted += rowsDeleted

            // No more rows in this batch — pruning is complete.
            if rowsDeleted == 0 { break }

            // Yield to the actor's cooperative executor so concurrent inserts and
            // queries are not starved between batches.
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
        if totalDeleted > 0, let db {
            sqlite3_exec(db, "PRAGMA incremental_vacuum(5000)", nil, nil, nil)
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
    @discardableResult
    public func pruneOldest(count: Int) async throws -> Int {
        guard count > 0 else { return 0 }
        let batchSize: Int32 = min(100_000, Int32(count))
        var remaining = count
        var totalDeleted = 0

        // Same pattern as prune(olderThan:) — delete FTS first so the
        // rowid subquery sees a stable event set, then the events.
        let deleteFTS = """
            DELETE FROM events_fts WHERE rowid IN (
                SELECT rowid FROM events ORDER BY timestamp ASC LIMIT ?1
            )
            """
        let deleteEvents = """
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events ORDER BY timestamp ASC LIMIT ?1
            )
            """

        while remaining > 0 {
            let thisBatch = min(batchSize, Int32(remaining))

            let ftsStmt = try prepare(deleteFTS)
            sqlite3_bind_int(ftsStmt, 1, thisBatch)
            let rc1 = sqlite3_step(ftsStmt)
            sqlite3_finalize(ftsStmt)
            guard rc1 == SQLITE_DONE else {
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw EventStoreError.stepFailed("FTS oldest-prune failed: \(msg)")
            }

            let evtStmt = try prepare(deleteEvents)
            sqlite3_bind_int(evtStmt, 1, thisBatch)
            let rc2 = sqlite3_step(evtStmt)
            sqlite3_finalize(evtStmt)
            guard rc2 == SQLITE_DONE else {
                let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
                throw EventStoreError.stepFailed("Event oldest-prune failed: \(msg)")
            }

            let deleted = Int(sqlite3_changes(db))
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

    /// Capture a snapshot of events within `windowSeconds` of the alert's
    /// timestamp into `alert_evidence`. Idempotent — re-running for the same
    /// `alertId` is safe (PRIMARY KEY on (alert_id, id) silently dedupes).
    ///
    /// Called from the alert-firing path so the dashboard's alert detail view
    /// can show "what else was happening when this fired?" even after the
    /// hot-tier retention drops the surrounding events.
    ///
    /// v1.8.0-rc6: capped at `maxRows` (default 50) to keep the evidence table
    /// bounded on high-volume hosts. Pre-cap, a 264 events/sec machine could
    /// drop ~30K rows per alert into evidence, and 1.6K alerts pushed the
    /// table past 800K rows / 2.4 GB on the field test host. Selection prefers
    /// higher-severity rows so the cap doesn't drop the most informative
    /// context — same-severity rows tie-break by closeness to the alert
    /// timestamp.
    public func recordAlertEvidence(
        alertId: String,
        alertTimestamp: Date,
        windowSeconds: TimeInterval = 30,
        maxRows: Int = 50
    ) throws {
        let lo = alertTimestamp.timeIntervalSince1970 - windowSeconds
        let hi = alertTimestamp.timeIntervalSince1970 + windowSeconds
        let alertTs = alertTimestamp.timeIntervalSince1970
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
            LIMIT ?5
            """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: alertId)
        sqlite3_bind_double(stmt, 2, lo)
        sqlite3_bind_double(stmt, 3, hi)
        sqlite3_bind_double(stmt, 4, alertTs)
        sqlite3_bind_int(stmt, 5, Int32(max(1, maxRows)))
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            throw EventStoreError.stepFailed("recordAlertEvidence failed: \(msg)")
        }
    }

    /// v1.8.0-rc6: trim alert_evidence to at most `perAlertMax` rows per
    /// alert. Selection prefers higher-severity + closer-to-alert rows.
    /// Used by the rollup sweep to bound an existing oversize evidence
    /// table — recordAlertEvidence above caps writes going forward, but
    /// existing rows from earlier releases need cleanup.
    @discardableResult
    public func pruneAlertEvidenceCap(perAlertMax: Int) async throws -> Int {
        guard perAlertMax > 0 else { return 0 }
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
            )
            """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(perAlertMax))
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            throw EventStoreError.stepFailed("pruneAlertEvidenceCap failed: \(msg)")
        }
        return Int(sqlite3_changes(db))
    }

    /// v1.8.0-rc6: drop alert_evidence rows older than `cutoff`. Aligns
    /// evidence retention with the parent alerts.db retention, so an
    /// orphaned evidence row whose alert was already pruned doesn't
    /// outlive the alert.
    @discardableResult
    public func pruneAlertEvidence(olderThan cutoff: Date) async throws -> Int {
        let sql = "DELETE FROM alert_evidence WHERE timestamp < ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, cutoff.timeIntervalSince1970)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown"
            throw EventStoreError.stepFailed("pruneAlertEvidence failed: \(msg)")
        }
        return Int(sqlite3_changes(db))
    }

    /// v1.17.5 (RC H2): bound the alert_evidence table by TOTAL payload size.
    /// Age + per-alert-cap pruning leave total size ungoverned, so on a busy
    /// host the table outgrew the events cap (field-observed 194 MB inside the
    /// 365-day window). Evicts the OLDEST rows across all alerts until the
    /// raw_json payload total is <= maxBytes. Returns rows deleted.
    @discardableResult
    public func pruneAlertEvidenceBySize(maxBytes: Int64, batchSize: Int = 2000) async throws -> Int {
        guard maxBytes > 0 else { return 0 }
        let batch = max(1, batchSize)
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
            let stmt = try prepare(
                "DELETE FROM alert_evidence WHERE rowid IN (SELECT rowid FROM alert_evidence ORDER BY timestamp ASC LIMIT \(batch))")
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
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

    /// Read events captured for `alertId` by `recordAlertEvidence`. Returns
    /// the surrounding ±windowSeconds of activity that the alert detail view
    /// renders. Empty if the alert pre-dates v1.8 evidence capture.
    public func evidenceFor(alertId: String) throws -> [Event] {
        let sql = "SELECT raw_json FROM alert_evidence WHERE alert_id = ?1 ORDER BY timestamp ASC"
        return try queryEvents(sql: sql, bindings: [(1, .text(alertId))])
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
    @discardableResult
    public func rollUpAndPrune(
        olderThan cutoff: Date,
        aggregateRetentionDays: Int = 30
    ) async throws -> Int {
        guard let db = db else { return 0 }

        // v1.8.0 audit fix: wrap aggregation + event-prune in a single
        // transaction. Pre-fix, a crash between Step 1 (INSERT INTO
        // event_aggregates ... ON CONFLICT DO UPDATE) and Step 2 (DELETE
        // events) caused silent double-counting on the next sweep — the
        // aggregates from the crashed run already existed, and re-aggregating
        // the same events on retry added to the existing counts.
        //
        // BEGIN IMMEDIATE acquires the write lock up front, so concurrent
        // actor writes queue behind it. The actor model already serializes
        // writes through this store, so the transaction is just a durability
        // guarantee — no additional latency over actor isolation alone.
        try execute("BEGIN IMMEDIATE TRANSACTION")
        var transactionCommitted = false
        defer {
            // Belt-and-braces: if we throw out of this function before the
            // explicit COMMIT, SQLite needs an explicit ROLLBACK to release
            // the write lock and discard partial aggregates.
            if !transactionCommitted {
                try? execute("ROLLBACK")
            }
        }

        // Step 1: roll up older events into daily aggregates.
        // strftime('%Y-%m-%d', timestamp, 'unixepoch') turns the REAL epoch
        // into a sortable ISO date string. UTC; localized display happens
        // in the UI layer.
        let aggregateSQL = """
            INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
            SELECT
                strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                event_category,
                COALESCE(process_signer, ''),
                COALESCE(process_path, ''),
                COUNT(*) AS c
            FROM events
            WHERE timestamp < ?1
            GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
            ON CONFLICT(day, event_category, process_signer, process_path)
            DO UPDATE SET count = count + excluded.count
            """
        let aggStmt = try prepare(aggregateSQL)
        sqlite3_bind_double(aggStmt, 1, cutoff.timeIntervalSince1970)
        guard sqlite3_step(aggStmt) == SQLITE_DONE else {
            let msg = String(cString: sqlite3_errmsg(db))
            sqlite3_finalize(aggStmt)
            throw EventStoreError.stepFailed("rollUp aggregate failed: \(msg)")
        }
        sqlite3_finalize(aggStmt)

        // Step 2: prune the rolled-up events. Reuses the existing batched
        // FTS+events delete loop — keeps the write lock from being held too
        // long on machines with 100K+ aged events to migrate on first run.
        // Inside the same transaction so a crash before COMMIT rolls back
        // both aggregates AND deletes atomically.
        let deleted = try await prune(olderThan: cutoff)

        try execute("COMMIT")
        transactionCommitted = true

        // Step 3: trim aggregates older than `aggregateRetentionDays`.
        // Independent + idempotent — runs outside the main transaction so it
        // doesn't block on Step 2's long delete batch. A crash here just
        // leaves stale aggregates that the next sweep cleans up.
        let aggDays = max(1, aggregateRetentionDays)
        let cutoffDay = Self.isoDay(Date().addingTimeInterval(-Double(aggDays) * 86400))
        let trimSQL = "DELETE FROM event_aggregates WHERE day < ?1"
        let trimStmt = try prepare(trimSQL)
        bindText(trimStmt, index: 1, value: cutoffDay)
        _ = sqlite3_step(trimStmt)
        sqlite3_finalize(trimStmt)

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
        _ = await walCheckpoint()
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.stepFailed("VACUUM failed: \(msg)")
        }
        _ = await walCheckpoint()
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
    public func walCheckpoint() async -> Bool {
        guard let db = db else { return false }
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
        return rcRestart == SQLITE_OK && restartLog == restartCkpt
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
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: maxPages)
        return result.pagesReclaimed
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

    // MARK: - Private Helpers

    /// A sum type for binding values to prepared statements.
    private enum BindingValue {
        case text(String)
        case double(Double)
        case int(Int32)
        case null
    }

    /// Executes a SQL statement that does not return rows.
    private func execute(_ sql: String) throws {
        var errmsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
        if rc != SQLITE_OK {
            let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
            sqlite3_free(errmsg)
            throw EventStoreError.stepFailed(msg)
        }
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
        if sqlite3_step(stmt) != SQLITE_DONE {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.stepFailed(msg)
        }
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
        let sql = """
            DELETE FROM attribution_overrides
            WHERE event_id NOT IN (SELECT id FROM events)
            """
        var changes = 0
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.prepareFailed(msg)
        }
        if sqlite3_step(stmt) == SQLITE_DONE {
            changes = Int(sqlite3_changes(db))
        }
        return changes
    }
}
