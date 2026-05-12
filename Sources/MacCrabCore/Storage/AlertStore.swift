// AlertStore.swift
// MacCrabCore
//
// SQLite-backed alert store using the sqlite3 C API directly (no dependencies).
// Uses WAL journal mode for concurrent reads during writes.
// Thread-safe via Swift actor isolation.

import Foundation
import Darwin
import SQLite3
import os.log

// MARK: - AlertStoreError

/// Errors that can occur during alert store operations.
public enum AlertStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let msg):  return "Database open failed: \(msg)"
        case .prepareFailed(let msg):       return "Prepare failed: \(msg)"
        case .stepFailed(let msg):          return "Step failed: \(msg)"
        }
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
///
/// Indexes cover the common query patterns: time-range, rule, severity,
/// and the composite triage path `(timestamp, severity, suppressed)`.
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
    private let databasePath: String

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
        // v3 (v1.11.1): persist the Alert "phantom" enrichments — D3FEND
        // chips, remediation hint, analyst metadata. Pre-v1.11.1 the V2
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

    /// Opens a SQLite database, creates schema, and prepares statements before
    /// actor isolation begins. Returns all handles so init can assign directly.
    private static func openDatabase(at path: String) throws -> (OpaquePointer, Bool, OpaquePointer?) {
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
        var flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
        var rc = sqlite3_open_v2(path, &db, flags, nil)
        if rc != SQLITE_OK {
            if let handle = db { sqlite3_close(handle) }
            db = nil
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = sqlite3_open_v2(path, &db, flags, nil)
            isReadOnly = true
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let db { sqlite3_close(db) }
            throw AlertStoreError.databaseOpenFailed(msg)
        }

        if !isReadOnly {
            // v1.6.22: pragmas centralized in StoragePragmas.applyAlertStorePragmas.
            // Alerts table is much smaller than events; uses tighter 4 MB cache
            // + 16 MB mmap.
            StoragePragmas.applyAlertStorePragmas(to: handle)
        }
        // v1.4.4 — see EventStore.swift for the busy_timeout rationale.
        Self.exec(handle, "PRAGMA busy_timeout = 5000")
        Self.exec(handle, "PRAGMA foreign_keys = ON")

        // Create schema
        let schemaSQLs = [
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                rule_id TEXT NOT NULL, rule_title TEXT NOT NULL,
                severity TEXT NOT NULL, event_id TEXT NOT NULL,
                process_path TEXT, process_name TEXT, description TEXT,
                mitre_tactics TEXT, mitre_techniques TEXT,
                suppressed INTEGER DEFAULT 0
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
        for sql in schemaSQLs { Self.exec(handle, sql) }

        // Apply versioned schema migrations on top of the baseline tables above.
        // v1 marks "baseline schema present"; later versions add columns for
        // campaign linkage, host context, analyst metadata, etc.
        if !isReadOnly {
            try SchemaMigrator.run(on: handle, migrations: Self.schemaMigrations)
        }

        // Prepare insert statement
        let insertSQL = """
            INSERT OR REPLACE INTO alerts (
                id, timestamp, rule_id, rule_title, severity,
                event_id, process_path, process_name, description,
                mitre_tactics, mitre_techniques, suppressed,
                llm_investigation_json,
                d3fend_techniques, remediation_hint, analyst_metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
            """
        var insertStmt: OpaquePointer?
        if sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw AlertStoreError.prepareFailed(msg)
        }

        return (handle, isReadOnly, insertStmt)
    }

    /// Execute a SQL statement on a raw handle (used during init before actor is live).
    /// Execute SQL on a raw handle and surface the error via os.log on
    /// failure. See the EventStore.exec comment for the rationale.
    private static func exec(_ db: OpaquePointer, _ sql: String) {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            Logger(subsystem: "com.maccrab.storage", category: "alert-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
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
    /// - Throws: `AlertStoreError` if the database cannot be opened or initialized.
    public init(directory: String = "/Library/Application Support/MacCrab") throws {
        let maccrabDir = URL(fileURLWithPath: directory)

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

        self.databasePath = maccrabDir.appendingPathComponent("alerts.db").path
        // See EventStore.init for why 0o007/0o660 (not 0o077/0o600 or
        // 0o027/0o640): sysext writes as root, dashboard runs as the
        // admin-group user and needs *write* access to suppress alerts.
        // 0o660 gives the admin-group dashboard the rw it needs without
        // making DBs world-readable.
        let oldUmask = umask(0o007)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        chmod(databasePath, 0o660)
        chmod(databasePath + "-wal", 0o660)
        chmod(databasePath + "-shm", 0o660)
    }

    /// Creates an `AlertStore` at a custom path (useful for testing).
    ///
    /// - Parameter path: Full file system path for the SQLite database.
    /// - Throws: `AlertStoreError` if the database cannot be opened or initialized.
    public init(path: String) throws {
        self.databasePath = path
        let (handle, ro, stmt) = try Self.openDatabase(at: path)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
    }

    deinit {
        if let insertStmt { sqlite3_finalize(insertStmt) }
        if let db { sqlite3_close(db) }
    }


    // MARK: - Insert

    /// Persists a single alert to the store.
    ///
    /// - Parameter alert: The alert to store.
    /// - Throws: `AlertStoreError` on database failure.
    public func insert(alert: Alert) throws {
        guard let stmt = insertStmt else {
            throw AlertStoreError.prepareFailed("Insert statement not prepared")
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
        // (schema v3, v1.11.1). Pre-v1.11.1 these existed on `Alert`
        // but were dropped on persist; the V2 inspector hid the chips
        // post-restart even though they'd been computed at alert time.
        if let d3fend = alert.d3fendTechniques, !d3fend.isEmpty {
            bindText(stmt, index: 14, value: d3fend.joined(separator: ","))
        } else {
            sqlite3_bind_null(stmt, 14)
        }
        // 15: remediation_hint — first-line guidance (schema v3, v1.11.1).
        bindTextOrNull(stmt, index: 15, value: alert.remediationHint)
        // 16: analyst_metadata_json — analyst workflow state (notes,
        // owner, status, ticket ref). Codable JSON blob (schema v3, v1.11.1).
        if let analyst = alert.analyst,
           let data = try? Self.investigationEncoder.encode(analyst),
           let json = String(data: data, encoding: .utf8) {
            bindText(stmt, index: 16, value: json)
        } else {
            sqlite3_bind_null(stmt, 16)
        }

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
    }

    /// Persists a batch of alerts inside a single transaction.
    ///
    /// - Parameter alerts: The alerts to store.
    /// - Throws: `AlertStoreError` on database failure.
    public func insert(alerts: [Alert]) throws {
        try execute("BEGIN TRANSACTION")
        do {
            for alert in alerts {
                try insert(alert: alert)
            }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
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

    /// Marks an alert as suppressed.
    ///
    /// - Parameter id: The alert's unique identifier.
    /// - Throws: `AlertStoreError` on database failure.
    public func suppress(alertId id: String) throws {
        let sql = "UPDATE alerts SET suppressed = 1 WHERE id = ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
    }

    /// Suppress every alert that belongs to a given campaign in a single
    /// SQL statement. Returns the number of rows updated.
    ///
    /// v1.11.1 (audit perf HIGH): pre-fix the MCP `suppress_campaign`
    /// handler pulled up to 10K alerts then issued a serial `suppress`
    /// per match. With 5K matching alerts × 6ms / write that wedged the
    /// handler for ~30s. Single SQL `UPDATE WHERE campaign_id = ?` is
    /// O(matched rows) at the page level, with a single COMMIT.
    @discardableResult
    public func suppress(campaignId id: String) throws -> Int {
        let sql = "UPDATE alerts SET suppressed = 1 WHERE campaign_id = ?1 AND suppressed = 0"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
        }
        return db.map { Int(sqlite3_changes($0)) } ?? 0
    }

    /// v1.11.1 (audit perf HIGH): SQL-side AI-Guard alert filter.
    /// Pre-fix the MCP `get_ai_alerts` handler pulled 10K alerts then
    /// substring-matched 8 keywords across rule_id + title in Swift.
    /// AI-Guard rule ids follow a stable prefix convention
    /// (`ai_tool_*`, `ai_guard_*`, `credential_fence_*`, `boundary_*`,
    /// `injection_*`, `mcp_*`, `prompt_*`), so a single SQL `LIKE`
    /// chain selects only the relevant rows.
    public func aiAlerts(since: Date, limit: Int) throws -> [Alert] {
        let sql = """
            SELECT * FROM alerts
             WHERE timestamp >= ?1
               AND suppressed = 0
               AND (rule_id LIKE 'ai_%'
                 OR rule_id LIKE 'maccrab.ai-guard.%'
                 OR rule_id LIKE 'credential_fence_%'
                 OR rule_id LIKE 'boundary_%'
                 OR rule_id LIKE 'injection_%'
                 OR rule_id LIKE 'mcp_%'
                 OR rule_id LIKE 'prompt_%')
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
        let sql = "UPDATE alerts SET suppressed = 0 WHERE id = ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
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
        let sql = "DELETE FROM alerts WHERE id = ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: id)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
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
        let batchSize: Int32 = 100_000
        let timestamp = date.timeIntervalSince1970
        var totalDeleted = 0

        let sql = """
            DELETE FROM alerts WHERE rowid IN (
                SELECT rowid FROM alerts WHERE timestamp < ?1
                ORDER BY rowid LIMIT ?2
            )
            """

        while true {
            let stmt = try prepare(sql)
            sqlite3_bind_double(stmt, 1, timestamp)
            sqlite3_bind_int(stmt, 2, batchSize)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
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
        let batchSize: Int32 = min(100_000, Int32(count))
        var remaining = count
        var totalDeleted = 0

        let sql = """
            DELETE FROM alerts WHERE rowid IN (
                SELECT rowid FROM alerts ORDER BY timestamp ASC LIMIT ?1
            )
            """

        while remaining > 0 {
            let thisBatch = min(batchSize, Int32(remaining))
            let stmt = try prepare(sql)
            sqlite3_bind_int(stmt, 1, thisBatch)
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
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
            throw AlertStoreError.stepFailed(msg)
        }
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
            // 9: mitre_tactics, 10: mitre_techniques, 11: suppressed

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
            // v1.11.1). Each is independently nullable — a row written
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
                analyst: analyst,
                d3fendTechniques: d3fend,
                remediationHint: remediation,
                llmInvestigation: investigation
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
        let sql = "UPDATE alerts SET llm_investigation_json = ?1 WHERE id = ?2"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        bindText(stmt, index: 1, value: json)
        bindText(stmt, index: 2, value: alertId)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AlertStoreError.stepFailed(msg)
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
