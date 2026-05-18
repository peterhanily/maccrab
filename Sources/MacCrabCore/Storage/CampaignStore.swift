// CampaignStore.swift
// MacCrabCore
//
// SQLite-backed persistent store for detected campaigns.
// Campaigns were previously kept in-memory only in CampaignDetector; this
// store survives restarts and lets the dashboard query campaigns
// independently of the detection actor.

import Foundation
import Darwin
import SQLite3
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
    private let databasePath: String
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private var insertStmt: OpaquePointer?
    private var isReadOnly = false

    // MARK: - Init

    /// Throw `CampaignStoreError.databaseOpenFailed` if `path` exists and is a
    /// symbolic link. A missing file is always OK — SQLite will create it.
    /// Matches the guard EventStore and AlertStore already apply: without this,
    /// a privileged attacker can swap the DB for a symlink pointing at an
    /// arbitrary root-owned file and redirect writes.
    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return
        }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw CampaignStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
        }
    }

    /// - Parameter forceReadOnly: When `true`, open with
    ///   `SQLITE_OPEN_READONLY` and skip the RW attempt. See
    ///   `EventStore.openDatabase` for the v1.12.6 Wave 9A background.
    private static func openDatabase(at path: String, forceReadOnly: Bool = false) throws -> (OpaquePointer, Bool, OpaquePointer?) {
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")

        var db: OpaquePointer?
        var isReadOnly = false
        var flags: Int32
        var rc: Int32
        if forceReadOnly {
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
            throw CampaignStoreError.databaseOpenFailed(msg)
        }

        if !isReadOnly {
            // Wave 9B.1 (v1.12.6 RC2): auto_vacuum MUST come BEFORE journal_mode
            // — SQLite silently refuses to flip auto_vacuum after the WAL setup
            // dirties the DB header. Pre-9B.1 fresh campaigns.db landed at
            // mode 0 (NONE) silently.
            Self.exec(handle, "PRAGMA auto_vacuum = INCREMENTAL")
            Self.exec(handle, "PRAGMA journal_mode = WAL")
            Self.exec(handle, "PRAGMA synchronous = NORMAL")
        }
        // v1.4.4 — see EventStore.swift for the busy_timeout rationale.
        Self.exec(handle, "PRAGMA busy_timeout = 5000")
        Self.exec(handle, "PRAGMA foreign_keys = ON")

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
            "CREATE INDEX IF NOT EXISTS idx_campaigns_first_seen ON campaigns(first_seen)",
        ]
        for sql in schemaSQLs {
            Self.exec(handle, sql)
        }

        if !isReadOnly {
            // v1.12.0 RC27 (perf): consistency with EventStore /
            // AlertStore / SQLiteCausalGraphStore — skip per-init
            // quick_check on the boot path. Round-10 perf audit caught
            // this as the only store still doing PRAGMA quick_check
            // synchronously.
            try SchemaMigrator.run(
                on: handle,
                migrations: Self.schemaMigrations,
                skipQuickCheck: true
            )
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
        if sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            throw CampaignStoreError.prepareFailed(msg)
        }

        return (handle, isReadOnly, insertStmt)
    }

    /// Execute SQL on a raw handle and surface the error via os.log on
    /// failure. See the EventStore.exec comment for the rationale.
    private static func exec(_ db: OpaquePointer, _ sql: String) {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            Logger(subsystem: "com.maccrab.storage", category: "campaign-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
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
    public init(directory: String = "/Library/Application Support/MacCrab", forceReadOnly: Bool = false) throws {
        let dir = URL(fileURLWithPath: directory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)

        self.databasePath = dir.appendingPathComponent("campaigns.db").path
        // See EventStore.init for rationale behind 0o007/0o660.
        let oldUmask = umask(0o007)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath, forceReadOnly: forceReadOnly)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        if !forceReadOnly {
            chmod(databasePath, 0o660)
            chmod(databasePath + "-wal", 0o660)
            chmod(databasePath + "-shm", 0o660)
        }
    }

    /// Open a CampaignStore at a custom path (useful for tests).
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

    /// Persist a campaign record. Overwrites any record with the same id.
    public func insert(_ r: Record) throws {
        guard let stmt = insertStmt else {
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

        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)

        bindText(stmt, index: 1, value: r.id)
        sqlite3_bind_double(stmt, 2, r.detectedAt.timeIntervalSince1970)
        bindText(stmt, index: 3, value: r.type)
        bindText(stmt, index: 4, value: r.severity.rawValue)
        bindText(stmt, index: 5, value: r.title)
        bindText(stmt, index: 6, value: r.tactics.joined(separator: ","))
        sqlite3_bind_double(stmt, 7, r.timeSpanSeconds)
        sqlite3_bind_int(stmt, 8, r.suppressed ? 1 : 0)
        bindTextOrNull(stmt, index: 9, value: r.notes)
        bindText(stmt, index: 10, value: jsonString)

        // v1.12.6 Wave 2C: aggregate attribution columns. JSON-encode the
        // string arrays; on encoder failure (unreachable for [String], but
        // we fail closed) bind NULL rather than blocking the campaign
        // persist — the raw_json blob still carries the full Record.
        bindTextOrNull(stmt, index: 11, value: encodeStringArrayOrNil(r.affectedUsers))
        bindTextOrNull(stmt, index: 12, value: encodeStringArrayOrNil(r.affectedExecutables))
        bindDoubleOrNull(stmt, index: 13, value: r.firstSeen?.timeIntervalSince1970)
        bindDoubleOrNull(stmt, index: 14, value: r.lastSeen?.timeIntervalSince1970)
        if let depth = r.processTreeDepth {
            sqlite3_bind_int(stmt, 15, Int32(depth))
        } else {
            sqlite3_bind_null(stmt, 15)
        }
        bindTextOrNull(stmt, index: 16, value: encodeStringArrayOrNil(r.techniques))
        bindTextOrNull(stmt, index: 17, value: encodeStringArrayOrNil(r.aiTools))

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            // v1.12.6 Wave 9N: surface SQLITE_FULL / SQLITE_IOERR_NOSPC
            // distinctly so disk-pressure isn't masked as a generic
            // step failure. Same shape as EventStore + AlertStore.
            if rc == SQLITE_FULL || (rc & 0xFF) == SQLITE_FULL || rc == 0x0D0A {
                throw CampaignStoreError.diskFull(msg)
            }
            throw CampaignStoreError.stepFailed(msg)
        }
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
        let sql = "DELETE FROM campaigns WHERE detected_at < ?1"
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, date.timeIntervalSince1970)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw CampaignStoreError.stepFailed(msg)
        }
        return Int(sqlite3_changes(db))
    }

    /// v1.8.0: drop the oldest `count` campaigns by detected_at. Defense-in-
    /// depth size cap when campaigns.db exceeds `campaignsMaxSizeMB`. Tiny
    /// table in practice — this exists for parity with the events / alerts
    /// stores rather than because campaigns ever fill 50 MB on real workloads.
    @discardableResult
    public func pruneOldest(count: Int) async throws -> Int {
        guard count > 0 else { return 0 }
        let sql = """
            DELETE FROM campaigns WHERE id IN (
                SELECT id FROM campaigns ORDER BY detected_at ASC LIMIT ?1
            )
            """
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(count))
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw CampaignStoreError.stepFailed(msg)
        }
        return Int(sqlite3_changes(db))
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
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: maxPages)
        return result.pagesReclaimed
    }

    /// Best-effort VACUUM. campaigns.db is small enough that this
    /// almost never gates on disk space, but the size-cap timer
    /// callers want a consistent API across all four stores.
    public func vacuum() async throws {
        guard let db = db else { return }
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw CampaignStoreError.stepFailed("VACUUM failed: \(msg)")
        }
    }

    /// PASSIVE→RESTART checkpoint chain. Used by the size-cap path
    /// to drain the WAL before measuring on-disk footprint.
    @discardableResult
    public func walCheckpoint() async -> Bool {
        guard let db = db else { return false }
        var passiveLog: Int32 = 0
        var passiveCkpt: Int32 = 0
        let rcPassive = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_PASSIVE),
            &passiveLog, &passiveCkpt
        )
        if rcPassive == SQLITE_OK, passiveLog == passiveCkpt { return true }

        var restartLog: Int32 = 0
        var restartCkpt: Int32 = 0
        let rcRestart = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_RESTART),
            &restartLog, &restartCkpt
        )
        return rcRestart == SQLITE_OK && restartLog == restartCkpt
    }

    /// Read the file's `PRAGMA auto_vacuum` mode. Returns 0/1/2
    /// (NONE / FULL / INCREMENTAL); 0 on closed/error.
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }

    // MARK: - Private helpers

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
