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

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "Campaign DB open failed: \(m)"
        case .prepareFailed(let m):      return "Campaign prepare failed: \(m)"
        case .stepFailed(let m):         return "Campaign step failed: \(m)"
        case .encodingFailed(let m):     return "Campaign encode failed: \(m)"
        case .decodingFailed(let m):     return "Campaign decode failed: \(m)"
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
            notes: String? = nil
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

    private static func openDatabase(at path: String) throws -> (OpaquePointer, Bool, OpaquePointer?) {
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
            throw CampaignStoreError.databaseOpenFailed(msg)
        }

        if !isReadOnly {
            Self.exec(handle, "PRAGMA journal_mode = WAL")
            Self.exec(handle, "PRAGMA synchronous = NORMAL")
        }
        // v1.4.4 — see EventStore.swift for the busy_timeout rationale.
        Self.exec(handle, "PRAGMA busy_timeout = 5000")
        Self.exec(handle, "PRAGMA foreign_keys = ON")

        let schemaSQLs = [
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
                raw_json TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_campaigns_detected_at ON campaigns(detected_at)",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_type ON campaigns(type)",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_severity ON campaigns(severity)",
            "CREATE INDEX IF NOT EXISTS idx_campaigns_sup_det ON campaigns(suppressed, detected_at)",
        ]
        for sql in schemaSQLs {
            Self.exec(handle, sql)
        }

        if !isReadOnly {
            try SchemaMigrator.run(on: handle, migrations: Self.schemaMigrations)
        }

        let insertSQL = """
            INSERT OR REPLACE INTO campaigns
              (id, detected_at, type, severity, title, tactics, time_span_seconds,
               suppressed, notes, raw_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
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
    public init(directory: String = "/Library/Application Support/MacCrab") throws {
        let dir = URL(fileURLWithPath: directory)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)

        self.databasePath = dir.appendingPathComponent("events.db").path
        // See EventStore.init for rationale behind 0o027/0o640.
        let oldUmask = umask(0o027)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        chmod(databasePath, 0o640)
        chmod(databasePath + "-wal", 0o640)
        chmod(databasePath + "-shm", 0o640)
    }

    /// Open a CampaignStore at a custom path (useful for tests).
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

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw CampaignStoreError.stepFailed(msg)
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
