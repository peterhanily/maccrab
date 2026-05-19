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
    private var insertStmt: OpaquePointer?
    private let databasePath: String
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
            if let h = db { sqlite3_close(h) }
            db = nil
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = sqlite3_open_v2(path, &db, flags, nil)
            isReadOnly = true
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let db { sqlite3_close(db) }
            throw AttributionOverrideStoreError.databaseOpenFailed(msg)
        }

        // Tiny store; conservative pragmas.
        // v1.12.6 Wave 9L: auto_vacuum = INCREMENTAL MUST be set
        // BEFORE journal_mode = WAL. SQLite silently refuses to flip
        // auto_vacuum once WAL setup has dirtied the DB header. Wave
        // 9B.1 fixed this across the five primary stores but missed
        // AttributionOverrideStore. Tiny-store impact is small but
        // the invariant is uniform — see StoragePragmas.swift comment.
        if !isReadOnly {
            sqlite3_exec(handle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA cache_size = -2000", nil, nil, nil)   // 2 MB
            sqlite3_exec(handle, "PRAGMA temp_store = MEMORY", nil, nil, nil)
        }
        sqlite3_exec(handle, "PRAGMA busy_timeout = 5000", nil, nil, nil)

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
        for sql in schema {
            if sqlite3_exec(handle, sql, nil, nil, nil) != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(handle))
                Logger(subsystem: "com.maccrab.storage", category: "attribution-overrides")
                    .error("schema exec failed: \(sql, privacy: .public) — \(msg, privacy: .public)")
            }
        }
        if !isReadOnly {
            try SchemaMigrator.run(on: handle, migrations: Self.schemaMigrations)
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
        if isReadOnly {
            stmt = nil
        } else if sqlite3_prepare_v2(handle, upsert, -1, &stmt, nil) != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            sqlite3_close(handle)
            throw AttributionOverrideStoreError.prepareFailed(msg)
        }
        return (handle, isReadOnly, stmt)
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
    public init(directory: String) throws {
        let url = URL(fileURLWithPath: directory)
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true, attributes: nil
        )
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: url.path
        )
        self.databasePath = url.appendingPathComponent("attribution_overrides.db").path
        let oldUmask = umask(0o022)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
    }

    /// Test-only path init.
    public init(path: String) throws {
        self.databasePath = path
        let (handle, ro, stmt) = try Self.openDatabase(at: path)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
    }

    deinit {
        if let s = insertStmt { sqlite3_finalize(s) }
        if let d = db { sqlite3_close(d) }
    }

    // MARK: - API

    /// UPSERT a verdict. Replaces on event_id collision; bumps
    /// updated_at. Single source of truth per event.
    public func record(_ override: AttributionOverride) throws {
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
        if sqlite3_step(stmt) != SQLITE_DONE {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw AttributionOverrideStoreError.stepFailed(msg)
        }
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
