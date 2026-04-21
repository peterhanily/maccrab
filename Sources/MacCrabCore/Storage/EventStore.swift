// EventStore.swift
// MacCrabCore
//
// SQLite-backed event store using the sqlite3 C API directly (no dependencies).
// Uses WAL journal mode for concurrent reads during writes.
// Thread-safe via Swift actor isolation.

import Foundation
import Darwin
import SQLite3
import os.log

// MARK: - EventStoreError

/// Errors that can occur during event store operations.
public enum EventStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)
    case encodingFailed(String)
    case decodingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let msg):  return "Database open failed: \(msg)"
        case .prepareFailed(let msg):       return "Prepare failed: \(msg)"
        case .stepFailed(let msg):          return "Step failed: \(msg)"
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

    // MARK: Prepared statement cache

    private var insertStmt: OpaquePointer?

    /// Whether this store was opened in read-only mode (fallback for non-owner access).
    private var isReadOnly = false

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
            throw EventStoreError.databaseOpenFailed(msg)
        }

        if !isReadOnly {
            Self.exec(handle, "PRAGMA journal_mode = WAL")
            Self.exec(handle, "PRAGMA synchronous = NORMAL")
            Self.exec(handle, "PRAGMA wal_autocheckpoint = 10000")  // Checkpoint every 10K pages (~40MB) instead of default 1K
            Self.exec(handle, "PRAGMA cache_size = -64000")  // 64MB cache (negative = KB)
            Self.exec(handle, "PRAGMA mmap_size = 268435456")  // 256MB memory-mapped I/O
        }
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
        if !isReadOnly {
            try SchemaMigrator.run(on: handle, migrations: Self.schemaMigrations)
        }

        // Prepare insert statement
        let insertSQL = """
            INSERT OR REPLACE INTO events (
                id, timestamp, event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)
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
    public init(directory: String = "/Library/Application Support/MacCrab") throws {
        let maccrabDir = URL(fileURLWithPath: directory)

        try FileManager.default.createDirectory(
            at: maccrabDir,
            withIntermediateDirectories: true,
            attributes: nil
        )
        // rwxr-xr-x: non-root MacCrab.app needs to traverse and read the DB
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: maccrabDir.path
        )

        self.databasePath = maccrabDir.appendingPathComponent("events.db").path

        // umask 0o027 ⇒ new SQLite WAL/SHM files get created 0o640 instead
        // of the world-readable 0o644 that umask 0o022 produced through
        // v1.3.8. 0o600 would be tighter but breaks the dashboard, which
        // runs as the user (typically admin-group) and needs read access
        // to render alerts/events. The directory stays 0o755 so dashboard
        // can traverse it.
        let oldUmask = umask(0o027)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        // Explicitly tighten any pre-existing files from an old install that
        // were created under the looser 0o644 default.
        chmod(databasePath, 0o640)
        chmod(databasePath + "-wal", 0o640)
        chmod(databasePath + "-shm", 0o640)
    }

    /// Creates an `EventStore` at a custom path (useful for testing).
    ///
    /// - Parameter path: Full file system path for the SQLite database.
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
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

    /// Persists a single event to the store.
    ///
    /// The event is serialised to JSON for the `raw_json` column, and
    /// commonly-queried fields are extracted into their own columns.
    ///
    /// - Parameter event: The event to store.
    /// - Throws: `EventStoreError` on serialisation or database failure.
    public func insert(event: Event) throws {
        guard let stmt = insertStmt else {
            throw EventStoreError.prepareFailed("Insert statement not prepared")
        }

        // Sanitize the command line to redact secrets (passwords, tokens, API keys)
        // before persisting to the database.
        let sanitizedCommandLine = CommandSanitizer.sanitize(event.process.commandLine)

        // Build the event with a sanitized process for JSON serialisation.
        let sanitizedProcess = ProcessInfo(
            pid: event.process.pid,
            ppid: event.process.ppid,
            rpid: event.process.rpid,
            name: event.process.name,
            executable: event.process.executable,
            commandLine: sanitizedCommandLine,
            args: event.process.args.map { CommandSanitizer.sanitize($0) },
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
        let sanitizedEvent = Event(
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

        let jsonData: Data
        do {
            jsonData = try encoder.encode(sanitizedEvent)
        } catch {
            throw EventStoreError.encodingFailed(error.localizedDescription)
        }
        guard let jsonString = String(data: jsonData, encoding: .utf8) else {
            throw EventStoreError.encodingFailed("Failed to convert JSON data to string")
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

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw EventStoreError.stepFailed(msg)
        }
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

    /// Performs a full-text search across indexed event fields.
    ///
    /// Uses the FTS5 virtual table to search process names, paths, command
    /// lines, file paths, network destinations, and TCC fields.
    ///
    /// - Parameters:
    ///   - text: The search query (FTS5 syntax supported).
    ///   - limit: Maximum number of results (default 100).
    /// - Returns: Matching events ordered by relevance.
    public func search(text: String, limit: Int = 100) throws -> [Event] {
        let sql = """
            SELECT e.raw_json
            FROM events e
            JOIN events_fts fts ON e.rowid = fts.rowid
            WHERE events_fts MATCH ?1
            ORDER BY fts.rank
            LIMIT ?2
            """
        return try queryEvents(sql: sql, bindings: [
            (1, .text(text)),
            (2, .int(Int32(limit)))
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
}
