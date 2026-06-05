// TraceStore.swift
// MacCrabCore
//
// v1.9 Agent Traces (PR-3a) — append-only store of OTLP-ingested spans.
//
// Lives in its OWN file (`traces.db`) per Pass 5 (events.db handle count
// must be exactly 2) and Pass 10 (co-resident store migration discipline).
// `traces.db` is brand-new, so its `PRAGMA user_version` chain starts at 1.
//
// PR-3a ships schema + a single-span insert API + a per-trace lookup. The
// stub OTLPReceiver in PR-3a does not yet wire to this store (it
// decodes-and-drops); PR-3b adds the receive-side sanitizer and writes
// here. Storing the schema + insert path now lets the unit tests pin the
// shape of the data we'll soon be writing.
//
// `attributes_json` carries already-sanitised KeyValue pairs as compact
// JSON. Sanitisation runs at the receiver boundary — anything stored here
// must already have secrets/PII redacted.

import Foundation
import CSQLCipher
import os.log

// MARK: - TraceStoreError

public enum TraceStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case insertFailed(String)
    case queryFailed(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "TraceStore: open failed: \(m)"
        case .prepareFailed(let m):       return "TraceStore: prepare failed: \(m)"
        case .insertFailed(let m):        return "TraceStore: insert failed: \(m)"
        case .queryFailed(let m):         return "TraceStore: query failed: \(m)"
        }
    }
}

// MARK: - SpanRecord

/// A single span as MacCrab persists it. Reduced to the fields rules and the
/// dashboard actually need — full proto round-trip is intentionally NOT a
/// goal (PR-3b's sanitizer drops vendor-specific attribute payloads anyway).
public struct SpanRecord: Sendable, Codable, Equatable {
    public let traceId: String           // 32 lowercase hex
    public let spanId: String            // 16 lowercase hex
    public let parentSpanId: String?     // 16 lowercase hex or nil
    public let startNs: UInt64           // start_time_unix_nano
    public let endNs: UInt64             // end_time_unix_nano
    public let serviceName: String?      // resource.service.name
    public let spanName: String          // span.name
    /// Best-effort agent tool resolution per Plan v3 review #6 ordering:
    /// span_name prefix > service.name > gen_ai.provider.name > legacy
    /// gen_ai.system > lineage. Stored verbatim from whichever resolution
    /// step won. Stored alongside the raw provider/legacy fields below for
    /// audit.
    public let agentTool: AIToolType?
    public let providerName: String?     // gen_ai.provider.name (current)
    public let legacyGenAiSystem: String? // gen_ai.system (deprecated)
    /// Sanitised KeyValue attributes as compact JSON. Receiver-side sanitiser
    /// guarantees no `*KEY*`/`*TOKEN*`/`*SECRET*`-shaped values reach this
    /// column.
    public let attributesJson: String?

    public init(
        traceId: String,
        spanId: String,
        parentSpanId: String?,
        startNs: UInt64,
        endNs: UInt64,
        serviceName: String?,
        spanName: String,
        agentTool: AIToolType?,
        providerName: String?,
        legacyGenAiSystem: String?,
        attributesJson: String?
    ) {
        self.traceId = traceId
        self.spanId = spanId
        self.parentSpanId = parentSpanId
        self.startNs = startNs
        self.endNs = endNs
        self.serviceName = serviceName
        self.spanName = spanName
        self.agentTool = agentTool
        self.providerName = providerName
        self.legacyGenAiSystem = legacyGenAiSystem
        self.attributesJson = attributesJson
    }
}

// MARK: - TraceStore

/// Actor wrapping a SQLite handle to `traces.db`. Single long-lived handle
/// — Pass 5's "events.db handles == 2" invariant doesn't apply here (this
/// is a different file) but the underlying discipline does.
public actor TraceStore {

    // MARK: Properties

    private var db: OpaquePointer?
    private var insertStmt: OpaquePointer?
    private let databasePath: String
    private var isReadOnly = false
    /// v1.9 Phase-2.2: optional column-level AES-GCM for `attributes_json`.
    /// When set, span attributes are encrypted with the ENC2: prefix before
    /// write and decrypted on read. Legacy plaintext rows decode unchanged
    /// (DatabaseEncryption.decrypt returns the input as-is when it doesn't
    /// see the prefix). Pass `nil` for plaintext (test/dev paths).
    private let encryption: DatabaseEncryption?

    private let logger = Logger(subsystem: "com.maccrab.storage", category: "trace-store")

    // MARK: - Schema migrations

    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "baseline_spans",
            sql: []
        ),
    ]

    // MARK: Initialization

    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return
        }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw TraceStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
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
            throw TraceStoreError.databaseOpenFailed(msg)
        }

        // Tighter pragmas than EventStore — traces are bursty + small;
        // 8 MB cache + 32 MB mmap is comfortable.
        //
        // Wave 9B.1 (v1.12.6 RC2): auto_vacuum MUST come BEFORE journal_mode
        // — SQLite silently refuses to flip auto_vacuum once the DB header
        // has been dirtied by WAL setup. Pre-9B.1 TraceStore never set
        // auto_vacuum, so traces.db stayed in mode 0 (NONE) and
        // incrementalVacuum's reclaim path was a no-op. See the matching
        // ordering note in StoragePragmas.applyEventStorePragmas.
        if !isReadOnly {
            sqlite3_exec(handle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA journal_mode = WAL", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA cache_size = -8000", nil, nil, nil)   // 8 MB
            sqlite3_exec(handle, "PRAGMA mmap_size = 33554432", nil, nil, nil) // 32 MB
            sqlite3_exec(handle, "PRAGMA temp_store = MEMORY", nil, nil, nil)
            sqlite3_exec(handle, "PRAGMA wal_autocheckpoint = 1000", nil, nil, nil)
        }
        sqlite3_exec(handle, "PRAGMA busy_timeout = 5000", nil, nil, nil)

        // Schema. PRIMARY KEY (trace_id, span_id) makes inserts idempotent —
        // duplicate spans (a re-export from the same agent) replace silently.
        let schemaSQLs = [
            """
            CREATE TABLE IF NOT EXISTS spans (
                trace_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                parent_span_id TEXT,
                start_ns INTEGER NOT NULL,
                end_ns INTEGER NOT NULL,
                service_name TEXT,
                span_name TEXT NOT NULL,
                agent_tool TEXT,
                provider_name TEXT,
                legacy_gen_ai_system TEXT,
                attributes_json TEXT,
                PRIMARY KEY (trace_id, span_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id)",
            "CREATE INDEX IF NOT EXISTS idx_spans_start ON spans(start_ns)",
        ]
        for sql in schemaSQLs {
            if sqlite3_exec(handle, sql, nil, nil, nil) != SQLITE_OK {
                let msg = String(cString: sqlite3_errmsg(handle))
                Logger(subsystem: "com.maccrab.storage", category: "trace-store")
                    .error("schema exec failed: \(sql, privacy: .public) — \(msg, privacy: .public)")
            }
        }

        if !isReadOnly {
            try SchemaMigrator.run(on: handle, migrations: Self.schemaMigrations)
        }

        let insertSQL = """
            INSERT OR REPLACE INTO spans (
                trace_id, span_id, parent_span_id,
                start_ns, end_ns,
                service_name, span_name, agent_tool,
                provider_name, legacy_gen_ai_system,
                attributes_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            """
        var stmt: OpaquePointer?
        if sqlite3_prepare_v2(handle, insertSQL, -1, &stmt, nil) != SQLITE_OK {
            // v1.9 audit Phase-1.6: close the handle before throwing.
            // Pre-fix the handle leaked because no cleanup ran on the
            // prepare-failure path. Mirrors AttributionOverrideStore +
            // EventStore pattern.
            let msg = String(cString: sqlite3_errmsg(handle))
            sqlite3_close(handle)
            throw TraceStoreError.prepareFailed(msg)
        }

        return (handle, isReadOnly, stmt)
    }

    /// Open `traces.db` in the default support directory.
    /// v1.9 Phase-2.2: pass an `encryption` instance to encrypt
    /// `attributes_json` at rest. Nil = plaintext (compat for tests
    /// + non-daemon callers).
    public init(
        directory: String = "/Library/Application Support/MacCrab",
        encryption: DatabaseEncryption? = nil
    ) throws {
        let url = URL(fileURLWithPath: directory)
        try FileManager.default.createDirectory(
            at: url, withIntermediateDirectories: true, attributes: nil
        )
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: url.path
        )
        self.databasePath = url.appendingPathComponent("traces.db").path
        let oldUmask = umask(0o007)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.encryption = encryption
        chmod(databasePath, 0o660)
        chmod(databasePath + "-wal", 0o660)
        chmod(databasePath + "-shm", 0o660)
    }

    /// Open at a custom path (used by tests).
    public init(path: String, encryption: DatabaseEncryption? = nil) throws {
        self.databasePath = path
        let (handle, ro, stmt) = try Self.openDatabase(at: path)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.encryption = encryption
    }

    deinit {
        if let s = insertStmt { sqlite3_finalize(s) }
        if let d = db { sqlite3_close(d) }
    }

    // MARK: - API

    /// Batch-insert spans inside a single transaction.
    ///
    /// v1.11.1 (audit perf HIGH): pre-fix `OTLPReceiver` called
    /// `insertSpan` per span inside the request handler. WAL mode means
    /// each INSERT is its own implicit COMMIT + fsync — at 500-1000
    /// spans per OTLP request that's 500-1000 fsyncs / request body.
    /// Wrapping the loop in `BEGIN; ...; COMMIT;` collapses to a single
    /// COMMIT + fsync. Returns (succeeded, failed) counts so the
    /// receiver can keep the per-span error metric accurate.
    @discardableResult
    public func insertSpans(_ records: [SpanRecord]) throws -> (succeeded: Int, failed: Int) {
        guard !records.isEmpty else { return (0, 0) }
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        var succeeded = 0
        var failed = 0
        sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil)
        for record in records {
            do {
                try insertSpan(record)
                succeeded += 1
            } catch {
                failed += 1
                // Don't let one bad span abort the whole batch.
            }
        }
        sqlite3_exec(db, "COMMIT", nil, nil, nil)
        return (succeeded, failed)
    }

    /// Insert (or replace) a single sanitised span.
    /// Caller must have already run the receiver-side sanitiser over
    /// `record.attributesJson`.
    public func insertSpan(_ record: SpanRecord) throws {
        guard let stmt = insertStmt else {
            throw TraceStoreError.insertFailed("insert statement not prepared")
        }
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)

        // SQLITE_TRANSIENT (-1) tells SQLite to copy strings.
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, record.traceId, -1, TRANSIENT)
        sqlite3_bind_text(stmt, 2, record.spanId, -1, TRANSIENT)
        if let psp = record.parentSpanId { sqlite3_bind_text(stmt, 3, psp, -1, TRANSIENT) }
        else { sqlite3_bind_null(stmt, 3) }
        sqlite3_bind_int64(stmt, 4, Int64(bitPattern: record.startNs))
        sqlite3_bind_int64(stmt, 5, Int64(bitPattern: record.endNs))
        if let s = record.serviceName { sqlite3_bind_text(stmt, 6, s, -1, TRANSIENT) }
        else { sqlite3_bind_null(stmt, 6) }
        sqlite3_bind_text(stmt, 7, record.spanName, -1, TRANSIENT)
        if let t = record.agentTool { sqlite3_bind_text(stmt, 8, t.rawValue, -1, TRANSIENT) }
        else { sqlite3_bind_null(stmt, 8) }
        if let p = record.providerName { sqlite3_bind_text(stmt, 9, p, -1, TRANSIENT) }
        else { sqlite3_bind_null(stmt, 9) }
        if let l = record.legacyGenAiSystem { sqlite3_bind_text(stmt, 10, l, -1, TRANSIENT) }
        else { sqlite3_bind_null(stmt, 10) }
        // v1.9 Phase-2.2: encrypt-on-write when a DatabaseEncryption
        // is wired. encrypt() emits the ENC2: prefix; nil-passthrough
        // when `encryption` is nil keeps test/dev paths plaintext.
        if let a = record.attributesJson {
            let encoded = encryption?.encrypt(a) ?? a
            sqlite3_bind_text(stmt, 11, encoded, -1, TRANSIENT)
        } else { sqlite3_bind_null(stmt, 11) }

        if sqlite3_step(stmt) != SQLITE_DONE {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.insertFailed(msg)
        }
    }

    /// Look up all spans for a given trace_id, ordered by start_ns ascending.
    public func spansForTrace(_ traceId: String) throws -> [SpanRecord] {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        let sql = """
            SELECT trace_id, span_id, parent_span_id,
                   start_ns, end_ns,
                   service_name, span_name, agent_tool,
                   provider_name, legacy_gen_ai_system,
                   attributes_json
            FROM spans
            WHERE trace_id = ?1
            ORDER BY start_ns ASC
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, traceId, -1, TRANSIENT)

        var out: [SpanRecord] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let traceIdStr = String(cString: sqlite3_column_text(stmt, 0))
            let spanIdStr = String(cString: sqlite3_column_text(stmt, 1))
            let parentSpan: String? = sqlite3_column_type(stmt, 2) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 2))
            let startNs = UInt64(bitPattern: sqlite3_column_int64(stmt, 3))
            let endNs = UInt64(bitPattern: sqlite3_column_int64(stmt, 4))
            let serviceName: String? = sqlite3_column_type(stmt, 5) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 5))
            let spanName = String(cString: sqlite3_column_text(stmt, 6))
            let agentTool: AIToolType? = sqlite3_column_type(stmt, 7) == SQLITE_NULL
                ? nil
                : AIToolType(rawValue: String(cString: sqlite3_column_text(stmt, 7)))
            let providerName: String? = sqlite3_column_type(stmt, 8) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 8))
            let legacy: String? = sqlite3_column_type(stmt, 9) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 9))
            let storedAttrs: String? = sqlite3_column_type(stmt, 10) == SQLITE_NULL
                ? nil
                : String(cString: sqlite3_column_text(stmt, 10))
            // v1.9 Phase-2.2: decrypt-on-read. decrypt() is a passthrough
            // for legacy plaintext rows (no ENC: prefix), so backfill is
            // automatic — pre-encryption rows still readable.
            let attrs: String? = storedAttrs.map { encryption?.decrypt($0) ?? $0 }
            out.append(SpanRecord(
                traceId: traceIdStr, spanId: spanIdStr,
                parentSpanId: parentSpan,
                startNs: startNs, endNs: endNs,
                serviceName: serviceName, spanName: spanName,
                agentTool: agentTool,
                providerName: providerName,
                legacyGenAiSystem: legacy,
                attributesJson: attrs
            ))
        }
        return out
    }

    /// Distinct trace_ids ordered by most-recent activity (max start_ns
    /// per trace). Used by `AgentTracesView` to render the recent-traces
    /// list. `limit` defaults to 200 — enough for several days of agent
    /// activity on a busy machine.
    public func recentTraceIds(limit: Int = 200) throws -> [String] {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        let sql = """
            SELECT trace_id, MAX(start_ns) AS latest
            FROM spans
            GROUP BY trace_id
            ORDER BY latest DESC
            LIMIT ?1
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        sqlite3_bind_int(stmt, 1, Int32(max(1, limit)))
        var out: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(String(cString: sqlite3_column_text(stmt, 0)))
        }
        return out
    }

    /// Total span count (for tests / metrics).
    public func count() throws -> Int {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM spans", -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            return 0
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Retention
    //
    // v1.10.0 audit fix: traces.db (introduced in v1.9 for OTLP/HTTP
    // span ingestion) had no prune/retention. On a developer machine
    // running Claude Code daily this grew 0.5–2 GB/month indefinitely.
    // Match EventStore's prune shape so the daily retention sweep
    // can drive both with the same timer.

    /// Delete every span whose `start_ns` is older than `cutoff`.
    /// Returns the number of rows removed.
    @discardableResult
    public func prune(olderThan cutoff: Date) throws -> Int {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        let cutoffNs = Int64(cutoff.timeIntervalSince1970 * 1_000_000_000)
        let sql = "DELETE FROM spans WHERE start_ns < ?1"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int64(stmt, 1, cutoffNs)
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        return Int(sqlite3_changes(db))
    }

    /// Drop the oldest `count` spans by `start_ns` ascending. Used as
    /// the size-cap escape hatch when the daemon's storage enforcer
    /// notices traces.db has exceeded its budget.
    @discardableResult
    public func pruneOldest(count: Int) throws -> Int {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        guard count > 0 else { return 0 }
        let sql = """
            DELETE FROM spans WHERE rowid IN (
                SELECT rowid FROM spans ORDER BY start_ns ASC LIMIT ?1
            )
            """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(count))
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed(msg)
        }
        return Int(sqlite3_changes(db))
    }

    /// Database file size in bytes — used by the storage enforcer.
    public func databaseSizeBytes() -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: databasePath)
        return (attrs?[.size] as? Int64) ?? 0
    }

    /// Live (non-freelist) data size = (page_count − freelist_count) × page_size.
    /// Unlike `databaseSizeBytes()` (the on-disk file footprint), this drops the
    /// moment rows are DELETEd. Because traces.db runs `auto_vacuum = INCREMENTAL`
    /// (set in openDatabase), freed pages sit on the freelist until a vacuum, so
    /// the FILE size does NOT shrink mid-prune-loop. The size-cap enforcer must
    /// break on THIS — breaking on the file size makes the loop run to its
    /// iteration cap and over-prune (the v1.18 traces.db sibling of the
    /// tracegraph over-prune fix).
    public func liveDataSizeBytes() -> Int64 {
        guard let db = db else { return 0 }
        func pragmaInt(_ name: String) -> Int64 {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &stmt, nil) == SQLITE_OK else { return 0 }
            defer { sqlite3_finalize(stmt) }
            return sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : 0
        }
        let pages = pragmaInt("page_count")
        let free = pragmaInt("freelist_count")
        let pageSize = pragmaInt("page_size")
        return max(0, (pages - free) * pageSize)
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6; auto_vacuum=INCREMENTAL since RC2)
    //
    // traces.db sets `auto_vacuum = INCREMENTAL` in openDatabase (before
    // journal_mode — SQLite refuses to flip it once the header is written), so
    // `incrementalVacuum` reclaims freelist pages to the OS. (Pre-RC2 the mode
    // was NONE and this was a no-op; any traces.db created then stays in mode 0
    // until a one-shot full VACUUM, which the caller handles on low disk.)
    @discardableResult
    public func incrementalVacuum(maxPages: Int) async throws -> Int {
        guard let db = db else { return 0 }
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: maxPages)
        return result.pagesReclaimed
    }

    /// Best-effort VACUUM. Required as the second leg of the Wave 9B
    /// low-disk fallback (full VACUUM also rewrites the file with
    /// the new auto_vacuum mode if PRAGMA was changed beforehand).
    public func vacuum() async throws {
        guard let db = db else { return }
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed("VACUUM failed: \(msg)")
        }
    }

    /// PASSIVE→RESTART checkpoint chain — used by the size-cap path
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

    /// Read the file's current `auto_vacuum` mode. Used by callers
    /// that want to log the gap when this DB is not in INCREMENTAL
    /// mode (mode 2). Mode 0 = NONE, 1 = FULL, 2 = INCREMENTAL.
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }
}
