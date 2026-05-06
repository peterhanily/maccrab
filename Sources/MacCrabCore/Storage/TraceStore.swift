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
import SQLite3
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
        if !isReadOnly {
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
        let oldUmask = umask(0o027)
        let (handle, ro, stmt) = try Self.openDatabase(at: databasePath)
        umask(oldUmask)
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.encryption = encryption
        chmod(databasePath, 0o640)
        chmod(databasePath + "-wal", 0o640)
        chmod(databasePath + "-shm", 0o640)
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
}
