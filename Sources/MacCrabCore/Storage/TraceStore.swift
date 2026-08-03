// TraceStore.swift
// MacCrabCore
//
// v1.9 Agent Traces (PR-3a) — store of OTLP-ingested spans. The ingest path
// only inserts/replaces; bounded actor-owned maintenance expires old rows.
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
import Darwin
import CSQLCipher
import os.log

// MARK: - TraceStoreError

public enum TraceStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case insertFailed(String)
    case queryFailed(String)
    case transactionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "TraceStore: open failed: \(m)"
        case .prepareFailed(let m):       return "TraceStore: prepare failed: \(m)"
        case .insertFailed(let m):        return "TraceStore: insert failed: \(m)"
        case .queryFailed(let m):         return "TraceStore: query failed: \(m)"
        case .transactionFailed(let m):   return "TraceStore: transaction failed: \(m)"
        }
    }
}

// MARK: - Storage admission

/// Why the OTLP span writer is refusing a growth mutation. Admission lives in
/// `TraceStore`, not only in `OTLPReceiver`, so future/import/test writers
/// cannot bypass the disk-safety contract by calling `insertSpan` directly.
public enum TraceStoreStorageBlockReason: String, Codable, Sendable, Equatable {
    case footprintLimit = "footprint_limit"
    case lowFreeSpace = "low_free_space"
    case probeFailure = "probe_failure"
    case mutationTooLarge = "mutation_too_large"
    case sqliteFull = "sqlite_full"
    case filesystemFull = "filesystem_full"
}

/// Typed storage-pressure failures. In particular, SQLite's own final
/// backstop is not flattened into a generic insert string: callers retain the
/// distinction between `SQLITE_FULL` and an `SQLITE_IOERR` whose VFS errno is
/// `ENOSPC`/`EDQUOT`.
public enum TraceStoreStorageAdmissionError: Error, LocalizedError, Sendable, Equatable {
    case footprintLimit(
        footprintBytes: Int64,
        admissionThresholdBytes: Int64,
        capBytes: Int64
    )
    case lowFreeSpace(
        freeBytes: Int64,
        floorBytes: Int64,
        requiredFreeBytes: Int64
    )
    case probeFailed(String)
    case mutationTooLarge(estimatedBytes: Int64, transactionReserveBytes: Int64)
    case sqliteFull(
        context: String,
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    )
    case filesystemFull(
        context: String,
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    )

    public var errorDescription: String? {
        switch self {
        case .footprintLimit(let footprint, let threshold, let cap):
            return "Agent-trace storage paused: SQLite-family footprint \(footprint) bytes reached the \(threshold)-byte admission threshold (absolute cap \(cap) bytes)"
        case .lowFreeSpace(let free, let floor, let required):
            return "Agent-trace storage paused: \(free) bytes free is below the \(required)-byte preflight requirement (\(floor)-byte hard floor plus transaction reserve)"
        case .probeFailed(let probe):
            return "Agent-trace storage paused: configured \(probe) probe failed"
        case .mutationTooLarge(let estimated, let reserve):
            return "Agent-trace storage paused: decoded batch upper bound \(estimated) bytes exceeds the \(reserve)-byte transaction reserve"
        case .sqliteFull(let context, let rc, let extended, let systemErrno):
            return "Agent-trace storage paused: SQLite full during \(context) (rc=\(rc), extended=\(extended), system_errno=\(systemErrno))"
        case .filesystemFull(let context, let rc, let extended, let systemErrno):
            return "Agent-trace storage paused: filesystem full/quota exhausted during \(context) (rc=\(rc), extended=\(extended), system_errno=\(systemErrno))"
        }
    }

    fileprivate var blockReason: TraceStoreStorageBlockReason {
        switch self {
        case .footprintLimit: return .footprintLimit
        case .lowFreeSpace: return .lowFreeSpace
        case .probeFailed: return .probeFailure
        case .mutationTooLarge: return .mutationTooLarge
        case .sqliteFull: return .sqliteFull
        case .filesystemFull: return .filesystemFull
        }
    }
}

public struct TraceStoreStorageAdmissionStatus: Sendable, Equatable {
    public let enabled: Bool
    public let blocked: Bool
    public let reason: TraceStoreStorageBlockReason?
    public let maxFootprintBytes: Int64?
    public let admissionThresholdBytes: Int64?
    public let transactionReserveBytes: Int64?
    public let footprintBytes: Int64?
    public let freeSpaceBytes: Int64?
    public let freeSpaceFloorBytes: Int64?
    public let shedMutationsTotal: UInt64
    public let pinnedReader: Bool
    public let recovering: Bool
}

public struct TraceStoreStorageRecoveryResult: Sendable, Equatable {
    public let pinnedReader: Bool
    public let spansDeleted: Int
    public let vacuumPagesReclaimed: Int
    public let footprintBytes: Int64?
    public let freeSpaceBytes: Int64?
    public let autoVacuumMode: Int
}

/// Injectable probes keep cap/floor behavior deterministic in tests. `nil` is
/// a probe failure and therefore fail-closed when its policy is enabled.
public typealias TraceStoreStorageProbe = @Sendable (_ path: String) -> Int64?

/// Single traces.db production policy shared by boot and SIGHUP reload.
public enum TraceStoreStoragePolicy {
    public static let bytesPerMiB: Int64 = 1_048_576
    public static let minimumCapMiB = 50
    public static let freeSpaceFloorBytes: Int64 = 1_024 * bytesPerMiB

    public static func capBytes(maxSizeMiB: Int) -> Int64 {
        let clampedMiB = max(
            minimumCapMiB,
            min(maxSizeMiB, Int(Int64.max / bytesPerMiB))
        )
        return Int64(clampedMiB) * bytesPerMiB
    }
}

/// Test-only fault seam for transaction-control statements. Production passes
/// nil. Skipping the named operation while returning these exact SQLite/VFS
/// codes lets tests prove that a failed COMMIT never reports committed rows.
public struct TraceStoreInjectedSQLiteFailure: Sendable, Equatable {
    public let resultCode: Int32
    public let extendedResultCode: Int32
    public let systemErrno: Int32

    public init(
        resultCode: Int32,
        extendedResultCode: Int32? = nil,
        systemErrno: Int32 = 0
    ) {
        self.resultCode = resultCode
        self.extendedResultCode = extendedResultCode ?? resultCode
        self.systemErrno = systemErrno
    }
}

public enum TraceStoreTransactionOperation: String, Sendable, Equatable {
    case begin
    case commit
    case rollback
}

public typealias TraceStoreTransactionFailureProbe = @Sendable (
    _ operation: TraceStoreTransactionOperation
) -> TraceStoreInjectedSQLiteFailure?

public enum TraceStorePragmaOperation: String, Sendable, Equatable, CaseIterable {
    case pageSizePrepare
    case pageSizeStep
    case maxPageCountPrepare
    case maxPageCountStep
    case pageCountPrepare
    case pageCountStep
    case journalSizeLimitPrepare
    case journalSizeLimitStep
}

public typealias TraceStorePragmaFailureProbe = @Sendable (
    _ operation: TraceStorePragmaOperation
) -> TraceStoreInjectedSQLiteFailure?

// MARK: - SpanRecord

/// Loopback is a network boundary, not an identity boundary: any local process
/// can submit OTLP. Deliberately expose no "authenticated" case until a real
/// authenticated transport is implemented and adversarially verified.
public enum AgentTraceTrust: String, Codable, Sendable, Equatable {
    case unauthenticatedSelfReported = "unauthenticated_self_reported"

    public var displayLabel: String { "Unauthenticated · self-reported" }
}

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
    /// Trust provenance for this span. OTLP loopback submissions are always
    /// unauthenticated/self-reported; they are advisory and must never become a
    /// detection authentication signal.
    public let trust: AgentTraceTrust

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
        attributesJson: String?,
        trust: AgentTraceTrust = .unauthenticatedSelfReported
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
        self.trust = trust
    }

    private enum CodingKeys: String, CodingKey {
        case traceId, spanId, parentSpanId, startNs, endNs, serviceName
        case spanName, agentTool, providerName, legacyGenAiSystem
        case attributesJson, trust
    }

    /// Backward JSON reads default old records to the only honest trust label.
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        traceId = try values.decode(String.self, forKey: .traceId)
        spanId = try values.decode(String.self, forKey: .spanId)
        parentSpanId = try values.decodeIfPresent(String.self, forKey: .parentSpanId)
        startNs = try values.decode(UInt64.self, forKey: .startNs)
        endNs = try values.decode(UInt64.self, forKey: .endNs)
        serviceName = try values.decodeIfPresent(String.self, forKey: .serviceName)
        spanName = try values.decode(String.self, forKey: .spanName)
        agentTool = try values.decodeIfPresent(AIToolType.self, forKey: .agentTool)
        providerName = try values.decodeIfPresent(String.self, forKey: .providerName)
        legacyGenAiSystem = try values.decodeIfPresent(String.self, forKey: .legacyGenAiSystem)
        attributesJson = try values.decodeIfPresent(String.self, forKey: .attributesJson)
        trust = try values.decodeIfPresent(AgentTraceTrust.self, forKey: .trust)
            ?? .unauthenticatedSelfReported
    }

    public func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(traceId, forKey: .traceId)
        try values.encode(spanId, forKey: .spanId)
        try values.encodeIfPresent(parentSpanId, forKey: .parentSpanId)
        try values.encode(startNs, forKey: .startNs)
        try values.encode(endNs, forKey: .endNs)
        try values.encodeIfPresent(serviceName, forKey: .serviceName)
        try values.encode(spanName, forKey: .spanName)
        try values.encodeIfPresent(agentTool, forKey: .agentTool)
        try values.encodeIfPresent(providerName, forKey: .providerName)
        try values.encodeIfPresent(legacyGenAiSystem, forKey: .legacyGenAiSystem)
        try values.encodeIfPresent(attributesJson, forKey: .attributesJson)
        try values.encode(trust, forKey: .trust)
    }
}

// MARK: - TraceStore

/// Actor wrapping a SQLite handle to `traces.db`. Single long-lived handle
/// — Pass 5's "events.db handles == 2" invariant doesn't apply here (this
/// is a different file) but the underlying discipline does.
public actor TraceStore {

    // MARK: Properties

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private var insertStmt: OpaquePointer?
    private let databasePath: String
    private var isReadOnly = false
    /// v1.9 Phase-2.2: optional column-level AES-GCM for `attributes_json`.
    /// When set, span attributes are encrypted with the ENC2: prefix before
    /// write and decrypted on read. Legacy plaintext rows decode unchanged
    /// (DatabaseEncryption.decrypt returns the input as-is when it doesn't
    /// see the prefix). Pass `nil` for plaintext (test/dev paths).
    private let encryption: DatabaseEncryption?

    /// Absolute cap for the exact live SQLite family: main + WAL + SHM.
    /// Admission stops at cap-reserve; max_page_count independently stops the
    /// main file at the same threshold if a logic bug bypasses preflight.
    private var maxFootprintBytes: Int64?
    private var freeSpaceFloorBytes: Int64?
    private var transactionReserveBytes: Int64?
    private var admissionThresholdBytes: Int64?
    private let storageVolumePath: String
    private let footprintProbe: TraceStoreStorageProbe
    private let freeSpaceProbe: TraceStoreStorageProbe
    private let transactionFailureProbe: TraceStoreTransactionFailureProbe?
    private let pragmaFailureProbe: TraceStorePragmaFailureProbe?
    private var lastFootprintBytes: Int64?
    private var lastFreeSpaceBytes: Int64?
    private var storageBlockReason: TraceStoreStorageBlockReason?
    private var shedMutationsTotal: UInt64 = 0
    private var sqliteStorageFailure: TraceStoreStorageAdmissionError?
    /// A monotonic generation prevents one recovery pass from clearing a newer
    /// FULL/ENOSPC failure observed re-entrantly during that pass.
    private var sqliteStorageFailureGeneration: UInt64 = 0
    private var pinnedReader = false
    private var recovering = false

    private static let mib: Int64 = 1_048_576
    private static let defaultMinimumTransactionReserve: Int64 = 8 * mib
    private static let defaultMaximumTransactionReserve: Int64 = 64 * mib
    private static let mutationBaseBytes: Int64 = 1 * mib
    private static let mutationBytesPerRow: Int64 = 16 * 1024

    private let logger = Logger(subsystem: "com.maccrab.storage", category: "trace-store")

    // MARK: - Schema migrations

    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "baseline_spans",
            sql: []
        ),
        // v1.21.6: plaintext SEARCHABLE PROJECTION beside the encrypted blob.
        // `attributes_json` is AES-GCM encrypted, which is correct — it carries
        // usernames, absolute project paths, session/org ids and tool inputs —
        // but it also made every span attribute unqueryable: no FTS, no LIKE,
        // no way to answer "which agent trace touched ~/.ssh/id_rsa". This
        // mirrors the pattern tracegraph.db already uses (trace_entities keeps
        // `display_name` in clear beside an encrypted `attributes_json`):
        // encrypt the bag, project the searchable substance.
        Migration(
            version: 2,
            name: "spans_search_projection",
            sql: [
                "ALTER TABLE spans ADD COLUMN search_text TEXT",
                "CREATE INDEX IF NOT EXISTS idx_spans_search ON spans(search_text)",
            ]
        ),
        Migration(
            version: 3,
            name: "spans_explicit_untrusted_provenance",
            sql: [
                "ALTER TABLE spans ADD COLUMN trust_label TEXT NOT NULL DEFAULT 'unauthenticated_self_reported'",
            ]
        ),
    ]

    // MARK: Initialization

    private static func rejectIfSymlink(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) == 0 {
            guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
                  info.st_nlink == 1 else {
                throw TraceStoreError.databaseOpenFailed(
                    "refusing unsafe or multiply-linked SQLite member: \(path)"
                )
            }
        } else if errno != ENOENT {
            throw TraceStoreError.databaseOpenFailed(
                "cannot inspect SQLite member \(path): errno \(errno)"
            )
        }
    }

    private static func openDatabase(
        at path: String,
        forceReadOnly: Bool,
        maximumMainFileBytes: Int64?,
        maxFootprintBytes: Int64?,
        freeSpaceFloorBytes: Int64?,
        transactionReserveBytes: Int64?,
        storageVolumePath: String,
        footprintProbe: @escaping TraceStoreStorageProbe,
        freeSpaceProbe: @escaping TraceStoreStorageProbe,
        pragmaFailureProbe: TraceStorePragmaFailureProbe?
    ) throws -> (
        OpaquePointer,
        Bool,
        OpaquePointer?,
        SQLiteControlledCheckpointController?
    ) {
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")

        var db: OpaquePointer?
        var isReadOnly = forceReadOnly
        // Decide read-only from the FILESYSTEM, not from sqlite3_open_v2's return
        // code. Opening READWRITE succeeds even on a file this process cannot
        // write — SQLite defers the permission check to the first write — so the
        // `isReadOnly` flag stayed false for every non-root reader (the uid-501
        // dashboard and CLI against the root-owned /Library store). That was
        // latent while no migration wrote at open time; the moment one did, every
        // non-root open failed with "attempt to write a readonly database".
        let fm = FileManager.default
        if !forceReadOnly,
           fm.fileExists(atPath: path),
           !fm.isWritableFile(atPath: path) {
            isReadOnly = true
        }
        // SQLiteOpenPathPolicy expands only macOS's trusted /var and /tmp
        // lexical aliases, then applies SQLITE_OPEN_NOFOLLOW to every path
        // component. Other parent symlinks intentionally fail.
        var flags = isReadOnly
            ? (SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX)
            : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_FULLMUTEX)
        var rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
        if rc != SQLITE_OK, !forceReadOnly {
            if let handle = db { sqlite3_close(handle) }
            db = nil
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
            isReadOnly = true
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let db { sqlite3_close(db) }
            throw TraceStoreError.databaseOpenFailed(msg)
        }
        var checkpointController: SQLiteControlledCheckpointController?
        var returnHandleToCaller = false
        defer {
            if !returnHandleToCaller {
                checkpointController?.detach(from: handle)
                sqlite3_close(handle)
            }
        }
        if !isReadOnly {
            checkpointController = try .install(
                on: handle,
                thresholdPages: StoragePragmas.walAutocheckpointPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: path,
                        storageVolumePath: storageVolumePath,
                        freeSpaceFloorBytes: freeSpaceFloorBytes ?? 0,
                        footprintProbe: footprintProbe,
                        freeSpaceProbe: freeSpaceProbe
                    ),
                ]
            )
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
            // Install the main-file backstop before *any* pragma/schema write.
            // journal_mode and auto_vacuum can dirty the header or create a
            // WAL, so installing this afterwards leaves an avoidable gap.
            try configureMaximumPageCount(
                on: handle,
                maximumMainFileBytes: maximumMainFileBytes,
                failureProbe: pragmaFailureProbe
            )
            try preflightSchemaStorageWork(
                SchemaStorageWork(
                    boundedMetadataStatementCount: 1,
                    rebuildStatementCount: 0
                ),
                databasePath: path,
                storageVolumePath: storageVolumePath,
                maxFootprintBytes: maxFootprintBytes,
                freeSpaceFloorBytes: freeSpaceFloorBytes,
                transactionReserveBytes: transactionReserveBytes,
                footprintProbe: footprintProbe,
                freeSpaceProbe: freeSpaceProbe
            )
            try execOpenPragmaChecked(
                on: handle, sql: "PRAGMA auto_vacuum = INCREMENTAL")
            try execOpenPragmaChecked(
                on: handle, sql: "PRAGMA journal_mode = WAL")
            try execOpenPragmaChecked(
                on: handle, sql: "PRAGMA synchronous = NORMAL")
            try execOpenPragmaChecked(
                on: handle, sql: "PRAGMA cache_size = -8000")
            try execOpenPragmaChecked(
                on: handle, sql: "PRAGMA mmap_size = 16777216")
            try execOpenPragmaChecked(
                on: handle, sql: "PRAGMA temp_store = MEMORY")
            // Keep an idle WAL from retaining more than the ordinary store
            // policy. Active transaction growth is bounded by admission.
            let journalLimit = min(
                StoragePragmas.journalSizeLimitBytes,
                maximumMainFileBytes ?? StoragePragmas.journalSizeLimitBytes
            )
            try setJournalSizeLimit(
                on: handle,
                bytes: journalLimit,
                failureProbe: pragmaFailureProbe,
                context: "open journal_size_limit"
            )
        }
        try execOpenPragmaChecked(on: handle, sql: "PRAGMA busy_timeout = 5000")

        // Schema. PRIMARY KEY (trace_id, span_id) makes inserts idempotent —
        // duplicate spans (a re-export from the same agent) replace silently.
        let createTableSQL = """
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
                search_text TEXT,
                trust_label TEXT NOT NULL DEFAULT 'unauthenticated_self_reported',
                PRIMARY KEY (trace_id, span_id)
            )
            """
        let indexSQLs = [
            "CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(trace_id)",
            "CREATE INDEX IF NOT EXISTS idx_spans_start ON spans(start_ns)",
            "CREATE INDEX IF NOT EXISTS idx_spans_search ON spans(search_text)",
        ]
        if !isReadOnly {
            try preflightSchemaStorageWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: [createTableSQL]
                ),
                databasePath: path,
                storageVolumePath: storageVolumePath,
                maxFootprintBytes: maxFootprintBytes,
                freeSpaceFloorBytes: freeSpaceFloorBytes,
                transactionReserveBytes: transactionReserveBytes,
                footprintProbe: footprintProbe,
                freeSpaceProbe: freeSpaceProbe
            )
            let createRC = sqlite3_exec(handle, createTableSQL, nil, nil, nil)
            if createRC != SQLITE_OK {
                throw sqliteFailure(
                    metadata: SQLiteFailureMetadata(resultCode: createRC, db: handle),
                    context: "span table setup"
                )
            }
            do {
                // Migrate before creating indexes that reference new columns.
                // A writable v1 database has no search_text column; the old
                // order attempted idx_spans_search first and failed before v2
                // could add it.
                try SchemaMigrator.run(
                    on: handle,
                    migrations: Self.schemaMigrations,
                    beforeStorageWork: { work in
                        try preflightSchemaStorageWork(
                            work,
                            databasePath: path,
                            storageVolumePath: storageVolumePath,
                            maxFootprintBytes: maxFootprintBytes,
                            freeSpaceFloorBytes: freeSpaceFloorBytes,
                            transactionReserveBytes: transactionReserveBytes,
                            footprintProbe: footprintProbe,
                            freeSpaceProbe: freeSpaceProbe
                        )
                    }
                )
            } catch let migration as SchemaMigrationError {
                if let failure = migration.sqliteFailureMetadata,
                   failure.isStorageExhaustion {
                    let error = sqliteFailure(
                        metadata: failure,
                        context: "schema migration"
                    )
                    throw error
                }
                throw migration
            }
            try preflightSchemaStorageWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: indexSQLs
                ),
                databasePath: path,
                storageVolumePath: storageVolumePath,
                maxFootprintBytes: maxFootprintBytes,
                freeSpaceFloorBytes: freeSpaceFloorBytes,
                transactionReserveBytes: transactionReserveBytes,
                footprintProbe: footprintProbe,
                freeSpaceProbe: freeSpaceProbe
            )
            for sql in indexSQLs {
                let schemaRC = sqlite3_exec(handle, sql, nil, nil, nil)
                if schemaRC != SQLITE_OK {
                    throw sqliteFailure(
                        metadata: SQLiteFailureMetadata(resultCode: schemaRC, db: handle),
                        context: "span index setup"
                    )
                }
            }
        }

        let insertSQL = """
            INSERT OR REPLACE INTO spans (
                trace_id, span_id, parent_span_id,
                start_ns, end_ns,
                service_name, span_name, agent_tool,
                provider_name, legacy_gen_ai_system,
                attributes_json, search_text, trust_label
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            """
        // A read-only store cannot insert, and preparing this statement against a
        // database whose migrations have NOT run (because we cannot write it)
        // fails on any column the migration would have added — turning a
        // perfectly good read into a hard open failure.
        var stmt: OpaquePointer?
        if isReadOnly {
            returnHandleToCaller = true
            return (handle, isReadOnly, nil, checkpointController)
        }
        if sqlite3_prepare_v2(handle, insertSQL, -1, &stmt, nil) != SQLITE_OK {
            // v1.9 audit Phase-1.6: close the handle before throwing.
            // Pre-fix the handle leaked because no cleanup ran on the
            // prepare-failure path. Mirrors AttributionOverrideStore +
            // EventStore pattern.
            let msg = String(cString: sqlite3_errmsg(handle))
            throw TraceStoreError.prepareFailed(msg)
        }

        returnHandleToCaller = true
        return (handle, isReadOnly, stmt, checkpointController)
    }

    private static func execOpenPragmaChecked(
        on db: OpaquePointer,
        sql: String
    ) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(resultCode: rc, db: db),
                context: sql
            )
        }
    }

    private static func injectedPragmaFailure(
        _ operation: TraceStorePragmaOperation,
        failureProbe: TraceStorePragmaFailureProbe?,
        context: String
    ) throws {
        guard let injected = failureProbe?(operation) else { return }
        throw sqliteFailure(
            metadata: SQLiteFailureMetadata(
                resultCode: injected.resultCode,
                extendedResultCode: injected.extendedResultCode,
                systemErrno: injected.systemErrno
            ),
            context: context
        )
    }

    /// journal_size_limit is a value-returning PRAGMA. Prepare and step are
    /// checked separately so either phase preserves FULL/ENOSPC metadata and is
    /// independently injectable in tests.
    private static func setJournalSizeLimit(
        on db: OpaquePointer,
        bytes: Int64,
        failureProbe: TraceStorePragmaFailureProbe?,
        context: String
    ) throws {
        var statement: OpaquePointer?
        defer { if let statement { sqlite3_finalize(statement) } }
        try injectedPragmaFailure(
            .journalSizeLimitPrepare,
            failureProbe: failureProbe,
            context: "prepare \(context)"
        )
        let prepareRC = sqlite3_prepare_v2(
            db, "PRAGMA journal_size_limit = \(max(0, bytes))", -1,
            &statement, nil
        )
        guard prepareRC == SQLITE_OK else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(resultCode: prepareRC, db: db),
                context: "prepare \(context)"
            )
        }
        try injectedPragmaFailure(
            .journalSizeLimitStep,
            failureProbe: failureProbe,
            context: "step \(context)"
        )
        let stepRC = sqlite3_step(statement)
        guard stepRC == SQLITE_ROW || stepRC == SQLITE_DONE else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(resultCode: stepRC, db: db),
                context: "step \(context)"
            )
        }
    }

    private static func configureMaximumPageCount(
        on db: OpaquePointer,
        maximumMainFileBytes: Int64?,
        failureProbe: TraceStorePragmaFailureProbe?
    ) throws {
        guard let maximumMainFileBytes, maximumMainFileBytes > 0 else { return }
        var pageSizeStatement: OpaquePointer?
        defer {
            if let pageSizeStatement { sqlite3_finalize(pageSizeStatement) }
        }
        var pageSize: Int64 = 4_096
        try injectedPragmaFailure(
            .pageSizePrepare,
            failureProbe: failureProbe,
            context: "prepare page_size for max_page_count"
        )
        let pageSizePrepareRC = sqlite3_prepare_v2(
            db, "PRAGMA page_size", -1, &pageSizeStatement, nil)
        guard pageSizePrepareRC == SQLITE_OK else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(
                    resultCode: pageSizePrepareRC, db: db),
                context: "prepare page_size for max_page_count"
            )
        }
        try injectedPragmaFailure(
            .pageSizeStep,
            failureProbe: failureProbe,
            context: "read page_size for max_page_count"
        )
        let pageSizeStepRC = sqlite3_step(pageSizeStatement)
        guard pageSizeStepRC == SQLITE_ROW else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(
                    resultCode: pageSizeStepRC, db: db),
                context: "read page_size for max_page_count"
            )
        }
        pageSize = max(512, sqlite3_column_int64(pageSizeStatement, 0))
        let pages = max(1, maximumMainFileBytes / pageSize)
        var limitStatement: OpaquePointer?
        defer { if let limitStatement { sqlite3_finalize(limitStatement) } }
        try injectedPragmaFailure(
            .maxPageCountPrepare,
            failureProbe: failureProbe,
            context: "prepare max_page_count backstop"
        )
        let prepareRC = sqlite3_prepare_v2(
            db,
            "PRAGMA max_page_count = \(pages)",
            -1,
            &limitStatement,
            nil
        )
        guard prepareRC == SQLITE_OK else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(resultCode: prepareRC, db: db),
                context: "prepare max_page_count backstop"
            )
        }
        try injectedPragmaFailure(
            .maxPageCountStep,
            failureProbe: failureProbe,
            context: "install max_page_count backstop"
        )
        let stepRC = sqlite3_step(limitStatement)
        guard stepRC == SQLITE_ROW else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(resultCode: stepRC, db: db),
                context: "install max_page_count backstop"
            )
        }
        let installedPages = sqlite3_column_int64(limitStatement, 0)

        // SQLite cannot lower max_page_count below an inherited DB's current
        // page_count. That case is valid (hot-path footprint admission latches
        // it immediately), but every other mismatch means the backstop did not
        // install and startup must fail closed.
        var countStatement: OpaquePointer?
        defer { if let countStatement { sqlite3_finalize(countStatement) } }
        try injectedPragmaFailure(
            .pageCountPrepare,
            failureProbe: failureProbe,
            context: "prepare page_count after max_page_count"
        )
        let countPrepareRC = sqlite3_prepare_v2(
            db, "PRAGMA page_count", -1, &countStatement, nil)
        guard countPrepareRC == SQLITE_OK else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(
                    resultCode: countPrepareRC, db: db),
                context: "prepare page_count after max_page_count"
            )
        }
        try injectedPragmaFailure(
            .pageCountStep,
            failureProbe: failureProbe,
            context: "verify page_count after max_page_count"
        )
        let countStepRC = sqlite3_step(countStatement)
        guard countStepRC == SQLITE_ROW else {
            throw sqliteFailure(
                metadata: SQLiteFailureMetadata(
                    resultCode: countStepRC, db: db),
                context: "verify page_count after max_page_count"
            )
        }
        let currentPages = sqlite3_column_int64(countStatement, 0)
        let expectedPages = max(pages, currentPages)
        guard installedPages == expectedPages else {
            throw TraceStoreError.databaseOpenFailed(
                "SQLite max_page_count backstop mismatch: requested \(pages), page_count \(currentPages), installed \(installedPages)"
            )
        }
    }

    private static func sqliteFailure(
        metadata: SQLiteFailureMetadata,
        context: String
    ) -> Error {
        let primary = metadata.extendedResultCode & 0xFF
        if metadata.resultCode == SQLITE_FULL || primary == SQLITE_FULL {
            return TraceStoreStorageAdmissionError.sqliteFull(
                context: context,
                resultCode: metadata.resultCode,
                extendedResultCode: metadata.extendedResultCode,
                systemErrno: metadata.systemErrno
            )
        }
        if (metadata.resultCode == SQLITE_IOERR || primary == SQLITE_IOERR),
           metadata.systemErrno == ENOSPC || metadata.systemErrno == EDQUOT {
            return TraceStoreStorageAdmissionError.filesystemFull(
                context: context,
                resultCode: metadata.resultCode,
                extendedResultCode: metadata.extendedResultCode,
                systemErrno: metadata.systemErrno
            )
        }
        return TraceStoreError.insertFailed(
            "\(context) failed (rc=\(metadata.resultCode), extended=\(metadata.extendedResultCode), system_errno=\(metadata.systemErrno))"
        )
    }

    private static func storageSettings(
        maxFootprintBytes: Int64?,
        freeSpaceFloorBytes: Int64?,
        transactionReserveBytes requestedReserve: Int64?
    ) -> (cap: Int64?, floor: Int64?, reserve: Int64?, threshold: Int64?) {
        let cap = maxFootprintBytes.flatMap { $0 > 0 ? $0 : nil }
        let floor = freeSpaceFloorBytes.flatMap { $0 > 0 ? $0 : nil }
        guard let cap else { return (nil, floor, nil, nil) }
        let automatic = min(
            defaultMaximumTransactionReserve,
            max(defaultMinimumTransactionReserve, cap / 4)
        )
        let reserve = min(
            requestedReserve.flatMap { $0 > 0 ? $0 : nil } ?? automatic,
            max(4_096, cap - 4_096)
        )
        return (cap, floor, reserve, max(0, cap - reserve))
    }

    /// Exact logical footprint of the live SQLite file family. Sidecars are
    /// optional, but any symlink/non-regular member fails the probe closed.
    nonisolated public static func exactSQLiteFootprintBytes(
        databasePath: String
    ) -> Int64? {
        func regularSize(_ path: String, required: Bool) -> Int64? {
            var info = stat()
            let rc = path.withCString { Darwin.lstat($0, &info) }
            if rc != 0 { return !required && errno == ENOENT ? 0 : nil }
            guard (info.st_mode & S_IFMT) == S_IFREG else { return nil }
            return info.st_size >= 0 ? Int64(info.st_size) : nil
        }
        guard let main = regularSize(databasePath, required: true),
              let wal = regularSize(databasePath + "-wal", required: false),
              let shm = regularSize(databasePath + "-shm", required: false),
              let journal = regularSize(
                databasePath + "-journal", required: false
              ),
              main <= Int64.max - wal,
              main + wal <= Int64.max - shm,
              main + wal + shm <= Int64.max - journal else { return nil }
        return main + wal + shm + journal
    }

    /// Immediately writable blocks (`f_bavail`), not APFS purgeable-space
    /// optimism. This is the value ordinary SQLite writes actually consume.
    nonisolated public static func availableFilesystemBytes(path: String) -> Int64? {
        var info = statfs()
        guard statfs(path, &info) == 0 else { return nil }
        let blocks = UInt64(info.f_bavail)
        let blockSize = UInt64(info.f_bsize)
        guard blockSize == 0 || blocks <= UInt64(Int64.max) / blockSize else {
            return nil
        }
        return Int64(blocks * blockSize)
    }

    private static func initialAdmissionMeasurements(
        databasePath: String,
        storageVolumePath: String,
        threshold: Int64?,
        floor: Int64?,
        reserve: Int64?,
        footprintProbe: TraceStoreStorageProbe,
        freeSpaceProbe: TraceStoreStorageProbe
    ) -> (Int64?, Int64?, TraceStoreStorageBlockReason?) {
        var footprint: Int64?
        var free: Int64?
        var reason: TraceStoreStorageBlockReason?
        if let threshold {
            footprint = footprintProbe(databasePath)
            if let footprint {
                if footprint >= threshold { reason = .footprintLimit }
            } else {
                reason = .probeFailure
            }
        }
        if let floor {
            free = freeSpaceProbe(storageVolumePath)
            let stableReserve = reserve ?? defaultMinimumTransactionReserve
            let (required, overflow) = floor.addingReportingOverflow(stableReserve)
            if let free {
                if overflow || free < required { reason = .lowFreeSpace }
            } else {
                reason = .probeFailure
            }
        }
        return (footprint, free, reason)
    }

    /// Refuse a configured writable open before WAL/schema/index mutations if
    /// the inherited SQLite family is already over budget or the volume is
    /// below its hard floor. `max_page_count` is still installed first inside
    /// `openDatabase` as the final SQLite backstop, but it cannot bound an
    /// active migration WAL on an inherited large database by itself.
    private static func preOpenStorageAdmission(
        databasePath: String,
        storageVolumePath: String,
        cap: Int64?,
        threshold: Int64?,
        floor: Int64?,
        reserve: Int64?,
        footprintProbe: TraceStoreStorageProbe,
        freeSpaceProbe: TraceStoreStorageProbe
    ) throws {
        if let cap, let threshold {
            let measured = footprintProbe(databasePath)
            let footprint: Int64
            if let measured {
                footprint = measured
            } else if sqliteFamilyIsEntirelyAbsent(databasePath) {
                // A genuinely fresh store has no main file for the exact-family
                // probe to measure. Every unexpected partial/non-regular family
                // remains a fail-closed probe error.
                footprint = 0
            } else {
                throw TraceStoreStorageAdmissionError.probeFailed(
                    "pre-open SQLite-family footprint"
                )
            }
            if footprint >= threshold {
                throw TraceStoreStorageAdmissionError.footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: threshold,
                    capBytes: cap
                )
            }
        }
        if let floor {
            guard let free = freeSpaceProbe(storageVolumePath) else {
                throw TraceStoreStorageAdmissionError.probeFailed(
                    "pre-open free-space"
                )
            }
            let stableReserve = reserve ?? defaultMinimumTransactionReserve
            let (required, overflow) = floor.addingReportingOverflow(
                stableReserve
            )
            if overflow || free < required {
                throw TraceStoreStorageAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: overflow ? Int64.max : required
                )
            }
        }
    }

    /// Re-probe immediately before schema work. CREATE INDEX scans the whole
    /// inherited spans table and can grow WAL/a new b-tree far beyond the
    /// ordinary decoded-span reserve, while missing tables/columns are bounded
    /// metadata. The classifier suppresses existing-object no-ops on every
    /// normal reopen.
    private static func preflightSchemaStorageWork(
        _ work: SchemaStorageWork,
        databasePath: String,
        storageVolumePath: String,
        maxFootprintBytes: Int64?,
        freeSpaceFloorBytes: Int64?,
        transactionReserveBytes: Int64?,
        footprintProbe: TraceStoreStorageProbe,
        freeSpaceProbe: TraceStoreStorageProbe
    ) throws {
        guard !work.isEmpty else { return }
        let configured = maxFootprintBytes != nil || freeSpaceFloorBytes != nil
        guard configured else { return }

        let metadataEstimate = work.boundedTransactionEstimateBytes
        if let reserve = transactionReserveBytes,
           metadataEstimate > reserve {
            throw TraceStoreStorageAdmissionError.mutationTooLarge(
                estimatedBytes: metadataEstimate,
                transactionReserveBytes: reserve
            )
        }
        guard let footprint = footprintProbe(databasePath) else {
            throw TraceStoreStorageAdmissionError.probeFailed(
                "schema SQLite-family footprint"
            )
        }
        guard let free = freeSpaceProbe(storageVolumePath) else {
            throw TraceStoreStorageAdmissionError.probeFailed(
                "schema free-space"
            )
        }

        if work.rebuildStatementCount > 0 {
            let main: Int64
            do {
                main = try SQLitePersistentStoreAdmission.measureMainFile(
                    databasePath
                )
            } catch {
                throw TraceStoreStorageAdmissionError.probeFailed(
                    "schema main-file measurement: \(error.localizedDescription)"
                )
            }
            let growth = SQLitePersistentStoreAdmission.saturatingMultiply(
                main,
                by: Int64(work.rebuildStatementCount)
            )
            let scratch = SQLitePersistentStoreAdmission.saturatingAdd(
                main,
                growth
            )
            let projected = SQLitePersistentStoreAdmission.saturatingAdd(
                footprint,
                growth
            )
            if let cap = maxFootprintBytes,
               projected > cap {
                throw TraceStoreStorageAdmissionError.footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: max(0, cap - growth),
                    capBytes: cap
                )
            }
            let floor = freeSpaceFloorBytes ?? 0
            let required = SQLitePersistentStoreAdmission.saturatingAdd(
                floor,
                scratch
            )
            if growth == Int64.max || scratch == Int64.max
                || projected == Int64.max || required == Int64.max
                || free < required {
                throw TraceStoreStorageAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                )
            }
            return
        }

        if let cap = maxFootprintBytes {
            let reserve = transactionReserveBytes ?? defaultMinimumTransactionReserve
            let threshold = max(0, cap - reserve)
            if footprint >= threshold {
                throw TraceStoreStorageAdmissionError.footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: threshold,
                    capBytes: cap
                )
            }
        }
        if let floor = freeSpaceFloorBytes {
            let reserve = transactionReserveBytes ?? defaultMinimumTransactionReserve
            let required = SQLitePersistentStoreAdmission.saturatingAdd(
                floor,
                reserve
            )
            if required == Int64.max || free < required {
                throw TraceStoreStorageAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                )
            }
        }
    }

    private static func sqliteFamilyIsEntirelyAbsent(_ databasePath: String) -> Bool {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            var info = stat()
            let rc = (databasePath + suffix).withCString {
                Darwin.lstat($0, &info)
            }
            if rc == 0 || errno != ENOENT { return false }
        }
        return true
    }

    /// Open `traces.db` in the default support directory.
    /// v1.9 Phase-2.2: pass an `encryption` instance to encrypt
    /// `attributes_json` at rest. Nil = plaintext (compat for tests
    /// + non-daemon callers).
    public init(
        directory: String = "/Library/Application Support/MacCrab",
        encryption: DatabaseEncryption? = nil,
        forceReadOnly: Bool = false,
        maxFootprintBytes: Int64? = nil,
        freeSpaceFloorBytes: Int64? = nil,
        transactionReserveBytes: Int64? = nil,
        storageVolumePath: String? = nil,
        footprintProbe: TraceStoreStorageProbe? = nil,
        freeSpaceProbe: TraceStoreStorageProbe? = nil,
        transactionFailureProbe: TraceStoreTransactionFailureProbe? = nil,
        pragmaFailureProbe: TraceStorePragmaFailureProbe? = nil
    ) throws {
        let url = URL(fileURLWithPath: directory)
        if !forceReadOnly {
            try FileManager.default.createDirectory(
                at: url, withIntermediateDirectories: true, attributes: nil
            )
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o755], ofItemAtPath: url.path
            )
        }
        self.databasePath = url.appendingPathComponent("traces.db").path
        self.encryption = encryption
        self.storageVolumePath = storageVolumePath ?? directory
        self.footprintProbe = footprintProbe
            ?? { Self.exactSQLiteFootprintBytes(databasePath: $0) }
        self.freeSpaceProbe = freeSpaceProbe
            ?? { Self.availableFilesystemBytes(path: $0) }
        self.transactionFailureProbe = transactionFailureProbe
        self.pragmaFailureProbe = pragmaFailureProbe
        let settings = Self.storageSettings(
            maxFootprintBytes: maxFootprintBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            transactionReserveBytes: transactionReserveBytes
        )
        self.maxFootprintBytes = settings.cap
        self.freeSpaceFloorBytes = settings.floor
        self.transactionReserveBytes = settings.reserve
        self.admissionThresholdBytes = settings.threshold
        if !forceReadOnly {
            try Self.preOpenStorageAdmission(
                databasePath: databasePath,
                storageVolumePath: self.storageVolumePath,
                cap: settings.cap,
                threshold: settings.threshold,
                floor: settings.floor,
                reserve: settings.reserve,
                footprintProbe: self.footprintProbe,
                freeSpaceProbe: self.freeSpaceProbe
            )
        }
        // v1.21.5 (audit sec-storage-crypto): 0o027/0o640 — group read-only,
        // not group-write. traces.db carries the continuity hash-chain +
        // trace evidence; column payloads are AES-GCM encrypted, so the
        // group-write exposure was deletion / DoS / continuity-ledger
        // rewrite rather than forgery, but it's still closed here. Non-root
        // readers open via the `path:` init (openDatabase falls back to a
        // read-only handle when it can't get write access).
        let oldUmask = umask(0o027)
        defer { umask(oldUmask) }
        let (handle, ro, stmt, controller) = try Self.openDatabase(
            at: databasePath,
            forceReadOnly: forceReadOnly,
            maximumMainFileBytes: settings.threshold,
            maxFootprintBytes: settings.cap,
            freeSpaceFloorBytes: settings.floor,
            transactionReserveBytes: settings.reserve,
            storageVolumePath: self.storageVolumePath,
            footprintProbe: self.footprintProbe,
            freeSpaceProbe: self.freeSpaceProbe,
            pragmaFailureProbe: pragmaFailureProbe
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.checkpointController = controller
        let initialAdmission = Self.initialAdmissionMeasurements(
            databasePath: databasePath,
            storageVolumePath: self.storageVolumePath,
            threshold: settings.threshold,
            floor: settings.floor,
            reserve: settings.reserve,
            footprintProbe: self.footprintProbe,
            freeSpaceProbe: self.freeSpaceProbe
        )
        self.lastFootprintBytes = initialAdmission.0
        self.lastFreeSpaceBytes = initialAdmission.1
        self.storageBlockReason = initialAdmission.2
        if !ro {
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
        }
    }

    /// Open at a custom path (used by tests).
    public init(
        path: String,
        encryption: DatabaseEncryption? = nil,
        forceReadOnly: Bool = false,
        maxFootprintBytes: Int64? = nil,
        freeSpaceFloorBytes: Int64? = nil,
        transactionReserveBytes: Int64? = nil,
        storageVolumePath: String? = nil,
        footprintProbe: TraceStoreStorageProbe? = nil,
        freeSpaceProbe: TraceStoreStorageProbe? = nil,
        transactionFailureProbe: TraceStoreTransactionFailureProbe? = nil,
        pragmaFailureProbe: TraceStorePragmaFailureProbe? = nil
    ) throws {
        self.databasePath = path
        self.encryption = encryption
        self.storageVolumePath = storageVolumePath
            ?? (path as NSString).deletingLastPathComponent
        self.footprintProbe = footprintProbe
            ?? { Self.exactSQLiteFootprintBytes(databasePath: $0) }
        self.freeSpaceProbe = freeSpaceProbe
            ?? { Self.availableFilesystemBytes(path: $0) }
        self.transactionFailureProbe = transactionFailureProbe
        self.pragmaFailureProbe = pragmaFailureProbe
        let settings = Self.storageSettings(
            maxFootprintBytes: maxFootprintBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            transactionReserveBytes: transactionReserveBytes
        )
        self.maxFootprintBytes = settings.cap
        self.freeSpaceFloorBytes = settings.floor
        self.transactionReserveBytes = settings.reserve
        self.admissionThresholdBytes = settings.threshold
        if !forceReadOnly {
            try Self.preOpenStorageAdmission(
                databasePath: databasePath,
                storageVolumePath: self.storageVolumePath,
                cap: settings.cap,
                threshold: settings.threshold,
                floor: settings.floor,
                reserve: settings.reserve,
                footprintProbe: self.footprintProbe,
                freeSpaceProbe: self.freeSpaceProbe
            )
        }
        let (handle, ro, stmt, controller) = try Self.openDatabase(
            at: path,
            forceReadOnly: forceReadOnly,
            maximumMainFileBytes: settings.threshold,
            maxFootprintBytes: settings.cap,
            freeSpaceFloorBytes: settings.floor,
            transactionReserveBytes: settings.reserve,
            storageVolumePath: self.storageVolumePath,
            footprintProbe: self.footprintProbe,
            freeSpaceProbe: self.freeSpaceProbe,
            pragmaFailureProbe: pragmaFailureProbe
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.checkpointController = controller
        let initialAdmission = Self.initialAdmissionMeasurements(
            databasePath: databasePath,
            storageVolumePath: self.storageVolumePath,
            threshold: settings.threshold,
            floor: settings.floor,
            reserve: settings.reserve,
            footprintProbe: self.footprintProbe,
            freeSpaceProbe: self.freeSpaceProbe
        )
        self.lastFootprintBytes = initialAdmission.0
        self.lastFreeSpaceBytes = initialAdmission.1
        self.storageBlockReason = initialAdmission.2
    }

    deinit {
        if let s = insertStmt { sqlite3_finalize(s) }
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
    }

    // MARK: - Storage admission

    /// Exact current DB+WAL+SHM+journal footprint without mutating admission.
    public func storageFootprintBytes() -> Int64? {
        footprintProbe(databasePath)
    }

    /// Runtime config hook used by SIGHUP. A lowered cap takes effect before
    /// the next mutation because the store actor owns both this update and all
    /// inserts.
    @discardableResult
    public func updateStorageAdmission(
        maxFootprintBytes: Int64?,
        freeSpaceFloorBytes: Int64?,
        transactionReserveBytes: Int64? = nil
    ) throws -> TraceStoreStorageAdmissionStatus {
        let settings = Self.storageSettings(
            maxFootprintBytes: maxFootprintBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            transactionReserveBytes: transactionReserveBytes
        )
        self.maxFootprintBytes = settings.cap
        self.freeSpaceFloorBytes = settings.floor
        self.transactionReserveBytes = settings.reserve
        self.admissionThresholdBytes = settings.threshold
        if !isReadOnly {
            try checkpointController?.updateFamily(
                schema: "main",
                configuration: SQLiteControlledCheckpointFamily(
                    databasePath: databasePath,
                    storageVolumePath: storageVolumePath,
                    freeSpaceFloorBytes: settings.floor ?? 0,
                    footprintProbe: footprintProbe,
                    freeSpaceProbe: freeSpaceProbe
                )
            )
        }
        self.sqliteStorageFailure = nil
        self.sqliteStorageFailureGeneration &+= 1

        if let db, !isReadOnly {
            if settings.threshold != nil {
                try Self.configureMaximumPageCount(
                    on: db,
                    maximumMainFileBytes: settings.threshold,
                    failureProbe: pragmaFailureProbe
                )
            } else {
                let rc = sqlite3_exec(
                    db, "PRAGMA max_page_count = 2147483646", nil, nil, nil)
                guard rc == SQLITE_OK else {
                    try throwSQLiteFailure(rc: rc, db: db, context: "raise max_page_count")
                }
            }
            let journalLimit = min(
                StoragePragmas.journalSizeLimitBytes,
                settings.reserve ?? StoragePragmas.journalSizeLimitBytes
            )
            do {
                try Self.setJournalSizeLimit(
                    on: db,
                    bytes: journalLimit,
                    failureProbe: pragmaFailureProbe,
                    context: "update journal_size_limit"
                )
            } catch let storage as TraceStoreStorageAdmissionError {
                sqliteStorageFailure = storage
                sqliteStorageFailureGeneration &+= 1
                try rejectGrowth(storage)
            }
        }
        refreshAdmissionMeasurements()
        return makeStorageAdmissionStatus()
    }

    public func storageAdmissionStatus() -> TraceStoreStorageAdmissionStatus {
        refreshAdmissionMeasurements()
        return makeStorageAdmissionStatus()
    }

    private func makeStorageAdmissionStatus() -> TraceStoreStorageAdmissionStatus {
        TraceStoreStorageAdmissionStatus(
            enabled: maxFootprintBytes != nil || freeSpaceFloorBytes != nil,
            blocked: storageBlockReason != nil,
            reason: storageBlockReason,
            maxFootprintBytes: maxFootprintBytes,
            admissionThresholdBytes: admissionThresholdBytes,
            transactionReserveBytes: transactionReserveBytes,
            footprintBytes: lastFootprintBytes,
            freeSpaceBytes: lastFreeSpaceBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            shedMutationsTotal: shedMutationsTotal,
            pinnedReader: pinnedReader,
            recovering: recovering
        )
    }

    /// Cheap pressure check used by the receiver before protobuf decoding. A
    /// zero growth estimate still reserves one complete transaction above the
    /// 1 GiB hard floor and below the configured footprint cap.
    public func preflightStorageAdmission(
        estimatedGrowthBytes: Int64 = 0
    ) throws {
        try admitGrowth(upperBoundBytes: max(0, estimatedGrowthBytes))
    }

    /// Exact decoded-batch preflight: accounts for every UTF-8 field that will
    /// be bound, plus the plaintext search projection and fixed row/index
    /// overhead. `insertSpans` repeats this centrally before BEGIN.
    public func preflightInsertSpans(_ records: [SpanRecord]) throws {
        guard !records.isEmpty else { return }
        try admitGrowth(upperBoundBytes: mutationUpperBound(for: records))
    }

    /// Exposed for deterministic admission tests and receiver diagnostics.
    public func estimatedInsertUpperBoundBytes(_ records: [SpanRecord]) -> Int64 {
        mutationUpperBound(for: records)
    }

    private func mutationUpperBound(for records: [SpanRecord]) -> Int64 {
        var payload = 0
        for record in records {
            payload = payloadAdd(payload, record.traceId.utf8.count)
            payload = payloadAdd(payload, record.spanId.utf8.count)
            payload = payloadAdd(payload, record.parentSpanId?.utf8.count ?? 0)
            payload = payloadAdd(payload, record.serviceName?.utf8.count ?? 0)
            payload = payloadAdd(payload, record.spanName.utf8.count)
            payload = payloadAdd(payload, record.agentTool?.rawValue.utf8.count ?? 0)
            payload = payloadAdd(payload, record.providerName?.utf8.count ?? 0)
            payload = payloadAdd(payload, record.legacyGenAiSystem?.utf8.count ?? 0)
            payload = payloadAdd(payload, record.attributesJson?.utf8.count ?? 0)
            payload = payloadAdd(payload, record.trust.rawValue.utf8.count)
            payload = payloadAdd(payload, Self.searchProjection(for: record).utf8.count)
        }
        let payload64 = Int64(max(0, payload))
        let payloadCharge = payload64 > Int64.max / 2 ? Int64.max : payload64 * 2
        let rows = Int64(max(1, records.count))
        let rowCharge = rows > Int64.max / Self.mutationBytesPerRow
            ? Int64.max
            : rows * Self.mutationBytesPerRow
        guard payloadCharge <= Int64.max - rowCharge,
              payloadCharge + rowCharge <= Int64.max - Self.mutationBaseBytes else {
            return Int64.max
        }
        return Self.mutationBaseBytes + payloadCharge + rowCharge
    }

    private func payloadAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : sum
    }

    private func saturatingAdd(_ lhs: Int64, _ rhs: Int64) -> Int64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int64.max : sum
    }

    private func requiredFreeBytes(
        floor: Int64,
        mutationUpperBound: Int64 = 0
    ) -> Int64 {
        saturatingAdd(
            floor,
            max(
                transactionReserveBytes ?? Self.defaultMinimumTransactionReserve,
                max(0, mutationUpperBound)
            )
        )
    }

    private func admitGrowth(upperBoundBytes: Int64) throws {
        guard !isReadOnly else {
            throw TraceStoreError.insertFailed("store was opened read-only")
        }
        guard maxFootprintBytes != nil || freeSpaceFloorBytes != nil else { return }

        refreshAdmissionMeasurements()
        if let sqliteStorageFailure {
            try rejectGrowth(sqliteStorageFailure)
        }
        if let reserve = transactionReserveBytes, upperBoundBytes > reserve {
            try rejectGrowth(.mutationTooLarge(
                estimatedBytes: upperBoundBytes,
                transactionReserveBytes: reserve
            ))
        }
        if let floor = freeSpaceFloorBytes {
            guard let free = freeSpaceProbe(storageVolumePath) else {
                lastFreeSpaceBytes = nil
                try rejectGrowth(.probeFailed("free-space"))
            }
            lastFreeSpaceBytes = free
            let required = requiredFreeBytes(
                floor: floor,
                mutationUpperBound: upperBoundBytes
            )
            if free < required {
                try rejectGrowth(.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                ))
            }
        }
        if let cap = maxFootprintBytes,
           let threshold = admissionThresholdBytes {
            guard let footprint = footprintProbe(databasePath) else {
                lastFootprintBytes = nil
                try rejectGrowth(.probeFailed("SQLite-family footprint"))
            }
            lastFootprintBytes = footprint
            if footprint >= threshold {
                try rejectGrowth(.footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: threshold,
                    capBytes: cap
                ))
            }
        }
        if storageBlockReason != nil {
            logger.notice("Agent-trace storage admission recovered; inserts resumed")
        }
        storageBlockReason = nil
    }

    private func rejectGrowth(
        _ error: TraceStoreStorageAdmissionError
    ) throws -> Never {
        shedMutationsTotal &+= 1
        if storageBlockReason != error.blockReason {
            logger.fault("\(error.localizedDescription, privacy: .public). OTLP persistence is shed; existing evidence is retained.")
        }
        storageBlockReason = error.blockReason
        throw error
    }

    private func refreshAdmissionMeasurements() {
        var reason: TraceStoreStorageBlockReason?
        if let threshold = admissionThresholdBytes {
            lastFootprintBytes = footprintProbe(databasePath)
            if let footprint = lastFootprintBytes {
                if footprint >= threshold { reason = .footprintLimit }
            } else {
                reason = .probeFailure
            }
        } else {
            lastFootprintBytes = nil
        }
        if let floor = freeSpaceFloorBytes {
            lastFreeSpaceBytes = freeSpaceProbe(storageVolumePath)
            if let free = lastFreeSpaceBytes {
                if free < requiredFreeBytes(floor: floor) { reason = .lowFreeSpace }
            } else {
                reason = .probeFailure
            }
        } else {
            lastFreeSpaceBytes = nil
        }
        storageBlockReason = sqliteStorageFailure?.blockReason ?? reason
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
        try preflightInsertSpans(records)
        var succeeded = 0
        var failed = 0
        try execTransaction(.begin, db: db)
        for record in records {
            do {
                try insertSpanUnchecked(record)
                succeeded += 1
            } catch let storage as TraceStoreStorageAdmissionError {
                try rollbackAndRethrow(storage, db: db)
            } catch {
                failed += 1
                // Don't let one bad span abort the whole batch.
            }
        }
        do {
            try execTransaction(.commit, db: db)
        } catch {
            // Counts are visible only after a checked COMMIT. A failed COMMIT
            // rolls the transaction back and throws, never returns successes.
            try rollbackAndRethrow(error, db: db)
        }
        return (succeeded, failed)
    }

    /// Insert (or replace) a single sanitised span.
    /// Caller must have already run the receiver-side sanitiser over
    /// `record.attributesJson`.
    public func insertSpan(_ record: SpanRecord) throws {
        // Keep every public writer on the same checked BEGIN/COMMIT/ROLLBACK
        // boundary. In autocommit mode sqlite3_step usually reports commit
        // failures, but an explicit transaction is the only invariant our
        // fault-injection tests can prove at each control statement.
        let result = try insertSpans([record])
        guard result.succeeded == 1, result.failed == 0 else {
            throw TraceStoreError.insertFailed(
                "single-span transaction completed without persisting its row"
            )
        }
    }

    private func insertSpanUnchecked(_ record: SpanRecord) throws {
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
        // Plaintext projection — see the v2 migration note. Built from the
        // structural columns plus attribute KEYS and path/identifier-shaped
        // VALUES, never free-form prompt text.
        let projection = Self.searchProjection(for: record)
        if projection.isEmpty { sqlite3_bind_null(stmt, 12) }
        else { sqlite3_bind_text(stmt, 12, projection, -1, TRANSIENT) }
        sqlite3_bind_text(stmt, 13, record.trust.rawValue, -1, TRANSIENT)

        let rc = sqlite3_step(stmt)
        if rc != SQLITE_DONE {
            guard let db else {
                throw TraceStoreError.insertFailed("database closed during insert")
            }
            try throwSQLiteFailure(rc: rc, db: db, context: "span insert")
        }
    }

    private func execTransaction(
        _ operation: TraceStoreTransactionOperation,
        db: OpaquePointer
    ) throws {
        if let injected = transactionFailureProbe?(operation) {
            let metadata = SQLiteFailureMetadata(
                resultCode: injected.resultCode,
                extendedResultCode: injected.extendedResultCode,
                systemErrno: injected.systemErrno
            )
            try throwSQLiteFailure(
                metadata: metadata,
                db: db,
                context: operation.rawValue.uppercased()
            )
        }
        let sql: String
        switch operation {
        case .begin: sql = "BEGIN IMMEDIATE"
        case .commit: sql = "COMMIT"
        case .rollback: sql = "ROLLBACK"
        }
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            try throwSQLiteFailure(rc: rc, db: db, context: sql)
        }
    }

    private func rollbackAndRethrow(
        _ primaryError: Error,
        db: OpaquePointer
    ) throws -> Never {
        do {
            try execTransaction(.rollback, db: db)
        } catch {
            logger.error("TraceStore ROLLBACK failed after \(String(describing: primaryError), privacy: .public): \(String(describing: error), privacy: .public)")
            // Preserve the originating typed FULL/ENOSPC signal. If the primary
            // wasn't storage pressure but rollback was, preserve the latter.
            if let storage = primaryError as? TraceStoreStorageAdmissionError {
                throw storage
            }
            if let storage = error as? TraceStoreStorageAdmissionError {
                throw storage
            }
            throw TraceStoreError.transactionFailed(
                "\(primaryError); rollback also failed: \(error)"
            )
        }
        throw primaryError
    }

    private func throwSQLiteFailure(
        rc: Int32,
        db: OpaquePointer,
        context: String
    ) throws -> Never {
        try throwSQLiteFailure(
            metadata: SQLiteFailureMetadata(resultCode: rc, db: db),
            db: db,
            context: context
        )
    }

    private func throwSQLiteFailure(
        metadata: SQLiteFailureMetadata,
        db: OpaquePointer,
        context: String
    ) throws -> Never {
        let mapped = Self.sqliteFailure(metadata: metadata, context: context)
        if let storage = mapped as? TraceStoreStorageAdmissionError {
            sqliteStorageFailure = storage
            sqliteStorageFailureGeneration &+= 1
            try rejectGrowth(storage)
        }
        throw TraceStoreError.insertFailed(
            "\(context) failed (rc=\(metadata.resultCode), extended=\(metadata.extendedResultCode), system_errno=\(metadata.systemErrno)): \(String(cString: sqlite3_errmsg(db)))"
        )
    }

    /// Look up all spans for a given trace_id, ordered by start_ns ascending.
    public func spansForTrace(_ traceId: String) throws -> [SpanRecord] {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        let trustProjection = trustLabelProjection()
        let sql = """
            SELECT trace_id, span_id, parent_span_id,
                   start_ns, end_ns,
                   service_name, span_name, agent_tool,
                   provider_name, legacy_gen_ai_system,
                   attributes_json, \(trustProjection)
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

        return try readSpanRows(stmt)
    }

    /// Decode SpanRecord rows from a prepared statement selecting the canonical
    /// 12-column projection. Extracted when `searchSpans` became a second caller
    /// of an identical loop.
    private func readSpanRows(_ stmt: OpaquePointer?) throws -> [SpanRecord] {
        var out: [SpanRecord] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                let message = db.map { String(cString: sqlite3_errmsg($0)) }
                    ?? "database closed"
                throw TraceStoreError.queryFailed(message)
            }
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
            let attrs: String? = storedAttrs.map { encryption?.decrypt($0, expectingEncrypted: true) ?? $0 }
            let trustRaw = sqlite3_column_type(stmt, 11) == SQLITE_NULL
                ? AgentTraceTrust.unauthenticatedSelfReported.rawValue
                : String(cString: sqlite3_column_text(stmt, 11))
            // There is deliberately no authenticated fallback. Unknown/newer
            // values read by an older binary remain explicitly untrusted.
            let trust = AgentTraceTrust(rawValue: trustRaw)
                ?? .unauthenticatedSelfReported
            out.append(SpanRecord(
                traceId: traceIdStr, spanId: spanIdStr,
                parentSpanId: parentSpan,
                startNs: startNs, endNs: endNs,
                serviceName: serviceName, spanName: spanName,
                agentTool: agentTool,
                providerName: providerName,
                legacyGenAiSystem: legacy,
                attributesJson: attrs,
                trust: trust
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

    // MARK: - Searchable projection (v1.21.6)

    /// Build the plaintext `search_text` projection for a span.
    ///
    /// PRIVACY CONTRACT — this column is NOT encrypted, so it must never carry
    /// free-form content. It includes:
    ///   * the structural columns (span name, service, tool, provider)
    ///   * attribute KEYS (schema, not data — always safe)
    ///   * attribute VALUES only when they are path- or identifier-shaped
    /// It deliberately EXCLUDES anything containing whitespace or exceeding
    /// `maxValueLength`, which is what prompt text, tool inputs and error
    /// messages look like. The full values stay in the encrypted blob.
    nonisolated static func searchProjection(for record: SpanRecord) -> String {
        var parts: [String] = [record.spanName]
        if let s = record.serviceName { parts.append(s) }
        if let t = record.agentTool { parts.append(t.rawValue) }
        if let p = record.providerName { parts.append(p) }

        if let json = record.attributesJson,
           let data = json.data(using: .utf8),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            for (key, value) in obj.sorted(by: { $0.key < $1.key }) {
                parts.append(key)
                guard let str = value as? String else { continue }
                if isProjectableValue(str) { parts.append(str) }
            }
        }
        // Deduplicate while preserving order; join with spaces for LIKE/FTS.
        var seen = Set<String>()
        return parts.filter { !$0.isEmpty && seen.insert($0).inserted }
            .joined(separator: " ")
    }

    /// Longest value admitted into the plaintext projection.
    nonisolated static let maxProjectedValueLength = 200

    /// A value is projectable when it is a filesystem path or a compact
    /// identifier — the things an analyst searches for. Whitespace is the
    /// discriminator that keeps prose out.
    nonisolated static func isProjectableValue(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= maxProjectedValueLength else { return false }
        guard !s.contains(where: { $0.isWhitespace || $0.isNewline }) else { return false }
        return true
    }

    /// Whether the `search_text` projection column exists in this database.
    /// False for a store opened read-only before the v2 migration could run.
    public func hasSearchProjection() -> Bool {
        hasSpanColumn("search_text")
    }

    /// Whether schema migration v3 has materialized the explicit trust column.
    /// A force-read-only client may legitimately open a v1/v2 database; its
    /// SELECT projection supplies the same untrusted default without migrating.
    public func hasTrustLabel() -> Bool {
        hasSpanColumn("trust_label")
    }

    private func hasSpanColumn(_ name: String) -> Bool {
        guard let db else { return false }
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, "PRAGMA table_info(spans)", -1, &stmt, nil) == SQLITE_OK else {
            return false
        }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let c = sqlite3_column_text(stmt, 1),
               String(cString: c) == name { return true }
        }
        return false
    }

    private func trustLabelProjection() -> String {
        hasTrustLabel()
            ? "trust_label"
            : "'unauthenticated_self_reported' AS trust_label"
    }

    /// Populate `search_text` for rows that predate the v2 migration.
    ///
    /// The migration itself is pure SQL and cannot decrypt `attributes_json`, so
    /// existing spans land with a NULL projection and would stay invisible to
    /// search forever. This decrypts each such row, rebuilds the projection and
    /// writes it back. Idempotent and bounded — it only touches NULL rows.
    /// Returns the number of rows backfilled.
    @discardableResult
    public func backfillSearchProjection(limit: Int = 10_000) throws -> Int {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        guard !isReadOnly else { return 0 }
        let trustProjection = trustLabelProjection()
        let selectSQL = """
            SELECT trace_id, span_id, parent_span_id,
                   start_ns, end_ns,
                   service_name, span_name, agent_tool,
                   provider_name, legacy_gen_ai_system,
                   attributes_json, \(trustProjection)
            FROM spans
            WHERE search_text IS NULL
            LIMIT ?1
            """
        var sel: OpaquePointer?
        defer { if let s = sel { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, selectSQL, -1, &sel, nil) == SQLITE_OK else {
            throw TraceStoreError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
        sqlite3_bind_int(sel, 1, Int32(max(1, limit)))
        let pending = try readSpanRows(sel)
        guard !pending.isEmpty else { return 0 }

        var upd: OpaquePointer?
        defer { if let u = upd { sqlite3_finalize(u) } }
        guard sqlite3_prepare_v2(
            db, "UPDATE spans SET search_text = ?1 WHERE trace_id = ?2 AND span_id = ?3",
            -1, &upd, nil) == SQLITE_OK else {
            throw TraceStoreError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        var done = 0
        // Backfill is a startup writer too. Process it in independently
        // admitted transactions so a legacy 10K-row store cannot turn one
        // migration helper into an unbounded WAL burst.
        let batchRows = 128
        var offset = 0
        while offset < pending.count {
            let end = min(pending.count, offset + batchRows)
            let batch = Array(pending[offset..<end])
            try preflightInsertSpans(batch)
            try execTransaction(.begin, db: db)
            var batchDone = 0
            do {
                for rec in batch {
                    sqlite3_reset(upd)
                    sqlite3_clear_bindings(upd)
                    sqlite3_bind_text(
                        upd, 1, Self.searchProjection(for: rec), -1, TRANSIENT)
                    sqlite3_bind_text(upd, 2, rec.traceId, -1, TRANSIENT)
                    sqlite3_bind_text(upd, 3, rec.spanId, -1, TRANSIENT)
                    let rc = sqlite3_step(upd)
                    guard rc == SQLITE_DONE else {
                        try throwSQLiteFailure(
                            rc: rc, db: db,
                            context: "search projection backfill update"
                        )
                    }
                    batchDone += 1
                }
                try execTransaction(.commit, db: db)
            } catch {
                try rollbackAndRethrow(error, db: db)
            }
            done += batchDone
            offset = end
        }
        return done
    }

    /// Test seam: blank every projection so a backfill can be exercised against
    /// rows shaped like pre-migration ones.
    // Internal on purpose: tests import MacCrabCore with `@testable`, while
    // production clients must not gain an ungated bulk-UPDATE entry point.
    func clearSearchProjectionForTesting() throws {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        guard sqlite3_exec(db, "UPDATE spans SET search_text = NULL", nil, nil, nil) == SQLITE_OK else {
            throw TraceStoreError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
    }

    /// Substring search across the plaintext projection. Case-insensitive.
    /// Returns matching spans newest-first.
    public func searchSpans(matching query: String, limit: Int = 100) throws -> [SpanRecord] {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        // A force-RO query client may open a v1 database before the daemon has
        // migrated it. Synthesize a structural-only projection rather than
        // issuing a write or failing on a missing `search_text` column.
        let searchProjection = hasSearchProjection()
            ? "search_text"
            : "(span_name || ' ' || COALESCE(service_name, '') || ' ' || COALESCE(agent_tool, '') || ' ' || COALESCE(provider_name, ''))"
        let trustProjection = trustLabelProjection()
        let sql = """
            SELECT trace_id, span_id, parent_span_id,
                   start_ns, end_ns,
                   service_name, span_name, agent_tool,
                   provider_name, legacy_gen_ai_system,
                   attributes_json, \(trustProjection)
            FROM spans
            WHERE \(searchProjection) LIKE ?1 ESCAPE '\\'
            ORDER BY start_ns DESC
            LIMIT ?2
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw TraceStoreError.queryFailed(String(cString: sqlite3_errmsg(db)))
        }
        // Escape LIKE wildcards in the user's query so a literal % or _ does not
        // silently widen the search.
        let escaped = trimmed
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "%", with: "\\%")
            .replacingOccurrences(of: "_", with: "\\_")
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, "%\(escaped)%", -1, TRANSIENT)
        sqlite3_bind_int(stmt, 2, Int32(max(1, min(limit, 1000))))
        return try readSpanRows(stmt)
    }

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

    /// Actor-owned bounded maintenance for traces.db. It never issues full
    /// VACUUM, never deletes while a reader pins the WAL, and never lets one
    /// DELETE consume more than the configured transaction reserve.
    public func recoverStorageBudget(
        retentionCutoff: Date,
        maxDeleteRows: Int = 256,
        maxVacuumPages: Int = 8_192
    ) async throws -> TraceStoreStorageRecoveryResult {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        guard !isReadOnly else { throw TraceStoreError.queryFailed("store is read-only") }
        guard !recovering else {
            return makeRecoveryResult(spansDeleted: 0, vacuumPagesReclaimed: 0)
        }
        let sqliteFailureGenerationAtStart = sqliteStorageFailureGeneration
        recovering = true
        defer { recovering = false }
        pinnedReader = false

        // Drain first, before measuring or deleting. A partial PASSIVE
        // checkpoint proves a live reader owns an old snapshot; adding DELETE
        // frames behind it would amplify the pinned WAL.
        if try recoveryCheckpointIsPinned(db: db) {
            pinnedReader = true
            refreshAdmissionMeasurements()
            return makeRecoveryResult(spansDeleted: 0, vacuumPagesReclaimed: 0)
        }
        refreshAdmissionMeasurements()

        let reserve = transactionReserveBytes
            ?? Self.defaultMinimumTransactionReserve
        let deleteBudget = max(
            64 * 1024,
            min(reserve / 2, 8 * Self.mib)
        )
        let boundedRows = max(1, min(maxDeleteRows, 2_048))
        var selection = try selectRecoveryRows(
            db: db,
            olderThan: retentionCutoff,
            maxRows: boundedRows,
            byteBudget: deleteBudget
        )
        // If retention has nothing to remove but pressure remains latched,
        // reclaim one bounded batch of the oldest data. This is the only
        // evidence-eviction path and it never runs on a healthy store.
        if selection.rowIDs.isEmpty, storageBlockReason != nil {
            selection = try selectRecoveryRows(
                db: db,
                olderThan: nil,
                maxRows: boundedRows,
                byteBudget: deleteBudget
            )
        }

        var deleted = 0
        if !selection.rowIDs.isEmpty {
            try admitMaintenance(upperBoundBytes: selection.upperBoundBytes)
            deleted = try deleteRecoveryRows(selection.rowIDs, db: db)
            refreshAdmissionMeasurements()
        }

        // Resample/checkpoint after DELETE before any vacuum phase. If a reader
        // appeared meanwhile, stop; incremental vacuum would otherwise add
        // more churn behind the newly pinned snapshot.
        if try recoveryCheckpointIsPinned(db: db) {
            pinnedReader = true
            refreshAdmissionMeasurements()
            return makeRecoveryResult(
                spansDeleted: deleted,
                vacuumPagesReclaimed: 0
            )
        }
        refreshAdmissionMeasurements()

        var reclaimed = 0
        let mode = Int(StoragePragmas.readAutoVacuumMode(db))
        if deleted > 0, mode == 2 {
            let boundedPages = max(0, min(maxVacuumPages, 8_192))
            if boundedPages > 0 {
                let vacuumBudget = min(
                    reserve,
                    Int64(boundedPages) * 4_096
                )
                try admitMaintenance(upperBoundBytes: vacuumBudget)
                do {
                    let result = try StoragePragmas.runIncrementalVacuum(
                        on: db,
                        maxPages: boundedPages
                    )
                    reclaimed = result.pagesReclaimed
                } catch let error as StoragePragmas.IncrementalVacuumError {
                    let metadata = error.sqliteFailureMetadata
                    try throwSQLiteFailure(
                        metadata: metadata,
                        db: db,
                        context: "bounded incremental vacuum"
                    )
                }
                // incremental_vacuum itself can append WAL frames. The shared
                // primitive deliberately cannot checkpoint because it has no
                // path/floor/family probes; finish through the same freshly
                // admitted PASSIVE -> TRUNCATE chain as the recovery phases.
                if try recoveryCheckpointIsPinned(db: db) {
                    pinnedReader = true
                }
                refreshAdmissionMeasurements()
            }
        }
        clearSQLiteStorageFailureAfterRecoveryIfHealthy(
            generationAtStart: sqliteFailureGenerationAtStart
        )
        return makeRecoveryResult(
            spansDeleted: deleted,
            vacuumPagesReclaimed: reclaimed
        )
    }

    private func clearSQLiteStorageFailureAfterRecoveryIfHealthy(
        generationAtStart: UInt64
    ) {
        guard sqliteStorageFailure != nil,
              sqliteStorageFailureGeneration == generationAtStart else { return }
        if let threshold = admissionThresholdBytes {
            guard let footprint = footprintProbe(databasePath),
                  footprint < threshold else { return }
            lastFootprintBytes = footprint
        }
        if let floor = freeSpaceFloorBytes {
            guard let free = freeSpaceProbe(storageVolumePath),
                  free >= requiredFreeBytes(floor: floor) else { return }
            lastFreeSpaceBytes = free
        }
        sqliteStorageFailure = nil
        refreshAdmissionMeasurements()
        logger.notice("Agent-trace SQLite storage backstop recovered; inserts may retry")
    }

    private struct RecoverySelection {
        var rowIDs: [Int64] = []
        var upperBoundBytes: Int64 = 64 * 1024
    }

    private func selectRecoveryRows(
        db: OpaquePointer,
        olderThan cutoff: Date?,
        maxRows: Int,
        byteBudget: Int64
    ) throws -> RecoverySelection {
        let predicate = cutoff == nil ? "" : "WHERE start_ns < ?1"
        let limitBinding = cutoff == nil ? "?1" : "?2"
        let sql = """
            SELECT rowid,
                   COALESCE(length(CAST(trace_id AS BLOB)), 0)
                 + COALESCE(length(CAST(span_id AS BLOB)), 0)
                 + COALESCE(length(CAST(parent_span_id AS BLOB)), 0)
                 + COALESCE(length(CAST(service_name AS BLOB)), 0)
                 + COALESCE(length(CAST(span_name AS BLOB)), 0)
                 + COALESCE(length(CAST(agent_tool AS BLOB)), 0)
                 + COALESCE(length(CAST(provider_name AS BLOB)), 0)
                 + COALESCE(length(CAST(legacy_gen_ai_system AS BLOB)), 0)
                 + COALESCE(length(CAST(attributes_json AS BLOB)), 0)
                 + COALESCE(length(CAST(search_text AS BLOB)), 0)
                 + COALESCE(length(CAST(trust_label AS BLOB)), 0)
              FROM spans
              \(predicate)
             ORDER BY start_ns ASC, rowid ASC
             LIMIT \(limitBinding)
            """
        var stmt: OpaquePointer?
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRC == SQLITE_OK else {
            try throwSQLiteFailure(
                rc: prepareRC, db: db, context: "select bounded recovery rows")
        }
        defer { sqlite3_finalize(stmt) }
        if let cutoff {
            let cutoffNs = Int64(cutoff.timeIntervalSince1970 * 1_000_000_000)
            sqlite3_bind_int64(stmt, 1, cutoffNs)
            sqlite3_bind_int(stmt, 2, Int32(maxRows))
        } else {
            sqlite3_bind_int(stmt, 1, Int32(maxRows))
        }

        var selection = RecoverySelection()
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                try throwSQLiteFailure(
                    rc: rc, db: db, context: "read bounded recovery rows")
            }
            let payload = max(0, sqlite3_column_int64(stmt, 1))
            let payloadCharge = payload > Int64.max / 2
                ? Int64.max
                : payload * 2
            let proposed = saturatingAdd(
                selection.upperBoundBytes,
                saturatingAdd(payloadCharge, Self.mutationBytesPerRow)
            )
            if proposed > byteBudget { break }
            selection.rowIDs.append(sqlite3_column_int64(stmt, 0))
            selection.upperBoundBytes = proposed
        }
        return selection
    }

    private func deleteRecoveryRows(
        _ rowIDs: [Int64],
        db: OpaquePointer
    ) throws -> Int {
        guard !rowIDs.isEmpty else { return 0 }
        let ids = rowIDs.map(String.init).joined(separator: ",")
        try execTransaction(.begin, db: db)
        do {
            let rc = sqlite3_exec(
                db,
                "DELETE FROM spans WHERE rowid IN (\(ids))",
                nil, nil, nil
            )
            if rc != SQLITE_OK {
                try throwSQLiteFailure(
                    rc: rc, db: db, context: "bounded recovery delete")
            }
            let deleted = Int(sqlite3_changes(db))
            try execTransaction(.commit, db: db)
            return deleted
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    private func admitMaintenance(upperBoundBytes: Int64) throws {
        if let reserve = transactionReserveBytes, upperBoundBytes > reserve {
            try rejectGrowth(.mutationTooLarge(
                estimatedBytes: upperBoundBytes,
                transactionReserveBytes: reserve
            ))
        }
        if let floor = freeSpaceFloorBytes {
            guard let free = freeSpaceProbe(storageVolumePath) else {
                try rejectGrowth(.probeFailed("free-space during recovery"))
            }
            lastFreeSpaceBytes = free
            let required = saturatingAdd(floor, max(0, upperBoundBytes))
            if free < required {
                try rejectGrowth(.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                ))
            }
        }
        if let cap = maxFootprintBytes,
           let threshold = admissionThresholdBytes {
            guard let footprint = footprintProbe(databasePath) else {
                try rejectGrowth(.probeFailed("SQLite-family footprint during recovery"))
            }
            lastFootprintBytes = footprint
            if footprint > cap - min(cap, max(0, upperBoundBytes)) {
                try rejectGrowth(.footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: threshold,
                    capBytes: cap
                ))
            }
        }
    }

    /// A checkpoint can copy every committed WAL frame into newly allocated
    /// main-file pages while the WAL remains allocated. Probe immediately at
    /// that operation boundary and preserve the configured floor plus the
    /// complete non-main family; the footprint cap is intentionally ignored
    /// because draining/truncating WAL is itself a recovery route.
    @discardableResult
    private func admitCheckpointHeadroom() throws
        -> SQLiteCheckpointAdmissionSnapshot {
        let configured = maxFootprintBytes != nil || freeSpaceFloorBytes != nil
        func fail(_ error: TraceStoreStorageAdmissionError) throws -> Never {
            pinnedReader = false
            if configured {
                if storageBlockReason != error.blockReason {
                    logger.fault("\(error.localizedDescription, privacy: .public). WAL checkpoint deferred; existing trace evidence is retained.")
                }
                storageBlockReason = error.blockReason
            }
            throw error
        }

        let main: Int64
        do {
            main = try SQLitePersistentStoreAdmission.measureMainFile(
                databasePath
            )
        } catch {
            try fail(.probeFailed(
                "checkpoint main-file measurement: \(error.localizedDescription)"
            ))
        }
        let measuredFamily = configured
            ? footprintProbe(databasePath)
            : Self.exactSQLiteFootprintBytes(databasePath: databasePath)
        guard let family = measuredFamily, family >= main else {
            lastFootprintBytes = nil
            try fail(.probeFailed("checkpoint SQLite-family footprint"))
        }
        lastFootprintBytes = family
        let measuredFree = configured
            ? freeSpaceProbe(storageVolumePath)
            : Self.availableFilesystemBytes(path: storageVolumePath)
        guard let free = measuredFree else {
            lastFreeSpaceBytes = nil
            try fail(.probeFailed("checkpoint free-space"))
        }
        lastFreeSpaceBytes = free
        let floor = freeSpaceFloorBytes ?? 0
        let snapshot = SQLitePersistentStoreAdmission
            .checkpointAdmissionSnapshot(
                mainFileBytes: main,
                familyFootprintBytes: family,
                freeSpaceBytes: free,
                freeSpaceFloorBytes: floor
            )
        guard snapshot.admitted else {
            try fail(.lowFreeSpace(
                freeBytes: free,
                floorBytes: floor,
                requiredFreeBytes: snapshot.requiredFreeBytes
            ))
        }
        return snapshot
    }

    private struct CheckpointObservation {
        let completed: Bool
        let pinned: Bool
        let logFrames: Int32
        let checkpointedFrames: Int32
    }

    /// Every mode gets its own fresh gate. PASSIVE may have drained part of the
    /// WAL before RESTART/TRUNCATE, so reusing the first filesystem observation
    /// would not prove headroom at the second mutating boundary.
    private func checkpointObservation(
        mode: Int32,
        db: OpaquePointer,
        context: String
    ) throws -> CheckpointObservation {
        try admitCheckpointHeadroom()
        var logFrames: Int32 = 0
        var checkpointedFrames: Int32 = 0
        let rc = sqlite3_wal_checkpoint_v2(
            db,
            nil,
            mode,
            &logFrames,
            &checkpointedFrames
        )
        if rc != SQLITE_OK && rc != SQLITE_BUSY && rc != SQLITE_LOCKED {
            try throwSQLiteFailure(rc: rc, db: db, context: context)
        }
        let frameGap = logFrames >= 0
            && checkpointedFrames >= 0
            && logFrames > checkpointedFrames
        let pinned = rc == SQLITE_BUSY || rc == SQLITE_LOCKED || frameGap
        pinnedReader = pinned
        return CheckpointObservation(
            completed: rc == SQLITE_OK && !frameGap,
            pinned: pinned,
            logFrames: logFrames,
            checkpointedFrames: checkpointedFrames
        )
    }

    private func recoveryCheckpointIsPinned(db: OpaquePointer) throws -> Bool {
        let passive = try checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_PASSIVE),
            db: db,
            context: "recovery passive checkpoint"
        )
        guard passive.completed && !passive.pinned else { return true }
        let truncate = try checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_TRUNCATE),
            db: db,
            context: "recovery truncate checkpoint"
        )
        return !truncate.completed || truncate.pinned
    }

    private func makeRecoveryResult(
        spansDeleted: Int,
        vacuumPagesReclaimed: Int
    ) -> TraceStoreStorageRecoveryResult {
        TraceStoreStorageRecoveryResult(
            pinnedReader: pinnedReader,
            spansDeleted: spansDeleted,
            vacuumPagesReclaimed: vacuumPagesReclaimed,
            footprintBytes: lastFootprintBytes,
            freeSpaceBytes: lastFreeSpaceBytes,
            autoVacuumMode: db.map { Int(StoragePragmas.readAutoVacuumMode($0)) } ?? 0
        )
    }

    /// Delete every span whose `start_ns` is older than `cutoff`.
    /// Returns the number of rows removed.
    @discardableResult
    public func prune(olderThan cutoff: Date) throws -> Int {
        guard let db else { throw TraceStoreError.queryFailed("db not open") }
        guard maxFootprintBytes == nil && freeSpaceFloorBytes == nil else {
            throw TraceStoreError.queryFailed(
                "configured TraceStore maintenance must use recoverStorageBudget"
            )
        }
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
        guard maxFootprintBytes == nil && freeSpaceFloorBytes == nil else {
            throw TraceStoreError.queryFailed(
                "configured TraceStore maintenance must use recoverStorageBudget"
            )
        }
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
        guard maxFootprintBytes == nil && freeSpaceFloorBytes == nil else {
            throw TraceStoreError.queryFailed(
                "configured TraceStore maintenance must use recoverStorageBudget"
            )
        }
        guard maxPages > 0,
              StoragePragmas.readAutoVacuumMode(db) == 2 else { return 0 }
        let leading = try checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_PASSIVE),
            db: db,
            context: "pre-incremental-VACUUM passive checkpoint"
        )
        guard leading.completed && !leading.pinned else {
            throw TraceStoreError.queryFailed(
                "incremental VACUUM deferred because the WAL could not be fully checkpointed"
            )
        }
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: maxPages)
        let trailing = try checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_TRUNCATE),
            db: db,
            context: "post-incremental-VACUUM truncate checkpoint"
        )
        guard trailing.completed && !trailing.pinned else {
            throw TraceStoreError.queryFailed(
                "incremental VACUUM completed but its WAL could not be fully truncated"
            )
        }
        return result.pagesReclaimed
    }

    /// Legacy/offline helper retained for unconfigured maintenance tools. A
    /// production store always has cap/floor admission configured and refuses
    /// this whole-file rewrite; its only online path is recoverStorageBudget.
    /// A pre-INCREMENTAL database that needs conversion must be handled with
    /// the engine stopped and enough scratch space for a deliberate offline
    /// operation.
    public func vacuum() async throws {
        guard let db = db else { return }
        guard maxFootprintBytes == nil && freeSpaceFloorBytes == nil else {
            throw TraceStoreError.queryFailed(
                "full online VACUUM is disabled for configured TraceStore; use bounded recovery"
            )
        }
        // Checkpoint PASSIVE before / TRUNCATE after — see the identical fix in
        // SQLiteCausalGraphStore.vacuum(). traces.db is in WAL mode and its
        // size-cap caller (DaemonTimers.swift:986) measures with
        // measureDatabaseFootprintMB (the complete SQLite family) after this
        // returns, so an un-checkpointed rebuild is counted on top of the file
        // it has not replaced yet — the cap reads as still-breached and the
        // next tick prunes more spans for nothing.
        let leading = try checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_PASSIVE),
            db: db,
            context: "pre-VACUUM passive checkpoint"
        )
        guard leading.completed && !leading.pinned else {
            throw TraceStoreError.queryFailed(
                "VACUUM deferred because the WAL could not be fully checkpointed"
            )
        }
        sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        try SQLitePersistentStoreAdmission.requireFullVacuumHeadroom(
            databasePath: databasePath,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent,
            freeSpaceFloorBytes: 0
        )
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw TraceStoreError.queryFailed("VACUUM failed: \(msg)")
        }
        let trailing = try checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_TRUNCATE),
            db: db,
            context: "post-VACUUM truncate checkpoint"
        )
        guard trailing.completed && !trailing.pinned else {
            throw TraceStoreError.queryFailed(
                "VACUUM completed but its WAL could not be fully truncated"
            )
        }
    }

    /// PASSIVE→RESTART checkpoint chain — used by the size-cap path
    /// to drain the WAL before measuring on-disk footprint.
    @discardableResult
    public func walCheckpoint() async -> Bool {
        guard let db = db else { return false }
        do {
            let passive = try checkpointObservation(
                mode: Int32(SQLITE_CHECKPOINT_PASSIVE),
                db: db,
                context: "public passive checkpoint"
            )
            if passive.completed { return true }
            let restart = try checkpointObservation(
                mode: Int32(SQLITE_CHECKPOINT_RESTART),
                db: db,
                context: "public restart checkpoint"
            )
            return restart.completed
        } catch {
            return false
        }
    }

    /// TRUNCATE checkpoint — drains the WAL into the main DB AND shrinks
    /// the `-wal` sidecar back to zero bytes. RESTART (above) drains the
    /// WAL but leaves the file pinned at its high-water mark, which under
    /// `journal_size_limit = 64 MiB` means traces.db-wal can sit at 64 MiB
    /// indefinitely — invisible to a file-only size check yet real
    /// footprint. Best-effort: degrades to RESTART semantics under an
    /// active reader, which is still progress.
    @discardableResult
    public func walCheckpointTruncate() async -> Bool {
        guard let db = db else { return false }
        do {
            return try checkpointObservation(
                mode: Int32(SQLITE_CHECKPOINT_TRUNCATE),
                db: db,
                context: "public truncate checkpoint"
            ).completed
        } catch {
            return false
        }
    }

    /// Read the file's current `auto_vacuum` mode. Used by callers
    /// that want to log the gap when this DB is not in INCREMENTAL
    /// mode (mode 2). Mode 0 = NONE, 1 = FULL, 2 = INCREMENTAL.
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }
}
