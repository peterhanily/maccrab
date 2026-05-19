// SQLiteCausalGraphStore.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6b) — SQLite-backed implementation of
// `CausalGraphStore` per §13 / §15.5 of the v1.10.0 spec.
//
// Backed by `tracegraph.db` (separate file from `events.db` and
// `traces.db` per §13.0). All 7 tables from §13 are created via the
// existing SchemaMigrator pattern. WAL + per-connection pragmas
// follow the TraceStore template.
//
// Encryption: `attributes_json` (entities) and `evidence_json` (edges)
// are encrypted at rest via the optional DatabaseEncryption (§13.0).
// Tests pass nil for plaintext storage; production wires the
// shared keychain-backed AES-256-GCM key.
//
// Graph traversal: BFS over edges within the time window, bounded
// by depth. v1.10.0 graphs are small (≤ 250 entities in the context
// budget per §14.3) so the iterative shape stays well under the
// performance budget; recursive CTE is a future optimization.
//
// Critical-path scoring (relation weights, confidence-weighted) is
// PR-8's responsibility. PR-6b returns an unweighted shortest path
// — the protocol contract is "shortest path subject to maxDepth";
// caller does the rest.

import Foundation
import Darwin
import CSQLCipher
import os.log

// MARK: - Error

public enum CausalGraphStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case schemaFailed(String)
    case prepareFailed(String)
    case bindFailed(String)
    case stepFailed(String)
    case decodeFailed(String)
    case unexpectedNull(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "CausalGraphStore: open failed: \(m)"
        case .schemaFailed(let m): return "CausalGraphStore: schema failed: \(m)"
        case .prepareFailed(let m): return "CausalGraphStore: prepare failed: \(m)"
        case .bindFailed(let m): return "CausalGraphStore: bind failed: \(m)"
        case .stepFailed(let m): return "CausalGraphStore: step failed: \(m)"
        case .decodeFailed(let m): return "CausalGraphStore: decode failed: \(m)"
        case .unexpectedNull(let m): return "CausalGraphStore: unexpected null: \(m)"
        }
    }
}

// MARK: - SQLiteCausalGraphStore

public actor SQLiteCausalGraphStore: CausalGraphStore {

    // MARK: Configuration

    private var db: OpaquePointer?
    private let databasePath: String
    private let encryption: DatabaseEncryption?
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "graph-store")

    // SQLITE_TRANSIENT lives at file scope (see bottom of file) — used
    // by every sqlite3_bind_text call site here.

    // MARK: Schema

    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "tracegraph_baseline",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS trace_entities (
                    id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    attributes_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(entity_type, stable_key)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_entities_type_seen ON trace_entities(entity_type, last_seen)",
                """
                CREATE TABLE IF NOT EXISTS trace_edges (
                    id TEXT PRIMARY KEY,
                    source_entity_id TEXT NOT NULL,
                    target_entity_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    confidence_tier TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    event_ids_json TEXT NOT NULL,
                    FOREIGN KEY(source_entity_id) REFERENCES trace_entities(id),
                    FOREIGN KEY(target_entity_id) REFERENCES trace_entities(id),
                    UNIQUE(source_entity_id, target_entity_id, relation)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_edges_source ON trace_edges(source_entity_id, last_seen)",
                "CREATE INDEX IF NOT EXISTS idx_edges_target ON trace_edges(target_entity_id, last_seen)",
                "CREATE INDEX IF NOT EXISTS idx_edges_relation ON trace_edges(relation, last_seen)",
                """
                CREATE TABLE IF NOT EXISTS traces (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    anchor_event_id TEXT NOT NULL,
                    root_entity_id TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    summary_json TEXT,
                    attack_json TEXT,
                    evidence_bundle_status TEXT DEFAULT 'not_created',
                    daemon_version TEXT NOT NULL,
                    ruleset_version TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    policy_snapshot_json TEXT NOT NULL,
                    trace_signing_key_mode TEXT NOT NULL,
                    replay_scope TEXT NOT NULL,
                    attribution_override_policy TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_traces_status_created ON traces(status, created_at)",
                """
                CREATE TABLE IF NOT EXISTS trace_membership (
                    trace_id TEXT NOT NULL,
                    entity_id TEXT,
                    edge_id TEXT,
                    role TEXT NOT NULL,
                    layer TEXT NOT NULL DEFAULT 'core',
                    added_at REAL NOT NULL,
                    PRIMARY KEY(trace_id, entity_id, edge_id),
                    CHECK ((entity_id IS NOT NULL) <> (edge_id IS NOT NULL))
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_membership_trace_layer ON trace_membership(trace_id, layer)",
                """
                CREATE TABLE IF NOT EXISTS trace_rule_hits (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_title TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    matched_event_id TEXT,
                    matched_entity_id TEXT,
                    matched_edge_id TEXT,
                    matched_at REAL NOT NULL,
                    explanation_json TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_rule_hits_trace ON trace_rule_hits(trace_id, matched_at)",
                """
                CREATE TABLE IF NOT EXISTS trace_replay_runs (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    ruleset_version TEXT NOT NULL,
                    daemon_version TEXT NOT NULL,
                    normalization_version TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    completed_at REAL,
                    deterministic INTEGER NOT NULL,
                    result_json TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_replay_runs_trace ON trace_replay_runs(trace_id, started_at)",
                """
                CREATE TABLE IF NOT EXISTS trace_hash_chain (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    previous_hash TEXT,
                    current_hash TEXT NOT NULL,
                    event_id TEXT,
                    edge_id TEXT,
                    chain_head_signature TEXT,
                    chain_head_published_to_unified_log INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    UNIQUE(trace_id, sequence_number)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_hash_chain_trace_seq ON trace_hash_chain(trace_id, sequence_number)",
            ]
        ),
    ]

    // MARK: Lifecycle

    /// - Parameters:
    ///   - databasePath: Filesystem path to `tracegraph.db`.
    ///   - encryption: Optional encryption layer for `attributes_json` /
    ///     `evidence_json` payloads.
    ///   - forceReadOnly: When `true`, open the database with
    ///     `SQLITE_OPEN_READONLY` and skip migrations / chmod. The
    ///     dashboard (MacCrabApp/V2LiveDataProvider) sets this to
    ///     guarantee its long-lived handle never holds shared/upgrade
    ///     locks that block the daemon's `VACUUM` /
    ///     `wal_checkpoint(TRUNCATE)`. Field background (v1.12.6 RC1,
    ///     Wave 9A): `tracegraph.db` grew to 11 GB while the size cap
    ///     was 300 MB because the daemon's VACUUM was blocked by the
    ///     dashboard's RW connection. See `EventStore.openDatabase` for
    ///     the full incident notes.
    public init(
        databasePath: String,
        encryption: DatabaseEncryption? = nil,
        forceReadOnly: Bool = false
    ) async throws {
        self.databasePath = databasePath
        self.encryption = encryption
        try openDatabase(forceReadOnly: forceReadOnly)
        // Migrations write to the schema (CREATE INDEX, ALTER TABLE). A
        // RO connection cannot run them — and shouldn't need to: the
        // daemon's RW connection has already applied the migrations
        // before the dashboard's RO open ever happens.
        if !forceReadOnly {
            try applyMigrations()
        }
    }

    deinit {
        if let db { sqlite3_close(db) }
    }

    public func close() {
        if let db {
            sqlite3_close(db)
            self.db = nil
        }
    }

    // MARK: Open + migrate

    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else { return }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw CausalGraphStoreError.databaseOpenFailed("refusing to open symlink: \(path)")
        }
    }

    private func openDatabase(forceReadOnly: Bool = false) throws {
        try Self.rejectIfSymlink(databasePath)
        try Self.rejectIfSymlink(databasePath + "-wal")
        try Self.rejectIfSymlink(databasePath + "-shm")
        try Self.rejectIfSymlink(databasePath + "-journal")

        // umask 0o007 ⇒ new SQLite WAL/SHM files get created 0o660.
        // Mirror EventStore/AlertStore/CampaignStore/TraceStore: the
        // dashboard runs as the admin-group user and needs write
        // access to mutate. 0o640 (the historical default) breaks any
        // future trace mutation flow with "database is read only".
        //
        // When forceReadOnly == true the dashboard is the caller: it
        // never creates new files (no CREATE flag) and never chmods —
        // the daemon owns the file and the dashboard has no business
        // touching its mode bits.
        var handle: OpaquePointer?
        let flags: Int32
        let rc: Int32
        if forceReadOnly {
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = sqlite3_open_v2(databasePath, &handle, flags, nil)
        } else {
            flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX
            let oldUmask = umask(0o007)
            rc = sqlite3_open_v2(databasePath, &handle, flags, nil)
            umask(oldUmask)
        }
        guard rc == SQLITE_OK, let openedHandle = handle else {
            let msg = handle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let handle { sqlite3_close(handle) }
            throw CausalGraphStoreError.databaseOpenFailed(msg)
        }
        self.db = openedHandle
        // Re-clamp existing files from prior installs that were created
        // under the older 0o640 default. Skip when forceReadOnly — see
        // umask block above.
        if !forceReadOnly {
            chmod(databasePath, 0o660)
            chmod(databasePath + "-wal", 0o660)
            chmod(databasePath + "-shm", 0o660)
        }

        // Per-connection pragmas: smaller than EventStore (graph data is
        // moderate volume), larger than alerts (recursive walks are
        // common). Roughly midway: 16 MB cache, 64 MB mmap.
        //
        // journal_mode = WAL is the only pragma that touches the file
        // (it changes the journaling format) — skip it on a RO handle
        // since the daemon already set the file's mode. The remaining
        // pragmas are per-connection state and are safe to apply
        // either way.
        // Wave 9B.1 (v1.12.6 RC2): auto_vacuum MUST come BEFORE journal_mode
        // — SQLite silently refuses to flip auto_vacuum after the WAL setup
        // dirties the DB header. Pre-9B.1 tracegraph.db never set
        // auto_vacuum, so it stayed in mode 0 (NONE) and incrementalVacuum
        // was a no-op. Field-confirmed bug: tracegraph.db at 11 GB in
        // mode 0 on a v1.12.6 RC1 user machine.
        if !forceReadOnly {
            sqlite3_exec(openedHandle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
            sqlite3_exec(openedHandle, "PRAGMA journal_mode = WAL", nil, nil, nil)
            sqlite3_exec(openedHandle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
            sqlite3_exec(openedHandle, "PRAGMA wal_autocheckpoint = 1000", nil, nil, nil)
        }
        sqlite3_exec(openedHandle, "PRAGMA cache_size = -16000", nil, nil, nil)
        sqlite3_exec(openedHandle, "PRAGMA mmap_size = 67108864", nil, nil, nil)
        sqlite3_exec(openedHandle, "PRAGMA temp_store = MEMORY", nil, nil, nil)
        sqlite3_exec(openedHandle, "PRAGMA busy_timeout = 5000", nil, nil, nil)
        sqlite3_exec(openedHandle, "PRAGMA foreign_keys = ON", nil, nil, nil)
    }

    private func applyMigrations() throws {
        guard let db else {
            throw CausalGraphStoreError.databaseOpenFailed("nil handle at migration time")
        }
        do {
            // v1.12.0 RC23: skip the per-init quick_check. Field-measured
            // boot path: tracegraph.db reached 7 GB on a long-running
            // install, and PRAGMA quick_check on a 7 GB SQLite file took
            // ~27 s — eating the whole daemon TraceGraph wiring step.
            // Same trade-off as EventStore: real corruption surfaces
            // immediately on actual queries, and an explicit operator
            // path exists in `maccrabctl maintenance check`.
            try SchemaMigrator.run(
                on: db,
                migrations: Self.schemaMigrations,
                logger: { msg in
                    self.logger.debug("\(msg, privacy: .public)")
                },
                skipQuickCheck: true
            )
        } catch let error as SchemaMigrationError {
            throw CausalGraphStoreError.schemaFailed(error.localizedDescription)
        }
    }

    // MARK: - upsertEntity

    public func upsertEntity(_ entity: TraceEntity) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT INTO trace_entities (
            id, entity_type, stable_key, display_name,
            first_seen, last_seen, attributes_json, source,
            confidence, observation_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(entity_type, stable_key) DO UPDATE SET
            last_seen = max(trace_entities.last_seen, excluded.last_seen),
            observation_count = trace_entities.observation_count + 1,
            attributes_json = excluded.attributes_json,
            confidence = excluded.confidence,
            display_name = excluded.display_name
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        let encryptedAttrs = encryption?.encrypt(entity.attributesJson) ?? entity.attributesJson

        sqlite3_bind_text(stmt, 1, entity.id, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, entity.entityType, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, entity.stableKey, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 4, entity.displayName, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 5, entity.firstSeen.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 6, entity.lastSeen.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 7, encryptedAttrs, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 8, entity.source, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 9, entity.confidence)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
    }

    // MARK: - upsertEdge

    public func upsertEdge(_ edge: TraceEdge) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT INTO trace_edges (
            id, source_entity_id, target_entity_id, relation,
            first_seen, last_seen, confidence, confidence_tier,
            evidence_json, event_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_entity_id, target_entity_id, relation) DO UPDATE SET
            last_seen = max(trace_edges.last_seen, excluded.last_seen),
            confidence = excluded.confidence,
            confidence_tier = excluded.confidence_tier,
            evidence_json = excluded.evidence_json,
            event_ids_json = excluded.event_ids_json
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        let encryptedEvidence = encryption?.encrypt(edge.evidenceJson) ?? edge.evidenceJson

        sqlite3_bind_text(stmt, 1, edge.id, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, edge.sourceEntityId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, edge.targetEntityId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 4, edge.relation, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 5, edge.firstSeen.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 6, edge.lastSeen.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 7, edge.confidence)
        sqlite3_bind_text(stmt, 8, edge.confidenceTier, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 9, encryptedEvidence, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 10, edge.eventIdsJson, -1, SQLITE_TRANSIENT)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
    }

    // MARK: - entity / edge lookups

    public func entity(id: String) async throws -> TraceEntity? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, entity_type, stable_key, display_name,
               first_seen, last_seen, attributes_json, source,
               confidence, observation_count
          FROM trace_entities WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeEntityRow(stmt!)
    }

    public func edge(id: String) async throws -> TraceEdge? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, source_entity_id, target_entity_id, relation,
               first_seen, last_seen, confidence, confidence_tier,
               evidence_json, event_ids_json
          FROM trace_edges WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeEdgeRow(stmt!)
    }

    // MARK: - Graph traversal (BFS)

    public func ancestors(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree {
        try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .incoming,
            relations: ["spawned"]
        )
    }

    public func descendants(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree {
        try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .outgoing,
            relations: ["spawned"]
        )
    }

    public func neighborhood(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree {
        // Bidirectional, all relations.
        let inSubtree = try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .incoming,
            relations: nil
        )
        let outSubtree = try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .outgoing,
            relations: nil
        )
        // Include the anchor entity itself in neighborhood results.
        var anchorEntities: [TraceEntity] = []
        if let anchor = try lookupEntitySync(id: entityId) {
            anchorEntities.append(anchor)
        }
        let mergedEntities = mergeUniqueEntities(anchorEntities + inSubtree.entities + outSubtree.entities)
        let mergedEdges = mergeUniqueEdges(inSubtree.edges + outSubtree.edges)
        let truncated = inSubtree.truncated || outSubtree.truncated
        return GraphSubtree(entities: mergedEntities, edges: mergedEdges, truncated: truncated)
    }

    public func criticalPath(from source: String, to target: String, maxDepth: Int) async throws -> [TraceEdge] {
        // Unweighted BFS shortest path (PR-8 will layer
        // confidence-weighted scoring on top).
        //
        // v1.12.0 RC4 fix (Perf-NEW-2): cap the frontier per BFS
        // level. Pre-fix this was the same unbounded-fan-out shape
        // that Perf-H2 closed in `walk()`. criticalPath is called
        // from TraceMaterializer.materialize on EVERY anchor (hot
        // path), so a widely-fanned process burst would re-introduce
        // the same actor-starvation symptom on the SQLite causal-
        // graph store. Frontier cap 256 matches `walk()`'s; we don't
        // signal truncation back to the caller because path-not-
        // found returns the same empty result.
        guard maxDepth > 0 else { return [] }
        if source == target { return [] }

        var visited: Set<String> = [source]
        var parentEdge: [String: TraceEdge] = [:]   // entityId → edge that reached it
        var frontier: [String] = [source]
        let frontierCap = 256

        for _ in 0 ..< maxDepth {
            var next: [String] = []
            outer: for current in frontier {
                let outgoing = try fetchEdges(
                    pivotId: current,
                    direction: .outgoing,
                    window: .unlimited,
                    relations: nil
                )
                for edge in outgoing {
                    let neighbor = edge.targetEntityId
                    if visited.contains(neighbor) { continue }
                    visited.insert(neighbor)
                    parentEdge[neighbor] = edge
                    if neighbor == target {
                        return reconstructPath(target: target, parentEdge: parentEdge)
                    }
                    next.append(neighbor)
                    if next.count >= frontierCap { break outer }
                }
            }
            if next.isEmpty { break }
            frontier = next
        }
        return []
    }

    private enum EdgeDirection { case incoming, outgoing }

    private func walk(
        startId: String,
        depth: Int,
        window: TimeWindow,
        edgeDirection: EdgeDirection,
        relations: Set<String>?
    ) throws -> GraphSubtree {
        guard depth > 0 else { return .empty }
        var visited: Set<String> = [startId]
        var entitiesById: [String: TraceEntity] = [:]
        var collectedEdges: [TraceEdge] = []
        var frontier: Set<String> = [startId]
        var truncated = false

        // v1.12.0 RC3 (Perf-H2): cap the frontier per BFS level. A
        // widely-fanned process (e.g. a `bun` shell with many
        // spawned children + many file edges) at depth-3 can pull
        // thousands of edges per walk. Under adversarial burst this
        // serializes on the single SQLiteCausalGraphStore actor that
        // is also handling the hot-path event writes — main pump
        // starves. Frontier cap of 256/level keeps the walk bounded;
        // when we hit the cap we set `truncated=true`.
        let frontierCap = 256
        for _ in 0 ..< depth {
            var nextFrontier: Set<String> = []
            outer: for pivot in frontier {
                let edges = try fetchEdges(
                    pivotId: pivot,
                    direction: edgeDirection,
                    window: window,
                    relations: relations
                )
                for edge in edges {
                    let other = (edgeDirection == .incoming) ? edge.sourceEntityId : edge.targetEntityId
                    if visited.contains(other) { continue }
                    visited.insert(other)
                    nextFrontier.insert(other)
                    collectedEdges.append(edge)
                    if let entity = try lookupEntitySync(id: other) {
                        entitiesById[other] = entity
                    }
                    if nextFrontier.count >= frontierCap {
                        truncated = true
                        break outer
                    }
                }
            }
            if nextFrontier.isEmpty { break }
            frontier = nextFrontier
        }

        // Truncation flag: did the BFS terminate because depth was hit
        // even though there were more frontier nodes available? We
        // detect this conservatively — if the loop exited via running
        // out of iterations rather than empty frontier.
        // (For v1.10.0 the simpler heuristic is: if the final frontier
        // had outgoing edges we didn't explore, mark truncated.)
        //
        // v1.12.0 RC4 fix (Perf-NEW-1): skip the post-pass entirely
        // when `truncated` is already true from the frontier-cap
        // path. The post-pass re-issues `fetchEdges` against every
        // node in the final frontier (up to 256 nodes from the
        // frontierCap) — a hot-path SQLite burst that partially
        // defeats Perf-H2's bound. If we already know we're
        // truncated, there's nothing new to learn.
        if !truncated {
            for pivot in frontier {
                let unexplored = try fetchEdges(
                    pivotId: pivot,
                    direction: edgeDirection,
                    window: window,
                    relations: relations
                )
                for edge in unexplored {
                    let other = (edgeDirection == .incoming) ? edge.sourceEntityId : edge.targetEntityId
                    if !visited.contains(other) {
                        truncated = true
                        break
                    }
                }
                if truncated { break }
            }
        }

        return GraphSubtree(
            entities: Array(entitiesById.values),
            edges: collectedEdges,
            truncated: truncated
        )
    }

    private func fetchEdges(
        pivotId: String,
        direction: EdgeDirection,
        window: TimeWindow,
        relations: Set<String>?
    ) throws -> [TraceEdge] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let pivotColumn = (direction == .incoming) ? "target_entity_id" : "source_entity_id"
        var sql = """
        SELECT id, source_entity_id, target_entity_id, relation,
               first_seen, last_seen, confidence, confidence_tier,
               evidence_json, event_ids_json
          FROM trace_edges
         WHERE \(pivotColumn) = ?
           AND last_seen >= ? AND last_seen <= ?
        """
        if let relations, !relations.isEmpty {
            let placeholders = relations.map { _ in "?" }.joined(separator: ", ")
            sql += " AND relation IN (\(placeholders))"
        }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, pivotId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 2, window.start.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 3, window.end.timeIntervalSince1970)
        if let relations, !relations.isEmpty {
            for (idx, rel) in relations.sorted().enumerated() {
                sqlite3_bind_text(stmt, Int32(4 + idx), rel, -1, SQLITE_TRANSIENT)
            }
        }

        var out: [TraceEdge] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeEdgeRow(stmt!))
        }
        return out
    }

    private func lookupEntitySync(id: String) throws -> TraceEntity? {
        guard let db else { return nil }
        let sql = """
        SELECT id, entity_type, stable_key, display_name,
               first_seen, last_seen, attributes_json, source,
               confidence, observation_count
          FROM trace_entities WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_ROW { return nil }
        return try decodeEntityRow(stmt!)
    }

    private func reconstructPath(target: String, parentEdge: [String: TraceEdge]) -> [TraceEdge] {
        var path: [TraceEdge] = []
        var current = target
        while let edge = parentEdge[current] {
            path.append(edge)
            current = edge.sourceEntityId
            if path.count > 1024 { break }   // pathological-loop guard
        }
        return path.reversed()
    }

    // MARK: - Trace lifecycle

    public func saveTrace(_ trace: Trace, members: [TraceMembership]) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        sqlite3_exec(db, "BEGIN TRANSACTION", nil, nil, nil)
        do {
            try insertOrReplaceTraceRow(trace, db: db)
            // Purge prior memberships for this trace id so re-saves are idempotent.
            try execBound(
                db: db,
                sql: "DELETE FROM trace_membership WHERE trace_id = ?",
                bindings: { stmt in
                    sqlite3_bind_text(stmt, 1, trace.id, -1, SQLITE_TRANSIENT)
                }
            )
            for member in members {
                try insertMembership(member, db: db)
            }
            sqlite3_exec(db, "COMMIT", nil, nil, nil)
        } catch {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw error
        }
    }

    public func loadTrace(id: String) async throws -> (trace: Trace, members: [TraceMembership])? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard let trace = try fetchTraceRow(id: id, db: db) else { return nil }
        let members = try fetchTraceMembership(traceId: id, db: db)
        return (trace, members)
    }

    public func updateTraceStatus(id: String, status: String, updatedAt: Date) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        try execBound(
            db: db,
            sql: "UPDATE traces SET status = ?, updated_at = ? WHERE id = ?",
            bindings: { stmt in
                sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT)
                sqlite3_bind_double(stmt, 2, updatedAt.timeIntervalSince1970)
                sqlite3_bind_text(stmt, 3, id, -1, SQLITE_TRANSIENT)
            }
        )
    }

    public func listTraces(limit: Int) async throws -> [Trace] {
        try await listTraces(limit: limit, status: nil)
    }

    /// v1.11.1 (audit perf MEDIUM): status-filtered listTraces. Pushes
    /// the filter into SQL — pre-fix `handleGetTraces` did
    /// `raw.filter { $0.status == f }` AFTER the limit, so a caller
    /// asking for `limit:25 status:open` could get fewer than 25
    /// results when more existed.
    public func listTraces(limit: Int, status: String?) async throws -> [Trace] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let baseSelect = """
        SELECT id, title, anchor_event_id, root_entity_id, severity, confidence,
               status, created_at, updated_at, summary_json, attack_json,
               evidence_bundle_status, daemon_version, ruleset_version,
               policy_id, policy_version, policy_sha256, policy_snapshot_json,
               trace_signing_key_mode, replay_scope, attribution_override_policy
          FROM traces
        """
        let sql: String
        if status != nil {
            sql = baseSelect + " WHERE status = ? ORDER BY created_at DESC LIMIT ?"
        } else {
            sql = baseSelect + " ORDER BY created_at DESC LIMIT ?"
        }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        if let status {
            sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 2, Int32(limit))
        } else {
            sqlite3_bind_int(stmt, 1, Int32(limit))
        }
        var out: [Trace] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeTraceRow(stmt!))
        }
        return out
    }

    /// v1.11.1 (audit perf LOW): SQL-side title substring search.
    /// Pre-fix `hunt_trace` listed up to 500 candidates then
    /// substring-filtered in Swift; pushing to SQL `LIKE` lets the
    /// query planner use an index when present and skips
    /// deserialization for non-matches.
    public func huntTraces(query: String, limit: Int) async throws -> [Trace] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, title, anchor_event_id, root_entity_id, severity, confidence,
               status, created_at, updated_at, summary_json, attack_json,
               evidence_bundle_status, daemon_version, ruleset_version,
               policy_id, policy_version, policy_sha256, policy_snapshot_json,
               trace_signing_key_mode, replay_scope, attribution_override_policy
          FROM traces
         WHERE LOWER(title) LIKE ?
         ORDER BY updated_at DESC
         LIMIT ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        let pattern = "%\(query.lowercased())%"
        sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 2, Int32(limit))
        var out: [Trace] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeTraceRow(stmt!))
        }
        return out
    }

    /// v1.11.1 (audit perf HIGH): O(1) member count by trace id. Pre-fix
    /// `handleGetTraces` called `loadTrace` per row just to read
    /// `members.count` — that's 2 SQL queries + full member-array
    /// deserialization for a one-line list endpoint. Up to 400 SQL
    /// queries on a 200-trace listing.
    public func memberCount(traceId: String) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = "SELECT COUNT(*) FROM trace_membership WHERE trace_id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// v1.11.1 (audit perf HIGH): "which trace contains this entity"
    /// in O(1) instead of O(traces × members). Used by MCP
    /// `trace_from_event` which previously listed 200 traces and
    /// linearly scanned each one's members.
    ///
    /// Returns the most recently-updated trace whose membership table
    /// references the entity, OR whose anchor event id matches.
    public func traceContaining(entityId: String) async throws -> Trace? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT t.id, t.title, t.anchor_event_id, t.root_entity_id, t.severity, t.confidence,
               t.status, t.created_at, t.updated_at, t.summary_json, t.attack_json,
               t.evidence_bundle_status, t.daemon_version, t.ruleset_version,
               t.policy_id, t.policy_version, t.policy_sha256, t.policy_snapshot_json,
               t.trace_signing_key_mode, t.replay_scope, t.attribution_override_policy
          FROM traces t
         WHERE t.id IN (
                 SELECT trace_id FROM trace_membership WHERE entity_id = ?
                 UNION
                 SELECT id FROM traces WHERE anchor_event_id = ?
               )
         ORDER BY t.updated_at DESC
         LIMIT 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, entityId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, entityId, -1, SQLITE_TRANSIENT)
        if sqlite3_step(stmt) == SQLITE_ROW {
            return try decodeTraceRow(stmt!)
        }
        return nil
    }

    // MARK: - Rule hits / replay / chain

    public func recordRuleHit(_ hit: TraceRuleHit) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT OR REPLACE INTO trace_rule_hits (
            id, trace_id, rule_id, rule_title, rule_version, severity,
            matched_event_id, matched_entity_id, matched_edge_id, matched_at, explanation_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, hit.id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, hit.traceId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, hit.ruleId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 4, hit.ruleTitle, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 5, hit.ruleVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 6, hit.severity, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 7, hit.matchedEventId)
            Self.bindOptionalText(stmt, 8, hit.matchedEntityId)
            Self.bindOptionalText(stmt, 9, hit.matchedEdgeId)
            sqlite3_bind_double(stmt, 10, hit.matchedAt.timeIntervalSince1970)
            sqlite3_bind_text(stmt, 11, hit.explanationJson, -1, SQLITE_TRANSIENT)
        }
    }

    public func recordReplayRun(_ run: TraceReplayRun) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT OR REPLACE INTO trace_replay_runs (
            id, trace_id, bundle_id, ruleset_version, daemon_version,
            normalization_version, started_at, completed_at, deterministic, result_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, run.id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, run.traceId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, run.bundleId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 4, run.rulesetVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 5, run.daemonVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 6, run.normalizationVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 7, run.startedAt.timeIntervalSince1970)
            if let completed = run.completedAt {
                sqlite3_bind_double(stmt, 8, completed.timeIntervalSince1970)
            } else {
                sqlite3_bind_null(stmt, 8)
            }
            sqlite3_bind_int(stmt, 9, run.deterministic ? 1 : 0)
            sqlite3_bind_text(stmt, 10, run.resultJson, -1, SQLITE_TRANSIENT)
        }
    }

    public func appendHashChain(_ entry: TraceHashChainEntry) async throws {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT INTO trace_hash_chain (
            id, trace_id, sequence_number, previous_hash, current_hash,
            event_id, edge_id, chain_head_signature,
            chain_head_published_to_unified_log, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, entry.id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, entry.traceId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 3, Int32(entry.sequenceNumber))
            Self.bindOptionalText(stmt, 4, entry.previousHash)
            sqlite3_bind_text(stmt, 5, entry.currentHash, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 6, entry.eventId)
            Self.bindOptionalText(stmt, 7, entry.edgeId)
            Self.bindOptionalText(stmt, 8, entry.chainHeadSignature)
            sqlite3_bind_int(stmt, 9, entry.chainHeadPublishedToUnifiedLog ? 1 : 0)
            sqlite3_bind_double(stmt, 10, entry.createdAt.timeIntervalSince1970)
        }
    }

    public func latestHashChainEntry(for traceId: String) async throws -> TraceHashChainEntry? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, trace_id, sequence_number, previous_hash, current_hash,
               event_id, edge_id, chain_head_signature,
               chain_head_published_to_unified_log, created_at
          FROM trace_hash_chain
         WHERE trace_id = ?
         ORDER BY sequence_number DESC
         LIMIT 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeHashChainRow(stmt!)
    }

    // MARK: - Title rewrite + cascade delete (for demo / housekeeping)

    /// Prefix the title of every trace whose id is in `ids` with the
    /// given string. Used by `maccrabctl trace demo` to mark
    /// synthetic traces as `[DEMO] ` after the materializer has emitted
    /// them with anchor-derived default titles.
    public func prefixTraceTitles(ids: [String], with prefix: String) async throws {
        guard let db, !ids.isEmpty else { return }
        let placeholders = ids.map { _ in "?" }.joined(separator: ", ")
        let sql = "UPDATE traces SET title = ? || title WHERE id IN (\(placeholders))"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_TRANSIENT)
        for (idx, id) in ids.enumerated() {
            sqlite3_bind_text(stmt, Int32(2 + idx), id, -1, SQLITE_TRANSIENT)
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
    }

    /// Delete every trace whose title starts with the given prefix,
    /// plus its membership / rule-hit / replay-run / hash-chain rows.
    /// Returns the count of trace rows removed. Orphaned entities +
    /// edges are left in place — they're invisible to the dashboard
    /// (which lists by trace) and harmless storage-wise.
    @discardableResult
    public func deleteTracesWithTitlePrefix(_ prefix: String) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let pattern = prefix + "%"

        // First, gather the matching trace ids.
        var ids: [String] = []
        do {
            let sql = "SELECT id FROM traces WHERE title LIKE ?"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT)
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let cstr = sqlite3_column_text(stmt, 0) {
                    ids.append(String(cString: cstr))
                }
            }
        }
        guard !ids.isEmpty else { return 0 }

        // Cascade delete in a single transaction so a partial failure
        // doesn't leave the DB half-cleaned.
        sqlite3_exec(db, "BEGIN TRANSACTION", nil, nil, nil)
        do {
            let placeholders = ids.map { _ in "?" }.joined(separator: ", ")
            let cascades = [
                "DELETE FROM trace_membership WHERE trace_id IN (\(placeholders))",
                "DELETE FROM trace_rule_hits  WHERE trace_id IN (\(placeholders))",
                "DELETE FROM trace_replay_runs WHERE trace_id IN (\(placeholders))",
                "DELETE FROM trace_hash_chain  WHERE trace_id IN (\(placeholders))",
                "DELETE FROM traces            WHERE id       IN (\(placeholders))",
            ]
            for sql in cascades {
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
                }
                for (idx, id) in ids.enumerated() {
                    sqlite3_bind_text(stmt, Int32(idx + 1), id, -1, SQLITE_TRANSIENT)
                }
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
                }
            }
            sqlite3_exec(db, "COMMIT", nil, nil, nil)
        } catch {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw error
        }
        return ids.count
    }

    // MARK: - Retention
    //
    // tracegraph.db lacked any prune logic in v1.10's first cut.
    // Every NOTIFY_EXEC anchor-worthy event added a trace + members +
    // rule_hits + edges, growing the file monotonically. On a busy
    // dev machine this hit several GB / month. The following two
    // methods mirror EventStore.prune / pruneOldest so the daemon's
    // daily retention sweep can apply a time-based cap and a size
    // safety net. v1.10.0 audit fix.

    /// Delete every trace older than `cutoff` (and cascade through
    /// trace_membership / trace_rule_hits / trace_replay_runs /
    /// trace_hash_chain). Returns the number of trace rows removed.
    /// Orphaned entities + edges are left in place; they're invisible
    /// to the dashboard (lists by trace) and the next anchor that
    /// references them can re-attach via upsert.
    @discardableResult
    public func pruneTraces(olderThan cutoff: Date) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let cutoffSecs = cutoff.timeIntervalSince1970

        var ids: [String] = []
        do {
            let sql = "SELECT id FROM traces WHERE updated_at < ?1 LIMIT 10000"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_double(stmt, 1, cutoffSecs)
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let cstr = sqlite3_column_text(stmt, 0) {
                    ids.append(String(cString: cstr))
                }
            }
        }
        guard !ids.isEmpty else { return 0 }
        try cascadeDeleteTraces(ids: ids)
        return ids.count
    }

    /// Drop the oldest `count` traces by `updated_at` ascending. Used
    /// as the size-cap escape hatch when the daemon's storage
    /// enforcer notices tracegraph.db has exceeded its budget.
    @discardableResult
    public func pruneOldestTraces(count: Int) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard count > 0 else { return 0 }

        var ids: [String] = []
        let sql = "SELECT id FROM traces ORDER BY updated_at ASC LIMIT ?1"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(count))
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 0) {
                ids.append(String(cString: cstr))
            }
        }
        guard !ids.isEmpty else { return 0 }
        try cascadeDeleteTraces(ids: ids)
        return ids.count
    }

    /// Database file size in bytes — used by the storage enforcer.
    public func databaseSizeBytes() -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: databasePath)
        return (attrs?[.size] as? Int64) ?? 0
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // KNOWN GAP: tracegraph.db does NOT set `auto_vacuum = INCREMENTAL`
    // on fresh DBs (see openDatabase — only journal_mode, cache, mmap,
    // wal_autocheckpoint, busy_timeout, foreign_keys are set). Field-
    // observed: tracegraph.db is the WORST offender of the four
    // stores, hitting 11 GB on a daily-Claude-Code dev box before any
    // Wave 9B mitigation. The runtime helper detects mode 0 and
    // short-circuits to a no-op so this method is harmless on
    // existing files but does nothing useful either.
    //
    // For new INCREMENTAL-mode DBs (post-v1.13 conversion) this will
    // reclaim freelist pages in place exactly like EventStore. Until
    // then operators must run `maccrabctl maintenance vacuum
    // tracegraph` to convert.
    @discardableResult
    public func incrementalVacuum(maxPages: Int) async throws -> Int {
        guard let db = db else { return 0 }
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: maxPages)
        return result.pagesReclaimed
    }

    /// Best-effort VACUUM. On a 11 GB tracegraph.db this is the only
    /// path that actually shrinks the file today (mode-0 auto_vacuum
    /// means incremental_vacuum is a no-op) — and VACUUM needs
    /// ~= DB-size of scratch space, which is exactly the low-disk
    /// problem Wave 9B exists to work around. The size-cap caller
    /// pre-flights free space and skips this when too tight.
    public func vacuum() async throws {
        guard let db = db else { return }
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw CausalGraphStoreError.stepFailed("VACUUM failed: \(msg)")
        }
    }

    /// PASSIVE→RESTART checkpoint chain. Drains the WAL so on-disk
    /// footprint measurements include WAL content.
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
    /// (DaemonTimers) to log the gap when this DB is not in
    /// INCREMENTAL mode (mode 2).
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }

    /// Total trace row count.
    public func traceCount() async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM traces", -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Cascade-delete the listed trace ids across every related
    /// table inside one transaction. Shared by `pruneTraces`,
    /// `pruneOldestTraces`, and `deleteTracesWithTitlePrefix`.
    private func cascadeDeleteTraces(ids: [String]) throws {
        guard let db, !ids.isEmpty else { return }
        sqlite3_exec(db, "BEGIN TRANSACTION", nil, nil, nil)
        do {
            let placeholders = ids.map { _ in "?" }.joined(separator: ", ")
            let cascades = [
                "DELETE FROM trace_membership WHERE trace_id IN (\(placeholders))",
                "DELETE FROM trace_rule_hits  WHERE trace_id IN (\(placeholders))",
                "DELETE FROM trace_replay_runs WHERE trace_id IN (\(placeholders))",
                "DELETE FROM trace_hash_chain  WHERE trace_id IN (\(placeholders))",
                "DELETE FROM traces            WHERE id       IN (\(placeholders))",
            ]
            for sql in cascades {
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
                }
                for (idx, id) in ids.enumerated() {
                    sqlite3_bind_text(stmt, Int32(idx + 1), id, -1, SQLITE_TRANSIENT)
                }
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
                }
            }
            sqlite3_exec(db, "COMMIT", nil, nil, nil)
        } catch {
            sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
            throw error
        }
    }

    public func hashChainLength(for traceId: String) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = "SELECT COUNT(*) FROM trace_hash_chain WHERE trace_id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Helpers

    private func insertOrReplaceTraceRow(_ trace: Trace, db: OpaquePointer) throws {
        let sql = """
        INSERT OR REPLACE INTO traces (
            id, title, anchor_event_id, root_entity_id, severity, confidence,
            status, created_at, updated_at, summary_json, attack_json,
            evidence_bundle_status, daemon_version, ruleset_version,
            policy_id, policy_version, policy_sha256, policy_snapshot_json,
            trace_signing_key_mode, replay_scope, attribution_override_policy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, trace.id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, trace.title, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, trace.anchorEventId, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 4, trace.rootEntityId)
            sqlite3_bind_text(stmt, 5, trace.severity, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 6, trace.confidence)
            sqlite3_bind_text(stmt, 7, trace.status, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 8, trace.createdAt.timeIntervalSince1970)
            sqlite3_bind_double(stmt, 9, trace.updatedAt.timeIntervalSince1970)
            Self.bindOptionalText(stmt, 10, trace.summaryJson)
            Self.bindOptionalText(stmt, 11, trace.attackJson)
            sqlite3_bind_text(stmt, 12, trace.evidenceBundleStatus, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 13, trace.daemonVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 14, trace.rulesetVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 15, trace.policyId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 16, trace.policyVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 17, trace.policySha256, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 18, trace.policySnapshotJson, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 19, trace.traceSigningKeyMode, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 20, trace.replayScope, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 21, trace.attributionOverridePolicy, -1, SQLITE_TRANSIENT)
        }
    }

    private func insertMembership(_ member: TraceMembership, db: OpaquePointer) throws {
        let sql = """
        INSERT OR REPLACE INTO trace_membership (
            trace_id, entity_id, edge_id, role, layer, added_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, member.traceId, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 2, member.entityId)
            Self.bindOptionalText(stmt, 3, member.edgeId)
            sqlite3_bind_text(stmt, 4, member.role, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 5, member.layer, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 6, member.addedAt.timeIntervalSince1970)
        }
    }

    private func fetchTraceRow(id: String, db: OpaquePointer) throws -> Trace? {
        let sql = """
        SELECT id, title, anchor_event_id, root_entity_id, severity, confidence,
               status, created_at, updated_at, summary_json, attack_json,
               evidence_bundle_status, daemon_version, ruleset_version,
               policy_id, policy_version, policy_sha256, policy_snapshot_json,
               trace_signing_key_mode, replay_scope, attribution_override_policy
          FROM traces WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeTraceRow(stmt!)
    }

    private func fetchTraceMembership(traceId: String, db: OpaquePointer) throws -> [TraceMembership] {
        let sql = """
        SELECT trace_id, entity_id, edge_id, role, layer, added_at
          FROM trace_membership WHERE trace_id = ?
         ORDER BY added_at ASC
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        var out: [TraceMembership] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeMembershipRow(stmt!))
        }
        return out
    }

    private func execBound(
        db: OpaquePointer,
        sql: String,
        bindings: (OpaquePointer?) -> Void
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        bindings(stmt)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
    }

    private static func bindOptionalText(_ stmt: OpaquePointer?, _ idx: Int32, _ value: String?) {
        if let value {
            sqlite3_bind_text(stmt, idx, value, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, idx)
        }
    }

    private static func columnText(_ stmt: OpaquePointer, _ idx: Int32) -> String? {
        guard let cstr = sqlite3_column_text(stmt, idx) else { return nil }
        return String(cString: cstr)
    }

    private static func columnDate(_ stmt: OpaquePointer, _ idx: Int32) -> Date {
        Date(timeIntervalSince1970: sqlite3_column_double(stmt, idx))
    }

    private static func columnDateOptional(_ stmt: OpaquePointer, _ idx: Int32) -> Date? {
        if sqlite3_column_type(stmt, idx) == SQLITE_NULL { return nil }
        return Date(timeIntervalSince1970: sqlite3_column_double(stmt, idx))
    }

    // MARK: - Decoders

    private func decodeEntityRow(_ stmt: OpaquePointer) throws -> TraceEntity {
        guard let id = Self.columnText(stmt, 0),
              let entityType = Self.columnText(stmt, 1),
              let stableKey = Self.columnText(stmt, 2),
              let displayName = Self.columnText(stmt, 3),
              let attributesJsonRaw = Self.columnText(stmt, 6),
              let source = Self.columnText(stmt, 7) else {
            throw CausalGraphStoreError.decodeFailed("trace_entities: required column null")
        }
        let attributesJson = encryption?.decrypt(attributesJsonRaw) ?? attributesJsonRaw
        return TraceEntity(
            id: id,
            entityType: entityType,
            stableKey: stableKey,
            displayName: displayName,
            firstSeen: Self.columnDate(stmt, 4),
            lastSeen: Self.columnDate(stmt, 5),
            attributesJson: attributesJson,
            source: source,
            confidence: sqlite3_column_double(stmt, 8),
            observationCount: Int(sqlite3_column_int64(stmt, 9))
        )
    }

    private func decodeEdgeRow(_ stmt: OpaquePointer) throws -> TraceEdge {
        guard let id = Self.columnText(stmt, 0),
              let sourceId = Self.columnText(stmt, 1),
              let targetId = Self.columnText(stmt, 2),
              let relation = Self.columnText(stmt, 3),
              let confidenceTier = Self.columnText(stmt, 7),
              let evidenceJsonRaw = Self.columnText(stmt, 8),
              let eventIdsJson = Self.columnText(stmt, 9) else {
            throw CausalGraphStoreError.decodeFailed("trace_edges: required column null")
        }
        let evidenceJson = encryption?.decrypt(evidenceJsonRaw) ?? evidenceJsonRaw
        return TraceEdge(
            id: id,
            sourceEntityId: sourceId,
            targetEntityId: targetId,
            relation: relation,
            firstSeen: Self.columnDate(stmt, 4),
            lastSeen: Self.columnDate(stmt, 5),
            confidence: sqlite3_column_double(stmt, 6),
            confidenceTier: confidenceTier,
            evidenceJson: evidenceJson,
            eventIdsJson: eventIdsJson
        )
    }

    private func decodeTraceRow(_ stmt: OpaquePointer) throws -> Trace {
        guard let id = Self.columnText(stmt, 0),
              let title = Self.columnText(stmt, 1),
              let anchorEventId = Self.columnText(stmt, 2),
              let severity = Self.columnText(stmt, 4),
              let status = Self.columnText(stmt, 6),
              let evidenceBundleStatus = Self.columnText(stmt, 11),
              let daemonVersion = Self.columnText(stmt, 12),
              let rulesetVersion = Self.columnText(stmt, 13),
              let policyId = Self.columnText(stmt, 14),
              let policyVersion = Self.columnText(stmt, 15),
              let policySha256 = Self.columnText(stmt, 16),
              let policySnapshotJson = Self.columnText(stmt, 17),
              let traceSigningKeyMode = Self.columnText(stmt, 18),
              let replayScope = Self.columnText(stmt, 19),
              let attributionOverridePolicy = Self.columnText(stmt, 20)
        else {
            throw CausalGraphStoreError.decodeFailed("traces: required column null")
        }
        return Trace(
            id: id,
            title: title,
            anchorEventId: anchorEventId,
            rootEntityId: Self.columnText(stmt, 3),
            severity: severity,
            confidence: sqlite3_column_double(stmt, 5),
            status: status,
            createdAt: Self.columnDate(stmt, 7),
            updatedAt: Self.columnDate(stmt, 8),
            summaryJson: Self.columnText(stmt, 9),
            attackJson: Self.columnText(stmt, 10),
            evidenceBundleStatus: evidenceBundleStatus,
            daemonVersion: daemonVersion,
            rulesetVersion: rulesetVersion,
            policyId: policyId,
            policyVersion: policyVersion,
            policySha256: policySha256,
            policySnapshotJson: policySnapshotJson,
            traceSigningKeyMode: traceSigningKeyMode,
            replayScope: replayScope,
            attributionOverridePolicy: attributionOverridePolicy
        )
    }

    private func decodeMembershipRow(_ stmt: OpaquePointer) throws -> TraceMembership {
        guard let traceId = Self.columnText(stmt, 0),
              let role = Self.columnText(stmt, 3),
              let layer = Self.columnText(stmt, 4)
        else {
            throw CausalGraphStoreError.decodeFailed("trace_membership: required column null")
        }
        return TraceMembership(
            traceId: traceId,
            entityId: Self.columnText(stmt, 1),
            edgeId: Self.columnText(stmt, 2),
            role: role,
            layer: layer,
            addedAt: Self.columnDate(stmt, 5)
        )
    }

    private func decodeHashChainRow(_ stmt: OpaquePointer) throws -> TraceHashChainEntry {
        guard let id = Self.columnText(stmt, 0),
              let traceId = Self.columnText(stmt, 1),
              let currentHash = Self.columnText(stmt, 4)
        else {
            throw CausalGraphStoreError.decodeFailed("trace_hash_chain: required column null")
        }
        return TraceHashChainEntry(
            id: id,
            traceId: traceId,
            sequenceNumber: Int(sqlite3_column_int64(stmt, 2)),
            previousHash: Self.columnText(stmt, 3),
            currentHash: currentHash,
            eventId: Self.columnText(stmt, 5),
            edgeId: Self.columnText(stmt, 6),
            chainHeadSignature: Self.columnText(stmt, 7),
            chainHeadPublishedToUnifiedLog: sqlite3_column_int(stmt, 8) != 0,
            createdAt: Self.columnDate(stmt, 9)
        )
    }

    // MARK: - Set merge helpers

    private func mergeUniqueEntities(_ entities: [TraceEntity]) -> [TraceEntity] {
        var seen: Set<String> = []
        var out: [TraceEntity] = []
        out.reserveCapacity(entities.count)
        for entity in entities where !seen.contains(entity.id) {
            seen.insert(entity.id)
            out.append(entity)
        }
        return out
    }

    private func mergeUniqueEdges(_ edges: [TraceEdge]) -> [TraceEdge] {
        var seen: Set<String> = []
        var out: [TraceEdge] = []
        out.reserveCapacity(edges.count)
        for edge in edges where !seen.contains(edge.id) {
            seen.insert(edge.id)
            out.append(edge)
        }
        return out
    }
}

// MARK: - SQLITE_TRANSIENT bridge helper

private let SQLITE_TRANSIENT = unsafeBitCast(
    OpaquePointer(bitPattern: -1)!,
    to: sqlite3_destructor_type.self
)
