// CausalGraphStore.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6b) — protocol + supporting types for the
// persistent causal-graph store described in §15.5 / §24.2 of the
// v1.10.0 spec.
//
// The protocol shape is intentionally backend-agnostic: SQLite is the
// v1.10.0 implementation but a future graph-database swap (Neo4j,
// embedded RocksDB graph layer, etc.) must not require rewriting the
// callers. SQLite-specific assumptions stay below the protocol line.
//
// PR-6b ships:
//   - this protocol + supporting types;
//   - `SQLiteCausalGraphStore` against `tracegraph.db`;
//   - schema for all 7 tables in §13;
//   - DatabaseEncryption applied to attributes_json + evidence_json
//     columns (§13.0).
//
// Higher-level types (ProcessNode, FileNode, etc.) layer on top in
// PR-7 — at this layer an entity is a generic typed blob with a
// stable key plus a JSON attributes payload.

import Foundation

// MARK: - TimeWindow

/// Inclusive [start, end] time range used by the graph traversal API.
public struct TimeWindow: Sendable, Equatable {
    public let start: Date
    public let end: Date

    public init(start: Date, end: Date) {
        self.start = start
        self.end = end
    }

    /// Convenience: the last `n` minutes ending now.
    public static func lastMinutes(_ n: Int, now: Date = Date()) -> TimeWindow {
        let interval = TimeInterval(n * 60)
        return TimeWindow(start: now.addingTimeInterval(-interval), end: now)
    }

    /// Convenience: open-ended window covering all observed time.
    public static let unlimited = TimeWindow(
        start: Date(timeIntervalSince1970: 0),
        end: Date(timeIntervalSince1970: 4_102_444_800) // 2100-01-01
    )
}

// MARK: - GraphSubtree

/// Result of an ancestor / descendant / neighborhood query.
public struct GraphSubtree: Sendable, Equatable {

    /// Entities in the subtree, in no guaranteed order. Callers that
    /// need an ordered traversal should reconstruct it from `edges`.
    public let entities: [TraceEntity]

    /// Edges in the subtree. Each edge's source + target entity is
    /// guaranteed to be in `entities` for ancestor/descendant queries;
    /// neighborhood queries may include edges whose far end falls just
    /// outside the depth budget — those are omitted from `entities`
    /// but the edges are still surfaced so the caller can decide
    /// whether to load further.
    public let edges: [TraceEdge]

    /// True if at least one query bound (depth, window, candidate count)
    /// truncated the result. Callers that need to surface
    /// `ancestry_truncated` per §6.3.1 read this flag.
    public let truncated: Bool

    public init(entities: [TraceEntity], edges: [TraceEdge], truncated: Bool) {
        self.entities = entities
        self.edges = edges
        self.truncated = truncated
    }

    public static let empty = GraphSubtree(entities: [], edges: [], truncated: false)
}

// MARK: - TraceEntity

/// Storage-level entity record — the shape of one row in `trace_entities`.
/// Specific node shapes (ProcessNode, FileNode, etc.) layer on top in
/// PR-7 by encoding their attributes into `attributesJson` and tagging
/// the row with the appropriate `entityType` string.
public struct TraceEntity: Sendable, Equatable, Codable {

    /// Globally-unique identifier for this row. Typically a UUID; for
    /// process entities, callers may also use `processKey` directly.
    public let id: String

    /// String tag identifying the typed shape (e.g. `"process"`,
    /// `"file"`, `"network"`, `"ai_agent"`, `"persistence"`).
    public let entityType: String

    /// Canonical key for this entity within its type. For processes
    /// this is `processKey`; for files, the path hash; for network
    /// endpoints, host:port; etc. UNIQUE per (entity_type, stable_key).
    public let stableKey: String

    public let displayName: String
    public let firstSeen: Date
    public let lastSeen: Date

    /// Type-specific attributes encoded as JSON. Encrypted at rest by
    /// the storage layer's optional DatabaseEncryption.
    public let attributesJson: String

    /// Collector or pipeline stage that produced the row (used for
    /// debugging multi-source merges).
    public let source: String

    /// Confidence the entity exists / is correctly typed. Most entities
    /// are 1.0; lower values reserved for inferred AI agents and similar.
    public let confidence: Double

    /// How many distinct observations have been merged into this row.
    public let observationCount: Int

    public init(
        id: String,
        entityType: String,
        stableKey: String,
        displayName: String,
        firstSeen: Date,
        lastSeen: Date,
        attributesJson: String,
        source: String,
        confidence: Double = 1.0,
        observationCount: Int = 1
    ) {
        self.id = id
        self.entityType = entityType
        self.stableKey = stableKey
        self.displayName = displayName
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.attributesJson = attributesJson
        self.source = source
        self.confidence = confidence
        self.observationCount = observationCount
    }
}

// MARK: - TraceEdge

public struct TraceEdge: Sendable, Equatable, Codable {

    public let id: String
    public let sourceEntityId: String
    public let targetEntityId: String

    /// String tag from the §9 vocabulary: `"spawned"`, `"read"`,
    /// `"wrote"`, `"renamed"`, `"deleted"`, `"connected_to"`,
    /// `"created_persistence"`, `"loaded_code"`, `"signed_by"`,
    /// `"associated_with_agent"`, `"triggered_rule"`,
    /// `"matched_sequence"`, `"caused"`.
    public let relation: String

    public let firstSeen: Date
    public let lastSeen: Date
    public let confidence: Double

    /// `"direct"`, `"strong_inferred"`, `"weak_inferred"`, `"temporal_only"`.
    public let confidenceTier: String

    /// Edge-type-specific evidence as JSON. Encrypted at rest.
    public let evidenceJson: String

    /// JSON array of event IDs backing this edge (one or more).
    public let eventIdsJson: String

    public init(
        id: String,
        sourceEntityId: String,
        targetEntityId: String,
        relation: String,
        firstSeen: Date,
        lastSeen: Date,
        confidence: Double,
        confidenceTier: String,
        evidenceJson: String,
        eventIdsJson: String
    ) {
        self.id = id
        self.sourceEntityId = sourceEntityId
        self.targetEntityId = targetEntityId
        self.relation = relation
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.confidence = confidence
        self.confidenceTier = confidenceTier
        self.evidenceJson = evidenceJson
        self.eventIdsJson = eventIdsJson
    }
}

// MARK: - Trace

public struct Trace: Sendable, Equatable, Codable {

    public let id: String
    public let title: String
    public let anchorEventId: String
    public let rootEntityId: String?
    public let severity: String
    public let confidence: Double
    public let status: String
    public let createdAt: Date
    public let updatedAt: Date
    public let summaryJson: String?
    public let attackJson: String?
    public let evidenceBundleStatus: String

    // Versioning + policy snapshot per §15.10.1
    public let daemonVersion: String
    public let rulesetVersion: String
    public let policyId: String
    public let policyVersion: String
    public let policySha256: String
    public let policySnapshotJson: String

    /// `"secure_enclave"` or `"filesystem_degraded"` — recorded so the
    /// bundle exporter can label the manifest honestly per §19.1.
    public let traceSigningKeyMode: String

    /// `"declared_deterministic_subset"` or `"include_bundled_state"`.
    public let replayScope: String

    /// `"include_as_human_annotation_do_not_apply_by_default"` or
    /// `"include_and_apply_on_replay_when_flagged"`.
    public let attributionOverridePolicy: String

    public init(
        id: String,
        title: String,
        anchorEventId: String,
        rootEntityId: String?,
        severity: String,
        confidence: Double,
        status: String = "open",
        createdAt: Date,
        updatedAt: Date,
        summaryJson: String? = nil,
        attackJson: String? = nil,
        evidenceBundleStatus: String = "not_created",
        daemonVersion: String,
        rulesetVersion: String,
        policyId: String,
        policyVersion: String,
        policySha256: String,
        policySnapshotJson: String,
        traceSigningKeyMode: String,
        replayScope: String,
        attributionOverridePolicy: String
    ) {
        self.id = id
        self.title = title
        self.anchorEventId = anchorEventId
        self.rootEntityId = rootEntityId
        self.severity = severity
        self.confidence = confidence
        self.status = status
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.summaryJson = summaryJson
        self.attackJson = attackJson
        self.evidenceBundleStatus = evidenceBundleStatus
        self.daemonVersion = daemonVersion
        self.rulesetVersion = rulesetVersion
        self.policyId = policyId
        self.policyVersion = policyVersion
        self.policySha256 = policySha256
        self.policySnapshotJson = policySnapshotJson
        self.traceSigningKeyMode = traceSigningKeyMode
        self.replayScope = replayScope
        self.attributionOverridePolicy = attributionOverridePolicy
    }
}

// MARK: - TraceMembership

/// Row in `trace_membership`. Either `entityId` or `edgeId` is non-nil
/// (never both, never neither).
public struct TraceMembership: Sendable, Equatable, Codable {

    public let traceId: String
    public let entityId: String?
    public let edgeId: String?
    public let role: String     // "root" | "anchor" | "critical_path" | "context" | "evidence" | "suppressed"
    public let layer: String    // "core" | "context"
    public let addedAt: Date

    public init(
        traceId: String,
        entityId: String? = nil,
        edgeId: String? = nil,
        role: String,
        layer: String = "core",
        addedAt: Date = Date()
    ) {
        precondition(
            (entityId != nil) != (edgeId != nil),
            "TraceMembership must reference exactly one of entityId / edgeId"
        )
        self.traceId = traceId
        self.entityId = entityId
        self.edgeId = edgeId
        self.role = role
        self.layer = layer
        self.addedAt = addedAt
    }
}

// MARK: - TraceRuleHit

public struct TraceRuleHit: Sendable, Equatable, Codable {

    public let id: String
    public let traceId: String
    public let ruleId: String
    public let ruleTitle: String
    public let ruleVersion: String
    public let severity: String
    public let matchedEventId: String?
    public let matchedEntityId: String?
    public let matchedEdgeId: String?
    public let matchedAt: Date
    public let explanationJson: String

    public init(
        id: String,
        traceId: String,
        ruleId: String,
        ruleTitle: String,
        ruleVersion: String,
        severity: String,
        matchedEventId: String? = nil,
        matchedEntityId: String? = nil,
        matchedEdgeId: String? = nil,
        matchedAt: Date,
        explanationJson: String
    ) {
        self.id = id
        self.traceId = traceId
        self.ruleId = ruleId
        self.ruleTitle = ruleTitle
        self.ruleVersion = ruleVersion
        self.severity = severity
        self.matchedEventId = matchedEventId
        self.matchedEntityId = matchedEntityId
        self.matchedEdgeId = matchedEdgeId
        self.matchedAt = matchedAt
        self.explanationJson = explanationJson
    }
}

// MARK: - TraceReplayRun

public struct TraceReplayRun: Sendable, Equatable, Codable {

    public let id: String
    public let traceId: String
    public let bundleId: String
    public let rulesetVersion: String
    public let daemonVersion: String
    public let normalizationVersion: String
    public let startedAt: Date
    public let completedAt: Date?
    public let deterministic: Bool
    public let resultJson: String

    public init(
        id: String,
        traceId: String,
        bundleId: String,
        rulesetVersion: String,
        daemonVersion: String,
        normalizationVersion: String,
        startedAt: Date,
        completedAt: Date?,
        deterministic: Bool,
        resultJson: String
    ) {
        self.id = id
        self.traceId = traceId
        self.bundleId = bundleId
        self.rulesetVersion = rulesetVersion
        self.daemonVersion = daemonVersion
        self.normalizationVersion = normalizationVersion
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.deterministic = deterministic
        self.resultJson = resultJson
    }
}

// MARK: - TraceHashChainEntry

/// Runtime in-DB hash-chain entry per §13.7. Distinct from the bundle
/// Merkle root in §19.2 — see §13.7's two-chain comparison table.
public struct TraceHashChainEntry: Sendable, Equatable, Codable {

    public let id: String
    public let traceId: String
    public let sequenceNumber: Int
    public let previousHash: String?
    public let currentHash: String
    public let eventId: String?
    public let edgeId: String?
    public let chainHeadSignature: String?
    public let chainHeadPublishedToUnifiedLog: Bool
    public let createdAt: Date

    public init(
        id: String,
        traceId: String,
        sequenceNumber: Int,
        previousHash: String?,
        currentHash: String,
        eventId: String? = nil,
        edgeId: String? = nil,
        chainHeadSignature: String? = nil,
        chainHeadPublishedToUnifiedLog: Bool = false,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.traceId = traceId
        self.sequenceNumber = sequenceNumber
        self.previousHash = previousHash
        self.currentHash = currentHash
        self.eventId = eventId
        self.edgeId = edgeId
        self.chainHeadSignature = chainHeadSignature
        self.chainHeadPublishedToUnifiedLog = chainHeadPublishedToUnifiedLog
        self.createdAt = createdAt
    }
}

// MARK: - CausalGraphStore (protocol)

/// Persistent causal-graph store. The shape allows a future swap to
/// a graph backend without rewriting callers — SQLite-specific
/// assumptions must not leak through.
public protocol CausalGraphStore: Sendable {

    // Entities + edges
    func upsertEntity(_ entity: TraceEntity) async throws
    func upsertEdge(_ edge: TraceEdge) async throws
    /// v1.17.4 (perf): persist all entities then all edges for one event in
    /// a single transaction. SQLite-backed stores override with a real
    /// BEGIN/COMMIT; the default below preserves correctness for any other
    /// conformer by looping the single-row upserts (entities first for FK).
    func upsertBatch(entities: [TraceEntity], edges: [TraceEdge]) async throws
    func entity(id: String) async throws -> TraceEntity?
    func edge(id: String) async throws -> TraceEdge?

    // Graph traversal
    func ancestors(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree
    func descendants(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree
    func neighborhood(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree
    func criticalPath(from source: String, to target: String, maxDepth: Int) async throws -> [TraceEdge]

    // Trace lifecycle
    func saveTrace(_ trace: Trace, members: [TraceMembership]) async throws
    func loadTrace(id: String) async throws -> (trace: Trace, members: [TraceMembership])?
    func updateTraceStatus(id: String, status: String, updatedAt: Date) async throws
    func listTraces(limit: Int) async throws -> [Trace]

    // Rule hits + replay + chain
    func recordRuleHit(_ hit: TraceRuleHit) async throws
    func recordReplayRun(_ run: TraceReplayRun) async throws
    func appendHashChain(_ entry: TraceHashChainEntry) async throws
    func latestHashChainEntry(for traceId: String) async throws -> TraceHashChainEntry?
    func hashChainLength(for traceId: String) async throws -> Int
}

public extension CausalGraphStore {
    /// Default upsertBatch: best-effort per-row, entities before edges so
    /// trace_edges→trace_entities FKs hold. SQLiteCausalGraphStore overrides
    /// this with a single transaction; this fallback keeps other conformers
    /// (e.g. test doubles) correct without each needing a transactional impl.
    func upsertBatch(entities: [TraceEntity], edges: [TraceEdge]) async throws {
        for entity in entities { try? await upsertEntity(entity) }
        for edge in edges { try? await upsertEdge(edge) }
    }
}
