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
import CryptoKit

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

    // MARK: - Continuity-chain digest (A3-04)

    /// Deterministic SHA-256 (lowercase hex) over the entry's immutable
    /// ledger fields. This is the value stored in `current_hash` when the
    /// materializer appends a continuity entry, and the value
    /// `verifyHashChain()` recomputes to detect an in-place mutation.
    ///
    /// Design notes (why these inputs / this encoding):
    ///   - Every input is a column persisted on the row, so a verifier can
    ///     recompute the digest from the stored row alone — no dependency on
    ///     the `traces` table (which retention prunes independently).
    ///   - `previousHash` binds each entry to its predecessor's `current_hash`,
    ///     forming the append-only continuity chain.
    ///   - `createdAt` is folded in at **millisecond** resolution. The raw
    ///     `timeIntervalSince1970` double survives a SQLite REAL round-trip
    ///     bit-exactly, but `Date(timeIntervalSince1970:)` re-derives through
    ///     `timeIntervalSinceReferenceDate`, which can perturb the value by a
    ///     ULP. Rounding to whole milliseconds absorbs that jitter so the
    ///     digest recomputes identically on read-back.
    ///   - Fields are hashed as a JSON array of strings (order-preserving,
    ///     with library-level escaping) so a value containing the delimiter
    ///     cannot forge a different field boundary.
    ///
    /// Scope: this digest certifies the *ledger* of materialized traces
    /// (id, trace id, anchor event/edge, position, time). It does not bind
    /// the full `traces` row content — mutating a trace's title/severity is
    /// out of this chain's scope and is covered instead by the per-export
    /// Merkle root + daemon signature. See docs/maccrabtrace.v1.spec.md §6.
    public static func computeCurrentHash(
        id: String,
        traceId: String,
        sequenceNumber: Int,
        previousHash: String?,
        eventId: String?,
        edgeId: String?,
        createdAt: Date
    ) -> String {
        let msEpoch = Int64((createdAt.timeIntervalSince1970 * 1000).rounded())
        let fields: [String] = [
            "maccrab.tracegraph.chain.v1",   // domain separation
            id,
            traceId,
            String(sequenceNumber),
            previousHash ?? "",
            eventId ?? "",
            edgeId ?? "",
            String(msEpoch),
        ]
        // JSONEncoder over [String] is deterministic (fixed order + canonical
        // escaping). The `\u{1F}` join is only a defensive fallback for the
        // (unreachable) encode failure — plain String has no non-encodable form.
        let payload = (try? JSONEncoder().encode(fields))
            ?? Data(fields.joined(separator: "\u{1F}").utf8)
        return SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
    }

    /// Recompute this entry's digest from its own stored fields.
    public func recomputedCurrentHash() -> String {
        Self.computeCurrentHash(
            id: id, traceId: traceId, sequenceNumber: sequenceNumber,
            previousHash: previousHash, eventId: eventId, edgeId: edgeId,
            createdAt: createdAt
        )
    }
}

// MARK: - HashChainVerification (A3-04)

/// Outcome of walking the on-DB continuity chain (`verifyHashChain()`).
///
/// The chain detects three tamper classes on the retained rows:
///   - **content** — a row's `current_hash` no longer recomputes from its
///     stored fields (an in-place UPDATE, or a sequence-number swap / reorder).
///   - **linkage** — a row's `previous_hash` does not equal the immediately
///     preceding retained row's `current_hash` (a deleted or inserted row).
///   - clean otherwise (also for the empty chain).
///
/// Honest scope: the check tolerates a *shifted start* — the oldest retained
/// row's back-link is not enforced, because retention prunes the oldest
/// entries (a prefix) and that is authorized. Tail-truncation (deleting the
/// newest rows) leaves the retained prefix internally consistent and is
/// therefore NOT caught by the on-DB chain alone; it is bounded by the
/// external unified-log witness and per-export daemon signature. Local root
/// can rewrite the whole chain and is out of scope (see docs/THREAT_MODEL.md).
public struct HashChainVerification: Sendable, Equatable {

    public enum Status: Sendable, Equatable {
        case ok
        case brokenContent(atSequence: Int)
        case brokenLinkage(atSequence: Int)
    }

    public let status: Status
    /// Number of rows successfully verified before the first break (or the
    /// full count when intact).
    public let entriesChecked: Int

    public init(status: Status, entriesChecked: Int) {
        self.status = status
        self.entriesChecked = entriesChecked
    }

    public var isIntact: Bool { status == .ok }
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

    // Continuity chain (A3-04). Distinct from the per-trace helpers above:
    // these treat `trace_hash_chain` as a single append-only ledger across
    // all traces, where each materialized trace contributes one linked entry.
    /// The current global chain head (highest `sequence_number`), or nil when
    /// the ledger is empty.
    func globalChainHead() async throws -> TraceHashChainEntry?
    /// Append one continuity entry for a newly-materialized trace, linked to
    /// the current global head. Atomic: reads the head and inserts in one hop.
    @discardableResult
    func appendTraceContinuity(
        traceId: String,
        eventId: String?,
        edgeId: String?,
        signature: String?,
        publishedToUnifiedLog: Bool,
        createdAt: Date
    ) async throws -> TraceHashChainEntry
    /// Walk the whole ledger and report whether it is intact. See
    /// `HashChainVerification` for the tamper classes detected + scope.
    func verifyHashChain() async throws -> HashChainVerification
}

public extension CausalGraphStore {

    /// Backward-compat defaults so conformers predating A3-04 still build.
    /// SQLiteCausalGraphStore overrides all three with real implementations.
    func globalChainHead() async throws -> TraceHashChainEntry? { nil }
    func verifyHashChain() async throws -> HashChainVerification {
        HashChainVerification(status: .ok, entriesChecked: 0)
    }

    /// Generic continuity append for conformers that do not provide an atomic
    /// override. Reads the head then appends — correct, but two hops, so a
    /// SQLite-backed store overrides this with a single-hop implementation to
    /// close the head-read/insert race under concurrent materialization.
    @discardableResult
    func appendTraceContinuity(
        traceId: String,
        eventId: String?,
        edgeId: String?,
        signature: String?,
        publishedToUnifiedLog: Bool,
        createdAt: Date = Date()
    ) async throws -> TraceHashChainEntry {
        let head = try await globalChainHead()
        let nextSeq = (head?.sequenceNumber ?? 0) + 1
        let id = UUID().uuidString
        let currentHash = TraceHashChainEntry.computeCurrentHash(
            id: id, traceId: traceId, sequenceNumber: nextSeq,
            previousHash: head?.currentHash, eventId: eventId, edgeId: edgeId,
            createdAt: createdAt
        )
        let entry = TraceHashChainEntry(
            id: id, traceId: traceId, sequenceNumber: nextSeq,
            previousHash: head?.currentHash, currentHash: currentHash,
            eventId: eventId, edgeId: edgeId,
            chainHeadSignature: signature,
            chainHeadPublishedToUnifiedLog: publishedToUnifiedLog,
            createdAt: createdAt
        )
        try await appendHashChain(entry)
        return entry
    }
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
