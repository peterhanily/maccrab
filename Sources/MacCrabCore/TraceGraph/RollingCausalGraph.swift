// RollingCausalGraph.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-8 ingestion tail) — turns normalized events
// into typed entities + edges, writes them to the CausalGraphStore,
// detects anchors via AnchorDetector, and triggers
// TraceMaterializer.materialize() when an anchor fires.
//
// Sits architecturally above v1.9's EventEnricher: callers convert a
// v1.9 Event into RollingCausalGraph.NormalizedEventInput before
// ingest. The translation layer is deliberately outside this actor
// so RollingCausalGraph stays decoupled from v1.9 Event's evolving
// shape — and so test fixtures can drive ingest with synthetic input.
//
// What this PR ships:
//   - process exec / exit handling (spawned edges, ProcessNode upsert)
//   - file event handling (read / wrote / etc. edges, FileNode upsert)
//   - network event handling (connected_to edge, NetworkNode upsert)
//   - AI-agent attribution (AIAgentNode upsert, associated_with_agent edge)
//   - persistence detection (PersistenceNode + created_persistence edge)
//   - anchor detection + materialization callback
//
// What's deferred:
//   - rule-hit / sequence-completion anchors (need v1.9 RuleEngine
//     wiring; surface via `recordExternalAnchor` for the wiring layer)
//   - TCC permission handling
//   - browser download tracking
//   - ESCollector wiring (a separate increment that touches v1.9 code)

import Foundation
import os.log

/// A hard-bounded insertion-ordered cache for recently materialized anchors.
///
/// Expiration alone is not a cardinality bound: an adversary can present more
/// than `capacity` distinct keys inside one window. The dictionary is capped
/// independently of expiry, while the generation-tagged queue keeps eviction
/// amortized O(1) and prevents an older observation of a refreshed key from
/// evicting its current value.
struct RecentAnchorDedupCache: Sendable {
    private struct Value: Sendable {
        let recordedAt: Date
        let generation: UInt64
    }

    private struct QueueEntry: Sendable {
        let key: String
        let generation: UInt64
    }

    let capacity: Int
    let window: TimeInterval

    private var values: [String: Value] = [:]
    private var queue: [QueueEntry] = []
    private var queueHead = 0
    private var nextGeneration: UInt64 = 0

    init(capacity: Int, window: TimeInterval) {
        precondition(capacity > 0)
        precondition(capacity <= Int.max / 2)
        precondition(window >= 0)
        self.capacity = capacity
        self.window = window
    }

    var count: Int { values.count }
    var evictionMetadataCount: Int { queue.count - queueHead }

    func contains(_ key: String, at now: Date) -> Bool {
        guard let value = values[key] else { return false }
        return now.timeIntervalSince(value.recordedAt) < window
    }

    mutating func record(_ key: String, at now: Date) {
        nextGeneration &+= 1
        let generation = nextGeneration
        values[key] = Value(recordedAt: now, generation: generation)
        queue.append(QueueEntry(key: key, generation: generation))

        while values.count > capacity {
            guard queueHead < queue.count else {
                assertionFailure("recent-anchor cache queue lost an active key")
                break
            }
            let candidate = queue[queueHead]
            queueHead += 1
            if values[candidate.key]?.generation == candidate.generation {
                values.removeValue(forKey: candidate.key)
            }
        }

        // Refreshes leave obsolete generations in the queue. Compact them at
        // a bounded threshold so both the key map and its eviction metadata
        // remain bounded during a long-lived process.
        if queueHead >= capacity || queue.count > capacity * 2 {
            queue = queue[queueHead...].filter {
                values[$0.key]?.generation == $0.generation
            }
            queueHead = 0
        }
    }
}

/// Bounds the write-behind window used by the daemon's rolling graph.
///
/// Detection-bearing anchors always force a flush before materialization, so
/// this policy delays only non-anchor substrate visibility. The immediate
/// policy remains the default for API compatibility and deterministic tools;
/// the daemon explicitly opts into `daemonCoalesced`.
public struct CausalGraphIngestionWritePolicy: Sendable, Equatable {
    public let maximumDelaySeconds: TimeInterval
    public let maximumPendingEvents: Int
    public let maximumPendingRows: Int

    public init(
        maximumDelaySeconds: TimeInterval,
        maximumPendingEvents: Int,
        maximumPendingRows: Int
    ) {
        precondition(maximumDelaySeconds >= 0)
        precondition(maximumPendingEvents > 0)
        precondition(maximumPendingRows > 0)
        self.maximumDelaySeconds = maximumDelaySeconds
        self.maximumPendingEvents = maximumPendingEvents
        self.maximumPendingRows = maximumPendingRows
    }

    public static let immediate = CausalGraphIngestionWritePolicy(
        maximumDelaySeconds: 0,
        maximumPendingEvents: 1,
        maximumPendingRows: 1
    )

    /// At the observed 5,917 file events/s this caps the normal hot path at
    /// roughly 24 graph transactions/s instead of one transaction per event.
    /// A novel anchor bypasses all three bounds and flushes immediately.
    public static let daemonCoalesced = CausalGraphIngestionWritePolicy(
        maximumDelaySeconds: 0.25,
        maximumPendingEvents: 256,
        maximumPendingRows: 1_024
    )
}

/// Live status deadline, independent of the stricter qualification drain gate.
/// Allow one daemon coalescing window, one preceding batch's SQLite busy wait,
/// and this batch's busy wait. This is a responsiveness target, not a total
/// execution timeout: a multi-statement transaction can exceed a busy timeout.
public enum CausalGraphWriteResponsiveness {
    public static let sqliteBusyTimeoutMilliseconds: Int32 = 5_000
    public static let maximumOutstandingAgeSeconds: TimeInterval =
        CausalGraphIngestionWritePolicy.daemonCoalesced.maximumDelaySeconds
            + 2 * Double(sqliteBusyTimeoutMilliseconds) / 1_000
}

/// Exact conservation counters for rolling-graph persistence.
///
/// At an actor-isolated snapshot:
///
///     inputEvents = committed + failed + inFlight + pending
///     writeAttempts = committedBatches + failedBatches + inFlightBatches
///     rowObservations = writeRowsAttempted + coalescedNoopRows
///         + physicalWriteSuppressedRows + pendingRows
///     writeRowsAttempted = committedRows + failedRows + inFlightRows
///
/// `coalescedNoopRows` counts redundant per-event UPSERTs removed before
/// SQLite. It does not mean an observation was lost: entity observation
/// weights are summed exactly, while edge last-seen/evidence retains the same
/// final value sequential UPSERTs would have produced.
public struct CausalGraphIngestionWriteTelemetry: Sendable, Equatable {
    public let inputEventsTotal: UInt64
    public let eventsCommittedTotal: UInt64
    public let eventsFailedTotal: UInt64
    public let eventsInFlight: Int
    public let eventsPending: Int
    public let entityObservationsTotal: UInt64
    public let edgeObservationsTotal: UInt64
    public let relevanceSuppressedFileEventsTotal: UInt64
    public let relevanceSuppressedRowsTotal: UInt64
    public let physicalWriteSuppressedEventsTotal: UInt64
    public let physicalWriteSuppressedRowsTotal: UInt64
    public let writeAttemptsTotal: UInt64
    public let writeBatchesCommittedTotal: UInt64
    public let writeBatchesFailedTotal: UInt64
    public let writeBatchesInFlight: Int
    public let writeRowsAttemptedTotal: UInt64
    public let writeRowsCommittedTotal: UInt64
    public let writeRowsFailedTotal: UInt64
    public let writeRowsInFlight: Int
    public let coalescedNoopRowsTotal: UInt64
    public let pendingEntityRows: Int
    public let pendingEdgeRows: Int
    /// Age of the oldest uncommitted batch, including an in-flight transaction.
    /// Measured with ContinuousClock; zero only when no work remains or a batch
    /// was just admitted. Wall-clock and event timestamps do not affect it.
    public let oldestOutstandingAgeSeconds: TimeInterval
}

public actor RollingCausalGraph {

    private struct EntityNaturalKey: Hashable {
        let entityType: String
        let stableKey: String
    }

    private struct EdgeNaturalKey: Hashable {
        let sourceEntityId: String
        let targetEntityId: String
        let relation: String
    }

    /// One bounded group of observations waiting for a SQLite transaction.
    /// Dictionary values are the exact result of applying the same rows in
    /// arrival order, except that redundant physical UPSERTs are removed.
    private struct PendingWriteBatch {
        var entities: [EntityNaturalKey: TraceEntity] = [:]
        var edges: [EdgeNaturalKey: TraceEdge] = [:]
        var eventCount = 0
        var firstEnqueuedAt: ContinuousClock.Instant?

        var rowCount: Int { entities.count + edges.count }

        mutating func append(
            entities newEntities: [TraceEntity],
            edges newEdges: [TraceEdge]
        ) -> Int {
            var coalescedRows = 0
            eventCount += 1

            for entity in newEntities {
                let key = EntityNaturalKey(
                    entityType: entity.entityType,
                    stableKey: entity.stableKey
                )
                let observationWeight = max(1, entity.observationCount)
                if let existing = entities[key] {
                    coalescedRows += 1
                    entities[key] = TraceEntity(
                        // SQLite preserves the first row id on natural-key
                        // conflict, so retain it here as well.
                        id: existing.id,
                        entityType: existing.entityType,
                        stableKey: existing.stableKey,
                        displayName: entity.displayName,
                        firstSeen: existing.firstSeen,
                        lastSeen: max(existing.lastSeen, entity.lastSeen),
                        attributesJson: entity.attributesJson,
                        // `source` is insert-only in the SQLite conflict
                        // clause, so preserve the first observation here.
                        source: existing.source,
                        confidence: entity.confidence,
                        observationCount: Self.saturatingAdd(
                            existing.observationCount,
                            observationWeight
                        )
                    )
                } else {
                    entities[key] = TraceEntity(
                        id: entity.id,
                        entityType: entity.entityType,
                        stableKey: entity.stableKey,
                        displayName: entity.displayName,
                        firstSeen: entity.firstSeen,
                        lastSeen: entity.lastSeen,
                        attributesJson: entity.attributesJson,
                        source: entity.source,
                        confidence: entity.confidence,
                        observationCount: observationWeight
                    )
                }
            }

            for edge in newEdges {
                let key = EdgeNaturalKey(
                    sourceEntityId: edge.sourceEntityId,
                    targetEntityId: edge.targetEntityId,
                    relation: edge.relation
                )
                if let existing = edges[key] {
                    coalescedRows += 1
                    edges[key] = TraceEdge(
                        // Same conflict semantics as SQLite: the first id and
                        // first_seen survive; mutable fields come from the last
                        // observation, with last_seen monotonic.
                        id: existing.id,
                        sourceEntityId: existing.sourceEntityId,
                        targetEntityId: existing.targetEntityId,
                        relation: existing.relation,
                        firstSeen: existing.firstSeen,
                        lastSeen: max(existing.lastSeen, edge.lastSeen),
                        confidence: edge.confidence,
                        confidenceTier: edge.confidenceTier,
                        evidenceJson: edge.evidenceJson,
                        eventIdsJson: edge.eventIdsJson
                    )
                } else {
                    edges[key] = edge
                }
            }
            return coalescedRows
        }

        var sortedEntities: [TraceEntity] {
            entities.values.sorted { $0.id < $1.id }
        }

        var sortedEdges: [TraceEdge] {
            edges.values.sorted { $0.id < $1.id }
        }

        private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
            let (sum, overflow) = lhs.addingReportingOverflow(rhs)
            return overflow ? Int.max : sum
        }
    }

    /// Bounded in-memory provenance carried from a physically-suppressed file
    /// callback into the next graph-relevant observation for that process. This
    /// preserves first-seen/observation weight if the process later anchors a
    /// trace, without turning ordinary file churn back into SQLite traffic.
    private struct DeferredProcessContextCache {
        let capacity: Int
        private(set) var entities: [String: TraceEntity] = [:]
        private var insertionOrder: [String] = []

        init(capacity: Int) {
            self.capacity = max(1, capacity)
        }

        mutating func record(_ entity: TraceEntity) {
            if let existing = entities[entity.id] {
                entities[entity.id] = Self.merge(existing, entity)
                return
            }
            if entities.count >= capacity {
                while let oldest = insertionOrder.first,
                      entities.removeValue(forKey: oldest) == nil {
                    insertionOrder.removeFirst()
                }
                if !insertionOrder.isEmpty { insertionOrder.removeFirst() }
            }
            if insertionOrder.count > capacity * 2 {
                insertionOrder = insertionOrder.filter { entities[$0] != nil }
            }
            entities[entity.id] = entity
            insertionOrder.append(entity.id)
        }

        mutating func take(id: String) -> TraceEntity? {
            entities.removeValue(forKey: id)
        }

        static func merge(_ first: TraceEntity, _ latest: TraceEntity) -> TraceEntity {
            TraceEntity(
                id: first.id,
                entityType: first.entityType,
                stableKey: first.stableKey,
                displayName: latest.displayName,
                firstSeen: min(first.firstSeen, latest.firstSeen),
                lastSeen: max(first.lastSeen, latest.lastSeen),
                attributesJson: latest.attributesJson,
                source: first.source,
                confidence: latest.confidence,
                observationCount: saturatingAdd(
                    max(1, first.observationCount),
                    max(1, latest.observationCount)
                )
            )
        }

        private static func saturatingAdd(_ lhs: Int, _ rhs: Int) -> Int {
            let (sum, overflow) = lhs.addingReportingOverflow(rhs)
            return overflow ? Int.max : sum
        }
    }

    // MARK: - Input

    public struct NormalizedEventInput: Sendable {
        public let eventId: String
        public let timestamp: Date
        public let category: Category
        public let action: Action
        public let process: ProcessObservation
        public let parentProcess: ProcessObservation?
        public let file: FileObservation?
        public let network: NetworkObservation?
        public let agent: AgentEnrichment?

        public init(
            eventId: String,
            timestamp: Date,
            category: Category,
            action: Action,
            process: ProcessObservation,
            parentProcess: ProcessObservation? = nil,
            file: FileObservation? = nil,
            network: NetworkObservation? = nil,
            agent: AgentEnrichment? = nil
        ) {
            self.eventId = eventId
            self.timestamp = timestamp
            self.category = category
            self.action = action
            self.process = process
            self.parentProcess = parentProcess
            self.file = file
            self.network = network
            self.agent = agent
        }

        public enum Category: String, Sendable, Equatable {
            case process, file, network, tcc
        }

        public enum Action: String, Sendable, Equatable {
            case exec, exit
            case fileCreate = "file_create"
            case fileWrite  = "file_write"
            case fileRead   = "file_read"
            case fileRename = "file_rename"
            case fileDelete = "file_delete"
            case netConnect = "net_connect"
            case tccGrant   = "tcc_grant"
        }
    }

    public struct ProcessObservation: Sendable {
        public let processKey: String
        public let pid: Int32
        public let ppid: Int32?
        public let executablePath: String
        public let executableHash: String?
        public let isAppleSigned: Bool
        public let isNotarized: Bool
        public let signingTeamId: String?
        public let signingIdentifier: String?
        public let startTime: Date
        public let user: String?
        public let parentProcessKey: String?

        public init(
            processKey: String,
            pid: Int32,
            ppid: Int32? = nil,
            executablePath: String,
            executableHash: String? = nil,
            isAppleSigned: Bool,
            isNotarized: Bool,
            signingTeamId: String? = nil,
            signingIdentifier: String? = nil,
            startTime: Date,
            user: String? = nil,
            parentProcessKey: String? = nil
        ) {
            self.processKey = processKey
            self.pid = pid
            self.ppid = ppid
            self.executablePath = executablePath
            self.executableHash = executableHash
            self.isAppleSigned = isAppleSigned
            self.isNotarized = isNotarized
            self.signingTeamId = signingTeamId
            self.signingIdentifier = signingIdentifier
            self.startTime = startTime
            self.user = user
            self.parentProcessKey = parentProcessKey
        }
    }

    public struct FileObservation: Sendable {
        public let path: String
        public let pathHash: String
        public let sha256: String?
        /// v1.21.4 (Phase-6 6B, leg 2): set by the bridge from
        /// `enrichments["untrusted_content"]` — carried through to the
        /// `FileNode` so the causal substrate records that this file (read
        /// by an agent-attributed process) held prompt-injection markers.
        public let untrustedContent: Bool

        public init(path: String, pathHash: String, sha256: String? = nil, untrustedContent: Bool = false) {
            self.path = path
            self.pathHash = pathHash
            self.sha256 = sha256
            self.untrustedContent = untrustedContent
        }
    }

    public struct NetworkObservation: Sendable {
        public let host: String?
        public let ip: String?
        public let port: Int?
        public let protocolName: String?
        public let reputation: NetworkReputation

        public init(
            host: String? = nil,
            ip: String? = nil,
            port: Int? = nil,
            protocolName: String? = nil,
            reputation: NetworkReputation = .unknown
        ) {
            self.host = host
            self.ip = ip
            self.port = port
            self.protocolName = protocolName
            self.reputation = reputation
        }
    }

    public struct AgentEnrichment: Sendable {
        public let agentName: String
        public let agentTool: String?
        public let traceId: String
        public let spanId: String?
        public let confidence: Double
        public let attributionMethod: AttributionMethod

        public init(
            agentName: String,
            agentTool: String? = nil,
            traceId: String,
            spanId: String? = nil,
            confidence: Double,
            attributionMethod: AttributionMethod
        ) {
            self.agentName = agentName
            self.agentTool = agentTool
            self.traceId = traceId
            self.spanId = spanId
            self.confidence = confidence
            self.attributionMethod = attributionMethod
        }
    }

    // MARK: - Configuration

    private let store: CausalGraphStore
    private let materializer: TraceMaterializer
    private let policy: TracePolicy
    private let ingestionWritePolicy: CausalGraphIngestionWritePolicy
    private let monotonicNow: @Sendable () -> ContinuousClock.Instant
    private let persistBatch: @Sendable ([TraceEntity], [TraceEdge]) async throws -> Void
    private let anchorCallback: (@Sendable (Trace, AnchorTrigger) async -> Void)?
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "rolling-graph")

    private var pendingWriteBatch = PendingWriteBatch()
    private var deferredProcessContexts = DeferredProcessContextCache(capacity: 4_096)
    private var scheduledFlush: Task<Void, Never>?
    private var scheduledFlushGeneration: UInt64 = 0
    /// Joinable handle for the physical store write. Actor reentrancy permits a
    /// lifecycle flush to enter while an earlier flush is suspended in the
    /// store actor; an empty pending batch does not mean that write completed.
    private var inFlightStoreWrite: Task<Void, Error>?
    // Exactly one pending and one in-flight timestamp: bounded independently
    // of event rate. Moving a batch never refreshes its original enqueue time.
    private var inFlightFirstEnqueuedAt: ContinuousClock.Instant?

    // Exact write-conservation counters. These are intentionally owned by the
    // rolling actor: only this layer knows how many input events and redundant
    // row observations one physical SQLite batch represents.
    private var inputEventsTotal: UInt64 = 0
    private var eventsCommittedTotal: UInt64 = 0
    private var eventsFailedTotal: UInt64 = 0
    private var eventsInFlight = 0
    private var entityObservationsTotal: UInt64 = 0
    private var edgeObservationsTotal: UInt64 = 0
    private var relevanceSuppressedFileEventsTotal: UInt64 = 0
    private var relevanceSuppressedRowsTotal: UInt64 = 0
    private var physicalWriteSuppressedEventsTotal: UInt64 = 0
    private var physicalWriteSuppressedRowsTotal: UInt64 = 0
    private var writeAttemptsTotal: UInt64 = 0
    private var writeBatchesCommittedTotal: UInt64 = 0
    private var writeBatchesFailedTotal: UInt64 = 0
    private var writeBatchesInFlight = 0
    private var writeRowsAttemptedTotal: UInt64 = 0
    private var writeRowsCommittedTotal: UInt64 = 0
    private var writeRowsFailedTotal: UInt64 = 0
    private var writeRowsInFlight = 0
    private var coalescedNoopRowsTotal: UInt64 = 0

    /// Anchors already materialized this window, keyed by anchor identity.
    /// High-rate anchors are aggregated by stable behavioural identity. Process
    /// entity ids cannot be used for polling CLIs: each invocation has a new
    /// pid/pidversion even when it repeats the same executable/file access.
    private var recentAnchorKeys = RecentAnchorDedupCache(
        capacity: 4096,
        window: 300
    )

    public init(
        store: CausalGraphStore,
        materializer: TraceMaterializer,
        policy: TracePolicy = .default,
        ingestionWritePolicy: CausalGraphIngestionWritePolicy = .immediate,
        anchorCallback: (@Sendable (Trace, AnchorTrigger) async -> Void)? = nil
    ) {
        self.init(
            store: store, materializer: materializer, policy: policy,
            ingestionWritePolicy: ingestionWritePolicy, anchorCallback: anchorCallback,
            monotonicNow: { ContinuousClock.now },
            persistBatch: { try await store.upsertBatch(entities: $0, edges: $1) }
        )
    }

    /// Internal dependency seam for deterministic clock/commit-boundary tests.
    /// The public initializer always uses the real monotonic clock and store.
    init(
        store: CausalGraphStore,
        materializer: TraceMaterializer,
        policy: TracePolicy = .default,
        ingestionWritePolicy: CausalGraphIngestionWritePolicy,
        anchorCallback: (@Sendable (Trace, AnchorTrigger) async -> Void)? = nil,
        monotonicNow: @escaping @Sendable () -> ContinuousClock.Instant,
        persistBatch: @escaping @Sendable ([TraceEntity], [TraceEdge]) async throws -> Void
    ) {
        self.store = store
        self.materializer = materializer
        self.policy = policy
        self.ingestionWritePolicy = ingestionWritePolicy
        self.anchorCallback = anchorCallback
        self.monotonicNow = monotonicNow
        self.persistBatch = persistBatch
    }

    private func anchorDedupKey(_ anchor: AnchorTrigger) -> String? {
        // Only the agent-activity anchors dedup. The rest are rare by nature and
        // a repeat genuinely is a separate incident worth its own trace.
        switch anchor {
        case .credentialAccess(_, let stableProcessIdentity, let fileEntityId, let operation):
            return "credentialAccess:\(stableProcessIdentity):\(fileEntityId):\(operation)"
        case .aiAgentSpawnsShell(let agentEntityId, _):
            return "aiAgentSpawnsShell:\(agentEntityId)"
        case .externalNetworkFromAgent(let agentEntityId, let networkEntityId):
            return "externalNetworkFromAgent:\(agentEntityId):\(networkEntityId)"
        default:
            return nil
        }
    }

    /// True when this anchor was successfully materialized inside the window.
    private func anchorIsDuplicate(_ anchor: AnchorTrigger, now: Date) -> Bool {
        guard let key = anchorDedupKey(anchor) else { return false }
        return recentAnchorKeys.contains(key, at: now)
    }

    private func recordMaterializedAnchor(_ anchor: AnchorTrigger, now: Date) {
        guard let key = anchorDedupKey(anchor) else { return }
        recentAnchorKeys.record(key, at: now)
    }

    // MARK: - Ingestion

    @discardableResult
    public func ingest(_ event: NormalizedEventInput) async throws -> [Trace] {
        let processNode = makeProcessNode(from: event.process, agent: event.agent)
        var processEntity = try processNode.toEntity(source: "rolling_graph")

        // High-rate ordinary file callbacks used to suppress their file node
        // and edge but still upsert the same process entity once per event.
        // Suppress that last physical row only when the event carries neither
        // a graph-relevant file nor any independent anchor/lineage evidence.
        if event.category == .file, let file = event.file {
            let kind = Self.inferFileKind(path: file.path)
            let processCanAnchor = AnchorDetector.processOnlyAnchor(
                processNode: processNode,
                policy: policy
            ) != nil
            if TraceGraphFileObservationPolicy.canSuppressPhysicalWrite(
                path: file.path,
                kind: kind,
                untrustedContent: file.untrustedContent,
                hasAgent: event.agent != nil,
                hasNetwork: event.network != nil,
                hasProcessLineage: event.parentProcess != nil
                    || event.process.parentProcessKey != nil,
                processCanAnchor: processCanAnchor
            ) {
                deferredProcessContexts.record(processEntity)
                inputEventsTotal = Self.saturatingAdd(inputEventsTotal, 1)
                eventsCommittedTotal = Self.saturatingAdd(eventsCommittedTotal, 1)
                entityObservationsTotal = Self.saturatingAdd(
                    entityObservationsTotal, 1)
                relevanceSuppressedFileEventsTotal = Self.saturatingAdd(
                    relevanceSuppressedFileEventsTotal, 1)
                // The irrelevant file entity+edge never become logical graph
                // rows; this retains the established relevance ledger.
                relevanceSuppressedRowsTotal = Self.saturatingAdd(
                    relevanceSuppressedRowsTotal, 2)
                physicalWriteSuppressedEventsTotal = Self.saturatingAdd(
                    physicalWriteSuppressedEventsTotal, 1)
                physicalWriteSuppressedRowsTotal = Self.saturatingAdd(
                    physicalWriteSuppressedRowsTotal, 1)
                return []
            }
        }

        // Collect this event's entities + edges as one logical observation.
        // The bounded writer may coalesce it with adjacent non-anchor events;
        // every physical batch still inserts all entities before all edges, so
        // the trace_edges→trace_entities FKs hold for in-batch endpoints.
        var entities: [TraceEntity] = []
        var edges: [TraceEdge] = []

        // 1. Process node. Restore any bounded context suppressed from prior
        // graph-irrelevant file callbacks before a relevant event can anchor.
        if let deferred = deferredProcessContexts.take(id: processEntity.id) {
            processEntity = DeferredProcessContextCache.merge(deferred, processEntity)
        }
        entities.append(processEntity)

        // 2. Parent process spawn edge (when present).
        if let parentObservation = event.parentProcess {
            let parentNode = makeProcessNode(from: parentObservation)
            let parentEntity = try parentNode.toEntity(source: "rolling_graph")
            entities.append(parentEntity)
            let edge = EdgeBuilder.build(
                from: parentNode,
                to: processNode,
                relation: .spawned,
                confidence: 0.95,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            edges.append(edge)
        } else if let parentKey = event.process.parentProcessKey {
            // Parent process key only — useful when we know the
            // ancestry but don't have a full ProcessObservation.
            let edge = EdgeBuilder.build(
                sourceEntityId: ProcessNode.entityType + ":" + parentKey,
                targetEntityId: processEntity.id,
                relation: .spawned,
                confidence: 0.85,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            edges.append(edge)
        }

        // 3. AI agent attribution.
        var agentEntityId: String?
        if let agent = event.agent {
            let agentNode = makeAgentNode(from: agent, observedAt: event.timestamp)
            let agentEntity = try agentNode.toEntity(
                source: "trace_correlator",
                confidence: agent.confidence
            )
            entities.append(agentEntity)
            agentEntityId = agentEntity.id
            let agentEdge = EdgeBuilder.build(
                from: agentNode,
                to: processNode,
                relation: .associatedWithAgent,
                confidence: agent.confidence,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            edges.append(agentEdge)
        }

        // 4. File event.
        var fileNode: FileNode?
        var persistenceNode: PersistenceNode?
        if let fileObs = event.file {
            let inferredKind = Self.inferFileKind(path: fileObs.path)
            if Self.fileObservationIsRelevant(
                path: fileObs.path,
                kind: inferredKind,
                untrustedContent: fileObs.untrustedContent
            ) {
                let node = FileNode(
                    path: fileObs.path,
                    pathHash: fileObs.pathHash,
                    fileKind: inferredKind,
                    sha256: fileObs.sha256,
                    untrustedContent: fileObs.untrustedContent,
                    firstSeen: event.timestamp,
                    lastSeen: event.timestamp
                )
                fileNode = node
                let fileEntity = try node.toEntity(source: "rolling_graph")
                entities.append(fileEntity)

                let relation: EdgeRelation = mapFileAction(event.action)
                let edge = EdgeBuilder.build(
                    from: processNode,
                    to: node,
                    relation: relation,
                    confidence: 0.9,
                    observedAt: event.timestamp,
                    eventIds: [event.eventId]
                )
                edges.append(edge)

                // Persistence detection: certain file kinds + create/write
                // trigger a parallel PersistenceNode + created_persistence edge.
                if let persistenceType = persistenceType(for: inferredKind),
                   event.action == .fileCreate || event.action == .fileWrite {
                    let persistence = PersistenceNode(
                        persistenceType: persistenceType,
                        path: fileObs.path,
                        label: nil,
                        createdByProcessKey: event.process.processKey,
                        firstSeen: event.timestamp,
                        lastSeen: event.timestamp
                    )
                    persistenceNode = persistence
                    let persistEntity = try persistence.toEntity(source: "rolling_graph")
                    entities.append(persistEntity)
                    let persistEdge = EdgeBuilder.build(
                        from: processNode,
                        to: persistence,
                        relation: .createdPersistence,
                        confidence: 0.95,
                        observedAt: event.timestamp,
                        eventIds: [event.eventId]
                    )
                    edges.append(persistEdge)
                }
            } else {
                // Current shipped graph detection needs file nodes only for
                // credential access, untrusted-content taint, and persistence
                // paths. Ordinary temp/build/source opens are not causal-rule
                // inputs; retaining each unique path produced the rc.5
                // 61k-entity/80k-edge churn. Process and AI-agent provenance
                // above is still retained and exactly observation-weighted.
                relevanceSuppressedFileEventsTotal = Self.saturatingAdd(
                    relevanceSuppressedFileEventsTotal,
                    1
                )
                relevanceSuppressedRowsTotal = Self.saturatingAdd(
                    relevanceSuppressedRowsTotal,
                    2
                )
            }
        }

        // 5. Network event.
        var networkNode: NetworkNode?
        if let netObs = event.network {
            let node = NetworkNode(
                destinationHost: netObs.host,
                destinationIP: netObs.ip,
                port: netObs.port,
                protocolName: netObs.protocolName,
                reputation: netObs.reputation,
                firstSeen: event.timestamp,
                lastSeen: event.timestamp
            )
            networkNode = node
            let netEntity = try node.toEntity(source: "rolling_graph")
            entities.append(netEntity)
            let edge = EdgeBuilder.build(
                from: processNode,
                to: node,
                relation: .connectedTo,
                confidence: 0.9,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            edges.append(edge)
        }

        // 6. Classify before persistence so a novel anchor can force all
        // pending observations to stable storage before the materializer reads
        // the graph. Previously classification happened after a per-event
        // commit; retaining this ordering contract is what makes bounded
        // cross-event coalescing detection-safe.
        let anchorContext = AnchorDetector.EventContext(
            processNode: processNode,
            fileNode: fileNode,
            networkNode: networkNode,
            persistenceNode: persistenceNode,
            agentEntityId: agentEntityId,
            credentialOperation: event.action.rawValue,
            policy: policy
        )
        let anchors = AnchorDetector.classify(anchorContext)

        inputEventsTotal = Self.saturatingAdd(inputEventsTotal, 1)
        entityObservationsTotal = Self.saturatingAdd(
            entityObservationsTotal,
            UInt64(entities.count)
        )
        edgeObservationsTotal = Self.saturatingAdd(
            edgeObservationsTotal,
            UInt64(edges.count)
        )
        if pendingWriteBatch.eventCount == 0 {
            pendingWriteBatch.firstEnqueuedAt = monotonicNow()
        }
        let coalesced = pendingWriteBatch.append(entities: entities, edges: edges)
        coalescedNoopRowsTotal = Self.saturatingAdd(
            coalescedNoopRowsTotal,
            UInt64(coalesced)
        )

        // A previously materialized/deduped anchor needs no special write: its
        // substrate is still flushed by the ordinary time/count bounds. A
        // novel anchor must be visible synchronously to TraceMaterializer.
        let hasNovelAnchor = anchors.contains {
            !anchorIsDuplicate($0, now: event.timestamp)
        }
        if hasNovelAnchor || shouldFlushPendingBatch {
            try await flushPending()
        } else {
            schedulePendingFlushIfNeeded()
        }

        // 7. Anchor materialization. Novel anchors have just forced a commit;
        // duplicate anchors remain suppressed by the existing cache.
        return await materializeAnchors(
            anchors,
            eventId: event.eventId,
            timestamp: event.timestamp
        )
    }

    private var shouldFlushPendingBatch: Bool {
        ingestionWritePolicy.maximumDelaySeconds == 0
            || pendingWriteBatch.eventCount >= ingestionWritePolicy.maximumPendingEvents
            || pendingWriteBatch.rowCount >= ingestionWritePolicy.maximumPendingRows
    }

    private func schedulePendingFlushIfNeeded() {
        guard scheduledFlush == nil, pendingWriteBatch.eventCount > 0 else { return }
        let seconds = ingestionWritePolicy.maximumDelaySeconds
        guard seconds > 0 else { return }
        let nanosecondsDouble = min(
            seconds * 1_000_000_000,
            Double(UInt64.max)
        )
        let nanoseconds = UInt64(nanosecondsDouble.rounded(.up))
        scheduledFlushGeneration &+= 1
        let generation = scheduledFlushGeneration
        scheduledFlush = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: nanoseconds)
            } catch {
                return
            }
            await self?.flushScheduledBatch(generation: generation)
        }
    }

    private func flushScheduledBatch(generation: UInt64) async {
        guard generation == scheduledFlushGeneration else { return }
        scheduledFlush = nil
        do {
            try await flushPending()
        } catch is CausalGraphStorageAdmissionError {
            // Expected fail-closed shedding. The SQLite store logs latch
            // transitions; the exact failed event/row totals remain visible in
            // writeTelemetry without producing one warning per timer tick.
        } catch {
            logger.warning("rolling graph coalesced flush failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Persist every currently pending observation in one transaction.
    /// Public so lifecycle owners and focused probes can establish a stable
    /// boundary; ordinary daemon callers rely on the automatic bounds above.
    public func flushPending() async throws {
        scheduledFlush?.cancel()
        scheduledFlush = nil
        scheduledFlushGeneration &+= 1

        // Join an earlier scheduled/anchor flush before deciding there is no
        // work. On success, loop until the owning continuation has published
        // its counters and cleared the handle; then flush any observations that
        // arrived during that physical write.
        while let existing = inFlightStoreWrite {
            do {
                try await existing.value
            } catch {
                while inFlightStoreWrite != nil { await Task.yield() }
                throw error
            }
            if inFlightStoreWrite != nil { await Task.yield() }
        }

        guard pendingWriteBatch.eventCount > 0 else { return }
        let batch = pendingWriteBatch
        pendingWriteBatch = PendingWriteBatch()
        inFlightFirstEnqueuedAt = batch.firstEnqueuedAt
        let entities = batch.sortedEntities
        let edges = batch.sortedEdges
        let rowCount = entities.count + edges.count

        writeAttemptsTotal = Self.saturatingAdd(writeAttemptsTotal, 1)
        writeRowsAttemptedTotal = Self.saturatingAdd(
            writeRowsAttemptedTotal,
            UInt64(rowCount)
        )
        writeBatchesInFlight += 1
        eventsInFlight += batch.eventCount
        writeRowsInFlight += rowCount

        let persistBatch = self.persistBatch
        let storeWrite = Task {
            try await persistBatch(entities, edges)
        }
        inFlightStoreWrite = storeWrite

        do {
            try await storeWrite.value
            inFlightStoreWrite = nil
            inFlightFirstEnqueuedAt = nil
            writeBatchesInFlight -= 1
            eventsInFlight -= batch.eventCount
            writeRowsInFlight -= rowCount
            writeBatchesCommittedTotal = Self.saturatingAdd(
                writeBatchesCommittedTotal,
                1
            )
            eventsCommittedTotal = Self.saturatingAdd(
                eventsCommittedTotal,
                UInt64(batch.eventCount)
            )
            writeRowsCommittedTotal = Self.saturatingAdd(
                writeRowsCommittedTotal,
                UInt64(rowCount)
            )
        } catch {
            inFlightStoreWrite = nil
            inFlightFirstEnqueuedAt = nil
            writeBatchesInFlight -= 1
            eventsInFlight -= batch.eventCount
            writeRowsInFlight -= rowCount
            writeBatchesFailedTotal = Self.saturatingAdd(
                writeBatchesFailedTotal,
                1
            )
            eventsFailedTotal = Self.saturatingAdd(
                eventsFailedTotal,
                UInt64(batch.eventCount)
            )
            writeRowsFailedTotal = Self.saturatingAdd(
                writeRowsFailedTotal,
                UInt64(rowCount)
            )
            throw error
        }
    }

    public func writeTelemetry() -> CausalGraphIngestionWriteTelemetry {
        let oldest = [pendingWriteBatch.firstEnqueuedAt, inFlightFirstEnqueuedAt]
            .compactMap { $0 }.min()
        let age: TimeInterval
        if let oldest {
            let elapsed = oldest.duration(to: monotonicNow()).components
            age = Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
        } else {
            age = 0
        }
        return CausalGraphIngestionWriteTelemetry(
            inputEventsTotal: inputEventsTotal,
            eventsCommittedTotal: eventsCommittedTotal,
            eventsFailedTotal: eventsFailedTotal,
            eventsInFlight: eventsInFlight,
            eventsPending: pendingWriteBatch.eventCount,
            entityObservationsTotal: entityObservationsTotal,
            edgeObservationsTotal: edgeObservationsTotal,
            relevanceSuppressedFileEventsTotal: relevanceSuppressedFileEventsTotal,
            relevanceSuppressedRowsTotal: relevanceSuppressedRowsTotal,
            physicalWriteSuppressedEventsTotal: physicalWriteSuppressedEventsTotal,
            physicalWriteSuppressedRowsTotal: physicalWriteSuppressedRowsTotal,
            writeAttemptsTotal: writeAttemptsTotal,
            writeBatchesCommittedTotal: writeBatchesCommittedTotal,
            writeBatchesFailedTotal: writeBatchesFailedTotal,
            writeBatchesInFlight: writeBatchesInFlight,
            writeRowsAttemptedTotal: writeRowsAttemptedTotal,
            writeRowsCommittedTotal: writeRowsCommittedTotal,
            writeRowsFailedTotal: writeRowsFailedTotal,
            writeRowsInFlight: writeRowsInFlight,
            coalescedNoopRowsTotal: coalescedNoopRowsTotal,
            pendingEntityRows: pendingWriteBatch.entities.count,
            pendingEdgeRows: pendingWriteBatch.edges.count,
            oldestOutstandingAgeSeconds: age
        )
    }

    private static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? UInt64.max : sum
    }

    /// Materialize classified anchors and commit their dedup key only after a
    /// successful write. Internal so focused tests can exercise the failure →
    /// retry contract without replacing the production materializer.
    func materializeAnchors(
        _ anchors: [AnchorTrigger],
        eventId: String,
        timestamp: Date
    ) async -> [Trace] {
        var materialized: [Trace] = []
        for anchor in anchors {
            if anchorIsDuplicate(anchor, now: timestamp) { continue }
            do {
                let trace = try await materializer.materialize(
                    anchorEntityId: anchor.anchorEntityId,
                    anchorEventId: eventId,
                    title: anchor.defaultTitle,
                    severity: anchor.defaultSeverity,
                    confidence: 0.9,
                    now: timestamp.addingTimeInterval(0.001)
                )
                materialized.append(trace)
                // Failed/denied materialization must not consume the 5-minute
                // dedup window; otherwise recovery could resume into a false
                // quiet period with no trace for the triggering behavior.
                recordMaterializedAnchor(anchor, now: timestamp)
                if let cb = anchorCallback {
                    await cb(trace, anchor)
                }
            } catch is CausalGraphStorageAdmissionError {
                // Expected shed while the central SQLite gate is latched. The
                // store owns the counter and transition-only operational log;
                // warning once per normal anchor would become a log flood.
                continue
            } catch {
                logger.error("materialization failed for anchor \(String(describing: anchor), privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
        return materialized
    }

    /// Surface for callers (RuleEngine wiring layer) that detect
    /// anchors outside the rolling graph's own classifier — rule
    /// hits, sequence completions, campaign completions, user-
    /// requested traces.
    @discardableResult
    public func recordExternalAnchor(
        anchorEntityId: String,
        anchorEventId: String,
        reason: String,
        severity: String,
        confidence: Double,
        observedAt: Date
    ) async throws -> Trace {
        // External rule/sequence/campaign anchors can target an entity that is
        // still inside the bounded coalescing window. Preserve the historical
        // contract that materialization reads a fully persisted substrate.
        try await flushPending()
        let trace = try await materializer.materialize(
            anchorEntityId: anchorEntityId,
            anchorEventId: anchorEventId,
            title: reason,
            severity: severity,
            confidence: confidence,
            now: observedAt.addingTimeInterval(0.001)
        )
        if let cb = anchorCallback {
            await cb(trace, .external(reason: reason, anchorEntityId: anchorEntityId))
        }
        return trace
    }

    // MARK: - Helpers

    private func makeProcessNode(
        from observation: ProcessObservation,
        agent: AgentEnrichment? = nil
    ) -> ProcessNode {
        ProcessNode(
            processKey: observation.processKey,
            pid: observation.pid,
            ppid: observation.ppid,
            executablePath: observation.executablePath,
            executableHash: observation.executableHash,
            commandLineRedacted: nil,
            signingTeamId: observation.signingTeamId,
            signingIdentifier: observation.signingIdentifier,
            isAppleSigned: observation.isAppleSigned,
            isNotarized: observation.isNotarized,
            startTime: observation.startTime,
            user: observation.user,
            agentTraceId: agent?.traceId,
            agentSpanId: agent?.spanId
        )
    }

    private func makeAgentNode(from agent: AgentEnrichment, observedAt: Date) -> AIAgentNode {
        let agentId = "\(agent.agentName.lowercased()):\(agent.traceId)"
        return AIAgentNode(
            agentId: agentId,
            agentName: agent.agentName,
            sourceApp: agent.agentName,
            toolName: agent.agentTool,
            traceId: agent.traceId,
            spanId: agent.spanId,
            confidence: agent.confidence,
            attributionMethod: agent.attributionMethod,
            firstSeen: observedAt,
            lastSeen: observedAt
        )
    }

    private func mapFileAction(_ action: NormalizedEventInput.Action) -> EdgeRelation {
        switch action {
        case .fileRead:    return .read
        case .fileWrite:   return .wrote
        case .fileCreate:  return .wrote
        case .fileRename:  return .renamed
        case .fileDelete:  return .deleted
        default:           return .read
        }
    }

    /// Classify graph file substrate with CredentialFence's canonical semantic
    /// credential matcher. ES OPEN admission is intentionally broader: it also
    /// carries Safari history, Notes, Messages, TCC, deception, and other
    /// sensitive-but-not-credential evidence. Treating that whole admission
    /// set as `credential_file` would create false graph edges and alerts. The
    /// broader ES set is retained by `fileObservationIsRelevant` below without
    /// lying about its FileKind.
    nonisolated static func inferFileKind(path: String) -> FileKind {
        TraceGraphFileObservationPolicy.classify(path: path).fileKind
    }

    /// Conservative pre-SQL relevance contract for file substrate rows.
    ///
    /// Every shipped graph rule containing a file node is guarded by either
    /// `file_kind == credential_file` or `untrusted_content == true`; focused
    /// tests scan the bundled rule corpus so a future rule cannot silently
    /// widen that assumption. The narrow ES OPEN-sensitive set stays retained
    /// too, but keeps its truthful semantic kind (for example Safari history is
    /// `.unknown`, never fabricated as a credential). Persistence anchors
    /// additionally require the four path kinds below. Process, AI-agent, and
    /// network substrate is not subject to this gate.
    nonisolated static func fileObservationIsRelevant(
        path: String? = nil,
        kind: FileKind,
        untrustedContent: Bool
    ) -> Bool {
        TraceGraphFileObservationPolicy.isRelevant(
            path: path,
            kind: kind,
            untrustedContent: untrustedContent
        )
    }

    private func persistenceType(for kind: FileKind) -> PersistenceType? {
        TraceGraphFileObservationPolicy.persistenceType(for: kind)
    }
}
