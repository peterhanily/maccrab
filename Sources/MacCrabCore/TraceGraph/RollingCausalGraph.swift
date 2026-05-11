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

public actor RollingCausalGraph {

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

        public init(path: String, pathHash: String, sha256: String? = nil) {
            self.path = path
            self.pathHash = pathHash
            self.sha256 = sha256
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
    private let anchorCallback: (@Sendable (Trace, AnchorTrigger) async -> Void)?
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "rolling-graph")

    public init(
        store: CausalGraphStore,
        materializer: TraceMaterializer,
        policy: TracePolicy = .default,
        anchorCallback: (@Sendable (Trace, AnchorTrigger) async -> Void)? = nil
    ) {
        self.store = store
        self.materializer = materializer
        self.policy = policy
        self.anchorCallback = anchorCallback
    }

    // MARK: - Ingestion

    @discardableResult
    public func ingest(_ event: NormalizedEventInput) async throws -> [Trace] {
        // 1. Process node — always present.
        let processNode = makeProcessNode(from: event.process, agent: event.agent)
        let processEntity = try processNode.toEntity(source: "rolling_graph")
        try await store.upsertEntity(processEntity)

        // 2. Parent process spawn edge (when present).
        if let parentObservation = event.parentProcess {
            let parentNode = makeProcessNode(from: parentObservation)
            let parentEntity = try parentNode.toEntity(source: "rolling_graph")
            try await store.upsertEntity(parentEntity)
            let edge = EdgeBuilder.build(
                from: parentNode,
                to: processNode,
                relation: .spawned,
                confidence: 0.95,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            try await store.upsertEdge(edge)
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
            try await store.upsertEdge(edge)
        }

        // 3. AI agent attribution.
        var agentEntityId: String?
        if let agent = event.agent {
            let agentNode = makeAgentNode(from: agent, observedAt: event.timestamp)
            let agentEntity = try agentNode.toEntity(
                source: "trace_correlator",
                confidence: agent.confidence
            )
            try await store.upsertEntity(agentEntity)
            agentEntityId = agentEntity.id
            let agentEdge = EdgeBuilder.build(
                from: agentNode,
                to: processNode,
                relation: .associatedWithAgent,
                confidence: agent.confidence,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            try await store.upsertEdge(agentEdge)
        }

        // 4. File event.
        var fileNode: FileNode?
        var persistenceNode: PersistenceNode?
        if let fileObs = event.file {
            let inferredKind = inferFileKind(path: fileObs.path)
            let node = FileNode(
                path: fileObs.path,
                pathHash: fileObs.pathHash,
                fileKind: inferredKind,
                sha256: fileObs.sha256,
                firstSeen: event.timestamp,
                lastSeen: event.timestamp
            )
            fileNode = node
            let fileEntity = try node.toEntity(source: "rolling_graph")
            try await store.upsertEntity(fileEntity)

            let relation: EdgeRelation = mapFileAction(event.action)
            let edge = EdgeBuilder.build(
                from: processNode,
                to: node,
                relation: relation,
                confidence: 0.9,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            try await store.upsertEdge(edge)

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
                try await store.upsertEntity(persistEntity)
                let persistEdge = EdgeBuilder.build(
                    from: processNode,
                    to: persistence,
                    relation: .createdPersistence,
                    confidence: 0.95,
                    observedAt: event.timestamp,
                    eventIds: [event.eventId]
                )
                try await store.upsertEdge(persistEdge)
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
            try await store.upsertEntity(netEntity)
            let edge = EdgeBuilder.build(
                from: processNode,
                to: node,
                relation: .connectedTo,
                confidence: 0.9,
                observedAt: event.timestamp,
                eventIds: [event.eventId]
            )
            try await store.upsertEdge(edge)
        }

        // 6. Anchor detection + materialization
        let anchorContext = AnchorDetector.EventContext(
            processNode: processNode,
            fileNode: fileNode,
            networkNode: networkNode,
            persistenceNode: persistenceNode,
            agentEntityId: agentEntityId,
            policy: policy
        )
        let anchors = AnchorDetector.classify(anchorContext)
        var materialized: [Trace] = []
        for anchor in anchors {
            do {
                let trace = try await materializer.materialize(
                    anchorEntityId: anchor.anchorEntityId,
                    anchorEventId: event.eventId,
                    title: anchor.defaultTitle,
                    severity: anchor.defaultSeverity,
                    confidence: 0.9,
                    now: event.timestamp.addingTimeInterval(0.001)
                )
                materialized.append(trace)
                if let cb = anchorCallback {
                    await cb(trace, anchor)
                }
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

    private func inferFileKind(path: String) -> FileKind {
        // Lightweight pattern-based classification. The CredentialFence
        // (existing v1.9) is the authoritative classifier and would be
        // wired in when ESCollector pumps events through; this lighter
        // version covers the §27.2 fixtures.
        if path.hasSuffix(".aws/credentials")
            || path.hasSuffix(".aws/config")
            || path.contains("/.ssh/id_")
            || path.hasSuffix("/.npmrc")
            || path.hasSuffix("/.docker/config.json") {
            return .credentialFile
        }
        if path.contains("/Library/LaunchAgents/")    { return .launchAgent }
        if path.contains("/Library/LaunchDaemons/")   { return .launchDaemon }
        if path.contains("/Library/LoginItems/")      { return .loginItem }
        if path.hasSuffix("/.zshrc") || path.hasSuffix("/.bashrc")
            || path.hasSuffix("/.bash_profile") || path.hasSuffix("/.zprofile") {
            return .shellProfile
        }
        if path.hasSuffix(".plist") { return .plist }
        if path.hasSuffix(".sh") || path.hasSuffix(".py") || path.hasSuffix(".rb") { return .script }
        if path.contains("/Downloads/") { return .browserDownload }
        if path.contains("/node_modules/") { return .packageFile }
        return .unknown
    }

    private func persistenceType(for kind: FileKind) -> PersistenceType? {
        switch kind {
        case .launchAgent:  return .launchAgent
        case .launchDaemon: return .launchDaemon
        case .loginItem:    return .loginItem
        case .shellProfile: return .shellProfile
        default:            return nil
        }
    }
}
