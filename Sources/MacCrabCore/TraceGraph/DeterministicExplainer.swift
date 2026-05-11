// DeterministicExplainer.swift
// MacCrabCore
//
// v1.10 TraceGraph (DeterministicExplainer) — produces the typed
// `StructuredExplanation` from a materialized trace per §15.7 + §16
// of the v1.10.0 spec.
//
// "Deterministic first. LLM second. The LLM summarizes the
//  deterministic explanation. It does not invent the explanation."
//
// The explainer is pure-functional: same inputs → same outputs,
// every run. No I/O, no LLM, no clock. The optional LLM summary in
// `llm/summary.md` consumes this exact JSON as its prompt input,
// preserving the determinism contract for the deterministic half of
// the explanation regardless of which LLM is wired downstream.

import Foundation

public enum DeterministicExplainer {

    public static func explain(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge],
        rootCauseEntityId: String?,
        rootCauseTrustTransition: String?,
        criticalPathEdgeIds: [String],
        attackTechniques: [String] = []
    ) -> StructuredExplanation {

        // Resolve root cause display.
        let rootEntity = rootCauseEntityId.flatMap { id in entities.first(where: { $0.id == id }) }
        let rootCause = StructuredExplanation.RootCause(
            entityId: rootCauseEntityId ?? trace.anchorEventId,
            display: rootDisplay(rootEntity: rootEntity, trace: trace),
            trustTransition: rootCauseTrustTransition
                ?? "materially relevant trust transition: \(rootEntity?.displayName ?? "unknown")"
        )

        // Resolve critical-path edges into typed PathEdge records.
        let entityById = Dictionary(uniqueKeysWithValues: entities.map { ($0.id, $0) })
        let pathEdges: [StructuredExplanation.PathEdge] = criticalPathEdgeIds.compactMap { edgeId in
            guard let edge = edges.first(where: { $0.id == edgeId }) else { return nil }
            let fromName = entityById[edge.sourceEntityId]?.displayName ?? edge.sourceEntityId
            let toName = entityById[edge.targetEntityId]?.displayName ?? edge.targetEntityId
            return StructuredExplanation.PathEdge(
                from: fromName, to: toName,
                relation: edge.relation,
                tier: edge.confidenceTier,
                edgeId: edge.id
            )
        }

        let severityReasons = computeSeverityReasons(entities: entities, edges: edges)
        let confidenceReasons = computeConfidenceReasons(trace: trace, entities: entities, edges: edges)

        return StructuredExplanation(
            rootCause: rootCause,
            criticalPath: pathEdges,
            severityReasons: severityReasons,
            confidenceReasons: confidenceReasons,
            attackMapping: attackTechniques.sorted()
        )
    }

    // MARK: - Root-cause display sentence

    private static func rootDisplay(rootEntity: TraceEntity?, trace: Trace) -> String {
        guard let rootEntity else {
            return "No root cause identified for trace \"\(trace.title)\"."
        }
        switch rootEntity.entityType {
        case ProcessNode.entityType:
            return "\(rootEntity.displayName) initiated the chain leading to the anchor event."
        case AIAgentNode.entityType:
            return "AI-agent activity from \(rootEntity.displayName) preceded the anchor event."
        case MCPServerNode.entityType:
            return "MCP server \(rootEntity.displayName) spawned the chain leading to the anchor."
        case PackageScriptNode.entityType:
            return "Package lifecycle script \(rootEntity.displayName) initiated the activity."
        case BrowserDownloadNode.entityType:
            return "Downloaded artifact \(rootEntity.displayName) executed and led to the anchor."
        default:
            return "\(rootEntity.displayName) is the materially-relevant trust transition for this trace."
        }
    }

    // MARK: - Severity reasons

    private static func computeSeverityReasons(
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) -> [String] {
        var reasons: [String] = []
        let entityTypes = Set(entities.map { $0.entityType })

        // AI agent involvement
        if entityTypes.contains(AIAgentNode.entityType) {
            // Was a shell spawned?
            let agentSpawnsShell = edges.contains { edge in
                edge.relation == EdgeRelation.spawned.rawValue
                && entities.first(where: { $0.id == edge.targetEntityId })
                    .map { isShellExecutable($0) } == true
            }
            if agentSpawnsShell {
                reasons.append("AI-agent associated shell execution")
            } else {
                reasons.append("AI-agent associated activity")
            }
        }

        // Credential access
        let credentialReads = edges.contains { edge in
            guard edge.relation == EdgeRelation.read.rawValue else { return false }
            guard let target = entities.first(where: { $0.id == edge.targetEntityId }),
                  target.entityType == FileNode.entityType else { return false }
            return decodedFileKind(of: target) == .credentialFile
        }
        if credentialReads {
            reasons.append("credential file access")
        }

        // External network connection (suspicious/malicious/unknown reputations).
        let externalNetwork = edges.contains { edge in
            guard edge.relation == EdgeRelation.connectedTo.rawValue else { return false }
            guard let target = entities.first(where: { $0.id == edge.targetEntityId }),
                  target.entityType == NetworkNode.entityType else { return false }
            return decodedNetworkExternal(target)
        }
        if externalNetwork {
            reasons.append("external network connection")
        }

        // Persistence creation
        if entityTypes.contains(PersistenceNode.entityType) {
            // Append the persistence type so the reason is specific.
            let persistenceTypes: [String] = entities
                .filter { $0.entityType == PersistenceNode.entityType }
                .compactMap { decodedPersistenceType(of: $0) }
            if persistenceTypes.isEmpty {
                reasons.append("persistence created")
            } else {
                let unique = Array(Set(persistenceTypes)).sorted()
                for kind in unique {
                    reasons.append("\(kind.replacingOccurrences(of: "_", with: " ")) persistence")
                }
            }
        }

        // Unsigned binary in download path
        let unsignedFromDownload = entities.contains { entity in
            guard entity.entityType == ProcessNode.entityType else { return false }
            guard let proc = decodeProcess(entity) else { return false }
            return !proc.isAppleSigned && proc.executablePath.contains("/Downloads/")
        }
        if unsignedFromDownload {
            reasons.append("unsigned binary executed from download location")
        }

        return reasons
    }

    // MARK: - Confidence reasons

    private static func computeConfidenceReasons(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) -> [String] {
        var reasons: [String] = []

        // Attribution method (when an AIAgentNode is present, look at its method).
        for entity in entities where entity.entityType == AIAgentNode.entityType {
            guard let agent = decodeAgent(entity) else { continue }
            switch agent.attributionMethod {
            case .directTraceparent:
                reasons.append("direct traceparent attribution")
            case .mcpProtocolObserved:
                reasons.append("MCP protocol observation")
            case .processLineageMatch:
                reasons.append("process lineage attribution")
            case .temporalProximity:
                reasons.append("temporal-proximity attribution")
            }
            break  // one agent reason is enough
        }

        // Stable lineage: do the spawn edges form a chain?
        let spawnEdges = edges.filter { $0.relation == EdgeRelation.spawned.rawValue }
        if spawnEdges.count >= 2 {
            reasons.append("stable process lineage")
        }

        // Time window: how spread out are the edges?
        if !edges.isEmpty {
            let times = edges.map { $0.lastSeen.timeIntervalSince1970 }
            if let minT = times.min(), let maxT = times.max() {
                let delta = Int(maxT - minT)
                if delta <= 0 {
                    reasons.append("events occurred at the same observation tick")
                } else {
                    reasons.append("events occurred within \(delta) seconds")
                }
            }
        }

        // Tier composition.
        let directCount = edges.filter { $0.confidenceTier == ConfidenceTier.direct.rawValue }.count
        if directCount >= edges.count, !edges.isEmpty {
            reasons.append("all critical-path edges directly observed")
        }

        return reasons
    }

    // MARK: - Decoding helpers

    private static func isShellExecutable(_ entity: TraceEntity) -> Bool {
        guard let proc = decodeProcess(entity) else { return false }
        let basename = (proc.executablePath as NSString).lastPathComponent
        return ["zsh", "bash", "sh", "ksh", "csh", "tcsh", "fish", "osascript"].contains(basename)
    }

    private static func decodedFileKind(of entity: TraceEntity) -> FileKind? {
        guard let data = entity.attributesJson.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = dict["fileKind"] as? String else { return nil }
        return FileKind(rawValue: raw)
    }

    private static func decodedPersistenceType(of entity: TraceEntity) -> String? {
        guard let data = entity.attributesJson.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = dict["persistenceType"] as? String else { return nil }
        return raw
    }

    private static func decodedNetworkExternal(_ entity: TraceEntity) -> Bool {
        guard let data = entity.attributesJson.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let raw = dict["reputation"] as? String,
              let rep = NetworkReputation(rawValue: raw) else { return true }
        switch rep {
        case .knownGood, .privateRange:
            return false
        case .unknown, .suspicious, .malicious:
            return true
        }
    }

    private static func decodeProcess(_ entity: TraceEntity) -> ProcessNode? {
        guard let data = entity.attributesJson.data(using: .utf8) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try? decoder.decode(ProcessNode.self, from: data)
    }

    private static func decodeAgent(_ entity: TraceEntity) -> AIAgentNode? {
        guard let data = entity.attributesJson.data(using: .utf8) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try? decoder.decode(AIAgentNode.self, from: data)
    }
}
