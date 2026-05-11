// ProvOEncoder.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10b) — emits the `prov/prov.jsonld` bundle
// artifact per §22.1 of the v1.10.0 spec. The output is a JSON-LD
// document with the W3C PROV-O context, mapping MacCrab graph
// elements to provenance concepts:
//
//   ProcessNode         → prov:Activity
//   FileNode            → prov:Entity
//   AIAgentNode         → prov:Agent
//   spawned edge        → prov:wasInformedBy
//   read edge           → activity prov:used entity
//   wrote edge          → entity prov:wasGeneratedBy activity
//   associated_with_agent → activity prov:wasAssociatedWith agent
//   ProcessNode startTime / endTime → prov:startedAtTime / prov:endedAtTime
//
// MacCrab-specific extensions live under the `maccrab:` namespace and
// follow the OpenTelemetry stability lifecycle per §22.2 of the spec.

import Foundation

public enum ProvOEncoder {

    private static let provNamespace = "http://www.w3.org/ns/prov#"
    private static let maccrabNamespace = "https://maccrab.com/ns#"

    /// Build the PROV-O JSON-LD document for the given trace contents.
    public static func encode(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) -> [String: Any] {
        var graph: [[String: Any]] = []

        for entity in entities {
            graph.append(provNode(for: entity))
        }
        for edge in edges {
            if let provEdge = provEdgeNode(for: edge) {
                graph.append(provEdge)
            }
        }

        return [
            "@context": [
                "prov": provNamespace,
                "maccrab": maccrabNamespace,
                "xsd": "http://www.w3.org/2001/XMLSchema#",
            ],
            "@graph": graph,
        ]
    }

    /// Encode the document to canonical JSON bytes (sorted keys, ISO-8601 dates).
    public static func encodeToData(
        trace: Trace,
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) throws -> Data {
        let document = encode(trace: trace, entities: entities, edges: edges)
        return try JSONSerialization.data(
            withJSONObject: document,
            options: [.sortedKeys]
        )
    }

    // MARK: - Per-entity / per-edge encoding

    private static func provNode(for entity: TraceEntity) -> [String: Any] {
        switch entity.entityType {
        case ProcessNode.entityType:
            return processActivityNode(entity)
        case FileNode.entityType:
            return fileEntityNode(entity)
        case AIAgentNode.entityType:
            return agentNode(entity)
        case PersistenceNode.entityType:
            return persistenceEntityNode(entity)
        default:
            // Generic fallback — emit as a prov:Entity with the
            // entity-type tag in maccrab:entity_type.
            return [
                "@id": "maccrab:\(entity.id)",
                "@type": "prov:Entity",
                "maccrab:entity_type": entity.entityType,
                "maccrab:display_name": entity.displayName,
            ]
        }
    }

    private static func processActivityNode(_ entity: TraceEntity) -> [String: Any] {
        var node: [String: Any] = [
            "@id": "maccrab:\(entity.id)",
            "@type": "prov:Activity",
            "maccrab:display_name": entity.displayName,
            "maccrab:process_key": entity.stableKey,
            "prov:startedAtTime": iso8601(entity.firstSeen),
        ]
        // Include endedAtTime when distinct from start — for a still-running
        // process, endTime equals startTime in our model so we skip.
        if entity.lastSeen != entity.firstSeen {
            node["prov:endedAtTime"] = iso8601(entity.lastSeen)
        }
        // Process-specific attributes: peek into attributesJson when available.
        if let processNode = decodeProcess(entity) {
            node["maccrab:executable_path"] = processNode.executablePath
            node["maccrab:is_apple_signed"] = processNode.isAppleSigned
            if let agent = processNode.agentTraceId {
                node["maccrab:agent_trace_id"] = agent
            }
        }
        return node
    }

    private static func fileEntityNode(_ entity: TraceEntity) -> [String: Any] {
        var node: [String: Any] = [
            "@id": "maccrab:\(entity.id)",
            "@type": "prov:Entity",
            "maccrab:display_name": entity.displayName,
            "maccrab:path_hash": entity.stableKey,
        ]
        if let fileNode = decode(FileNode.self, from: entity) {
            node["maccrab:file_kind"] = fileNode.fileKind.rawValue
            node["maccrab:path"] = fileNode.path   // already redacted by exporter sweep
            if let sha = fileNode.sha256 {
                node["maccrab:sha256"] = sha
            }
        }
        return node
    }

    private static func agentNode(_ entity: TraceEntity) -> [String: Any] {
        var node: [String: Any] = [
            "@id": "maccrab:\(entity.id)",
            "@type": "prov:Agent",
            "maccrab:display_name": entity.displayName,
        ]
        if let agentNode = decode(AIAgentNode.self, from: entity) {
            node["maccrab:agent_name"] = agentNode.agentName
            node["maccrab:agent_attribution_method"] = agentNode.attributionMethod.rawValue
            node["maccrab:agent_attribution_confidence"] = agentNode.confidence
            if let traceId = agentNode.traceId {
                node["maccrab:agent_trace_id"] = traceId
            }
        }
        return node
    }

    private static func persistenceEntityNode(_ entity: TraceEntity) -> [String: Any] {
        var node: [String: Any] = [
            "@id": "maccrab:\(entity.id)",
            "@type": "prov:Entity",
            "maccrab:display_name": entity.displayName,
        ]
        if let persistenceNode = decode(PersistenceNode.self, from: entity) {
            node["maccrab:persistence_type"] = persistenceNode.persistenceType.rawValue
        }
        return node
    }

    private static func provEdgeNode(for edge: TraceEdge) -> [String: Any]? {
        guard let relation = EdgeRelation(rawValue: edge.relation) else { return nil }
        let sourceRef = "maccrab:\(edge.sourceEntityId)"
        let targetRef = "maccrab:\(edge.targetEntityId)"

        switch relation {
        case .spawned:
            // child wasInformedBy parent
            return [
                "@id": "maccrab:edge:\(edge.id)",
                "@type": "prov:Communication",
                "prov:informant": sourceRef,
                "prov:informed": targetRef,
                "maccrab:trace_edge_relation": relation.rawValue,
                "maccrab:trace_edge_confidence_tier": edge.confidenceTier,
                "prov:atTime": iso8601(edge.lastSeen),
            ]
        case .read:
            // activity used entity
            return [
                "@id": "maccrab:edge:\(edge.id)",
                "@type": "prov:Usage",
                "prov:activity": sourceRef,
                "prov:entity": targetRef,
                "maccrab:trace_edge_relation": relation.rawValue,
                "maccrab:trace_edge_confidence_tier": edge.confidenceTier,
                "prov:atTime": iso8601(edge.lastSeen),
            ]
        case .wrote, .createdPersistence:
            // entity wasGeneratedBy activity
            return [
                "@id": "maccrab:edge:\(edge.id)",
                "@type": "prov:Generation",
                "prov:entity": targetRef,
                "prov:activity": sourceRef,
                "maccrab:trace_edge_relation": relation.rawValue,
                "maccrab:trace_edge_confidence_tier": edge.confidenceTier,
                "prov:atTime": iso8601(edge.lastSeen),
            ]
        case .associatedWithAgent:
            // activity wasAssociatedWith agent
            return [
                "@id": "maccrab:edge:\(edge.id)",
                "@type": "prov:Association",
                "prov:activity": sourceRef,
                "prov:agent": targetRef,
                "maccrab:trace_edge_relation": relation.rawValue,
                "maccrab:trace_edge_confidence_tier": edge.confidenceTier,
                "maccrab:agent_attribution_confidence": edge.confidence,
                "prov:atTime": iso8601(edge.lastSeen),
            ]
        case .connectedTo, .loadedCode, .signedBy, .renamed, .deleted, .triggeredRule, .matchedSequence, .caused:
            // Generic relation — emit as a derivation with maccrab-specific type tag.
            return [
                "@id": "maccrab:edge:\(edge.id)",
                "@type": "prov:Derivation",
                "prov:generatedEntity": targetRef,
                "prov:usedEntity": sourceRef,
                "maccrab:trace_edge_relation": relation.rawValue,
                "maccrab:trace_edge_confidence_tier": edge.confidenceTier,
                "prov:atTime": iso8601(edge.lastSeen),
            ]
        }
    }

    // MARK: - Helpers

    private static func iso8601(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    private static func decodeProcess(_ entity: TraceEntity) -> ProcessNode? {
        decode(ProcessNode.self, from: entity)
    }

    private static func decode<T: Decodable>(_ type: T.Type, from entity: TraceEntity) -> T? {
        guard let data = entity.attributesJson.data(using: .utf8) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try? decoder.decode(T.self, from: data)
    }
}
