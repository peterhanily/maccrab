// EdgeBuilder.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-7) — turns a (source, target, relation,
// observation context) tuple into a `TraceEdge` ready for
// `CausalGraphStore.upsertEdge(_:)`.
//
// Edge id derivation is deterministic so the store's UPSERT on
// (source_entity_id, target_entity_id, relation) collapses repeat
// observations into one row regardless of which collector fired
// first. The id encodes the natural key explicitly so a third-party
// validator can verify edge identity without dereferencing the row.

import Foundation
import CryptoKit

public enum EdgeBuilder {

    /// Deterministic edge id derived from the natural-key triple.
    /// Lowercase-hex SHA-256 over `source_id || "|" || target_id ||
    /// "|" || relation.rawValue`. Matches the bundle Merkle's
    /// canonical-string discipline (§19.2).
    public static func edgeId(
        sourceEntityId: String,
        targetEntityId: String,
        relation: EdgeRelation
    ) -> String {
        let payload = "\(sourceEntityId)|\(targetEntityId)|\(relation.rawValue)"
        let digest = SHA256.hash(data: Data(payload.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Build an edge between two typed nodes.
    public static func build<S: TraceGraphNode, T: TraceGraphNode>(
        from source: S,
        to target: T,
        relation: EdgeRelation,
        confidence: Double,
        observedAt: Date,
        eventIds: [String] = [],
        evidenceJson: String = "{}"
    ) -> TraceEdge {
        let sourceId = source.canonicalId
        let targetId = target.canonicalId
        let id = edgeId(sourceEntityId: sourceId, targetEntityId: targetId, relation: relation)
        let tier = ConfidenceTier(score: confidence)
        let eventIdsJson: String = {
            guard !eventIds.isEmpty else { return "[]" }
            // Canonical JSON array (sorted for determinism). The id
            // strings are opaque, so lexical sort is fine.
            let sorted = eventIds.sorted()
            // Naive escape: wrap each in quotes after escaping " and \.
            let escaped = sorted.map { id -> String in
                let escapedQuotes = id.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")
                return "\"\(escapedQuotes)\""
            }
            return "[\(escaped.joined(separator: ","))]"
        }()
        return TraceEdge(
            id: id,
            sourceEntityId: sourceId,
            targetEntityId: targetId,
            relation: relation.rawValue,
            firstSeen: observedAt,
            lastSeen: observedAt,
            confidence: confidence,
            confidenceTier: tier.rawValue,
            evidenceJson: evidenceJson,
            eventIdsJson: eventIdsJson
        )
    }

    /// Build an edge between already-resolved entity ids. Used when
    /// the caller already has the canonical ids in hand (e.g. when
    /// reconstructing from candidate edges where the target was
    /// resolved separately).
    public static func build(
        sourceEntityId: String,
        targetEntityId: String,
        relation: EdgeRelation,
        confidence: Double,
        observedAt: Date,
        eventIds: [String] = [],
        evidenceJson: String = "{}"
    ) -> TraceEdge {
        let id = edgeId(sourceEntityId: sourceEntityId, targetEntityId: targetEntityId, relation: relation)
        let tier = ConfidenceTier(score: confidence)
        let eventIdsJson: String = {
            guard !eventIds.isEmpty else { return "[]" }
            let sorted = eventIds.sorted()
            let escaped = sorted.map { id -> String in
                let escapedQuotes = id.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")
                return "\"\(escapedQuotes)\""
            }
            return "[\(escaped.joined(separator: ","))]"
        }()
        return TraceEdge(
            id: id,
            sourceEntityId: sourceEntityId,
            targetEntityId: targetEntityId,
            relation: relation.rawValue,
            firstSeen: observedAt,
            lastSeen: observedAt,
            confidence: confidence,
            confidenceTier: tier.rawValue,
            evidenceJson: evidenceJson,
            eventIdsJson: eventIdsJson
        )
    }
}
