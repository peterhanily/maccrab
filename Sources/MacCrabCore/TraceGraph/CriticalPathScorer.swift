// CriticalPathScorer.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-8) — confidence-weighted critical path per
// §14.4 of the spec. CausalGraphStore's BFS shortest-path is
// unweighted; this layer re-scores candidate paths by edge confidence,
// relation importance, and trust-boundary crossings to pick the
// path that the explainer should foreground.
//
// Suggested relation weights from §14.4:
//
//   created_persistence                                  → High
//   read credential file                                 → High
//   connected_to external/suspicious network endpoint    → High
//   associated_with_agent direct or strong inferred      → High
//   spawned shell or script interpreter                  → Medium
//   wrote project file                                   → Low / context
//   temporal-only                                        → Excluded from core
//
// PR-8 implements relation weights + confidence + trust-boundary
// scoring; FileKind sensitivity (credential vs project) layers in
// once the typed FileNode attributes are inspected.

import Foundation

public enum CriticalPathScorer {

    /// Score for a single edge — used to pick between candidate paths.
    /// Higher == more important to surface in the core trace.
    public static func score(
        edge: TraceEdge,
        crossesTrustBoundary: Bool = false
    ) -> Double {
        guard let relation = EdgeRelation(rawValue: edge.relation) else {
            // Unknown relation — treat as low-importance.
            return edge.confidence * 0.5
        }

        // §11.2 invariant: temporal-only edges never participate in the
        // core trace. Caller should also enforce this when filtering;
        // we surface it here too with a hard zero.
        if edge.confidenceTier == ConfidenceTier.temporalOnly.rawValue {
            return 0.0
        }

        let relationWeight = baseWeight(for: relation)
        let confidenceWeight = edge.confidence
        let trustBonus: Double = crossesTrustBoundary ? 1.5 : 1.0

        return relationWeight * confidenceWeight * trustBonus
    }

    /// Score an entire path. The path's score is the sum of its edge
    /// scores — paths are usually similar lengths (≤ 5 hops in the
    /// default budget), so summation discourages trivial single-edge
    /// paths only when those edges are weak.
    public static func score(
        path: [TraceEdge],
        trustBoundaryEdgeIds: Set<String> = []
    ) -> Double {
        path.reduce(0.0) { acc, edge in
            acc + score(edge: edge, crossesTrustBoundary: trustBoundaryEdgeIds.contains(edge.id))
        }
    }

    /// Pick the highest-scoring path from a set of candidate paths
    /// (each path is an ordered edge list from source to target).
    /// Returns nil if no candidates pass the temporal-only filter.
    public static func pickCriticalPath(
        candidates: [[TraceEdge]],
        trustBoundaryEdgeIds: Set<String> = []
    ) -> [TraceEdge]? {
        let viable = candidates.filter { path in
            !path.contains(where: { $0.confidenceTier == ConfidenceTier.temporalOnly.rawValue })
        }
        guard !viable.isEmpty else { return nil }
        return viable.max { lhs, rhs in
            score(path: lhs, trustBoundaryEdgeIds: trustBoundaryEdgeIds)
                < score(path: rhs, trustBoundaryEdgeIds: trustBoundaryEdgeIds)
        }
    }

    /// Per-relation base weight per §14.4. Returned in arbitrary
    /// units; what matters is the relative ordering across relations.
    private static func baseWeight(for relation: EdgeRelation) -> Double {
        switch relation {
        case .createdPersistence:    return 4.0    // High
        case .associatedWithAgent:   return 4.0    // High
        case .connectedTo:           return 3.0    // High (often, depends on reputation — caller can boost)
        case .read:                  return 3.0    // High when target is credential, otherwise medium — caller can boost
        case .caused:                return 3.0
        case .spawned:               return 2.0    // Medium
        case .triggeredRule:         return 2.0
        case .matchedSequence:       return 2.0
        case .loadedCode:            return 1.5
        case .signedBy:              return 1.0
        case .renamed:               return 1.0
        case .deleted:               return 1.0
        case .wrote:                 return 0.5    // Low / context
        }
    }
}
