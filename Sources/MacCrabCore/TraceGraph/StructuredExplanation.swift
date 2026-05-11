// StructuredExplanation.swift
// MacCrabCore
//
// v1.10 TraceGraph (DeterministicExplainer) — typed result of the
// deterministic explainer per §16.1 of the v1.10.0 spec.
//
// Structure mirrors the JSON shape the spec publishes verbatim — an
// optional LLM summary downstream consumes this exact object as its
// input, ensuring replay-determinism for the deterministic half of
// the explanation regardless of which LLM is wired (or whether one
// is wired at all).

import Foundation

public struct StructuredExplanation: Codable, Sendable, Equatable {

    public let rootCause: RootCause
    public let criticalPath: [PathEdge]
    public let severityReasons: [String]
    public let confidenceReasons: [String]
    public let attackMapping: [String]

    public init(
        rootCause: RootCause,
        criticalPath: [PathEdge],
        severityReasons: [String],
        confidenceReasons: [String],
        attackMapping: [String]
    ) {
        self.rootCause = rootCause
        self.criticalPath = criticalPath
        self.severityReasons = severityReasons
        self.confidenceReasons = confidenceReasons
        self.attackMapping = attackMapping
    }

    public struct RootCause: Codable, Sendable, Equatable {
        public let entityId: String
        public let display: String
        public let trustTransition: String

        public init(entityId: String, display: String, trustTransition: String) {
            self.entityId = entityId
            self.display = display
            self.trustTransition = trustTransition
        }

        enum CodingKeys: String, CodingKey {
            case entityId = "entity_id"
            case display
            case trustTransition = "trust_transition"
        }
    }

    public struct PathEdge: Codable, Sendable, Equatable {
        public let from: String          // display name
        public let to: String            // display name
        public let relation: String      // §9 relation rawValue
        public let tier: String          // ConfidenceTier rawValue
        public let edgeId: String        // canonical edge id (so the dashboard / CLI can drill down)

        public init(from: String, to: String, relation: String, tier: String, edgeId: String) {
            self.from = from
            self.to = to
            self.relation = relation
            self.tier = tier
            self.edgeId = edgeId
        }
    }

    enum CodingKeys: String, CodingKey {
        case rootCause = "root_cause"
        case criticalPath = "critical_path"
        case severityReasons = "severity_reasons"
        case confidenceReasons = "confidence_reasons"
        case attackMapping = "attack_mapping"
    }
}
