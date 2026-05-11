// GraphRule.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-13) — Codable types for graph-native
// detection rules per §23 of the v1.10.0 spec.
//
// PR-13 ships JSON as the canonical on-disk format. The §23.1 YAML
// example is illustrative — both forms encode the same `GraphRule`
// type; YAML compilation lands as a separate increment alongside the
// existing v1.9 rule compiler in Compiler/.
//
// The schema is published in `docs/tracegraph-rule-schema.md`. JSON
// Schema validation lands when the YAML compiler does.

import Foundation

public struct GraphRule: Codable, Sendable, Equatable {

    public let id: String
    public let title: String
    public let severity: String
    public let type: String
    public let nodes: [String: NodeSpec]
    public let edges: [EdgeSpec]
    public let scope: Scope?
    public let constraints: Constraints?
    public let attack: [String]?

    public init(
        id: String,
        title: String,
        severity: String,
        type: String = "graph",
        nodes: [String: NodeSpec],
        edges: [EdgeSpec],
        scope: Scope? = nil,
        constraints: Constraints? = nil,
        attack: [String]? = nil
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.type = type
        self.nodes = nodes
        self.edges = edges
        self.scope = scope
        self.constraints = constraints
        self.attack = attack
    }

    // MARK: - NodeSpec

    public struct NodeSpec: Codable, Sendable, Equatable {
        /// Entity-type tag that the bound entity must carry. Lowercase
        /// names matching `TraceEntity.entityType`: `process`, `file`,
        /// `network`, `ai_agent`, `persistence`, `mcp_server`,
        /// `package_script`, `browser_download`, etc.
        public let type: String

        /// Optional attribute filters keyed by attribute path. Supported
        /// paths per entity type are documented in
        /// `docs/tracegraph-rule-schema.md`.
        public let `where`: [String: WhereClause]?

        public init(type: String, where whereClauses: [String: WhereClause]? = nil) {
            self.type = type
            self.where = whereClauses
        }

        public struct WhereClause: Codable, Sendable, Equatable {
            public let `in`: [String]?
            public let notIn: [String]?
            public let equals: String?
            public let equalsBool: Bool?

            enum CodingKeys: String, CodingKey {
                case `in`
                case notIn = "not_in"
                case equals
                case equalsBool = "equals_bool"
            }

            public init(
                `in`: [String]? = nil,
                notIn: [String]? = nil,
                equals: String? = nil,
                equalsBool: Bool? = nil
            ) {
                self.in = `in`
                self.notIn = notIn
                self.equals = equals
                self.equalsBool = equalsBool
            }
        }
    }

    // MARK: - EdgeSpec

    public struct EdgeSpec: Codable, Sendable, Equatable {
        public let from: String       // node binding name
        public let to: String         // node binding name
        public let relation: String   // EdgeRelation.rawValue
        public let minTier: String?   // ConfidenceTier.rawValue; nil → relation default per §23.2

        enum CodingKeys: String, CodingKey {
            case from, to, relation
            case minTier = "min_tier"
        }

        public init(from: String, to: String, relation: String, minTier: String? = nil) {
            self.from = from
            self.to = to
            self.relation = relation
            self.minTier = minTier
        }
    }

    // MARK: - Scope

    public struct Scope: Codable, Sendable, Equatable {
        public let commonAncestor: String?  // node binding name
        public let maxDepth: Int?

        enum CodingKeys: String, CodingKey {
            case commonAncestor = "common_ancestor"
            case maxDepth = "max_depth"
        }

        public init(commonAncestor: String? = nil, maxDepth: Int? = nil) {
            self.commonAncestor = commonAncestor
            self.maxDepth = maxDepth
        }
    }

    // MARK: - Constraints

    public struct Constraints: Codable, Sendable, Equatable {
        public let withinSeconds: Double?
        public let minConfidence: Double?

        enum CodingKeys: String, CodingKey {
            case withinSeconds = "within_seconds"
            case minConfidence = "min_confidence"
        }

        public init(withinSeconds: Double? = nil, minConfidence: Double? = nil) {
            self.withinSeconds = withinSeconds
            self.minConfidence = minConfidence
        }
    }
}

// MARK: - Match

/// A successful match of one graph rule against a trace.
public struct GraphRuleMatch: Sendable, Equatable {
    public let ruleId: String
    public let ruleTitle: String
    public let severity: String
    public let attack: [String]
    public let bindings: [String: String]  // node binding name → entity id
    public let matchedEdgeIds: [String]

    public init(
        ruleId: String,
        ruleTitle: String,
        severity: String,
        attack: [String] = [],
        bindings: [String: String],
        matchedEdgeIds: [String]
    ) {
        self.ruleId = ruleId
        self.ruleTitle = ruleTitle
        self.severity = severity
        self.attack = attack
        self.bindings = bindings
        self.matchedEdgeIds = matchedEdgeIds
    }
}
