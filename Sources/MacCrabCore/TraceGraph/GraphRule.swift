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

    /// v1.21.5: Sigma-style status tier so graph rules participate in the F-04
    /// rule_profile gate. All shipped graph rules are curated `stable`
    /// precision rules; a file without the key (pre-v1.21.5) is grandfathered
    /// as stable by `GraphRuleLoader`, so nothing silently drops.
    public let status: String?

    public init(
        id: String,
        title: String,
        severity: String,
        type: String = "graph",
        nodes: [String: NodeSpec],
        edges: [EdgeSpec],
        scope: Scope? = nil,
        constraints: Constraints? = nil,
        attack: [String]? = nil,
        status: String? = nil
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
        self.status = status
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

    /// The ATT&CK tactics of `attack`, in the engine's `attack.<tactic>`
    /// form, for the techniques the graph corpus uses. A technique without
    /// an entry contributes nothing rather than a guess.
    public var tactics: [String] { Self.tactics(for: attack) }

    static func tactics(for techniques: [String]) -> [String] {
        var seen: Set<String> = []
        var result: [String] = []
        for technique in techniques {
            let base = String(technique.uppercased().split(separator: ".").first ?? Substring(technique))
            guard let tactic = tacticByTechnique[base], seen.insert(tactic).inserted else { continue }
            result.append(tactic)
        }
        return result
    }

    /// Each technique's tactic in the ATT&CK matrix; where a technique sits
    /// under two, the one the graph rules detect it for.
    private static let tacticByTechnique: [String: String] = [
        "T1195": "attack.initial_access",       // Supply Chain Compromise
        "T1059": "attack.execution",            // Command and Scripting Interpreter
        "T1543": "attack.persistence",          // Create or Modify System Process
        "T1547": "attack.persistence",          // Boot or Logon Autostart Execution
        "T1098": "attack.persistence",          // Account Manipulation
        "T1555": "attack.credential_access",    // Credentials from Password Stores
        "T1105": "attack.command_and_control",  // Ingress Tool Transfer
        "T1041": "attack.exfiltration",         // Exfiltration Over C2 Channel
        "T1567": "attack.exfiltration",         // Exfiltration Over Web Service
    ]
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
