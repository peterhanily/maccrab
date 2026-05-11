// GraphRuleEvaluator.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-13) — evaluates graph rules against a
// materialized trace per §23 of the v1.10.0 spec.
//
// Algorithm: backtracking constraint satisfaction. For each rule:
//   1. Order node bindings.
//   2. For each binding name, try every entity matching the
//      NodeSpec.type + where filters.
//   3. After all nodes are bound, verify that every EdgeSpec has a
//      corresponding TraceEdge between the bound entities at or
//      above the required `min_tier`.
//   4. Verify scope (common ancestor) and constraints (within /
//      min_confidence).
//   5. First successful match per rule is reported.
//
// `temporal_only` edges never satisfy graph rules per §23.2 unless
// a future `temporal_correlation` operator is explicitly opted into
// (deferred to v1.10.x).

import Foundation

public actor GraphRuleEvaluator {

    public let rules: [GraphRule]

    public init(rules: [GraphRule]) {
        self.rules = rules
    }

    /// Evaluate every loaded rule against the supplied trace contents.
    /// Returns one `GraphRuleMatch` per rule that successfully matched.
    public func evaluate(
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) async -> [GraphRuleMatch] {
        var matches: [GraphRuleMatch] = []
        for rule in rules {
            if let match = evaluate(rule: rule, entities: entities, edges: edges) {
                matches.append(match)
            }
        }
        return matches
    }

    // MARK: - Per-rule evaluation

    private func evaluate(
        rule: GraphRule,
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) -> GraphRuleMatch? {
        let orderedNodeNames = orderNodes(rule)
        return bind(
            rule: rule,
            remainingNodes: orderedNodeNames,
            bindings: [:],
            entities: entities,
            edges: edges
        )
    }

    /// Order node bindings so the most-restrictive nodes are bound
    /// first — reduces backtracking in the common case. The first
    /// node is `commonAncestor` if set; otherwise nodes with `where`
    /// filters come before nodes without.
    private func orderNodes(_ rule: GraphRule) -> [String] {
        let names = Array(rule.nodes.keys)
        return names.sorted { lhs, rhs in
            if let common = rule.scope?.commonAncestor {
                if lhs == common { return true }
                if rhs == common { return false }
            }
            let lhsHasWhere = rule.nodes[lhs]?.where?.isEmpty == false
            let rhsHasWhere = rule.nodes[rhs]?.where?.isEmpty == false
            if lhsHasWhere != rhsHasWhere { return lhsHasWhere }
            return lhs < rhs
        }
    }

    private func bind(
        rule: GraphRule,
        remainingNodes: [String],
        bindings: [String: TraceEntity],
        entities: [TraceEntity],
        edges: [TraceEdge]
    ) -> GraphRuleMatch? {
        guard let nodeName = remainingNodes.first else {
            // All nodes bound — verify edges + scope + constraints.
            guard let matchedEdges = verifyEdges(rule: rule, bindings: bindings, edges: edges) else {
                return nil
            }
            guard verifyConstraints(rule: rule, matchedEdges: matchedEdges) else {
                return nil
            }
            // Scope (commonAncestor) — for PR-13 baseline, accept the
            // binding if the named common ancestor is itself one of
            // the bound entities. Full ancestor-walk verification is
            // a v1.10.x increment that will validate connectivity via
            // spawned-edge traversal.
            if let commonAncestorName = rule.scope?.commonAncestor,
               bindings[commonAncestorName] == nil {
                return nil
            }
            return GraphRuleMatch(
                ruleId: rule.id,
                ruleTitle: rule.title,
                severity: rule.severity,
                attack: rule.attack ?? [],
                bindings: bindings.mapValues { $0.id },
                matchedEdgeIds: matchedEdges.map { $0.id }.sorted()
            )
        }

        let remaining = Array(remainingNodes.dropFirst())
        guard let nodeSpec = rule.nodes[nodeName] else { return nil }
        let candidates = candidates(for: nodeSpec, in: entities, alreadyBound: Set(bindings.values.map { $0.id }))
        for candidate in candidates {
            var newBindings = bindings
            newBindings[nodeName] = candidate
            if let match = bind(
                rule: rule,
                remainingNodes: remaining,
                bindings: newBindings,
                entities: entities,
                edges: edges
            ) {
                return match
            }
        }
        return nil
    }

    // MARK: - Candidates

    private func candidates(
        for nodeSpec: GraphRule.NodeSpec,
        in entities: [TraceEntity],
        alreadyBound: Set<String>
    ) -> [TraceEntity] {
        let typed = entities.filter { $0.entityType == nodeSpec.type }
        return typed.filter { entity in
            if alreadyBound.contains(entity.id) { return false }
            return matchesWhere(entity: entity, where: nodeSpec.where)
        }
    }

    private func matchesWhere(entity: TraceEntity, where: [String: GraphRule.NodeSpec.WhereClause]?) -> Bool {
        guard let `where`, !`where`.isEmpty else { return true }
        let attrs = decodeAttributes(entity)
        for (path, clause) in `where` {
            let value = lookupAttribute(entity: entity, attrs: attrs, path: path)
            if !matches(value: value, clause: clause) {
                return false
            }
        }
        return true
    }

    private func matches(value: AttributeValue, clause: GraphRule.NodeSpec.WhereClause) -> Bool {
        if let allowed = clause.in {
            switch value {
            case .string(let s): return allowed.contains(s)
            case .bool, .number, .none: return false
            }
        }
        if let denied = clause.notIn {
            switch value {
            case .string(let s): return !denied.contains(s)
            case .bool, .number, .none: return true
            }
        }
        if let exact = clause.equals {
            switch value {
            case .string(let s): return s == exact
            case .bool, .number, .none: return false
            }
        }
        if let exactBool = clause.equalsBool {
            switch value {
            case .bool(let b): return b == exactBool
            case .string, .number, .none: return false
            }
        }
        // No clauses set → vacuously true (shouldn't happen in practice).
        return true
    }

    // MARK: - Edge verification

    private func verifyEdges(
        rule: GraphRule,
        bindings: [String: TraceEntity],
        edges: [TraceEdge]
    ) -> [TraceEdge]? {
        var matched: [TraceEdge] = []
        for spec in rule.edges {
            guard let sourceEntity = bindings[spec.from],
                  let targetEntity = bindings[spec.to] else {
                return nil
            }
            let requiredTier: ConfidenceTier = {
                if let raw = spec.minTier, let tier = ConfidenceTier(rawValue: raw) {
                    return tier
                }
                if let relation = EdgeRelation(rawValue: spec.relation) {
                    return relation.defaultMinimumTier
                }
                return .weakInferred
            }()
            // §23.2: temporal_only never satisfies graph rules unless
            // an explicit temporal_correlation operator is used (deferred).
            // We enforce that here: even if a rule sets min_tier to
            // temporal_only, the actual edge must not BE temporal_only.
            let viable = edges.first { edge in
                guard edge.sourceEntityId == sourceEntity.id,
                      edge.targetEntityId == targetEntity.id,
                      edge.relation == spec.relation else { return false }
                if edge.confidenceTier == ConfidenceTier.temporalOnly.rawValue {
                    return false
                }
                let edgeTier = ConfidenceTier(rawValue: edge.confidenceTier) ?? .weakInferred
                return edgeTier.meets(requiredTier)
            }
            guard let viable else { return nil }
            matched.append(viable)
        }
        return matched
    }

    // MARK: - Constraints

    private func verifyConstraints(rule: GraphRule, matchedEdges: [TraceEdge]) -> Bool {
        guard let constraints = rule.constraints else { return true }
        if let minConf = constraints.minConfidence {
            for edge in matchedEdges where edge.confidence < minConf {
                return false
            }
        }
        if let withinSeconds = constraints.withinSeconds, !matchedEdges.isEmpty {
            let times = matchedEdges.map { $0.lastSeen.timeIntervalSince1970 }
            let minT = times.min()!
            let maxT = times.max()!
            if maxT - minT > withinSeconds {
                return false
            }
        }
        return true
    }

    // MARK: - Attribute lookup

    private enum AttributeValue {
        case string(String)
        case bool(Bool)
        case number(Double)
        case none
    }

    private func decodeAttributes(_ entity: TraceEntity) -> [String: Any] {
        guard let data = entity.attributesJson.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return obj
    }

    private func lookupAttribute(
        entity: TraceEntity,
        attrs: [String: Any],
        path: String
    ) -> AttributeValue {
        // Derived attributes the JSON doesn't expose directly.
        if path == "executable_name", let exec = attrs["executablePath"] as? String {
            return .string((exec as NSString).lastPathComponent)
        }
        // Camel-case the snake-cased path for the canonical JSON shape.
        let camelKey = camelCase(path)
        if let raw = attrs[camelKey] {
            return wrap(raw)
        }
        // Fallback: try the raw snake_case key.
        if let raw = attrs[path] {
            return wrap(raw)
        }
        return .none
    }

    private func wrap(_ raw: Any) -> AttributeValue {
        if let s = raw as? String { return .string(s) }
        if let b = raw as? Bool { return .bool(b) }
        if let n = raw as? Double { return .number(n) }
        if let n = raw as? Int { return .number(Double(n)) }
        return .none
    }

    private func camelCase(_ snake: String) -> String {
        let parts = snake.split(separator: "_")
        guard let first = parts.first else { return snake }
        let rest = parts.dropFirst().map { $0.prefix(1).uppercased() + $0.dropFirst() }
        return String(first) + rest.joined()
    }
}
