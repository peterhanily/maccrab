// TraceMaterializer.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-8) — orchestrates trace crystallization per
// §15.6 of the spec. Given an anchor entity id (and the surrounding
// graph already in `CausalGraphStore`), the materializer:
//
//   1. Loads the anchor entity.
//   2. Walks ancestors / descendants / neighborhood within the policy's
//      window + depth budget.
//   3. Resolves the root cause via `RootCauseResolver`.
//   4. Computes the confidence-weighted critical path (PR-8 calls
//      `CriticalPathScorer` against the store's BFS shortest path).
//   5. Assembles the dynamic core + context layers per §14.3.
//   6. Saves the `Trace` row + `TraceMembership` rows.
//   7. Returns the resulting Trace.
//
// PR-8 covers steps 1-7. The ingestion side (RollingCausalGraph
// extends ProcessLineage / EventEnricher to feed entities + edges
// into the store) lands in a separate increment alongside the
// ESCollector wiring.

import Foundation
import os.log

public actor TraceMaterializer {

    public enum MaterializeError: Error, LocalizedError {
        case anchorNotFound(String)
        case storeError(String)

        public var errorDescription: String? {
            switch self {
            case .anchorNotFound(let id): return "TraceMaterializer: anchor entity not found: \(id)"
            case .storeError(let m):       return "TraceMaterializer: store error: \(m)"
            }
        }
    }

    private let store: CausalGraphStore
    private let policy: TracePolicy
    private let daemonVersion: String
    private let rulesetVersion: String
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "materializer")

    public init(
        store: CausalGraphStore,
        policy: TracePolicy = .default,
        daemonVersion: String = MacCrabVersion.current,
        rulesetVersion: String = MacCrabVersion.current
    ) {
        self.store = store
        self.policy = policy
        self.daemonVersion = daemonVersion
        self.rulesetVersion = rulesetVersion
    }

    // MARK: - materialize

    public func materialize(
        anchorEntityId: String,
        anchorEventId: String,
        title: String,
        severity: String,
        confidence: Double,
        attackTechniques: [String] = [],
        now: Date = Date()
    ) async throws -> Trace {
        // 1. Load anchor
        guard let anchor = try await store.entity(id: anchorEntityId) else {
            throw MaterializeError.anchorNotFound(anchorEntityId)
        }

        let lookbackWindow = TimeWindow(
            start: now.addingTimeInterval(-Double(policy.lookbackMinutes * 60)),
            end: now.addingTimeInterval(Double(policy.lookaheadMinutes * 60))
        )
        let neighborhoodWindow = TimeWindow(
            start: now.addingTimeInterval(-policy.materializationWindow),
            end: now.addingTimeInterval(policy.materializationWindow)
        )

        // 2. Walk ancestors / descendants / neighborhood
        let ancestors = try await store.ancestors(
            of: anchor.id,
            depth: policy.ancestorDepth,
            within: lookbackWindow
        )
        let descendants = try await store.descendants(
            of: anchor.id,
            depth: policy.descendantDepth,
            within: lookbackWindow
        )
        let neighborhood = try await store.neighborhood(
            of: anchor.id,
            depth: 2,
            within: neighborhoodWindow
        )

        // 3. Resolve root cause
        let orderedAncestors = orderAncestorsClosestFirst(
            ancestors.entities,
            edges: ancestors.edges,
            anchorId: anchor.id
        )
        let rootCause = RootCauseResolver.resolve(
            anchor: anchor,
            ancestors: orderedAncestors,
            decoder: RootCauseResolver.defaultProcessNodeDecoder,
            policy: policy.trustedConduitPolicy
        )

        // 4. Critical path: ask the store for the BFS shortest path
        // from rootCause → anchor, then re-score via CriticalPathScorer.
        //
        // When root == anchor (the anchor itself is the trust transition,
        // or no ancestor was observed), the store's criticalPath returns
        // empty. In that case we fall back to the ancestor spawn chain
        // leading to the anchor — that's the lineage the user expects
        // to see in the core layer regardless of the formal definition
        // of "critical path".
        let storeCandidatePath = try await store.criticalPath(
            from: rootCause.rootEntityId,
            to: anchor.id,
            maxDepth: policy.ancestorDepth + policy.descendantDepth
        )
        let scoredPath: [TraceEdge]
        if storeCandidatePath.isEmpty {
            scoredPath = ancestorChainEdges(ancestors.edges, anchorId: anchor.id)
        } else {
            let trustBoundaryEdgeIds = identifyTrustBoundaryEdges(
                in: storeCandidatePath,
                rootCauseEntityId: rootCause.rootEntityId
            )
            scoredPath = CriticalPathScorer.pickCriticalPath(
                candidates: [storeCandidatePath],
                trustBoundaryEdgeIds: trustBoundaryEdgeIds
            ) ?? storeCandidatePath
        }

        // 5. Assemble core + context layers
        let core = buildCoreLayer(
            criticalPath: scoredPath,
            ancestors: ancestors,
            descendants: descendants,
            anchor: anchor,
            rootCauseEntityId: rootCause.rootEntityId
        )
        let context = buildContextLayer(
            neighborhood: neighborhood,
            ancestors: ancestors,
            descendants: descendants,
            excluding: core
        )

        // 6. Apply §12.2 trustedAncestry severity downgrade if applicable
        let finalSeverity = adjustSeverityForRootCause(severity: severity, rootCauseKind: rootCause.kind)

        // 7. Build + persist Trace + memberships
        // Gather the entities the explainer needs to dereference for
        // display names + reason classification. Dedup by id since
        // TraceEntity / TraceEdge are not Hashable by design (the
        // domain identity is `id`, not the full struct).
        let allEntities: [TraceEntity] = {
            var byId: [String: TraceEntity] = [:]
            for e in ancestors.entities + descendants.entities + neighborhood.entities + [anchor] {
                byId[e.id] = e
            }
            return Array(byId.values)
        }()
        let allEdges: [TraceEdge] = {
            var byId: [String: TraceEdge] = [:]
            for e in ancestors.edges + descendants.edges + neighborhood.edges {
                byId[e.id] = e
            }
            return Array(byId.values)
        }()
        let explanation = DeterministicExplainer.explain(
            trace: Trace(
                id: "",
                title: title, anchorEventId: anchorEventId,
                rootEntityId: rootCause.rootEntityId,
                severity: finalSeverity, confidence: confidence,
                createdAt: now, updatedAt: now,
                daemonVersion: daemonVersion, rulesetVersion: rulesetVersion,
                policyId: policy.id, policyVersion: policy.version,
                policySha256: policySha256(policy),
                policySnapshotJson: encodePolicySnapshot(policy),
                traceSigningKeyMode: policy.traceSigningKeyMode,
                replayScope: policy.replayScope,
                attributionOverridePolicy: policy.attributionOverridePolicy
            ),
            entities: allEntities,
            edges: allEdges,
            rootCauseEntityId: rootCause.rootEntityId,
            rootCauseTrustTransition: rootCause.trustTransitionExplanation,
            criticalPathEdgeIds: scoredPath.map { $0.id },
            attackTechniques: attackTechniques
        )
        let summaryJson: String? = {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            guard let data = try? encoder.encode(explanation) else { return nil }
            return String(data: data, encoding: .utf8)
        }()
        let trace = Trace(
            id: UUID().uuidString,
            title: title,
            anchorEventId: anchorEventId,
            rootEntityId: rootCause.rootEntityId,
            severity: finalSeverity,
            confidence: confidence,
            createdAt: now,
            updatedAt: now,
            summaryJson: summaryJson,
            attackJson: try? encodeAttackTechniques(attackTechniques),
            daemonVersion: daemonVersion,
            rulesetVersion: rulesetVersion,
            policyId: policy.id,
            policyVersion: policy.version,
            policySha256: policySha256(policy),
            policySnapshotJson: encodePolicySnapshot(policy),
            traceSigningKeyMode: policy.traceSigningKeyMode,
            replayScope: policy.replayScope,
            attributionOverridePolicy: policy.attributionOverridePolicy
        )

        let members = buildMemberships(
            traceId: trace.id,
            anchor: anchor,
            rootCauseId: rootCause.rootEntityId,
            criticalPath: scoredPath,
            core: core,
            context: context
        )

        do {
            try await store.saveTrace(trace, members: members)
        } catch {
            throw MaterializeError.storeError(error.localizedDescription)
        }

        // A3-04: extend the on-DB append-only continuity chain with one linked
        // entry certifying that this trace was materialized, in this position,
        // at this time. Best-effort: a ledger-append failure must never fail
        // the detection path (materialize is on the hot ingest path), but it
        // is logged so a persistent failure is visible. The signed per-export
        // bundle + unified-log witness anchor the head independently.
        do {
            _ = try await store.appendTraceContinuity(
                traceId: trace.id,
                eventId: trace.anchorEventId,
                edgeId: nil,
                signature: nil,
                publishedToUnifiedLog: false,
                createdAt: now
            )
        } catch {
            logger.error("continuity-chain append failed for trace \(trace.id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }

        return trace
    }

    // MARK: - Layer assembly

    private struct Layer {
        var entityIds: Set<String>
        var edgeIds: Set<String>

        var entitiesArray: [String] { Array(entityIds) }
        var edgesArray: [String] { Array(edgeIds) }
    }

    private func buildCoreLayer(
        criticalPath: [TraceEdge],
        ancestors: GraphSubtree,
        descendants: GraphSubtree,
        anchor: TraceEntity,
        rootCauseEntityId: String
    ) -> Layer {
        var entityIds: Set<String> = [anchor.id, rootCauseEntityId]
        var edgeIds: Set<String> = []

        for edge in criticalPath {
            entityIds.insert(edge.sourceEntityId)
            entityIds.insert(edge.targetEntityId)
            edgeIds.insert(edge.id)
            if entityIds.count >= policy.coreEntityCap || edgeIds.count >= policy.coreEdgeCap { break }
        }

        return Layer(entityIds: entityIds, edgeIds: edgeIds)
    }

    private func buildContextLayer(
        neighborhood: GraphSubtree,
        ancestors: GraphSubtree,
        descendants: GraphSubtree,
        excluding core: Layer
    ) -> Layer {
        var entityIds: Set<String> = []
        var edgeIds: Set<String> = []

        // Add ancestors first (typically more interesting for context),
        // then descendants, then neighborhood. Stop at the cap.
        let allEntities = ancestors.entities + descendants.entities + neighborhood.entities
        let allEdges = ancestors.edges + descendants.edges + neighborhood.edges

        for entity in allEntities {
            if core.entityIds.contains(entity.id) { continue }
            entityIds.insert(entity.id)
            if entityIds.count >= policy.contextEntityCap { break }
        }
        for edge in allEdges {
            if core.edgeIds.contains(edge.id) { continue }
            edgeIds.insert(edge.id)
            if edgeIds.count >= policy.contextEdgeCap { break }
        }

        return Layer(entityIds: entityIds, edgeIds: edgeIds)
    }

    private func buildMemberships(
        traceId: String,
        anchor: TraceEntity,
        rootCauseId: String,
        criticalPath: [TraceEdge],
        core: Layer,
        context: Layer
    ) -> [TraceMembership] {
        var out: [TraceMembership] = []
        let now = Date()

        // anchor
        out.append(TraceMembership(traceId: traceId, entityId: anchor.id, role: "anchor", layer: "core", addedAt: now))
        // root (only if distinct from anchor)
        if rootCauseId != anchor.id {
            out.append(TraceMembership(traceId: traceId, entityId: rootCauseId, role: "root", layer: "core", addedAt: now))
        }

        // critical-path edges + intermediate entities
        var seenEntities: Set<String> = [anchor.id, rootCauseId]
        for edge in criticalPath {
            out.append(TraceMembership(traceId: traceId, edgeId: edge.id, role: "critical_path", layer: "core", addedAt: now))
            for eid in [edge.sourceEntityId, edge.targetEntityId] where !seenEntities.contains(eid) {
                seenEntities.insert(eid)
                out.append(TraceMembership(traceId: traceId, entityId: eid, role: "critical_path", layer: "core", addedAt: now))
            }
        }

        // context-layer entities + edges
        for eid in context.entityIds where !core.entityIds.contains(eid) {
            out.append(TraceMembership(traceId: traceId, entityId: eid, role: "context", layer: "context", addedAt: now))
        }
        for edgeId in context.edgeIds {
            out.append(TraceMembership(traceId: traceId, edgeId: edgeId, role: "context", layer: "context", addedAt: now))
        }

        return out
    }

    // MARK: - Helpers

    /// Order ancestors by hop distance from the anchor (closest first).
    /// The store returns an unordered set; for the trust-walk we need
    /// the natural lineage ordering. This implementation walks the
    /// edge graph from the anchor backward using only `spawned` edges.
    private func orderAncestorsClosestFirst(
        _ ancestors: [TraceEntity],
        edges: [TraceEdge],
        anchorId: String
    ) -> [TraceEntity] {
        guard !ancestors.isEmpty else { return [] }
        let entityById = Dictionary(uniqueKeysWithValues: ancestors.map { ($0.id, $0) })
        let parentByChild: [String: String] = Dictionary(
            uniqueKeysWithValues: edges
                .filter { $0.relation == EdgeRelation.spawned.rawValue }
                .map { ($0.targetEntityId, $0.sourceEntityId) }
        )
        var ordered: [TraceEntity] = []
        var visited: Set<String> = [anchorId]
        var current = anchorId
        while let parentId = parentByChild[current], !visited.contains(parentId) {
            visited.insert(parentId)
            if let entity = entityById[parentId] {
                ordered.append(entity)
            }
            current = parentId
        }
        return ordered
    }

    /// Identify edges whose source-or-target straddles the trust-boundary
    /// — currently approximates "edge is on the path through the
    /// root cause" so the scorer rewards paths that pass through the
    /// transition explicitly.
    private func identifyTrustBoundaryEdges(in path: [TraceEdge], rootCauseEntityId: String) -> Set<String> {
        Set(path.filter { $0.sourceEntityId == rootCauseEntityId || $0.targetEntityId == rootCauseEntityId }.map { $0.id })
    }

    /// Walk the spawn chain from the anchor backward and return the
    /// edges in root → anchor order. Used as the critical-path
    /// fallback when the store's source→target BFS is empty (i.e.,
    /// when the root cause is the anchor itself).
    private func ancestorChainEdges(_ edges: [TraceEdge], anchorId: String) -> [TraceEdge] {
        var result: [TraceEdge] = []
        var current = anchorId
        var visited: Set<String> = [anchorId]
        while let edge = edges.first(where: {
            $0.targetEntityId == current && $0.relation == EdgeRelation.spawned.rawValue
        }) {
            result.append(edge)
            let next = edge.sourceEntityId
            if visited.contains(next) { break }
            visited.insert(next)
            current = next
            if result.count > policy.ancestorDepth { break }   // safety bound
        }
        return result.reversed()  // emit oldest → anchor
    }

    private func adjustSeverityForRootCause(severity: String, rootCauseKind: RootCauseResolver.Resolution.Kind) -> String {
        guard rootCauseKind == .trustedAncestry else { return severity }
        // Downgrade by one level per §12.2.
        switch severity.lowercased() {
        case "critical": return "high"
        case "high":     return "medium"
        case "medium":   return "low"
        case "low":      return "informational"
        default:         return severity
        }
    }

    // MARK: - Encoding helpers

    private func encodeSummary(rootCause: RootCauseResolver.Resolution, criticalPath: [TraceEdge]) throws -> String? {
        struct Summary: Encodable {
            let rootEntityId: String
            let trustTransition: String
            let kind: String
            let criticalPathEdgeIds: [String]
        }
        let kindString: String
        switch rootCause.kind {
        case .trustTransition:  kindString = "trust_transition"
        case .trustedAncestry:  kindString = "trusted_ancestry"
        case .anchorIsRoot:     kindString = "anchor_is_root"
        }
        let summary = Summary(
            rootEntityId: rootCause.rootEntityId,
            trustTransition: rootCause.trustTransitionExplanation,
            kind: kindString,
            criticalPathEdgeIds: criticalPath.map { $0.id }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(summary)
        return String(data: data, encoding: .utf8)
    }

    private func encodeAttackTechniques(_ techniques: [String]) throws -> String? {
        guard !techniques.isEmpty else { return nil }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(techniques.sorted())
        return String(data: data, encoding: .utf8)
    }

    private func policySha256(_ policy: TracePolicy) -> String {
        // PR-8: stable identifier derived from id + version. PR-15.10.1
        // will swap this for a real sha256 over the canonical policy
        // snapshot once the full policy serialization lands.
        "policy-\(policy.id)-v\(policy.version)"
    }

    private func encodePolicySnapshot(_ policy: TracePolicy) -> String {
        // PR-8: minimal snapshot. Full canonical encoding lands when
        // TracePolicy gains all the §15.10 fields and a Codable conformance.
        let snapshot = """
        {"id":"\(policy.id)","version":"\(policy.version)","ancestorDepth":\(policy.ancestorDepth),"descendantDepth":\(policy.descendantDepth),"coreEntityCap":\(policy.coreEntityCap),"contextEntityCap":\(policy.contextEntityCap),"aiAttributionAssertionThreshold":\(policy.aiAttributionAssertionThreshold)}
        """
        return snapshot
    }
}
