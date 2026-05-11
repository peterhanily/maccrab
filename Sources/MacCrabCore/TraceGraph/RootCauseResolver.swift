// RootCauseResolver.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-8) — implements the §12 root-cause rule:
//
//   "Root cause is the earliest materially relevant trust-transition
//    point in the trace: the first ancestor where execution moves
//    from trusted, expected, user-initiated, or platform-controlled
//    code into untrusted, unsigned, unexpected, externally supplied,
//    agent-supplied, or policy-violating code."
//
// Algorithm: walk the ancestor chain from oldest (root) toward the
// anchor. While the current ancestor is a trusted conduit per
// `TrustedConduitPolicy`, advance. The first untrusted ancestor (or
// the anchor itself if every ancestor is trusted) is the root cause.
//
// If every entity in the chain is trusted including the anchor →
// emit `trustedAncestry` per §12.2 (the trace is downgraded one
// severity level by the caller).

import Foundation

public enum RootCauseResolver {

    public struct Resolution: Sendable, Equatable {
        public let rootEntityId: String
        public let trustTransitionExplanation: String
        public let kind: Kind

        public enum Kind: Sendable, Equatable {
            /// Standard root-cause result: trust transitioned at this entity.
            case trustTransition

            /// §12.2 — every entity in the chain (including anchor) was
            /// trusted. Caller should downgrade the trace severity by one
            /// level per §12.2.
            case trustedAncestry

            /// Fallback when the ancestor chain is empty (no parents
            /// observed in the lineage window). The anchor itself is
            /// reported as the root cause; severity stays as-is.
            case anchorIsRoot
        }
    }

    /// Resolve the root cause for a materialized trace.
    ///
    /// - Parameters:
    ///   - anchor: the entity the trace materialized around
    ///   - ancestors: ancestor entities ordered closest-first (direct
    ///     parent at index 0, root-most at the end). Matches
    ///     `CausalGraphStore.ancestors(of:depth:within:)` semantics
    ///     when its `entities` collection is sorted by hop distance.
    ///   - decoder: closure that decodes a `TraceEntity` of type
    ///     `"process"` into a `ProcessNode`. Returns nil for entities
    ///     that aren't processes (the resolver treats non-process
    ///     entities as untrusted by default — they don't shield
    ///     downstream activity).
    ///   - policy: trusted-conduit policy (typically `TracePolicy.trustedConduitPolicy`).
    public static func resolve(
        anchor: TraceEntity,
        ancestors: [TraceEntity],
        decoder: (TraceEntity) -> ProcessNode?,
        policy: TrustedConduitPolicy
    ) -> Resolution {
        // Walk from oldest ancestor toward the anchor.
        let chainOldestFirst = ancestors.reversed() + [anchor]

        if ancestors.isEmpty {
            // No ancestor chain observed — anchor IS the root by default.
            // Caller decides whether to surface this as suspicious.
            return Resolution(
                rootEntityId: anchor.id,
                trustTransitionExplanation: explanation(for: anchor, decoder: decoder),
                kind: .anchorIsRoot
            )
        }

        // Walk oldest → anchor. The first untrusted entity is the root cause.
        for entity in chainOldestFirst {
            if !isTrusted(entity: entity, decoder: decoder, policy: policy) {
                let kind: Resolution.Kind = (entity.id == anchor.id) ? .trustTransition : .trustTransition
                return Resolution(
                    rootEntityId: entity.id,
                    trustTransitionExplanation: explanation(for: entity, decoder: decoder),
                    kind: kind
                )
            }
        }

        // Every entity in the chain (including anchor) is trusted →
        // §12.2 trustedAncestry. Report the anchor as the root entity
        // for graph consistency; caller honors the severity downgrade.
        return Resolution(
            rootEntityId: anchor.id,
            trustTransitionExplanation: "trusted ancestry — all observed ancestors and the anchor are trusted conduits per policy",
            kind: .trustedAncestry
        )
    }

    // MARK: - Trust check

    private static func isTrusted(
        entity: TraceEntity,
        decoder: (TraceEntity) -> ProcessNode?,
        policy: TrustedConduitPolicy
    ) -> Bool {
        // Only ProcessNodes participate in the conduit decision. Other
        // entity types (FileNode, NetworkNode, AIAgentNode, etc.)
        // appear in the chain incidentally and don't shield downstream
        // activity. Treat them as not-trusted here — but in practice
        // they don't appear in the spawned-only ancestor walk that
        // produces the chain (CausalGraphStore.ancestors only follows
        // the `spawned` relation, which always points process → process).
        guard entity.entityType == ProcessNode.entityType else {
            return false
        }
        guard let node = decoder(entity) else {
            // Decode failed — be conservative and say not-trusted.
            return false
        }
        return policy.isTrustedConduit(node)
    }

    // MARK: - Explanation prose

    private static func explanation(
        for entity: TraceEntity,
        decoder: (TraceEntity) -> ProcessNode?
    ) -> String {
        if entity.entityType == ProcessNode.entityType, let node = decoder(entity) {
            // Distinct messages for the most common transitions help
            // the deterministic explainer produce useful prose.
            if !node.isAppleSigned && node.executablePath.contains("/Downloads/") {
                return "materially relevant trust transition: unsigned binary executed from a download location (\(node.executablePath))"
            }
            if !node.isAppleSigned {
                return "materially relevant trust transition: non-Apple-signed code (\(entity.displayName))"
            }
            return "materially relevant trust transition: \(entity.displayName)"
        }
        return "materially relevant trust transition: \(entity.displayName)"
    }

    // MARK: - Process-node decoder convenience

    /// Convenience decoder for the common case where ProcessNodes were
    /// stored via `node.toEntity(...)` and the JSON is unencrypted.
    /// Decoders that need to handle encrypted attributes_json should
    /// decrypt before calling.
    public static func defaultProcessNodeDecoder(_ entity: TraceEntity) -> ProcessNode? {
        guard entity.entityType == ProcessNode.entityType else { return nil }
        guard let data = entity.attributesJson.data(using: .utf8) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try? decoder.decode(ProcessNode.self, from: data)
    }
}
