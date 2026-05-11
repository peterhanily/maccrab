// CompactPersistentLineage.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6a) — protocol for the compact persistent
// lineage fallback described in §6.3.1 of the v1.10.0 spec.
//
// The rolling graph evicts skeletons under memory pressure but must
// never silently lose ancestry. Before evicting a skeleton that has
// descendants, candidate edges, AI attribution, rule references, or
// a parent within enriched-entity reach, the rolling graph promotes
// the skeleton into compact persistent storage. If a trace later
// needs ancestry that has been evicted from memory, the fallback is
// consulted before the slower `events.db` reconstruction path.
//
// PR-6a ships:
//   - this protocol;
//   - an in-memory implementation suitable for tests and for the
//     pre-PR-6b daemon (when `tracegraph.db` doesn't exist yet).
//
// PR-6b ships:
//   - `SQLiteCompactPersistentLineage` backed by a table in
//     `tracegraph.db`.
//
// The split keeps PR-6a's diff free of SQLite migration risk while
// still establishing the contract that the rolling graph relies on.

import Foundation

/// Compact persistent storage for skeletons promoted out of the
/// rolling graph. Implementations are expected to be cheap to query
/// for ancestor walks but small in footprint compared to a full
/// rehydration of `events.db`.
public protocol CompactPersistentLineage: Sendable {

    /// Persist a skeleton. Idempotent — repeat calls with the same
    /// `processKey` overwrite previous state. Implementations may
    /// reorder edges in storage but must preserve the ancestry chain
    /// declared by `parentProcessKey`.
    func promote(_ skeleton: ProcessSkeleton) async throws

    /// Look up a single skeleton by its canonical key.
    func skeleton(forProcessKey key: String) async throws -> ProcessSkeleton?

    /// Walk the parent chain of a skeleton, returning ancestors in
    /// closest-first order (direct parent at index 0). Returns an
    /// empty array if the skeleton is unknown or has no parent in
    /// storage.
    ///
    /// `depth` is the maximum number of hops walked. Callers are
    /// expected to enforce the rolling-graph ancestor depth budget
    /// themselves; this method only enforces an internal cycle guard
    /// using the same pattern as `ProcessLineage.ancestors`.
    func ancestors(of processKey: String, depth: Int) async throws -> [ProcessSkeleton]

    /// Approximate count of stored skeletons. Used for telemetry and
    /// memory-pressure tests; implementations may return an estimate.
    func count() async throws -> Int
}

/// In-memory implementation. Used by tests and as the daemon's default
/// before `tracegraph.db` is created in PR-6b. Bounded only by total
/// promoted skeleton count — relies on the rolling graph not promoting
/// unbounded skeletons (which is enforced by the eviction policy in
/// §6.3.1).
public actor InMemoryCompactPersistentLineage: CompactPersistentLineage {

    // Rolling-causal-graph eviction policy (§6.3.1) caps promoted
    // skeleton count upstream — this in-memory stub never sees
    // unbounded growth in production. Tests reset the actor between
    // runs.
    private var byKey: [String: ProcessSkeleton] = [:] // bounded: upstream rolling-graph eviction (§6.3.1)
    // Children index mirrors byKey's membership, so it can't outgrow it.
    private var childrenByParent: [String: Set<String>] = [:] // bounded: mirrors byKey (cap upstream)

    public init() {}

    public func promote(_ skeleton: ProcessSkeleton) {
        // If we're overwriting an existing entry whose parent has
        // changed, update the children index accordingly.
        if let existing = byKey[skeleton.processKey],
           existing.parentProcessKey != skeleton.parentProcessKey,
           let oldParent = existing.parentProcessKey {
            childrenByParent[oldParent]?.remove(skeleton.processKey)
            if childrenByParent[oldParent]?.isEmpty == true {
                childrenByParent.removeValue(forKey: oldParent)
            }
        }

        byKey[skeleton.processKey] = skeleton
        if let parentKey = skeleton.parentProcessKey {
            childrenByParent[parentKey, default: []].insert(skeleton.processKey)
        }
    }

    public func skeleton(forProcessKey key: String) -> ProcessSkeleton? {
        byKey[key]
    }

    public func ancestors(of processKey: String, depth: Int) -> [ProcessSkeleton] {
        guard depth > 0 else { return [] }
        var out: [ProcessSkeleton] = []
        var visited: Set<String> = [processKey]
        var current = processKey
        for _ in 0 ..< depth {
            guard let node = byKey[current], let parentKey = node.parentProcessKey else { break }
            if visited.contains(parentKey) { break }
            guard let parent = byKey[parentKey] else { break }
            out.append(parent)
            visited.insert(parentKey)
            current = parentKey
        }
        return out
    }

    public func count() -> Int { byKey.count }

    // MARK: - Test helpers

    /// Direct child set (test surface only — not part of the protocol).
    public func children(of parentKey: String) -> Set<String> {
        childrenByParent[parentKey] ?? []
    }
}
