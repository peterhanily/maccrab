// EntityResolver.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6a) — converts normalised events into stable
// graph entities by applying the merge policy in §10.2 of the v1.10.0
// spec. Without explicit deduplication, the graph accretes duplicate
// ProcessNodes whenever a process is observed by both ESCollector and
// (e.g.) FSEventsCollector with slightly different metadata, and the
// explainer silently degrades.
//
// PR-6a scope: process entities only. Edge entity types
// (FileNode, NetworkNode, AIAgentNode, PersistenceNode, etc.) land in
// PR-7 alongside the entity + edge builders. The scaffolding here is
// intentionally process-focused so the §10.2 table can be tested in
// isolation before more entity types add merge cases of their own.

import Foundation
import os.log

/// Canonical resolved process entity in the graph.
public struct ResolvedProcessEntity: Sendable, Equatable {
    public let processKey: String
    public let identity: ProcessIdentity
    public let firstSeen: Date
    public var lastSeen: Date
    public var observationCount: Int

    public init(
        processKey: String,
        identity: ProcessIdentity,
        firstSeen: Date,
        lastSeen: Date,
        observationCount: Int
    ) {
        self.processKey = processKey
        self.identity = identity
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.observationCount = observationCount
    }
}

/// Outcome of `EntityResolver.merge()` per §10.2.
public enum EntityMergeOutcome: Sendable, Equatable {

    /// No prior observation for either the canonical key or the pid;
    /// a brand new entity was registered.
    case createdNew(processKey: String)

    /// The canonical key was already known; attributes were unioned and
    /// `observationCount` incremented. `lastSeen` advanced if the new
    /// observation timestamp was later.
    case mergedIntoExisting(processKey: String)

    /// A different `ProcessIdentity` previously held this pid; the new
    /// observation is treated as a separate entity (PID recycle). Both
    /// entities remain registered — the graph keeps the historical
    /// entity addressable while the new one becomes the canonical
    /// owner of the pid.
    case pidRecycle(oldProcessKey: String, newProcessKey: String)
}

/// Actor that maintains the canonical entity store the rolling causal
/// graph reads from.
public actor EntityResolver {

    // MARK: - Storage

    private var entitiesByKey: [String: ResolvedProcessEntity] = [:]

    /// pid → canonical processKey for the entity that currently owns
    /// that pid in the live window. Historical (recycled-out) entities
    /// remain in `entitiesByKey` but lose their pid index ownership.
    private var pidToCanonicalKey: [pid_t: String] = [:]

    // MARK: - Counters

    private var pidRecycleRejected: UInt64 = 0
    private var silentMerges: UInt64 = 0

    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "entity-resolver")

    public init() {}

    // MARK: - API

    /// Apply the §10.2 merge policy for a process observation.
    @discardableResult
    public func merge(identity: ProcessIdentity, observedAt: Date = Date()) -> EntityMergeOutcome {
        let key = identity.processKey

        // Case 1 / 4: same canonical key already known → merge attributes.
        if var existing = entitiesByKey[key] {
            existing.observationCount += 1
            if observedAt > existing.lastSeen { existing.lastSeen = observedAt }
            entitiesByKey[key] = existing
            silentMerges &+= 1
            // Refresh the pid index even if the canonical key didn't change;
            // a long-running entity keeps its pid ownership.
            pidToCanonicalKey[identity.pid] = key
            return .mergedIntoExisting(processKey: key)
        }

        // Case 3: same pid currently mapped to a different canonical key
        // → PID recycle. Register the new entity, transfer pid ownership.
        if let priorKey = pidToCanonicalKey[identity.pid], priorKey != key {
            pidRecycleRejected &+= 1
            entitiesByKey[key] = ResolvedProcessEntity(
                processKey: key,
                identity: identity,
                firstSeen: observedAt,
                lastSeen: observedAt,
                observationCount: 1
            )
            pidToCanonicalKey[identity.pid] = key
            logger.debug("pid recycle: pid=\(identity.pid, privacy: .public) old_key=\(priorKey, privacy: .public) new_key=\(key, privacy: .public)")
            return .pidRecycle(oldProcessKey: priorKey, newProcessKey: key)
        }

        // Case 4: new entity. Register and own the pid.
        entitiesByKey[key] = ResolvedProcessEntity(
            processKey: key,
            identity: identity,
            firstSeen: observedAt,
            lastSeen: observedAt,
            observationCount: 1
        )
        pidToCanonicalKey[identity.pid] = key
        return .createdNew(processKey: key)
    }

    /// Look up an entity by its canonical key.
    public func entity(forKey key: String) -> ResolvedProcessEntity? {
        entitiesByKey[key]
    }

    /// Look up the canonical key currently owning a pid.
    public func canonicalKey(forPid pid: pid_t) -> String? {
        pidToCanonicalKey[pid]
    }

    /// Drop the pid → canonical-key index entry on NOTIFY_EXIT. The
    /// entity itself is retained (it may still be referenced by edges
    /// or as ancestry in active traces) until explicit eviction by the
    /// rolling graph's memory budget.
    public func releasePidOwnership(pid: pid_t) {
        pidToCanonicalKey.removeValue(forKey: pid)
    }

    /// Remove an entity entirely (called by the rolling graph's eviction
    /// policy when the entity is outside the active window and not
    /// referenced by any rule, sequence, alert, or trace).
    public func evict(processKey: String) {
        guard let entity = entitiesByKey.removeValue(forKey: processKey) else { return }
        if pidToCanonicalKey[entity.identity.pid] == processKey {
            pidToCanonicalKey.removeValue(forKey: entity.identity.pid)
        }
    }

    public struct Metrics: Sendable, Codable, Equatable {
        public let entityCount: Int
        public let livePidCount: Int
        public let pidRecycleRejected: UInt64
        public let silentMerges: UInt64

        public init(
            entityCount: Int,
            livePidCount: Int,
            pidRecycleRejected: UInt64,
            silentMerges: UInt64
        ) {
            self.entityCount = entityCount
            self.livePidCount = livePidCount
            self.pidRecycleRejected = pidRecycleRejected
            self.silentMerges = silentMerges
        }
    }

    public func metrics() -> Metrics {
        Metrics(
            entityCount: entitiesByKey.count,
            livePidCount: pidToCanonicalKey.count,
            pidRecycleRejected: pidRecycleRejected,
            silentMerges: silentMerges
        )
    }
}
