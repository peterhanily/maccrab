// CandidateEdge.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-7) — bounded ring buffer of pre-enrichment
// edge observations carried alongside each ProcessSkeleton per
// §6.3.2 of the v1.10.0 spec.
//
// The skeleton-then-enrich pattern would otherwise lose evidence:
// a process that wasn't interesting at exec time but later turned
// out to be AI-attributed needs its early file/network/persistence
// touches reconstructed. The candidate buffer captures those touches
// as they happen; when the skeleton becomes enriched, candidates
// are materialized into real graph edges.
//
// Buffer overflow priority (§6.3.2):
//   1. Sensitive-path / persistence / AI-associated / rule-referenced
//      candidates are RETAINED.
//   2. Generic file operations are dropped first.

import Foundation

/// A single pre-enrichment edge observation. Lighter-weight than
/// `TraceEdge` — no canonical id, no canonical entity ids, just
/// enough to reconstruct the edge later when the target entity is
/// resolved.
public struct CandidateEdge: Sendable, Codable, Equatable {

    /// Pid of the process the buffer is attached to (the source side).
    public let sourcePid: Int32

    /// Type tag of the target. The target's stable key is enough
    /// information to look it up at materialization time.
    public let targetEntityType: String
    public let targetStableKey: String

    public let relation: EdgeRelation
    public let observedAt: Date

    /// Coarse priority used by the eviction policy. Sensitive +
    /// persistence + AI + rule-referenced candidates are HIGH;
    /// generic file ops are LOW.
    public let priority: Priority

    /// Original event id backing this candidate, if available.
    public let eventId: String?

    /// Type-specific evidence as JSON. Kept small; the full evidence
    /// payload lives on the materialized TraceEdge.
    public let evidenceJson: String

    public enum Priority: String, Sendable, Codable, Equatable {
        case high   // never dropped under normal pressure
        case low    // dropped first under buffer overflow
    }

    public init(
        sourcePid: Int32,
        targetEntityType: String,
        targetStableKey: String,
        relation: EdgeRelation,
        observedAt: Date,
        priority: Priority,
        eventId: String? = nil,
        evidenceJson: String = "{}"
    ) {
        self.sourcePid = sourcePid
        self.targetEntityType = targetEntityType
        self.targetStableKey = targetStableKey
        self.relation = relation
        self.observedAt = observedAt
        self.priority = priority
        self.eventId = eventId
        self.evidenceJson = evidenceJson
    }
}

/// Bounded ring buffer of candidate edges with priority-aware eviction.
public struct CandidateEdgeRingBuffer: Sendable {

    public private(set) var entries: [CandidateEdge] = []
    public let capacity: Int

    public init(capacity: Int = 64) {
        self.capacity = max(8, capacity)
    }

    public mutating func append(_ candidate: CandidateEdge) {
        entries.append(candidate)
        if entries.count > capacity {
            evictOnce()
        }
    }

    /// Drop one entry to make room. Prefer the oldest LOW priority
    /// entry; if no LOW entries exist, drop the oldest HIGH (this
    /// indicates real overflow — the rolling graph should already
    /// have promoted to compact persistent storage by then).
    private mutating func evictOnce() {
        if let idx = entries.firstIndex(where: { $0.priority == .low }) {
            entries.remove(at: idx)
            return
        }
        if !entries.isEmpty {
            entries.removeFirst()
        }
    }

    public var count: Int { entries.count }

    public mutating func drain() -> [CandidateEdge] {
        let drained = entries
        entries.removeAll(keepingCapacity: true)
        return drained
    }

    /// Drop entries older than the given cutoff. Used by the rolling
    /// graph's window-based decay.
    public mutating func dropOlderThan(_ cutoff: Date) {
        entries.removeAll { $0.observedAt < cutoff }
    }
}
