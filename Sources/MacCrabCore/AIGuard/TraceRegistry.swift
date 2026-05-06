// TraceRegistry.swift
// MacCrabCore
//
// v1.9 Agent Traces (PR-2) — actor-protected pid → trace context map.
//
// Identity is `ProcessIdentity` (audit_token + path hash). Plain `pid_t`
// would be unsafe because the kernel recycles pids on busy machines and we
// must NEVER attribute a fresh process's actions to a dead binding.
//
// Bounding (Pass 8): cap defaults to 4096 entries. LRU eviction by
// `accessSeq` mirrors `MCPAttributor` and `RuleEngine.regexAccessSeq`. We
// allow that allocation pattern under Pass 8 because the cap and eviction
// are both explicit — same shape as the existing actors.

import Foundation
import os.log

public actor TraceRegistry {

    // MARK: - Public types

    /// What we record about a process whose env held a TRACEPARENT.
    ///
    /// The struct is intentionally narrow: only fields that survive the
    /// hardest review of "what does this leak?" and that are needed for
    /// later correlation. The TraceContext was already validated by
    /// `TraceExtractor.parseTraceparent`.
    public struct Binding: Sendable, Hashable {
        public let identity: ProcessIdentity
        public let context: TraceContext
        public let agentTool: AIToolType?
        public let boundAt: Date

        public init(
            identity: ProcessIdentity,
            context: TraceContext,
            agentTool: AIToolType?,
            boundAt: Date = Date()
        ) {
            self.identity = identity
            self.context = context
            self.agentTool = agentTool
            self.boundAt = boundAt
        }
    }

    /// The ancestor walk's outcome for `lookup(forPid:ancestors:)`.
    public struct LookupResult: Sendable {
        public let binding: Binding
        /// Hop distance: 0 = direct hit on the queried pid; 1 = parent; etc.
        public let hopCount: Int
        /// Pid of the ancestor that actually carried the binding (== queried
        /// pid when hopCount == 0).
        public let matchedPid: pid_t
    }

    // MARK: - Configuration

    /// Maximum live bindings. Cap chosen so the memory footprint stays in
    /// the same order as `MCPAttributor.cache` (5 000 entries). 4 096 is
    /// the largest power of two ≤ that — slightly cheaper Dictionary
    /// resize behaviour, and it leaves headroom for the cap floor.
    private let cap: Int

    /// Maximum hops walked when looking up via ancestors. Same fixed bound
    /// as MCPAttributor's ancestor walk — keeps the lookup path strictly
    /// O(1) in practice.
    private let maxAncestorHops: Int

    // MARK: - Storage (bounded — Pass 8)

    /// pid → Binding. Identity disambiguation happens at lookup time —
    /// the registry can hold a stale entry for a recycled pid until the
    /// next bind/evict touches it, but the lookup compares full
    /// `ProcessIdentity` and refuses any mismatch.
    private var bindings: [pid_t: Binding] = [:]

    /// LRU access counter map. Bumped on every hit (lookup) and
    /// insert (bind). Lowest-seq entry is evicted at the cap.
    private var accessSeq: [pid_t: UInt64] = [:]
    private var accessCounter: UInt64 = 0

    // MARK: - Telemetry counters

    /// Stale-identity rejections. The registry held a binding for a pid
    /// but the queried `ProcessIdentity` didn't match (typically a
    /// recycled pid or an executable path swap). Surfaced via
    /// `metricsSnapshot()` so a Pass 11 audit can verify the counter
    /// is non-zero on a properly-stressed test host.
    private var pidRecycleRejected: UInt64 = 0
    /// Cap evictions performed since boot. Useful for the dashboard
    /// status panel.
    private var capEvictions: UInt64 = 0

    private let logger = Logger(subsystem: "com.maccrab.aiguard", category: "trace-registry")

    public init(cap: Int = 4_096, maxAncestorHops: Int = 8) {
        self.cap = max(64, cap)
        self.maxAncestorHops = max(1, maxAncestorHops)
    }

    // MARK: - API

    /// Bind a `TraceContext` to a process identity. Called from
    /// `ESCollector` at NOTIFY_EXEC time when the env scan returned a
    /// valid TRACEPARENT.
    ///
    /// If a binding already exists for the same pid (typical: parent's
    /// binding was recorded, then the child execs and re-emits its
    /// inherited TRACEPARENT), the new binding replaces the old. The
    /// underlying ProcessIdentity is what matters for correctness; the
    /// pid is just the lookup key.
    public func bind(_ binding: Binding) {
        evictIfNeeded()
        let pid = binding.identity.pid
        bindings[pid] = binding
        accessCounter &+= 1
        accessSeq[pid] = accessCounter
    }

    /// Direct lookup by full `ProcessIdentity`. Returns nil unless the
    /// stored binding's identity exactly matches (anti-pid-recycle).
    public func lookupDirect(identity: ProcessIdentity) -> Binding? {
        guard let stored = bindings[identity.pid] else { return nil }
        if stored.identity == identity {
            accessCounter &+= 1
            accessSeq[identity.pid] = accessCounter
            return stored
        }
        // PID-recycle pin: the stored binding belongs to a different
        // process (different audit_token / pidversion / pathHash). We do
        // NOT auto-evict here — a later `bind()` for the new identity
        // will overwrite, or the cap-evict will reclaim. We only refuse
        // to attribute.
        pidRecycleRejected &+= 1
        return nil
    }

    /// Lookup with lineage fallback.
    ///
    /// 1. Try direct lookup on `identity`. Hit → return with `hopCount=0`.
    /// 2. For each ancestor pid (in order, parent → root), check if a
    ///    binding exists. If so AND the binding's identity matches the
    ///    ancestor's full `ProcessIdentity` (caller supplies via the
    ///    `ancestorIdentity` closure), return with `hopCount=N`.
    ///
    /// The second pass is bounded by `maxAncestorHops` — same shape as
    /// `MCPAttributor`'s walk.
    ///
    /// - Parameters:
    ///   - identity: full process identity for the firing event's pid
    ///   - ancestors: ancestor chain (parent first, root last)
    ///   - ancestorIdentity: closure that returns the ancestor's
    ///     ProcessIdentity if it can be resolved cheaply. Returning nil
    ///     causes that hop to be skipped — better than fabricating an
    ///     identity and risking a false-positive PID-recycle hit.
    public func lookup(
        forIdentity identity: ProcessIdentity,
        ancestors: [ProcessAncestor],
        ancestorIdentity: (ProcessAncestor) -> ProcessIdentity?
    ) -> LookupResult? {
        if let direct = lookupDirect(identity: identity) {
            return LookupResult(binding: direct, hopCount: 0, matchedPid: identity.pid)
        }
        let hopLimit = min(maxAncestorHops, ancestors.count)
        for i in 0..<hopLimit {
            let ancestor = ancestors[i]
            guard let ancId = ancestorIdentity(ancestor) else { continue }
            guard let stored = bindings[ancId.pid] else { continue }
            if stored.identity == ancId {
                accessCounter &+= 1
                accessSeq[ancId.pid] = accessCounter
                return LookupResult(binding: stored, hopCount: i + 1, matchedPid: ancId.pid)
            } else {
                // Stale binding on the ancestor pid — same anti-recycle
                // contract as direct lookup. Increment the counter so a
                // soak test surfaces real-world recycle volume.
                pidRecycleRejected &+= 1
            }
        }
        return nil
    }

    /// Explicit eviction on NOTIFY_EXIT. Optional — the cap eviction
    /// handles drift on its own — but cleaning up at exit time keeps
    /// the cap headroom available for newer processes.
    public func evict(pid: pid_t) {
        bindings.removeValue(forKey: pid)
        accessSeq.removeValue(forKey: pid)
    }

    /// Current binding count (for tests / metrics).
    public func count() -> Int { bindings.count }

    /// Snapshot of telemetry counters. Cheap; safe to surface in a
    /// status JSON without affecting hot-path behaviour.
    public func metricsSnapshot() -> Metrics {
        Metrics(
            liveBindings: bindings.count,
            cap: cap,
            pidRecycleRejected: pidRecycleRejected,
            capEvictions: capEvictions
        )
    }

    public struct Metrics: Sendable, Codable, Equatable {
        public let liveBindings: Int
        public let cap: Int
        public let pidRecycleRejected: UInt64
        public let capEvictions: UInt64
    }

    // MARK: - Internals

    /// Evict the lowest-seq entry if at cap. Mirrors `MCPAttributor`.
    /// O(n) walk over `accessSeq` per eviction; amortised cost is
    /// bounded by the eviction rate (rare in practice — most processes
    /// exit before the cap is hit, and `evict(pid:)` cleans up at exit).
    private func evictIfNeeded() {
        guard bindings.count >= cap else { return }
        guard let victim = accessSeq.min(by: { $0.value < $1.value })?.key else { return }
        bindings.removeValue(forKey: victim)
        accessSeq.removeValue(forKey: victim)
        capEvictions &+= 1
    }
}
