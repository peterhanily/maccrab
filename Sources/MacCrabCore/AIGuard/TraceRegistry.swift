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
        /// Bind time, refreshed to "now" on every successful lookup so it
        /// tracks last activity. The sliding TTL (`bindingTTL`) reads this to
        /// reclaim idle/likely-dead bindings whose NOTIFY_EXIT was dropped.
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

        /// Copy with a refreshed `boundAt`. Used by the sliding-TTL path so a
        /// live process that keeps emitting events (and thus keeps being
        /// looked up) never expires. Everything else is preserved.
        func refreshing(boundAt newBoundAt: Date) -> Binding {
            Binding(
                identity: identity,
                context: context,
                agentTool: agentTool,
                boundAt: newBoundAt
            )
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

    /// Sliding time-to-live for a binding, in seconds (rc.3 audit,
    /// corr-agent-traces). A binding whose `boundAt` — refreshed on every
    /// successful lookup, so it tracks last activity — is older than this is
    /// treated as absent and reclaimed.
    ///
    /// Why: NOTIFY_EXIT signals are best-effort. Under ES per-client
    /// backpressure an exit can be dropped, and without a TTL the dead
    /// process's binding lingered until cap eviction (up to `cap` entries
    /// later), wasting a slot and producing spurious `pidRecycleRejected`
    /// hits when the kernel reused the pid. The TTL is *sliding*: any event a
    /// live agent process emits refreshes its binding, so only genuinely-idle
    /// (typically dead) bindings expire — an over-eager reap only downgrades
    /// a still-live process's later events from `.traceparent` to `.lineage`
    /// confidence, never a mis-attribution. A value <= 0 disables the TTL
    /// (pre-audit behaviour).
    private let bindingTTL: TimeInterval

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

    /// Bindings reclaimed because their sliding TTL elapsed (idle/likely-dead
    /// process whose NOTIFY_EXIT was never observed). Surfaced via
    /// `metricsSnapshot()`.
    private var ttlEvictions: UInt64 = 0

    private let logger = Logger(subsystem: "com.maccrab.aiguard", category: "trace-registry")

    // MARK: - Nonisolated fast-path hint (rc.3 audit, corr-agent-traces)
    //
    // Race-tolerant mirror of `!bindings.isEmpty`, readable WITHOUT an actor
    // hop — the exact shape of `AIProcessTracker.hasActiveSessionsHint`. The
    // hot event loop can consult this before paying the actor hop for the
    // per-event direct-correlation lookup: when the registry is empty (no
    // process ever carried a TRACEPARENT — the majority of field installs),
    // the lookup can be skipped entirely. A stale read that lags `bindings`
    // by one event is harmless: the next event sees the updated flag.
    public nonisolated var hasBindingsHint: Bool {
        _hasBindingsFlag.withLock { $0 }
    }
    private let _hasBindingsFlag = OSAllocatedUnfairLock<Bool>(initialState: false)

    /// Update the nonisolated hint. Called by every method that mutates
    /// `bindings` (bind / evict / lazy-expire / sweep / cap-evict).
    private func refreshBindingsHint() {
        let nonEmpty = !bindings.isEmpty
        _hasBindingsFlag.withLock { $0 = nonEmpty }
    }

    public init(cap: Int = 4_096, maxAncestorHops: Int = 8, bindingTTL: TimeInterval = 3_600) {
        self.cap = max(64, cap)
        self.maxAncestorHops = max(1, maxAncestorHops)
        self.bindingTTL = bindingTTL
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
    public func bind(_ binding: Binding, now: Date = Date()) {
        evictIfNeeded(now: now)
        let pid = binding.identity.pid
        bindings[pid] = binding
        accessCounter &+= 1
        accessSeq[pid] = accessCounter
        refreshBindingsHint()
    }

    /// Direct lookup by full `ProcessIdentity`. Returns nil unless the
    /// stored binding's identity exactly matches (anti-pid-recycle).
    public func lookupDirect(identity: ProcessIdentity, now: Date = Date()) -> Binding? {
        guard let stored = bindings[identity.pid] else { return nil }
        // Sliding TTL: an expired binding is reclaimed and treated as absent,
        // regardless of identity match. This is NOT a recycle rejection.
        if isExpired(stored, now: now) {
            bindings.removeValue(forKey: identity.pid)
            accessSeq.removeValue(forKey: identity.pid)
            ttlEvictions &+= 1
            refreshBindingsHint()
            return nil
        }
        if stored.identity == identity {
            accessCounter &+= 1
            accessSeq[identity.pid] = accessCounter
            // Refresh the activity timestamp so a live process never expires.
            if bindingTTL > 0 {
                bindings[identity.pid] = stored.refreshing(boundAt: now)
            }
            return stored
        }
        // PID-recycle pin: the stored binding belongs to a different
        // process (different audit_token / pidversion / pathHash). We do
        // NOT auto-evict here — a later `bind()` for the new identity
        // will overwrite, or the cap-evict will reclaim. We only refuse
        // to attribute.
        //
        // rc.3 audit (corr-agent-traces, finding F): only count a rejection
        // when the QUERIED identity carries a real audit token
        // (`pidversion != 0`). The lineage ancestor resolvers and non-ES
        // event sources build a degraded identity with `pidversion == 0`,
        // which can NEVER equal a real stored token — so a mismatch there is
        // expected, not a recycle, and counting it systematically inflated
        // the metric on every AI-child event. Real macOS processes always
        // carry a non-zero pidversion.
        if identity.auditIdentity.pidversion != 0 {
            pidRecycleRejected &+= 1
        }
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
        ancestorIdentity: (ProcessAncestor) -> ProcessIdentity?,
        now: Date = Date()
    ) -> LookupResult? {
        if let direct = lookupDirect(identity: identity, now: now) {
            return LookupResult(binding: direct, hopCount: 0, matchedPid: identity.pid)
        }
        let hopLimit = min(maxAncestorHops, ancestors.count)
        for i in 0..<hopLimit {
            let ancestor = ancestors[i]
            guard let ancId = ancestorIdentity(ancestor) else { continue }
            guard let stored = bindings[ancId.pid] else { continue }
            // Sliding TTL: reclaim an expired ancestor binding and keep
            // walking (it is neither a hit nor a recycle rejection).
            if isExpired(stored, now: now) {
                bindings.removeValue(forKey: ancId.pid)
                accessSeq.removeValue(forKey: ancId.pid)
                ttlEvictions &+= 1
                refreshBindingsHint()
                continue
            }
            if stored.identity == ancId {
                accessCounter &+= 1
                accessSeq[ancId.pid] = accessCounter
                if bindingTTL > 0 {
                    bindings[ancId.pid] = stored.refreshing(boundAt: now)
                }
                return LookupResult(binding: stored, hopCount: i + 1, matchedPid: ancId.pid)
            } else if ancId.auditIdentity.pidversion != 0 {
                // Stale binding on the ancestor pid — same anti-recycle
                // contract as direct lookup. rc.3 audit (finding F): only
                // count when the ancestor identity carries a real audit
                // token; the production lineage resolvers build a zeroed
                // (`pidversion == 0`) identity, whose mismatch is expected
                // and must not inflate the recycle metric.
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
        refreshBindingsHint()
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
            capEvictions: capEvictions,
            ttlEvictions: ttlEvictions
        )
    }

    public struct Metrics: Sendable, Codable, Equatable {
        public let liveBindings: Int
        public let cap: Int
        public let pidRecycleRejected: UInt64
        public let capEvictions: UInt64
        public let ttlEvictions: UInt64
    }

    // MARK: - Internals

    /// Evict the lowest-seq entry if at cap. Mirrors `MCPAttributor`.
    /// O(n) walk over `accessSeq` per eviction; amortised cost is
    /// bounded by the eviction rate (rare in practice — most processes
    /// exit before the cap is hit, and `evict(pid:)` cleans up at exit).
    private func evictIfNeeded(now: Date = Date()) {
        guard bindings.count >= cap else { return }
        // rc.3 audit (corr-agent-traces): prefer reclaiming TTL-expired
        // (idle/likely-dead) bindings over LRU-evicting a possibly-live one.
        // Bounds the sweep's O(n) cost to cap-hit frequency (rare) rather
        // than paying it on every bind.
        if sweepExpired(now: now) > 0, bindings.count < cap { return }
        guard let victim = accessSeq.min(by: { $0.value < $1.value })?.key else { return }
        bindings.removeValue(forKey: victim)
        accessSeq.removeValue(forKey: victim)
        capEvictions &+= 1
        refreshBindingsHint()
    }

    /// Reclaim every binding whose sliding TTL has elapsed. Cheap O(n) walk.
    /// Run opportunistically from `evictIfNeeded` at the cap, and available
    /// as a public entry point for a periodic sweep timer. Returns the count
    /// reclaimed. No-op when the TTL is disabled or the registry is empty.
    @discardableResult
    public func sweepExpired(now: Date = Date()) -> Int {
        guard bindingTTL > 0, !bindings.isEmpty else { return 0 }
        let expired = bindings.compactMap { pid, binding in
            now.timeIntervalSince(binding.boundAt) > bindingTTL ? pid : nil
        }
        guard !expired.isEmpty else { return 0 }
        for pid in expired {
            bindings.removeValue(forKey: pid)
            accessSeq.removeValue(forKey: pid)
        }
        ttlEvictions &+= UInt64(expired.count)
        refreshBindingsHint()
        return expired.count
    }

    /// Whether a binding is past its sliding TTL relative to `now`.
    private func isExpired(_ binding: Binding, now: Date) -> Bool {
        bindingTTL > 0 && now.timeIntervalSince(binding.boundAt) > bindingTTL
    }
}
