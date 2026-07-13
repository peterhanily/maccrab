// ESSeqTracker.swift
// MacCrabCore
//
// v1.21.4 Phase-0 (D1 + D4) — kernel-drop accounting + hot-path gauges for
// the native Endpoint Security callback.
//
// # Why this exists (D1)
//
// Under a file-write flood the kernel applies per-client-queue backpressure
// and silently drops messages *before* delivery. MacCrab was blind to this by
// construction: the `es_new_client` callback read only `event_type` and never
// `seq_num`/`global_seq_num`, so `events_dropped` (a downstream AsyncStream
// eviction count) structurally could not see a kernel drop. The kernel assigns
// `seq_num` (per-client, per-event-type) and `global_seq_num` (per-client) to
// every message it *decides to deliver*; a hole in either sequence is a
// message the kernel dropped. This tracker turns those holes into honest
// per-type and global drop tallies at the callback boundary — the right
// instrument (DB-row presence is not, because it conflates a kernel ingest
// drop with the ~30× retention fast-eviction).
//
// # D4 gauges (same instance, one lock)
//
// The same object also carries the cheap leading-indicator gauges — per-type
// processed counts, a p99 handler-latency histogram, and the count of
// AsyncStream `yield` results that came back `.dropped` (userspace backlog).
// Rising latency / backlog precedes kernel drops, so these are D2's numeric
// input. Sharing ESSeqTracker means the hot callback pays exactly one lock,
// not two.
//
// # Concurrency
//
// The ES callback fires on a kernel-managed serial queue; readers are the 30 s
// heartbeat tick on the daemon executor. A single `NSLock` (mirroring
// `LockedCounter`) is enough — an actor would impose a hop the synchronous
// callback cannot afford. The hot paths (`record`, `recordProcessed`) are
// allocation-free once each event type has been seen once (in-place dictionary
// updates on existing keys + a fixed-size histogram array).

import Foundation

/// Thread-safe accountant for kernel `seq_num`/`global_seq_num` gaps (D1) plus
/// per-type processed counts, a handler-latency histogram, and stream-yield
/// backlog (D4). One `NSLock` guards all state; see file header.
public final class ESSeqTracker: @unchecked Sendable {
    private let lock = NSLock()

    // MARK: - D1 state (kernel-drop accounting)

    /// Last per-event-type `seq_num` seen. Absence of a key = not yet seeded.
    private var lastSeqByType: [UInt32: UInt64] = [:]
    /// Last `global_seq_num` seen; validity gated by `haveGlobalSeq` so a
    /// legitimate small first value is not miscounted as a gap.
    private var lastGlobalSeq: UInt64 = 0
    private var haveGlobalSeq = false
    /// Cumulative dropped-message tally per event type (per-type `seq_num` gaps).
    private var droppedByTypeMap: [UInt32: UInt64] = [:]
    /// Cumulative dropped-message tally across the whole client (`global_seq_num` gaps).
    private var globalDroppedCount: UInt64 = 0

    // MARK: - D4 state (gauges)

    /// Count of callback invocations per event type — the "seen at the callback"
    /// denominator the D1 flood test measures marker execs against.
    private var processedByTypeMap: [UInt32: UInt64] = [:]
    /// Yield results: `.dropped` (userspace backlog full → oldest evicted) vs
    /// everything else. Only counted when an event was actually yielded.
    private var yieldDroppedCount: UInt64 = 0
    private var yieldEnqueuedCount: UInt64 = 0

    /// Fixed handler-latency histogram (microseconds, upper-inclusive bounds).
    /// Allocated once; per-event we index in place, so the hot path never
    /// allocates. p99 is computed on read by walking the cumulative counts.
    private static let latencyBoundsMicros: [UInt64] =
        [1, 2, 4, 8, 16, 32, 64, 128, 256, 512,
         1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000, 256_000]
    /// One counter per bound plus a trailing overflow bucket.
    private var latencyBuckets: [UInt64]
    private var latencyTotalCount: UInt64 = 0

    public init() {
        latencyBuckets = [UInt64](repeating: 0, count: Self.latencyBoundsMicros.count + 1)
    }

    // MARK: - D1 record (hot path — before normalise)

    /// Feed one message's sequence numbers. On a gap (`cur > last + 1`) the
    /// hole size is added to the matching tally; `last` is always advanced.
    /// Seeds (no gap) on the first message of each type and on the first
    /// message after `reset()`.
    public func record(eventType: UInt32, seqNum: UInt64, globalSeq: UInt64) {
        lock.lock()
        defer { lock.unlock() }

        // Per-type seq_num.
        if let last = lastSeqByType[eventType] {
            if seqNum > last &+ 1 {
                droppedByTypeMap[eventType, default: 0] &+= seqNum &- last &- 1
            }
            lastSeqByType[eventType] = seqNum
        } else {
            lastSeqByType[eventType] = seqNum   // first-per-type seed
        }

        // Client-global global_seq_num.
        if haveGlobalSeq {
            if globalSeq > lastGlobalSeq &+ 1 {
                globalDroppedCount &+= globalSeq &- lastGlobalSeq &- 1
            }
            lastGlobalSeq = globalSeq
        } else {
            lastGlobalSeq = globalSeq            // first / first-after-reset seed
            haveGlobalSeq = true
        }
    }

    // MARK: - D4 record (hot path — after normalise + yield)

    /// Record the per-type processed count, the handler wall-time (nanoseconds,
    /// bucketed into microseconds), and the yield outcome. `yielded == false`
    /// (unhandled event type, no yield) contributes to the processed count and
    /// latency but not the yield tallies.
    public func recordProcessed(eventType: UInt32,
                                elapsedNanos: UInt64,
                                yielded: Bool,
                                yieldDropped: Bool) {
        lock.lock()
        defer { lock.unlock() }

        processedByTypeMap[eventType, default: 0] &+= 1
        recordLatencyLocked(micros: elapsedNanos / 1000)
        if yielded {
            if yieldDropped { yieldDroppedCount &+= 1 } else { yieldEnqueuedCount &+= 1 }
        }
    }

    /// Bucket one latency sample. Caller holds `lock`.
    private func recordLatencyLocked(micros: UInt64) {
        let bounds = Self.latencyBoundsMicros
        var idx = bounds.count   // overflow bucket
        var i = 0
        while i < bounds.count {
            if micros <= bounds[i] { idx = i; break }
            i &+= 1
        }
        latencyBuckets[idx] &+= 1
        latencyTotalCount &+= 1
    }

    // MARK: - Lifecycle

    /// Zero all state and drop every seed. Called on ES client (re)create: a
    /// new `es_client_t` restarts `seq_num`/`global_seq_num` at 0, so a fresh
    /// client must not be miscounted as a giant backward gap.
    public func reset() {
        lock.lock()
        defer { lock.unlock() }

        lastSeqByType.removeAll(keepingCapacity: true)
        lastGlobalSeq = 0
        haveGlobalSeq = false
        droppedByTypeMap.removeAll(keepingCapacity: true)
        globalDroppedCount = 0

        processedByTypeMap.removeAll(keepingCapacity: true)
        for i in 0..<latencyBuckets.count { latencyBuckets[i] = 0 }
        latencyTotalCount = 0
        yieldDroppedCount = 0
        yieldEnqueuedCount = 0
    }

    // MARK: - Accessors (heartbeat read path)

    /// Per-event-type kernel-drop tally (D1, per-type `seq_num` gaps).
    public func droppedByType() -> [UInt32: UInt64] {
        lock.lock()
        defer { lock.unlock() }
        return droppedByTypeMap
    }

    /// Whole-client kernel-drop tally (D1, `global_seq_num` gaps).
    public func globalDropped() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return globalDroppedCount
    }

    /// Per-event-type processed (seen-at-callback) counts (D4).
    public func processedByType() -> [UInt32: UInt64] {
        lock.lock()
        defer { lock.unlock() }
        return processedByTypeMap
    }

    /// p99-estimate of handler wall-time in microseconds (D4). Returns the
    /// upper bound of the bucket that first crosses the 99th percentile;
    /// 0 when no samples have been recorded.
    public func handlerP99Micros() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        guard latencyTotalCount > 0 else { return 0 }

        let bounds = Self.latencyBoundsMicros
        let target = ((latencyTotalCount &* 99) &+ 99) / 100   // ceil(0.99 · n)
        var cum: UInt64 = 0
        var i = 0
        while i < latencyBuckets.count {
            cum &+= latencyBuckets[i]
            if cum >= target {
                return i < bounds.count ? bounds[i] : bounds[bounds.count - 1]
            }
            i &+= 1
        }
        return bounds[bounds.count - 1]
    }

    /// Count of `yield` results that came back `.dropped` — userspace backlog
    /// evicted the oldest event (D4).
    public func yieldDroppedTotal() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return yieldDroppedCount
    }

    /// Count of `yield` results that were accepted (`.enqueued`) (D4).
    public func yieldEnqueuedTotal() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return yieldEnqueuedCount
    }
}
