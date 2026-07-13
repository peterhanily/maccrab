// ESSeqTrackerTests.swift
// MacCrabCoreTests
//
// v1.21.4 Phase-0 (D1 + D4). Deterministic unit coverage for ESSeqTracker:
//   • D1 — per-type + global kernel-drop tallies from synthetic seq streams
//          with injected gaps; per-type isolation; reset-on-reconnect;
//          duplicate/out-of-order never underflowing.
//   • D4 — processed counts, yield outcome counts, and the p99 histogram math.
//
// The tracker keys are opaque UInt32s (es_event_type_t.rawValue in production);
// these tests use arbitrary distinct constants so they don't depend on the ES
// enum layout.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ESSeqTracker: D1 kernel-drop accounting")
struct ESSeqTrackerD1Tests {

    // Arbitrary, distinct opaque type keys.
    private let EXEC: UInt32 = 9
    private let WRITE: UInt32 = 12

    @Test("first message per type seeds without counting a drop")
    func firstMessageSeeds() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC, seqNum: 1, globalSeq: 1)
        #expect(t.droppedByType()[EXEC] == nil)
        #expect(t.globalDropped() == 0)
    }

    @Test("a contiguous per-type stream reports no drops")
    func contiguousNoDrops() {
        let t = ESSeqTracker()
        for s in UInt64(1)...UInt64(5) { t.record(eventType: EXEC, seqNum: s, globalSeq: s) }
        #expect((t.droppedByType()[EXEC] ?? 0) == 0)
        #expect(t.globalDropped() == 0)
    }

    @Test("a per-type hole is tallied exactly, global stays clean")
    func perTypeGap() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC, seqNum: 1, globalSeq: 1)
        t.record(eventType: EXEC, seqNum: 2, globalSeq: 2)
        // seq jumps 2 -> 5 (3,4 dropped) while global stays contiguous 2 -> 3.
        t.record(eventType: EXEC, seqNum: 5, globalSeq: 3)
        #expect(t.droppedByType()[EXEC] == 2)
        #expect(t.globalDropped() == 0)
    }

    @Test("a global hole is tallied exactly, per-type stays clean")
    func globalGap() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC, seqNum: 1, globalSeq: 1)
        // per-type contiguous 1 -> 2, but global jumps 1 -> 4 (2,3 dropped).
        t.record(eventType: EXEC, seqNum: 2, globalSeq: 4)
        #expect(t.globalDropped() == 2)
        #expect((t.droppedByType()[EXEC] ?? 0) == 0)
    }

    @Test("per-type drops are isolated across event types")
    func perTypeIsolation() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC,  seqNum: 1, globalSeq: 1)
        t.record(eventType: WRITE, seqNum: 1, globalSeq: 2)
        // EXEC hole (1 -> 3, one dropped); WRITE contiguous; global contiguous.
        t.record(eventType: EXEC,  seqNum: 3, globalSeq: 3)
        t.record(eventType: WRITE, seqNum: 2, globalSeq: 4)
        #expect(t.droppedByType()[EXEC] == 1)
        #expect((t.droppedByType()[WRITE] ?? 0) == 0)
        #expect(t.globalDropped() == 0)
    }

    @Test("duplicate or out-of-order arrivals never underflow to a huge count")
    func noUnderflow() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC, seqNum: 5, globalSeq: 5)
        t.record(eventType: EXEC, seqNum: 5, globalSeq: 6) // duplicate seq
        t.record(eventType: EXEC, seqNum: 3, globalSeq: 7) // out-of-order (backward)
        #expect((t.droppedByType()[EXEC] ?? 0) == 0)
        #expect(t.globalDropped() == 0)
    }

    @Test("reset zeroes every tally and reseeds without a false drop")
    func resetReseeds() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC, seqNum: 1, globalSeq: 1)
        t.record(eventType: EXEC, seqNum: 10, globalSeq: 10) // big gaps both axes
        #expect((t.droppedByType()[EXEC] ?? 0) > 0)
        #expect(t.globalDropped() > 0)

        t.reset()
        #expect(t.droppedByType().isEmpty)
        #expect(t.globalDropped() == 0)

        // A fresh es_client_t restarts sequences at a low value — must reseed,
        // not count a giant backward gap.
        t.record(eventType: EXEC, seqNum: 1, globalSeq: 1)
        t.record(eventType: EXEC, seqNum: 2, globalSeq: 2)
        #expect((t.droppedByType()[EXEC] ?? 0) == 0)
        #expect(t.globalDropped() == 0)
    }

    @Test("a client restart to a lower seq (no reset) self-heals, never false-counts")
    func restartWithoutResetSelfHeals() {
        let t = ESSeqTracker()
        t.record(eventType: EXEC, seqNum: 100, globalSeq: 100) // seed high
        // New client (we forgot to reset) restarts at 1 — `cur > last+1` is
        // false, so no drop is counted; last self-heals downward.
        t.record(eventType: EXEC, seqNum: 1, globalSeq: 1)
        t.record(eventType: EXEC, seqNum: 2, globalSeq: 2)
        #expect((t.droppedByType()[EXEC] ?? 0) == 0)
        #expect(t.globalDropped() == 0)
    }
}

@Suite("ESSeqTracker: D4 gauges")
struct ESSeqTrackerD4Tests {

    private let EXEC: UInt32 = 9
    private let WRITE: UInt32 = 12

    @Test("processed counts increment per event type regardless of yield")
    func processedCounts() {
        let t = ESSeqTracker()
        t.recordProcessed(eventType: EXEC,  elapsedNanos: 1_000, yielded: true,  yieldDropped: false)
        t.recordProcessed(eventType: EXEC,  elapsedNanos: 1_000, yielded: false, yieldDropped: false)
        t.recordProcessed(eventType: WRITE, elapsedNanos: 1_000, yielded: true,  yieldDropped: true)
        #expect(t.processedByType()[EXEC] == 2)
        #expect(t.processedByType()[WRITE] == 1)
    }

    @Test("yield outcome counts split dropped vs enqueued; unyielded counts neither")
    func yieldCounts() {
        let t = ESSeqTracker()
        t.recordProcessed(eventType: EXEC, elapsedNanos: 1_000, yielded: true,  yieldDropped: false) // enqueued
        t.recordProcessed(eventType: EXEC, elapsedNanos: 1_000, yielded: true,  yieldDropped: true)  // dropped
        t.recordProcessed(eventType: EXEC, elapsedNanos: 1_000, yielded: true,  yieldDropped: true)  // dropped
        t.recordProcessed(eventType: EXEC, elapsedNanos: 1_000, yielded: false, yieldDropped: false) // no yield
        #expect(t.yieldDroppedTotal() == 2)
        #expect(t.yieldEnqueuedTotal() == 1)
    }

    @Test("p99 is 0 with no samples")
    func p99Empty() {
        let t = ESSeqTracker()
        #expect(t.handlerP99Micros() == 0)
    }

    @Test("p99 lands in the correct bucket: 99×5us + 1×100ms -> 8us bound")
    func p99Bucket() {
        let t = ESSeqTracker()
        for _ in 0..<99 {
            t.recordProcessed(eventType: EXEC, elapsedNanos: 5_000, yielded: true, yieldDropped: false) // 5us
        }
        t.recordProcessed(eventType: EXEC, elapsedNanos: 100_000_000, yielded: true, yieldDropped: false) // 100ms outlier
        // n=100, ceil(0.99*100)=99; the 99th sample sits in the <=8us bucket.
        #expect(t.handlerP99Micros() == 8)
    }

    @Test("p99 tracks a uniform sample set to its bucket bound")
    func p99Uniform() {
        let t = ESSeqTracker()
        for _ in 0..<10 {
            t.recordProcessed(eventType: EXEC, elapsedNanos: 3_000, yielded: true, yieldDropped: false) // 3us -> <=4us
        }
        #expect(t.handlerP99Micros() == 4)
    }

    @Test("a p99 in the overflow bucket reports the top finite bound")
    func p99Overflow() {
        let t = ESSeqTracker()
        // 1s handler time -> far past the 256_000us top bound -> overflow bucket.
        t.recordProcessed(eventType: EXEC, elapsedNanos: 1_000_000_000, yielded: true, yieldDropped: false)
        #expect(t.handlerP99Micros() == 256_000)
    }

    @Test("reset clears the gauges too")
    func resetClearsGauges() {
        let t = ESSeqTracker()
        t.recordProcessed(eventType: EXEC, elapsedNanos: 5_000, yielded: true, yieldDropped: true)
        #expect(t.processedByType()[EXEC] == 1)
        #expect(t.yieldDroppedTotal() == 1)
        #expect(t.handlerP99Micros() > 0)

        t.reset()
        #expect(t.processedByType().isEmpty)
        #expect(t.yieldDroppedTotal() == 0)
        #expect(t.yieldEnqueuedTotal() == 0)
        #expect(t.handlerP99Micros() == 0)
    }
}
