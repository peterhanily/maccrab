// CandidateEdgeRingBufferTests.swift
// v1.10 TraceGraph (PR-7) — tests for the candidate-edge ring buffer
// per §6.3.2 of the spec.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: CandidateEdgeRingBuffer")
struct CandidateEdgeRingBufferTests {

    private func makeCandidate(
        priority: CandidateEdge.Priority,
        observedAt: Date = Date(timeIntervalSince1970: 1_700_000_000),
        relation: EdgeRelation = .read
    ) -> CandidateEdge {
        CandidateEdge(
            sourcePid: 100,
            targetEntityType: "file",
            targetStableKey: "h-\(observedAt.timeIntervalSince1970)",
            relation: relation,
            observedAt: observedAt,
            priority: priority
        )
    }

    @Test("Append within capacity preserves all entries")
    func appendUnderCapacity() {
        var buf = CandidateEdgeRingBuffer(capacity: 16)
        for _ in 0..<10 {
            buf.append(makeCandidate(priority: .low))
        }
        #expect(buf.count == 10)
    }

    @Test("Overflow drops the oldest LOW priority entry first")
    func overflowDropsLowFirst() {
        var buf = CandidateEdgeRingBuffer(capacity: 8)
        let baseTime = Date(timeIntervalSince1970: 1_700_000_000)

        // Fill with 4 LOW + 4 HIGH (mixed insertion order).
        for n in 0..<4 {
            buf.append(makeCandidate(priority: .low,
                observedAt: baseTime.addingTimeInterval(Double(n))))
        }
        for n in 0..<4 {
            buf.append(makeCandidate(priority: .high,
                observedAt: baseTime.addingTimeInterval(Double(10 + n))))
        }
        #expect(buf.count == 8)

        // One more entry triggers eviction. The oldest LOW should be dropped.
        buf.append(makeCandidate(priority: .high,
            observedAt: baseTime.addingTimeInterval(100)))
        #expect(buf.count == 8)

        // Verify: the LOW count dropped by 1, all HIGH retained.
        let lowCount = buf.entries.filter { $0.priority == .low }.count
        let highCount = buf.entries.filter { $0.priority == .high }.count
        #expect(lowCount == 3)
        #expect(highCount == 5)
    }

    @Test("All-HIGH overflow drops the oldest HIGH entry")
    func allHighOverflow() {
        var buf = CandidateEdgeRingBuffer(capacity: 8)
        let baseTime = Date(timeIntervalSince1970: 1_700_000_000)
        for n in 0..<10 {
            buf.append(makeCandidate(priority: .high,
                observedAt: baseTime.addingTimeInterval(Double(n))))
        }
        #expect(buf.count == 8)
        // Oldest two HIGHs (n=0,1) evicted; n=2..9 retained.
        let kept = buf.entries.map { $0.observedAt.timeIntervalSince1970 - 1_700_000_000 }.sorted()
        #expect(kept == [2, 3, 4, 5, 6, 7, 8, 9])
    }

    @Test("drain returns all entries and clears the buffer")
    func drainClears() {
        var buf = CandidateEdgeRingBuffer(capacity: 16)
        for _ in 0..<5 {
            buf.append(makeCandidate(priority: .low))
        }
        let drained = buf.drain()
        #expect(drained.count == 5)
        #expect(buf.count == 0)
    }

    @Test("dropOlderThan removes stale entries")
    func dropOlderRemoves() {
        var buf = CandidateEdgeRingBuffer(capacity: 16)
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let t1 = t0.addingTimeInterval(60)
        let t2 = t0.addingTimeInterval(120)

        buf.append(makeCandidate(priority: .low, observedAt: t0))
        buf.append(makeCandidate(priority: .low, observedAt: t1))
        buf.append(makeCandidate(priority: .low, observedAt: t2))

        buf.dropOlderThan(t1)   // drops t0 only

        let times = buf.entries.map { $0.observedAt }.sorted()
        #expect(times == [t1, t2])
    }

    @Test("Capacity is clamped to a sensible minimum")
    func capacityFloor() {
        let buf = CandidateEdgeRingBuffer(capacity: 1)
        #expect(buf.capacity >= 8)
    }
}
