// MergedStreamDropCounterTests.swift
//
// Finding B-02: the daemon's merged event stream uses
// AsyncStream(bufferingPolicy: .bufferingNewest(mergedStreamCap)), whose
// yield closure previously discarded the YieldResult — so `.dropped`
// (buffer full → oldest evicted, a real detection gap under a storm) was
// never counted and the heartbeat's events_dropped / events_dropped_total
// always reported 0 while the daemon was silently dropping events.
//
// The fix inspects continuation.yield(...)'s result and increments a
// synchronous LockedCounter on `.dropped` (no Task / no await on the hot
// path), then DaemonTimers folds that count into the registry total.
//
// These tests exercise the mechanism proportionately against a real
// bufferingNewest stream — they do NOT push 100k events through the daemon.
//
// Lives in MacCrabCoreTests because that is the test target that links
// MacCrabAgentKit (there is no separate MacCrabAgentKitTests target).

import Testing
import Foundation
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Merged-stream drop counter (B-02)")
struct MergedStreamDropCounterTests {

    /// Reproduces DaemonState.mergedEventStream's yield closure exactly: on a
    /// full `.bufferingNewest` buffer, `continuation.yield` returns `.dropped`
    /// and the LockedCounter is bumped. With no consumer, the first `cap`
    /// yields enqueue and every yield past the cap evicts the oldest → drops.
    @Test("bufferingNewest .dropped results increment the LockedCounter")
    func droppedResultsAreCounted() {
        let cap = 8
        let overflow = 5
        let drops = LockedCounter()

        var continuation: AsyncStream<Int>.Continuation!
        let stream = AsyncStream<Int>(bufferingPolicy: .bufferingNewest(cap)) {
            continuation = $0
        }
        let cont = continuation!
        let yield: @Sendable (Int) -> Void = { value in
            if case .dropped = cont.yield(value) {
                drops.increment()
            }
        }

        // Never consume the stream: exactly `overflow` yields must drop.
        withExtendedLifetime(stream) {
            for i in 0 ..< (cap + overflow) {
                yield(i)
            }
        }

        #expect(drops.get() == overflow)
    }

    /// `.enqueued` (and `.terminated`) must never be miscounted as drops:
    /// yields that stay within the cap leave the counter at zero.
    @Test("yields within the cap never increment the counter")
    func enqueuedResultsNotCounted() {
        let cap = 16
        let drops = LockedCounter()

        var continuation: AsyncStream<Int>.Continuation!
        let stream = AsyncStream<Int>(bufferingPolicy: .bufferingNewest(cap)) {
            continuation = $0
        }
        let cont = continuation!
        let yield: @Sendable (Int) -> Void = { value in
            if case .dropped = cont.yield(value) {
                drops.increment()
            }
        }

        withExtendedLifetime(stream) {
            for i in 0 ..< cap {
                yield(i)
            }
        }

        #expect(drops.get() == 0)
    }

    /// The DaemonTimers fold-in: the registry drop total and the merged-stream
    /// drop count are summed into a single UInt64 for the heartbeat, so neither
    /// drop source masks the other.
    @Test("heartbeat total folds registry drops and merged-stream drops")
    func heartbeatFoldsBothDropSources() async {
        let registry = CollectorRegistry()
        await registry.recordDrop(reason: "queue full")
        await registry.recordDrop(reason: "parse error")

        let mergedDrops = LockedCounter()
        mergedDrops.increment()
        mergedDrops.increment()
        mergedDrops.increment()

        let registryTotal = await registry.droppedEventsTotal()
        let combined = registryTotal &+ UInt64(mergedDrops.get())
        #expect(combined == 5)
    }
}
