// HeavyEnrichmentSplitRefusalTests.swift
//
// v1.21.6-rc.45: the engine-killing force-unwrap on the heavy-enrichment
// timeout path, and the budget refusal that fed it.
//
// WHAT THIS PINS (measured on installed hosts, 2026-08-23 -> 2026-08-30):
// 16 crash reports, byte-identical every time, across BOTH rc.43 and rc.44
// (which differ by a Python-only commit, so they share one binary layout):
//
//   EXC_BREAKPOINT (SIGTRAP), codes 0x1
//   queue com.apple.root.utility-qos.cooperative
//   imageOffsets 8087988 8085524 8082616 8152461 ... libswift_Concurrency
//                completeTaskWithClosure
//
// Resolved by disassembly, not by nearest-symbol guessing: the trap PC
// 0x1007b69b4 is the 4th of four `brk #0x1` in one trap block, and exactly one
// branch in the entire binary targets it — `cbz x0, 0x1007b69b4`, immediately
// after a call to `EventPipelineMemoryLease.split(bytes:owner:)` with owner
// case 3 (`.heavyResult`). That is
// `HeavyEnrichmentPlane.terminalize(...)`'s `split(...)!`, reached from
// `scheduleDeadline`'s detached utility task -> `deadlineFired(workID:)` ->
// `terminalize(outcome: .timedOut, retainLingeringReservation: true)`.
//
// WHY split REFUSED — the actual defect. `split` divides credit that is already
// admitted; it decrements the source owner and increments the target by the same
// amount, so `currentBytes` is unchanged. But it applied the GROWTH gate anyway:
//
//     currentBytes > maximumAggregateBytes(for: owner)
//
// `maximumAggregateBytes(.heavyResult)` is `maximumBytes - forwardProgressReserveBytes`,
// and the clause compared GLOBAL currentBytes against it — so once total pipeline
// usage crossed the forward-progress line, EVERY heavy-result split failed
// regardless of how little `.heavyResult` actually held. With
// `operationTimeoutSeconds` at 50 ms over code-signing and hashing work, the
// timeout path is hot, so pressure and the crash path coincide by construction.
//
// This is the same class as the storage reclaim gate fixed in the same release:
// an admission check applied to an operation that relieves, rather than causes,
// the pressure it guards.
//
// FAIL-WITHOUT / PASS-WITH: restore the `|| currentBytes > maximumAggregateBytes(for: owner)`
// clause in EventPipelineLiveMemoryBudget.split and
// `splitSucceedsWhileTheEnvelopeIsUnderForwardProgressPressure` fails.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Heavy-enrichment split refusal (v1.21.6-rc.45)")
struct HeavyEnrichmentSplitRefusalTests {

    /// The exact shape of the crash: the pipeline is holding more than
    /// `maximumBytes - forwardProgressReserveBytes`, and a timed-out operation
    /// tries to carve a small terminal marker out of credit it ALREADY owns.
    /// That must succeed — it consumes no new credit.
    @Test("split succeeds while the envelope is under forward-progress pressure")
    func splitSucceedsWhileTheEnvelopeIsUnderForwardProgressPressure() {
        // maximumAggregateBytes(.heavyResult) == maximumBytes - forwardProgressReserveBytes
        //                                     == 1_000_000 - 300_000 == 700_000.
        // Only .eventStoreWorkspace and .journalPrepared can carry the envelope
        // ABOVE that line, which is exactly the real production shape: storage
        // and journal ownership push global usage past the forward-progress
        // reserve while a heavy-enrichment operation is still in flight.
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 1_000_000,
            forwardProgressReserveBytes: 300_000,
            eventStoreWorkspaceReserveBytes: 300_000
        )

        // The already-admitted heavy-enrichment operation reservation.
        let operationLease = budget.tryAcquire(bytes: 4_096, owner: .heavyResult)
        #expect(operationLease != nil, "fixture must own an operation reservation")

        let storage = budget.tryAcquire(bytes: 300_000, owner: .eventStoreWorkspace)
        #expect(storage != nil, "fixture: storage ownership")
        let journal = budget.tryAcquire(bytes: 400_000, owner: .journalPrepared)
        #expect(journal != nil, "fixture: journal ownership")

        let before = budget.snapshot().currentBytes
        #expect(
            before > 700_000,
            "fixture must drive global usage ABOVE maximumAggregateBytes(.heavyResult) (was \(before))"
        )

        // The terminal marker carve-out: small, and strictly inside credit the
        // caller already holds.
        let carved = operationLease?.split(bytes: 512, owner: .heavyResult)
        #expect(
            carved != nil,
            "split divides credit already granted and cannot grow the envelope; refusing it under ambient pressure is what crashed installed hosts 16 times"
        )

        // The invariant that makes removing the growth gate safe.
        #expect(
            budget.snapshot().currentBytes == before,
            "split must leave the aggregate byte count unchanged"
        )

        withExtendedLifetime(operationLease) {}
        withExtendedLifetime(storage) {}
        withExtendedLifetime(journal) {}
        withExtendedLifetime(carved) {}
    }

    /// The conservation invariant `split` must still enforce: it may never hand
    /// out more than the source reservation holds.
    @Test("split still refuses to over-draw its source reservation")
    func splitStillRefusesToOverdrawItsSource() {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 1_000_000,
            forwardProgressReserveBytes: 200_000
        )
        let lease = budget.tryAcquire(bytes: 4_096, owner: .heavyResult)
        #expect(lease != nil)
        #expect(
            lease?.split(bytes: 8_192, owner: .heavyResult) == nil,
            "a split larger than the source reservation must still be refused"
        )
        #expect(lease?.split(bytes: 0, owner: .heavyResult) == nil)
        withExtendedLifetime(lease) {}
    }

    /// And the caller must survive a refusal rather than trapping. This drives
    /// the real refusal condition (over-draw) through a lease and confirms the
    /// caller-side contract: a nil split is a value to handle, not an
    /// impossible state. Before rc.45 the sole production caller wrote `!`.
    @Test("a refused split is an ordinary nil, not an impossible state")
    func aRefusedSplitIsAnOrdinaryNil() {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: 1_000_000,
            forwardProgressReserveBytes: 200_000
        )
        guard let lease = budget.tryAcquire(bytes: 1_024, owner: .heavyResult) else {
            Issue.record("fixture reservation failed")
            return
        }
        // Exactly the caller's fallback: on nil, keep using the existing lease
        // rather than carving a new one. No trap, no resize, no lost marker.
        let carved = lease.split(bytes: 4_096, owner: .heavyResult)
        let markerLease = carved ?? lease
        #expect(carved == nil, "this fixture must actually exercise the refusal")
        #expect(
            markerLease === lease,
            "the refusal path must fall back to the shared reservation"
        )
        withExtendedLifetime(lease) {}
    }

    /// END TO END, through the real plane, on the exact production shape.
    ///
    /// `HeavyEnrichmentPlaneTests.stalledWorkerStaysCharged` ALREADY walks this
    /// code path — a stalled worker that ignores cancellation, timing out into
    /// `terminalize(retainLingeringReservation: true)`. It never caught the
    /// crash because it builds a FRESH, EMPTY budget, so `currentBytes` sits far
    /// below the `.heavyResult` aggregate line and the gate never fires. That
    /// gap is the whole reason a defect that killed installed hosts 16 times
    /// survived a 4,300-test suite.
    ///
    /// This is the same scenario with the envelope actually under pressure —
    /// measured live on the crashing host: currentBytes 66,963,563 against a
    /// `.heavyResult` aggregate cap of 45,211,648, while `.heavyResult` itself
    /// held 1,848 bytes. Before the fix this traps and takes the process down.
    @Test("a stalled worker times out safely while the envelope is under pressure")
    func stalledWorkerTimesOutSafelyUnderEnvelopePressure() async {
        let budget = EventPipelineLiveMemoryBudget(
            maximumBytes: EventPipelineLiveMemoryBudget.productionMaximumBytes,
            forwardProgressReserveBytes: EventPipelineLiveMemoryBudget
                .productionForwardProgressReserveBytes,
            eventStoreWorkspaceReserveBytes: EventPipelineLiveMemoryBudget
                .productionEventStoreWorkspaceReserveBytes,
            compactReceiptReserveBytes: EventPipelineLiveMemoryBudget
                .productionCompactReceiptReserveBytes
        )

        // NOTE ON ORDERING — this is the production sequence, and it matters.
        // `offer` acquires the subscriber reservation through `.heavyResult`,
        // which IS a growth operation and is correctly refused under pressure.
        // The crash happens to an operation admitted while there was headroom,
        // whose TIMEOUT then fires after the envelope has filled. So: admit
        // first, fill second, time out third.
        let heavyResultAggregateCap = EventPipelineLiveMemoryBudget
            .productionMaximumBytes
            - EventPipelineLiveMemoryBudget.productionForwardProgressReserveBytes

        let plane = HeavyEnrichmentPlane(
            configuration: .init(
                maximumConcurrentWorkers: 1,
                maximumQueuedWorkItems: 1,
                maximumOutstandingResults: 8,
                cacheCapacity: 0,
                operationTimeoutSeconds: 1.5
            ),
            liveMemoryBudget: budget
        )

        let gate = SplitRefusalGate()
        let event = Event(
            timestamp: Date(),
            eventCategory: .process, eventType: .start, eventAction: "exec",
            process: ProcessInfo(
                pid: 4242, ppid: 1, rpid: 1,
                name: "stall", executable: "/bin/stall", commandLine: "/bin/stall",
                args: [], workingDirectory: "/",
                userId: 501, userName: "", groupId: 20,
                startTime: Date(), ancestors: [], isPlatformBinary: false
            )
        )
        let binding = HeavyEnrichmentBinding(event: event)

        // A worker that ignores cancellation is what makes the plane RETAIN the
        // lingering reservation — the `retainLingeringReservation: true` branch
        // that carried the force-unwrap.
        let offer = await plane.offer(component: .userName, binding: binding) {
            await gate.runIgnoringCancellation()
            return .userName("stalled")
        }
        guard case .pending = offer else {
            Issue.record("offer should be accepted; got \(offer)")
            await gate.release()
            _ = await plane.shutdown()
            return
        }
        await gate.waitUntilEntered()

        // The operation is now admitted and running. Fill the envelope past the
        // `.heavyResult` aggregate line, so the deadline fires into exactly the
        // pressure that made `split` refuse on installed hosts.
        var ballast: [EventPipelineMemoryLease] = []
        if let storage = budget.tryAcquire(
            bytes: EventPipelineLiveMemoryBudget
                .productionEventStoreWorkspaceReserveBytes,
            owner: .eventStoreWorkspace
        ) { ballast.append(storage) }
        while budget.snapshot().currentBytes <= heavyResultAggregateCap {
            guard let chunk = budget.tryAcquire(
                bytes: 1_048_576, owner: .journalPrepared
            ) else { break }
            ballast.append(chunk)
        }
        let occupied = budget.snapshot().currentBytes
        #expect(
            occupied > heavyResultAggregateCap,
            "fixture must put the envelope above the .heavyResult aggregate line (\(occupied) vs \(heavyResultAggregateCap))"
        )

        var snapshot = await plane.snapshot()
        for _ in 0..<800 where snapshot.timedOutRequestsTotal == 0 {
            try? await Task.sleep(nanoseconds: 5_000_000)
            snapshot = await plane.snapshot()
        }

        // Reaching here at all is the primary assertion: before the fix the
        // timeout trapped the process instead of returning.
        #expect(
            snapshot.timedOutRequestsTotal == 1,
            "the stalled worker must time out (got \(snapshot.timedOutRequestsTotal))"
        )
        #expect(snapshot.requestsConserved)
        #expect(
            snapshot.lingeringReservationSplitRefusalsTotal == 0,
            "with the same-owner exemption the ordinary timeout path needs no fallback; a nonzero count here means the split is still being refused under pressure"
        )

        await gate.release()
        _ = await plane.shutdown()
        withExtendedLifetime(ballast) {}
    }
}

/// Lets a worker enter, ignore cancellation, and be released on demand — the
/// shape that makes the plane retain a lingering reservation.
private actor SplitRefusalGate {
    private var entered = false
    private var released = false

    func runIgnoringCancellation() async {
        entered = true
        while !released {
            try? await Task.sleep(nanoseconds: 2_000_000)
        }
    }

    func waitUntilEntered() async {
        while !entered {
            try? await Task.sleep(nanoseconds: 2_000_000)
        }
    }

    func release() { released = true }
}
