// ESMessageWorkerTests.swift
// MacCrabCoreTests
//
// v1.21.4 Phase-3 (Mitigation B — async ES handler). Deterministic unit
// coverage for ESMessageWorker, the bounded off-thread worker that owns each
// retained es_message_t between the ES callback boundary and normalise/yield.
//
// The whole risk of the async-handler change is MESSAGE-LIFETIME correctness, so
// these tests pin the three invariants the worker exists to guarantee — WITHOUT
// synthesizing a real es_message_t (the live es_retain/es_release path is
// on-device only). The worker treats each handle as an opaque token; here the
// tokens are arbitrary non-null pointers and the injected `free` closure records
// which tokens were freed and how many times:
//
//   1. every submitted handle is freed EXACTLY ONCE (no leak, no double-free);
//   2. over-bound submissions are DROPPED, FREED, and COUNTED (backpressure);
//   3. shutdown DRAINS all in-flight handles, freeing each exactly once.
//
// Backpressure/race tests are semaphore-driven. Only the idle-wakeup test polls
// the observable zero-in-flight boundary, with a bounded deadline.

import Testing
import Foundation
import EndpointSecurity
@testable import MacCrabCore

/// Thread-safe tally of `process`/`free` calls, keyed by the opaque handle. Both
/// closures fire from multiple threads (the worker's serial queue for accepted
/// items, the calling thread for inline drops/shutdown), so it locks like the
/// production primitives.
private final class HandleRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var freed: [UnsafeRawPointer: Int] = [:]
    private var processed: [UnsafeRawPointer: Int] = [:]
    private var order: [UnsafeRawPointer] = []

    func recordProcess(_ h: UnsafeRawPointer) {
        lock.lock(); processed[h, default: 0] += 1; order.append(h); lock.unlock()
    }
    func recordFree(_ h: UnsafeRawPointer) {
        lock.lock(); freed[h, default: 0] += 1; lock.unlock()
    }
    func freeCount(_ h: UnsafeRawPointer) -> Int {
        lock.lock(); defer { lock.unlock() }; return freed[h] ?? 0
    }
    func totalFrees() -> Int {
        lock.lock(); defer { lock.unlock() }; return freed.values.reduce(0, +)
    }
    func distinctFreed() -> Int {
        lock.lock(); defer { lock.unlock() }; return freed.keys.count
    }
    /// Largest free-count for any single handle — must never exceed 1 (a value
    /// of 2 would be a double-free, which crashes the ES client in production).
    func maxFreeCount() -> Int {
        lock.lock(); defer { lock.unlock() }; return freed.values.max() ?? 0
    }
    func processOrder() -> [UnsafeRawPointer] {
        lock.lock(); defer { lock.unlock() }; return order
    }
}

private final class WorkerTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 100

    func now() -> UInt64 {
        lock.lock(); defer { lock.unlock() }; return value
    }
    func set(_ next: UInt64) {
        lock.lock(); value = next; lock.unlock()
    }
}

/// Build `n` distinct, non-null opaque handles. The worker never dereferences
/// them, so arbitrary bit-patterns are safe stand-ins for retained messages.
private func handles(_ range: ClosedRange<Int>) -> [UnsafeRawPointer] {
    range.map { UnsafeRawPointer(bitPattern: $0)! }
}

@Suite("ESMessageWorker: free-exactly-once + bounded backpressure")
struct ESMessageWorkerTests {

    @Test("every submitted handle is freed exactly once (no leak, no double-free)")
    func freeExactlyOnce() {
        let rec = HandleRecorder()
        let worker = ESMessageWorker(
            maxInFlight: 1024,
            process: { rec.recordProcess($0) },
            free: { rec.recordFree($0) }
        )
        let n = 200
        let hs = handles(1...n)
        for h in hs { worker.submit(h) }
        worker.shutdownAndDrain()   // barrier: every enqueued block has run + freed

        #expect(rec.distinctFreed() == n)     // all freed
        #expect(rec.totalFrees() == n)        // exactly n frees
        #expect(rec.maxFreeCount() == 1)      // none freed twice
        #expect(worker.backpressureDropped() == 0)
        #expect(worker.inFlightCount() == 0)
    }

    @Test("over-bound submissions are dropped, freed, and counted")
    func boundEnforced() {
        let rec = HandleRecorder()
        // Gate `process` so accepted items STAY in-flight (never complete, never
        // decrement inFlight) until we release them — makes the bound test fully
        // deterministic without any sleep.
        let gate = DispatchSemaphore(value: 0)
        let bound = 8
        let worker = ESMessageWorker(
            maxInFlight: bound,
            process: { h in rec.recordProcess(h); gate.wait() },
            free: { rec.recordFree($0) }
        )

        // Fill exactly to the cap. inFlight is incremented synchronously in
        // `submit`, so after these calls inFlight == bound with nothing freed.
        let accepted = handles(1...bound)
        for h in accepted { worker.submit(h) }
        #expect(worker.inFlightCount() == bound)

        // Submit past the cap: each is dropped INLINE — freed + counted right now.
        let overflow = handles((bound + 1)...(bound + 12))
        for h in overflow { worker.submit(h) }
        #expect(worker.backpressureDropped() == 12)
        for h in overflow { #expect(rec.freeCount(h) == 1) }   // dropped ⇒ freed
        let full = worker.snapshot()
        #expect(full.offeredTotal == 20)
        #expect(full.acceptedTotal == 8)
        #expect(full.completedTotal == 0)
        #expect(full.capacityDroppedTotal == 12)
        #expect(full.inFlight == 8)
        #expect(full.inFlightHighWater == 8)
        #expect(full.offeredTotal == full.acceptedTotal + full.capacityDroppedTotal + full.shutdownRejectedTotal)
        #expect(full.acceptedTotal == full.completedTotal + UInt64(full.inFlight))

        // Release the gate; the 8 accepted now complete and are freed. Drain
        // blocks until they do.
        for _ in 0..<bound { gate.signal() }
        worker.shutdownAndDrain()

        for h in accepted { #expect(rec.freeCount(h) == 1) }
        #expect(rec.totalFrees() == bound + 12)   // every handle freed once
        #expect(rec.maxFreeCount() == 1)          // no double-free anywhere
        #expect(worker.inFlightCount() == 0)
        let drained = worker.snapshot()
        #expect(drained.completedTotal == 8)
        #expect(drained.inFlight == 0)
        #expect(drained.queued == 0)
    }

    @Test("shutdown drains and frees all in-flight handles")
    func drainFreesInFlight() {
        let rec = HandleRecorder()
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 64,
            process: { h in rec.recordProcess(h); gate.wait() },
            free: { rec.recordFree($0) }
        )
        let hs = handles(1...5)
        for h in hs { worker.submit(h) }

        // All 5 are genuinely in-flight and NONE freed yet — proving the worker
        // holds the retained message across the boundary rather than freeing
        // early. (free only runs after `process`, which is blocked on the gate.)
        #expect(worker.inFlightCount() == 5)
        #expect(rec.totalFrees() == 0)

        for _ in 0..<5 { gate.signal() }
        worker.shutdownAndDrain()

        #expect(rec.distinctFreed() == 5)   // drain freed every in-flight handle
        #expect(rec.totalFrees() == 5)
        #expect(rec.maxFreeCount() == 1)    // each exactly once
        #expect(worker.inFlightCount() == 0)
    }

    @Test("shutdownAndDrain is idempotent; post-shutdown submits free inline")
    func drainIdempotentAndPostShutdownFreesInline() {
        let rec = HandleRecorder()
        let worker = ESMessageWorker(
            maxInFlight: 8,
            process: { rec.recordProcess($0) },
            free: { rec.recordFree($0) }
        )
        worker.submit(handles(1...1)[0])
        worker.shutdownAndDrain()
        worker.shutdownAndDrain()   // second call must not hang or crash
        #expect(rec.totalFrees() == 1)

        // A submit after shutdown is freed inline (drain path), never enqueued.
        worker.submit(handles(2...2)[0])
        #expect(rec.totalFrees() == 2)
        #expect(rec.maxFreeCount() == 1)
    }

    @Test("maxInFlight is clamped to at least 1")
    func boundClampedToOne() {
        let rec = HandleRecorder()
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 0,   // invalid → clamped to 1
            process: { h in rec.recordProcess(h); gate.wait() },
            free: { rec.recordFree($0) }
        )
        worker.submit(handles(1...1)[0])          // accepted (cap == 1)
        #expect(worker.inFlightCount() == 1)
        worker.submit(handles(2...2)[0])          // over cap → dropped + freed + counted
        #expect(worker.backpressureDropped() == 1)
        #expect(rec.freeCount(handles(2...2)[0]) == 1)

        gate.signal()
        worker.shutdownAndDrain()
        #expect(rec.totalFrees() == 2)
        #expect(rec.maxFreeCount() == 1)
    }

    @Test("reservesLineageSlots:false lets non-critical traffic use the full budget")
    func lineageReserveDisabledUsesFullBudget() {
        let rec = HandleRecorder()
        // Gate `process` so accepted items STAY in-flight until released, exactly
        // like `boundEnforced` above — keeps the cap check deterministic.
        let gate = DispatchSemaphore(value: 0)
        let bound = 100
        let worker = ESMessageWorker(
            maxInFlight: bound,
            reservesLineageSlots: false,
            process: { h in rec.recordProcess(h); gate.wait() },
            free: { rec.recordFree($0) }
        )

        // With no reserve withheld, all 100 non-critical (e.g. FILE-client WRITE)
        // submissions fit in the full budget — none of the old 25% set-aside.
        let accepted = handles(1...bound)
        for h in accepted { worker.submit(h, lineageCritical: false) }
        #expect(worker.inFlightCount() == bound)
        #expect(worker.backpressureDropped() == 0)

        // The 101st is genuinely over the (undiminished) cap and is dropped.
        let overflowHandle = handles((bound + 1)...(bound + 1))[0]
        let overflowAccepted = worker.submit(overflowHandle, lineageCritical: false)
        #expect(overflowAccepted == false)
        #expect(worker.backpressureDropped() == 1)
        #expect(rec.freeCount(overflowHandle) == 1)

        for _ in 0..<bound { gate.signal() }
        worker.shutdownAndDrain()
        #expect(rec.totalFrees() == bound + 1)
        #expect(rec.maxFreeCount() == 1)
    }

    @Test("reservesLineageSlots:true (default) withholds a quarter of the budget from non-critical traffic")
    func lineageReserveDefaultWithholdsQuarter() {
        let rec = HandleRecorder()
        let gate = DispatchSemaphore(value: 0)
        let bound = 100
        // reservesLineageSlots omitted — pins the unchanged default (exec/unified
        // client) behavior as a regression guard against this fix accidentally
        // widening that admission too.
        let worker = ESMessageWorker(
            maxInFlight: bound,
            process: { h in rec.recordProcess(h); gate.wait() },
            free: { rec.recordFree($0) }
        )

        // lineageReserve = max(1, min(99, 25)) == 25, so non-critical admission
        // caps at 100 - 25 = 75.
        let attempted = handles(1...bound)
        var acceptedCount = 0
        for h in attempted {
            if worker.submit(h, lineageCritical: false) { acceptedCount += 1 }
        }
        #expect(acceptedCount == 75)
        #expect(worker.inFlightCount() == 75)
        #expect(worker.backpressureDropped() == 25)
        for h in attempted[75...] { #expect(rec.freeCount(h) == 1) }   // dropped ⇒ freed inline

        // A lineage-critical handle is still accepted even though non-critical
        // admission is already exhausted at inFlight == 75 — the withheld quarter
        // is reserved for exactly this case.
        let criticalHandle = handles((bound + 1)...(bound + 1))[0]
        let criticalAccepted = worker.submit(criticalHandle, lineageCritical: true)
        #expect(criticalAccepted == true)
        #expect(worker.inFlightCount() == 76)

        for _ in 0..<76 { gate.signal() }
        worker.shutdownAndDrain()
        #expect(rec.totalFrees() == bound + 1)   // 75 accepted + 25 dropped + 1 critical
        #expect(rec.maxFreeCount() == 1)
    }

    @Test("FIFO survives ring wraparound with one drain and exact completion accounting")
    func ringWraparoundPreservesFIFO() throws {
        let rec = HandleRecorder()
        let entered = DispatchSemaphore(value: 0)
        let permit = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 4,
            process: { h in rec.recordProcess(h); entered.signal(); permit.wait() },
            free: { rec.recordFree($0) }
        )
        defer {
            for _ in 0..<12 { permit.signal() }
            worker.shutdownAndDrain()
        }
        let hs = handles(1...12)
        for h in hs.prefix(4) { #expect(worker.submit(h)) }
        try #require(entered.wait(timeout: .now() + 5) == .success)
        // Keep the FIFO continuously busy. Starting the next process proves
        // its predecessor was freed and its admission slot is reusable.
        for h in hs.dropFirst(4) {
            permit.signal()
            try #require(entered.wait(timeout: .now() + 5) == .success)
            #expect(worker.submit(h))
            #expect(worker.inFlightCount() == 4)
        }
        for _ in 0..<4 { permit.signal() }
        worker.shutdownAndDrain()
        #expect(rec.processOrder() == hs)
        #expect(rec.totalFrees() == 12)
        #expect(rec.maxFreeCount() == 1)
        let snapshot = worker.snapshot()
        #expect(snapshot.capacity == 4)
        #expect(snapshot.inFlightHighWater == 4)
        #expect(snapshot.offeredTotal == 12)
        #expect(snapshot.acceptedTotal == 12)
        #expect(snapshot.completedTotal == 12)
        #expect(snapshot.capacityDroppedTotal == 0)
        #expect(snapshot.drainDispatchesTotal == 1)
        #expect(snapshot.inFlight == 0 && snapshot.queued == 0)
    }

    @Test("every idle-to-busy transition schedules a fresh drain without a lost wakeup")
    func idleWakeup() throws {
        let rec = HandleRecorder()
        let freed = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 1,
            process: { rec.recordProcess($0) },
            free: { rec.recordFree($0); freed.signal() }
        )
        defer { worker.shutdownAndDrain() }
        for h in handles(1...20) {
            try #require(worker.submit(h))
            try #require(freed.wait(timeout: .now() + 5) == .success)
            // free precedes accounting. Wait for the coherent idle state,
            // rather than treating entry into free as a finished drain.
            let deadline = DispatchTime.now().uptimeNanoseconds + 5_000_000_000
            while worker.inFlightCount() > 0 && DispatchTime.now().uptimeNanoseconds < deadline {
                Thread.sleep(forTimeInterval: 0.001)
            }
            try #require(worker.inFlightCount() == 0)
        }
        worker.shutdownAndDrain()
        #expect(rec.processOrder() == handles(1...20))
        #expect(rec.totalFrees() == 20)
        #expect(rec.maxFreeCount() == 1)
        #expect(worker.snapshot().drainDispatchesTotal == 20)
        #expect(worker.snapshot().completedTotal == 20)
    }

    @Test("shutdown racing with producers frees all offers exactly once and conserves counters")
    func shutdownRacesWithEnqueues() throws {
        let rec = HandleRecorder()
        let first = handles(1...1)[0]
        let entered = DispatchSemaphore(value: 0)
        let releaseFirst = DispatchSemaphore(value: 0)
        let start = DispatchSemaphore(value: 0)
        let producers = DispatchGroup()
        let stopped = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 16,
            process: { h in
                rec.recordProcess(h)
                if h == first { entered.signal(); releaseFirst.wait() }
            },
            free: { rec.recordFree($0) }
        )
        defer { releaseFirst.signal(); worker.shutdownAndDrain() }
        try #require(worker.submit(first))
        try #require(entered.wait(timeout: .now() + 5) == .success)
        for shard in 0..<2 {
            producers.enter()
            DispatchQueue.global().async {
                start.wait()
                for i in 0..<64 {
                    let h = UnsafeRawPointer(bitPattern: 2 + shard * 64 + i)!
                    worker.submit(h, lineageCritical: i.isMultiple(of: 2), eventType: UInt32(shard))
                }
                producers.leave()
            }
        }
        DispatchQueue.global().async {
            start.wait()
            worker.shutdownAndDrain()
            stopped.signal()
        }
        for _ in 0..<3 { start.signal() }
        let producersFinished = producers.wait(timeout: .now() + 5)
        releaseFirst.signal()
        try #require(producersFinished == .success)
        try #require(stopped.wait(timeout: .now() + 5) == .success)
        worker.shutdownAndDrain() // also pins idempotence after a racing stop
        #expect(!worker.submit(UnsafeRawPointer(bitPattern: 130)!))
        let snapshot = worker.snapshot()
        #expect(rec.totalFrees() == 130)
        #expect(rec.distinctFreed() == 130)
        #expect(rec.maxFreeCount() == 1)
        #expect(snapshot.offeredTotal == 130)
        #expect(snapshot.offeredTotal == snapshot.acceptedTotal + snapshot.capacityDroppedTotal + snapshot.shutdownRejectedTotal)
        #expect(snapshot.acceptedTotal == snapshot.completedTotal)
        #expect(snapshot.completedTotal == UInt64(rec.processOrder().count))
        #expect(snapshot.shutdownRejectedTotal >= 1)
        #expect(snapshot.inFlight == 0 && snapshot.queued == 0)
        #expect(snapshot.inFlightHighWater <= snapshot.capacity)
        #expect(worker.backpressureDroppedByEventType().values.reduce(0, +) == snapshot.capacityDroppedTotal)
    }

    @Test("queue wait, service and live ages use separate monotonic boundaries")
    func queueAndServiceTelemetry() throws {
        let clock = WorkerTestClock()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let first = handles(1...1)[0]
        let worker = ESMessageWorker(
            maxInFlight: 4,
            uptimeNanoseconds: { clock.now() },
            process: { h in
                if h == first { entered.signal(); release.wait() }
                else { clock.set(400) }
            },
            free: { _ in }
        )
        defer { release.signal(); worker.shutdownAndDrain() }
        try #require(worker.submit(first)) // enqueued and started at 100
        try #require(entered.wait(timeout: .now() + 5) == .success)
        clock.set(200)
        try #require(worker.submit(handles(2...2)[0]))
        clock.set(300)
        let busy = worker.snapshot()
        #expect(busy.inFlight == 2 && busy.queued == 1)
        #expect(busy.completedTotal == 0)
        #expect(busy.oldestQueuedAgeNanoseconds == 100)
        #expect(busy.currentServiceAgeNanoseconds == 200)
        #expect(busy.queueWaitNanosecondsTotal == 0)
        #expect(busy.serviceNanosecondsTotal == 0)
        release.signal() // first finishes at 300; second runs from 300 to 400
        worker.shutdownAndDrain()
        let finished = worker.snapshot()
        #expect(finished.completedTotal == 2)
        #expect(finished.queueWaitNanosecondsTotal == 100)
        #expect(finished.queueWaitNanosecondsMax == 100)
        #expect(finished.serviceNanosecondsTotal == 300)
        #expect(finished.serviceNanosecondsMax == 200)
        #expect(finished.oldestQueuedAgeNanoseconds == 0)
        #expect(finished.currentServiceAgeNanoseconds == 0)
        #expect(finished.inFlight == 0 && finished.queued == 0)
    }

    @Test("worker telemetry encodes the documented heartbeat keys without handles")
    func snapshotEncoding() throws {
        let worker = ESMessageWorker(maxInFlight: 8, process: { _ in }, free: { _ in })
        worker.shutdownAndDrain()
        let data = try JSONEncoder().encode(worker.snapshot())
        let json = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(json.keys) == Set([
            "capacity", "reserved_capacity", "offered_total", "accepted_total", "completed_total",
            "capacity_dropped_total", "shutdown_rejected_total", "in_flight", "queued",
            "in_flight_high_water", "drain_dispatches_total", "queue_wait_nanoseconds_total",
            "queue_wait_nanoseconds_max", "service_nanoseconds_total", "service_nanoseconds_max",
            "oldest_queued_age_nanoseconds", "current_service_age_nanoseconds",
        ]))
        let decoded = try JSONDecoder().decode(ESMessageWorker.Snapshot.self, from: data)
        #expect(decoded.capacity == 8)
        #expect(decoded.reservedCapacity == 2)
        #expect(decoded.offeredTotal == 0 && decoded.inFlight == 0)
    }
}

@Suite("ESMessageWorker top reserve")
struct ESMessageWorkerTopReserveTests {
    @Test("a write flood cannot take the top reserve; a protected message still gets in")
    func writeFloodLeavesTopReserve() {
        let freed = ManagedAtomicCounter()
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 64,
            uptimeNanoseconds: { DispatchTime.now().uptimeNanoseconds },
            process: { _ in gate.wait() },
            free: { _ in freed.increment() }
        )
        func handle() -> ESMessageWorker.Handle { UnsafeRawPointer(bitPattern: 0x1000)! }
        var ordinary = 0, writes = 0
        for _ in 0..<64 where worker.submit(handle(), lineageCritical: false) { ordinary += 1 }
        for _ in 0..<64 where worker.submit(handle(), lineageCritical: false, writeFamily: true) { writes += 1 }
        // lineageReserve 16, top 4: ordinary stops at 48, writes at 60.
        #expect(ordinary == 48)
        #expect(writes == 12)
        #expect(worker.submit(handle(), lineageCritical: true))
        for _ in 0..<70 { gate.signal() }
        worker.shutdownAndDrain()
    }

    @Test("a chmod +x flood submitted as the collector submits it leaves lineage its whole reserve")
    func setmodeFloodLeavesLineageReserve() {
        let setmode = ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue
        #expect(!ESCollector.usesWorkerTopReserve(eventType: setmode, protectedOpen: false, carriesLineage: true))
        #expect(!ESCollector.writeFamilyRawValues.contains(setmode))
        let freed = ManagedAtomicCounter()
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 64,
            uptimeNanoseconds: { DispatchTime.now().uptimeNanoseconds },
            process: { _ in gate.wait() },
            free: { _ in freed.increment() }
        )
        func handle() -> ESMessageWorker.Handle { UnsafeRawPointer(bitPattern: 0x1000)! }
        var chmods = 0, lineage = 0
        for _ in 0..<64 where worker.submit(
            handle(),
            lineageCritical: ESCollector.usesWorkerTopReserve(
                eventType: setmode, protectedOpen: false, carriesLineage: true
            ),
            writeFamily: ESCollector.writeFamilyRawValues.contains(setmode),
            eventType: setmode
        ) { chmods += 1 }
        for _ in 0..<64 where worker.submit(
            handle(), lineageCritical: true, eventType: ES_EVENT_TYPE_NOTIFY_EXEC.rawValue
        ) { lineage += 1 }
        #expect(chmods == 48)
        #expect(lineage == 16, "EXEC/FORK/EXIT keep the full quarter-cap reserve")
        for _ in 0..<70 { gate.signal() }
        worker.shutdownAndDrain()
    }
}

extension ESMessageWorkerTopReserveTests {
    @Test("a protected-OPEN flood leaves lineage the top slice on a worker that also carries it")
    func protectedOpenFloodLeavesLineageTopSlice() {
        let open = ES_EVENT_TYPE_NOTIFY_OPEN.rawValue
        // The split file client carries no lineage, so there a protected OPEN
        // keeps the top slice against a write flood.
        #expect(ESCollector.usesWorkerTopReserve(eventType: open, protectedOpen: true, carriesLineage: false))
        #expect(!ESCollector.usesWorkerTopReserve(eventType: open, protectedOpen: true, carriesLineage: true))
        #expect(!ESCollector.usesWorkerTopReserve(eventType: open, protectedOpen: false, carriesLineage: false))
        #expect(ESCollector.usesWriteFamilyReserve(eventType: open, protectedOpen: true))
        #expect(!ESCollector.usesWriteFamilyReserve(eventType: open, protectedOpen: false))
        #expect(!ESCollector.carriesLineage(
            ESCollector.fileClientTypes(subscribeFileOpen: true, subscribeIntrospection: true)))
        #expect(ESCollector.carriesLineage(
            ESCollector.execClientTypes(subscribeFileOpen: true, subscribeIntrospection: true)))
        #expect(ESCollector.carriesLineage(
            ESCollector.fullSubscription(subscribeFileOpen: true, subscribeIntrospection: true)),
                "the degraded single client carries lineage")
        let freed = ManagedAtomicCounter()
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 64,
            uptimeNanoseconds: { DispatchTime.now().uptimeNanoseconds },
            process: { _ in gate.wait() },
            free: { _ in freed.increment() }
        )
        func handle() -> ESMessageWorker.Handle { UnsafeRawPointer(bitPattern: 0x1000)! }
        var opens = 0, lineage = 0
        for _ in 0..<64 where worker.submit(
            handle(),
            lineageCritical: ESCollector.usesWorkerTopReserve(
                eventType: open, protectedOpen: true, carriesLineage: true
            ),
            writeFamily: ESCollector.usesWriteFamilyReserve(eventType: open, protectedOpen: true),
            eventType: open
        ) { opens += 1 }
        for _ in 0..<64 where worker.submit(
            handle(), lineageCritical: true, eventType: ES_EVENT_TYPE_NOTIFY_EXEC.rawValue
        ) { lineage += 1 }
        #expect(opens == 60, "a protected OPEN still uses the reserve below the top slice")
        #expect(lineage == 4, "EXEC/FORK/EXIT keep the top slice")
        for _ in 0..<70 { gate.signal() }
        worker.shutdownAndDrain()
    }
}

extension ESMessageWorkerTopReserveTests {
    @Test("a protected-OPEN flood on the file client holds one top-slice slot per process and leaves the write family its tier")
    func protectedOpenSliceIsPerProcess() {
        let open = ES_EVENT_TYPE_NOTIFY_OPEN.rawValue
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: 64,
            uptimeNanoseconds: { DispatchTime.now().uptimeNanoseconds },
            process: { _ in gate.wait() },
            free: { _ in }
        )
        func handle() -> ESMessageWorker.Handle { UnsafeRawPointer(bitPattern: 0x1000)! }
        let split = ESCollector.WorkerTierPolicy(subscribedTypes:
            ESCollector.fileClientTypes(subscribeFileOpen: true, subscribeIntrospection: true))
        let tier = split.tier(eventType: open, protectedOpen: true)
        func submitProtected(pid: pid_t) -> Bool {
            worker.submit(handle(), lineageCritical: tier.lineageCritical, writeFamily: tier.writeFamily,
                          protectedOpen: true, sourceProcessID: pid, eventType: open)
        }
        // lineageReserve 16, top slice 4, one slice slot per process: the
        // flood holds one slot, then rides the ordinary tier to 48.
        var flood = 0
        for _ in 0..<64 where submitProtected(pid: 1) { flood += 1 }
        #expect(flood == 48, "an open() loop takes one slice slot and the ordinary tier, not the write family's")
        #expect(submitProtected(pid: 2), "another process's protected OPEN takes its own slice slot")
        #expect(!submitProtected(pid: 2), "and no second one while the ordinary tier is full")
        var writes = 0
        for _ in 0..<64 where worker.submit(
            handle(), lineageCritical: false, writeFamily: true, eventType: ES_EVENT_TYPE_NOTIFY_WRITE.rawValue
        ) { writes += 1 }
        #expect(writes == 11, "the write family keeps its tier above the ordinary OPENs")
        #expect(submitProtected(pid: 3), "a third process still finds a slice slot above the writes")
        #expect(worker.protectedOpenInFlightCount() == 3)
        #expect(worker.protectedOpenSliceDemoted() == 64)
        for _ in 0..<80 { gate.signal() }
        worker.shutdownAndDrain()
        #expect(worker.protectedOpenInFlightCount() == 0, "completion releases every slice slot")
    }
}

extension ESMessageWorkerTopReserveTests {
    @Test("a client's subscription decides whether a protected OPEN may take the top slice")
    func tierPolicyFollowsTheSubscription() throws {
        let open = ES_EVENT_TYPE_NOTIFY_OPEN.rawValue
        let degraded = ESCollector.WorkerTierPolicy(subscribedTypes:
            ESCollector.fullSubscription(subscribeFileOpen: true, subscribeIntrospection: true))
        let split = ESCollector.WorkerTierPolicy(subscribedTypes:
            ESCollector.fileClientTypes(subscribeFileOpen: true, subscribeIntrospection: true))
        // The degraded single client: lineage keeps the top slice, and a
        // protected OPEN shares the write family's tier below it.
        #expect(!degraded.tier(eventType: open, protectedOpen: true).lineageCritical)
        #expect(degraded.tier(eventType: open, protectedOpen: true).writeFamily)
        for lineage in [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT] {
            #expect(degraded.tier(eventType: lineage.rawValue, protectedOpen: false).lineageCritical)
        }
        // The split file client carries no lineage, so a protected OPEN keeps
        // the top slice against a write flood; an ordinary one does not.
        #expect(split.tier(eventType: open, protectedOpen: true).lineageCritical)
        #expect(!split.tier(eventType: open, protectedOpen: false).lineageCritical)
        #expect(!split.tier(eventType: open, protectedOpen: false).writeFamily)
        // The collector hands each message over with its client's policy.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let collector = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabCore/Collectors/ESCollector.swift"), encoding: .utf8)
        let start = try #require(collector.range(of: "private func openClient(for context: ESClientContext)"))
        let end = try #require(collector.range(of: "context.client = newClient", range: start.upperBound..<collector.endIndex))
        let body = collector[start.upperBound..<end.lowerBound]
        #expect(body.contains("WorkerTierPolicy(subscribedTypes: context.subscribedTypes)"))
        #expect(body.contains("lineageCritical: tier.lineageCritical"))
        #expect(body.contains("writeFamily: tier.writeFamily"))
    }
}

private final class ManagedAtomicCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func increment() { lock.lock(); value += 1; lock.unlock() }
}
