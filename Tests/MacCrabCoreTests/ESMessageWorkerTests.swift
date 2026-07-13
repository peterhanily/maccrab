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
// All tests are gate-driven (DispatchSemaphore), not sleep-driven, so they are
// deterministic under parallel execution.

import Testing
import Foundation
@testable import MacCrabCore

/// Thread-safe tally of `process`/`free` calls, keyed by the opaque handle. Both
/// closures fire from multiple threads (the worker's serial queue for accepted
/// items, the calling thread for inline drops/shutdown), so it locks like the
/// production primitives.
private final class HandleRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var freed: [UnsafeRawPointer: Int] = [:]
    private var processed: [UnsafeRawPointer: Int] = [:]

    func recordProcess(_ h: UnsafeRawPointer) {
        lock.lock(); processed[h, default: 0] += 1; lock.unlock()
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

        // Release the gate; the 8 accepted now complete and are freed. Drain
        // blocks until they do.
        for _ in 0..<bound { gate.signal() }
        worker.shutdownAndDrain()

        for h in accepted { #expect(rec.freeCount(h) == 1) }
        #expect(rec.totalFrees() == bound + 12)   // every handle freed once
        #expect(rec.maxFreeCount() == 1)          // no double-free anywhere
        #expect(worker.inFlightCount() == 0)
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
}
