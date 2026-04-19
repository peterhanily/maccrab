// MonitorSupervisorTests.swift
//
// Contract tests for MonitorSupervisor — the actor that gives SIGTERM a
// clean shutdown path for every long-running background monitor the
// daemon spawns. Without this, Sparkle auto-updates hit `exit(0)` with
// supervised work mid-flight.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("MonitorSupervisor")
struct MonitorSupervisorTests {

    @Test("start() launches work that runs to completion")
    func startRuns() async {
        let sup = MonitorSupervisor()
        let marker = MarkerBox()

        await sup.start("simple") {
            await marker.markDone()
        }

        // Give the task a beat to run. The supervisor doesn't wait for
        // completion on start(), which is intentional — monitors run
        // for the lifetime of the daemon. Shutdown is the join point.
        try? await Task.sleep(nanoseconds: 100_000_000)
        #expect(await marker.done == true)

        await sup.shutdown(deadline: 1.0)
    }

    @Test("shutdown() cancels a for-await loop within the deadline")
    func shutdownCancelsForAwait() async {
        let sup = MonitorSupervisor()
        let marker = MarkerBox()

        // An AsyncStream that never produces; the for-await blocks
        // forever unless cancellation arrives.
        let stream = AsyncStream<Int> { _ in
            // Never yields, never finishes.
        }

        await sup.start("pending-loop") {
            for await value in stream {
                _ = value  // unreachable
            }
            await marker.markDone()
        }
        try? await Task.sleep(nanoseconds: 50_000_000)

        let shutdownStart = Date()
        await sup.shutdown(deadline: 2.0)
        let shutdownElapsed = Date().timeIntervalSince(shutdownStart)

        #expect(shutdownElapsed < 1.0, "shutdown should unwind in well under its deadline")
        #expect(await marker.done == true, "for-await should exit when the enclosing task is cancelled")
        #expect(await sup.activeCount() == 0)
    }

    @Test("start() with an existing name cancels the previous task")
    func startReplacesExisting() async {
        let sup = MonitorSupervisor()
        let firstCompleted = MarkerBox()
        let secondCompleted = MarkerBox()

        // First task sleeps; cancellation wakes it with CancellationError.
        await sup.start("slot") {
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                // cancelled — fall through
            }
            await firstCompleted.markDone()
        }

        // Replace with second task.
        try? await Task.sleep(nanoseconds: 50_000_000)
        await sup.start("slot") {
            await secondCompleted.markDone()
        }

        try? await Task.sleep(nanoseconds: 200_000_000)
        #expect(await firstCompleted.done == true, "first task should have been cancelled + completed")
        #expect(await secondCompleted.done == true, "second task should have run")
        #expect(await sup.activeCount() == 1, "exactly one task under the slot name")

        await sup.shutdown(deadline: 1.0)
    }

    @Test("deadline is respected when a task ignores cancellation")
    func deadlineEnforced() async {
        let sup = MonitorSupervisor()

        // Ignore cancellation: no Task.checkCancellation, no awaits that
        // throw on cancel. Exits only after the sleep — longer than our
        // deadline. Tests the race guarantee.
        await sup.start("stubborn") {
            while !Task.isCancelled {
                // Busy-poll the cancel flag but never yield the actor.
                // Swift will preempt eventually so this isn't truly
                // unkillable, but it models a monitor that's slow to
                // notice cancellation.
                try? await Task.sleep(nanoseconds: 200_000_000)
            }
        }
        try? await Task.sleep(nanoseconds: 50_000_000)

        let shutdownStart = Date()
        await sup.shutdown(deadline: 0.5)  // deliberately tight
        let elapsed = Date().timeIntervalSince(shutdownStart)

        // The deadline is a soft race winner — shutdown should return
        // at most ~deadline + ~50ms of scheduler jitter.
        #expect(elapsed < 1.0, "shutdown returned after \(elapsed)s, expected < 1.0s")
    }

    @Test("shutdown() is a no-op when there are no tasks")
    func emptyShutdown() async {
        let sup = MonitorSupervisor()
        await sup.shutdown(deadline: 1.0)
        #expect(await sup.activeCount() == 0)
    }

    @Test("10 rapid start/shutdown cycles leave no residue")
    func rapidCycles() async {
        let sup = MonitorSupervisor()
        for i in 0..<10 {
            await sup.start("cycle-\(i)") {
                let stream = AsyncStream<Int> { _ in }
            for await _ in stream {}
            }
        }
        #expect(await sup.activeCount() == 10)
        await sup.shutdown(deadline: 1.0)
        #expect(await sup.activeCount() == 0)

        // Subsequent start() after shutdown works — shutdown clears the
        // dictionary but doesn't disable the supervisor.
        await sup.start("post-shutdown") {
            let stream = AsyncStream<Int> { _ in }
            for await _ in stream {}
        }
        #expect(await sup.activeCount() == 1)
        await sup.shutdown(deadline: 1.0)
    }
}

/// Tiny Sendable marker for checking "did the task body run at all" from
/// inside a captured closure. Swift Concurrency hates naked Bool mutation
/// across isolation boundaries; wrapping in an actor side-steps that.
private actor MarkerBox {
    var done: Bool = false
    func markDone() { done = true }
}
