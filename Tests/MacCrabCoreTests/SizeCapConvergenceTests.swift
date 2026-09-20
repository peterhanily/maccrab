// SizeCapConvergenceTests.swift
// v1.22.1: SizeCapConvergence had NO test coverage at all, while owning a latch
// that suppresses the full VACUUM for six hours and tells the operator the size
// cap is structurally unreachable. This change set makes that latch reachable in
// a new way -- `vacuum(waitForReaders: false)` can now throw at its non-waiting
// pre-checkpoint WITHOUT rebuilding anything -- so the scoring contract and the
// call-site contract both need pinning.

import Foundation
import Testing
@testable import MacCrabAgentKit

// Serialized: SizeCapConvergence is process-global mutable state behind a lock.
// Parallel cases would race each other's streaks rather than the code.
@Suite("Size-cap convergence latch", .serialized)
struct SizeCapConvergenceTests {
    /// The type exposes no reset, and a converged record is defined to clear
    /// both the streak and the suppression, so this is the supported way back
    /// to a known state.
    private func resetLatch() {
        _ = SizeCapConvergence.record(converged: true)
    }

    @Test("The latch trips exactly once, on the failureLimit-th consecutive non-convergence")
    func latchTripsOnceAtTheLimit() {
        resetLatch()
        let now = Date(timeIntervalSince1970: 1_000_000)
        for attempt in 1..<SizeCapConvergence.failureLimit {
            #expect(!SizeCapConvergence.record(converged: false, now: now),
                    "attempt \(attempt) must not trip the latch early")
        }
        #expect(SizeCapConvergence.record(converged: false, now: now),
                "the failureLimit-th consecutive failure trips the latch")
        // Once per back-off window, not once per sweep: the caller logs a
        // cap-unreachable error on a true return.
        #expect(!SizeCapConvergence.record(converged: false, now: now),
                "a latched window must not re-log on every later sweep")
        resetLatch()
    }

    @Test("One convergence clears the streak, so failures must be CONSECUTIVE")
    func convergenceClearsTheStreak() {
        resetLatch()
        let now = Date(timeIntervalSince1970: 2_000_000)
        #expect(!SizeCapConvergence.record(converged: false, now: now))
        #expect(!SizeCapConvergence.record(converged: false, now: now))
        #expect(!SizeCapConvergence.record(converged: true, now: now))
        // If the streak had survived, this third failure would trip the latch.
        #expect(!SizeCapConvergence.record(converged: false, now: now),
                "a converged rebuild must reset the consecutive-failure count")
        resetLatch()
    }

    @Test("A latched window suppresses the rebuild until the back-off elapses, then rearms")
    func suppressionExpiresAndRearms() {
        resetLatch()
        let start = Date(timeIntervalSince1970: 3_000_000)
        for _ in 0..<SizeCapConvergence.failureLimit {
            _ = SizeCapConvergence.record(converged: false, now: start)
        }
        #expect(!SizeCapConvergence.shouldFullVacuum(
            now: start.addingTimeInterval(SizeCapConvergence.backoffSeconds - 1)
        ), "the rebuild stays suppressed for the whole back-off window")
        #expect(SizeCapConvergence.shouldFullVacuum(
            now: start.addingTimeInterval(SizeCapConvergence.backoffSeconds)
        ), "the window expires and the rebuild is eligible again")
        // Expiry also clears the streak, so one later failure cannot instantly
        // re-latch a host that was merely transiently over target.
        #expect(!SizeCapConvergence.record(
            converged: false,
            now: start.addingTimeInterval(SizeCapConvergence.backoffSeconds)
        ), "expiry rearms from a clean streak")
        resetLatch()
    }

    // The latch measures whether REBUILDING converges. Since v1.22.1 the sweep's
    // `vacuum(waitForReaders: false)` can throw EventStoreError.busy at its
    // non-waiting pre-checkpoint without rebuilding anything; scoring that as a
    // non-converging rebuild would latch a six-hour suppression and emit an
    // operator-facing claim that the cap is structurally unreachable -- which
    // would be false. Pin the call-site contract, since the type itself cannot
    // tell whether its caller actually ran a VACUUM.
    @Test("The sweep only scores convergence when a rebuild actually ran")
    func convergenceIsScoredOnlyAfterARealRebuild() throws {
        let timers = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent().deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"),
            encoding: .utf8
        )
        let call = try #require(
            timers.range(of: "SizeCapConvergence.record(converged:"),
            "the sweep no longer records full-VACUUM convergence"
        )
        let preceding = String(timers[..<call.lowerBound])
        let guardRange = try #require(
            preceding.range(of: "guard rebuiltThisSweep else {", options: .backwards),
            "convergence must be guarded on the rebuild having run"
        )
        let vacuumRange = try #require(
            preceding.range(of: "try await eventStore.vacuum(waitForReaders: false)",
                            options: .backwards),
            "the tier-rollup rebuild call site moved"
        )
        #expect(vacuumRange.lowerBound < guardRange.lowerBound,
                "the guard must follow the rebuild attempt it is reporting on")
        // The busy deferral must be distinguished from a genuine VACUUM failure,
        // or the operator sees a false structural verdict.
        let between = String(preceding[vacuumRange.upperBound...])
        #expect(between.contains("case .busy"),
                "reader contention must be recognised, not folded into failure")
    }
}
