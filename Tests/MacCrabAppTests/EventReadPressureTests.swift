// EventReadPressureTests.swift
//
// v1.21.6-rc.38. The dashboard's event and histogram reads caught every error
// identically and rendered it as "evidence could not be read completely" — a
// string that reads like permanent data loss.
//
// Decoding a journal block needs a bounded record-ownership lease. A momentary
// shortage is back-pressure that clears on the next poll, and an installed host
// surfaced exactly that as a coverage failure:
//
//   "Event evidence could not be read completely: Event pipeline memory lease
//    unavailable: event journal block 28634 decode is waiting for bounded
//    record ownership"
//
// The evidence was intact the whole time. Real storage faults must still reach
// the user, so this classification is the thing worth pinning.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("rc.38 dashboard read pressure classification")
struct EventReadPressureTests {

    @Test("Pipeline back-pressure is treated as transient")
    func backPressureIsTransient() {
        // Both are bounded waits inside the store; neither means evidence loss.
        #expect(AppState.isTransientReadPressure(
            .memoryLeaseUnavailable(
                "event journal block 28634 decode is waiting for bounded record ownership"
            )
        ))
        #expect(AppState.isTransientReadPressure(.busy("database is locked")))
    }

    @Test("Real storage faults are NOT treated as transient")
    func realFaultsStillSurface() {
        // If these were swallowed the user would lose the only signal that
        // something is genuinely wrong with their evidence.
        #expect(!AppState.isTransientReadPressure(.stepFailed("disk I/O error")))
        #expect(!AppState.isTransientReadPressure(
            .diskFull("database or disk is full")
        ))
        #expect(!AppState.isTransientReadPressure(
            .storageNotReady("schema migration incomplete")
        ))
        #expect(!AppState.isTransientReadPressure(
            .decodingFailed("canonical digest mismatch")
        ))
    }
}
