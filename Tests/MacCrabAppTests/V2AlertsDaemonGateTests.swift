// V2AlertsDaemonGateTests.swift
// MacCrabAppTests
//
// B6 "daemon-down looks safe" gate. An empty Open / Campaigns / Suppressions
// list may only be rendered as an "all clear" empty state when the engine is
// actually reporting — a live provider with a fresh (non-stale) heartbeat.
// Any other state (offline, mock, missing heartbeat, or a stale one) must read
// as not-reporting so the stale banner shows and the reassuring empty state is
// withheld. Pins V2AlertsWorkspace.isDaemonReporting, the pure seam all three
// tab bodies gate on.

import Testing
@testable import MacCrabApp

@Suite("V2 alerts daemon-liveness gate (B6)")
struct V2AlertsDaemonGateTests {

    @Test("live provider with a fresh heartbeat is the only reporting state")
    func liveFreshReports() {
        #expect(V2AlertsWorkspace.isDaemonReporting(mode: .live, heartbeatStale: false))
    }

    @Test("live provider with a stale heartbeat is NOT reporting")
    func liveStaleDoesNotReport() {
        #expect(!V2AlertsWorkspace.isDaemonReporting(mode: .live, heartbeatStale: true))
    }

    @Test("live provider with a missing heartbeat is NOT reporting")
    func liveMissingHeartbeatDoesNotReport() {
        #expect(!V2AlertsWorkspace.isDaemonReporting(mode: .live, heartbeatStale: nil))
    }

    @Test("offline provider never reports even with a fresh heartbeat")
    func offlineNeverReports() {
        #expect(!V2AlertsWorkspace.isDaemonReporting(mode: .offline, heartbeatStale: false))
        #expect(!V2AlertsWorkspace.isDaemonReporting(mode: .offline, heartbeatStale: nil))
    }

    @Test("mock provider never reports (sample data is knowingly synthetic)")
    func mockNeverReports() {
        #expect(!V2AlertsWorkspace.isDaemonReporting(mode: .mock, heartbeatStale: false))
    }
}
