// V2OverviewDataTokenTests.swift
// MacCrabAppTests
//
// PERF-2: the Overview gates its alerts/campaigns/KPI/histogram SQL fan-out on a
// cheap change-token built from the engine's monotonic heartbeat counters + the
// selected range. A quiet tick reuses the token and skips the SQL; new activity
// or a range change mints a new token and refetches. No heartbeat (offline/mock)
// ⇒ nil token ⇒ "always fetch" (pre-PERF-2 behaviour preserved). These pin that
// pure token so the gate can't silently freeze the tiles.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2OverviewWorkspace.overviewDataToken")
struct V2OverviewDataTokenTests {

    @Test("no heartbeat counters ⇒ nil (always fetch)")
    func nilWithoutHeartbeat() {
        #expect(V2OverviewWorkspace.overviewDataToken(
            eventsProcessed: nil, alertsEmitted: nil, rangeKey: "6h") == nil)
        #expect(V2OverviewWorkspace.overviewDataToken(
            eventsProcessed: 10, alertsEmitted: nil, rangeKey: "6h") == nil)
        #expect(V2OverviewWorkspace.overviewDataToken(
            eventsProcessed: nil, alertsEmitted: 3, rangeKey: "6h") == nil)
    }

    @Test("identical counters + range ⇒ identical token (quiet tick skips SQL)")
    func stableWhenUnchanged() {
        let a = V2OverviewWorkspace.overviewDataToken(eventsProcessed: 100, alertsEmitted: 4, rangeKey: "6h")
        let b = V2OverviewWorkspace.overviewDataToken(eventsProcessed: 100, alertsEmitted: 4, rangeKey: "6h")
        #expect(a != nil)
        #expect(a == b)
    }

    @Test("any counter or range change ⇒ new token (refetch)")
    func changesInvalidate() {
        let base = V2OverviewWorkspace.overviewDataToken(eventsProcessed: 100, alertsEmitted: 4, rangeKey: "6h")
        // New events flowed.
        #expect(base != V2OverviewWorkspace.overviewDataToken(eventsProcessed: 101, alertsEmitted: 4, rangeKey: "6h"))
        // A new alert was emitted.
        #expect(base != V2OverviewWorkspace.overviewDataToken(eventsProcessed: 100, alertsEmitted: 5, rangeKey: "6h"))
        // The operator switched the histogram range.
        #expect(base != V2OverviewWorkspace.overviewDataToken(eventsProcessed: 100, alertsEmitted: 4, rangeKey: "24h"))
    }
}
