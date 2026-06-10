// ChartAccessibilityTests.swift
// v1.18.1 (a11y): the dashboard charts expose a one-sentence VoiceOver
// summary instead of per-bar traversal. Pin the summary builder so the
// stale-comment failure mode (EventTimeHistogram's doc comment claimed a
// label that never existed) can't silently recur.

import Foundation
import Testing
@testable import MacCrabApp

@Suite("Chart accessibility summaries (a11y)")
struct ChartAccessibilityTests {

    @Test("histogram summary carries total, bin count, and peak")
    func summaryCarriesTotals() {
        let base = Date(timeIntervalSince1970: 1_750_000_000)
        let bins = [
            EventTimeBin(id: base, date: base, count: 10),
            EventTimeBin(id: base.addingTimeInterval(3600), date: base.addingTimeInterval(3600), count: 42),
            EventTimeBin(id: base.addingTimeInterval(7200), date: base.addingTimeInterval(7200), count: 5),
        ]
        let summary = EventTimeHistogram.accessibilitySummary(bins: bins, unitLabel: "Hour")
        #expect(summary.contains("57"), "total event count missing: \(summary)")
        #expect(summary.contains("3"), "bin count missing: \(summary)")
        #expect(summary.contains("42"), "peak count missing: \(summary)")
    }

    @Test("empty and zero-count histograms summarize as empty, not 'peak 0'")
    func emptySummary() {
        let none = EventTimeHistogram.accessibilitySummary(bins: [], unitLabel: "Hour")
        #expect(!none.isEmpty)
        #expect(!none.contains("peak"), "empty bins must not report a peak: \(none)")

        let zero = Date(timeIntervalSince1970: 1_750_000_000)
        let zeroBins = [EventTimeBin(id: zero, date: zero, count: 0)]
        let zeroSummary = EventTimeHistogram.accessibilitySummary(bins: zeroBins, unitLabel: "Hour")
        #expect(!zeroSummary.contains("peak"), "all-zero bins must not report a peak: \(zeroSummary)")
    }
}
