// EventTimeHistogram.swift
// MacCrabApp
//
// v1.8.0: Discover-style time histogram for the Events tab. Renders the
// loaded events (≤24h hot tier) or aggregate rows (>24h warm tier) as
// hourly / daily bars so the user can see at a glance "what time of day
// did most of this happen?".
//
// Hidden by default behind the @AppStorage("events.showHistogram") flag —
// the dashboard ships in simple mode (today's flat table) for users who
// don't want SIEM chrome. Phase 2c adds the toggle to the Events tab
// toolbar; v1.9 will expand to faceted filters + KQL-lite query.

import SwiftUI
import Charts
import MacCrabCore

/// One bar in the histogram. Date is the bin's start (UTC-anchored when
/// rendering aggregates; local-anchored within the 24h hot tier).
struct EventTimeBin: Identifiable {
    let id: Date
    let date: Date
    let count: Int
}

/// Hourly histogram of event volume across the currently displayed range.
/// Caller computes the bins; this view only renders. Empty state is a
/// 32-pt-tall transparent placeholder so removing it doesn't shift the
/// table layout when the user toggles the histogram off.
struct EventTimeHistogram: View {
    let bins: [EventTimeBin]
    /// "Hour" or "Day" — used in the axis label so a 7-day-range chart
    /// labels the X axis "Day" instead of "Hour".
    let unitLabel: String

    var body: some View {
        if bins.isEmpty {
            Color.clear.frame(height: 32)
        } else {
            Chart(bins) { bin in
                BarMark(
                    x: .value(unitLabel, bin.date),
                    y: .value("Count", bin.count)
                )
                .foregroundStyle(Color.accentColor.opacity(0.7))
            }
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3))
            }
            .frame(height: 90)
            .padding(.horizontal)
            .padding(.vertical, 4)
        }
    }
}

// MARK: - Bin computation helpers

extension EventTimeHistogram {
    /// Hourly bins from a loaded event list (hot-tier path). Empty input
    /// returns empty bins; SwiftUI Charts handles the empty-domain case.
    static func hourlyBins(from events: [EventViewModel]) -> [EventTimeBin] {
        guard !events.isEmpty else { return [] }
        let cal = Calendar(identifier: .gregorian)
        var counts: [Date: Int] = [:]
        for event in events {
            // Truncate to the hour so all events in the same hour land in
            // the same bin. components+date round-trip is the canonical
            // "floor to hour" idiom.
            let comps = cal.dateComponents([.year, .month, .day, .hour], from: event.timestamp)
            if let bucket = cal.date(from: comps) {
                counts[bucket, default: 0] += 1
            }
        }
        return counts
            .map { EventTimeBin(id: $0.key, date: $0.key, count: $0.value) }
            .sorted { $0.date < $1.date }
    }

    /// Daily bins from aggregate rows (warm-tier path). Day strings are
    /// already grouped per-day; we just sum across categories within each
    /// day so the chart shows total volume.
    static func dailyBins(from aggregates: [EventStore.AggregateRow]) -> [EventTimeBin] {
        guard !aggregates.isEmpty else { return [] }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.locale = Locale(identifier: "en_US_POSIX")

        var counts: [Date: Int] = [:]
        for agg in aggregates {
            guard let day = formatter.date(from: agg.day) else { continue }
            counts[day, default: 0] += agg.count
        }
        return counts
            .map { EventTimeBin(id: $0.key, date: $0.key, count: $0.value) }
            .sorted { $0.date < $1.date }
    }
}
