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

/// Granularity hint for axis formatting + bin width.
///   - minute: HH:mm ticks, 1-minute bin width (Last Hour view)
///   - hour:   HH:mm ticks, 1-hour bin width (Last 24h view)
///   - day:    MMM-d ticks, 1-day bin width (Last 7d / aggregate view)
enum HistogramGranularity {
    case minute, hour, day
}

/// Hourly histogram of event volume across the currently displayed range.
/// Caller computes the bins; this view only renders. Empty state is a
/// 32-pt-tall transparent placeholder so removing it doesn't shift the
/// table layout when the user toggles the histogram off.
struct EventTimeHistogram: View {
    let bins: [EventTimeBin]
    /// "Hour" or "Day" — used in the chart's accessibility label.
    let unitLabel: String
    /// Granularity controls X-axis formatting (HH:mm vs MMM-d).
    let granularity: HistogramGranularity

    init(bins: [EventTimeBin], unitLabel: String, granularity: HistogramGranularity = .hour) {
        self.bins = bins
        self.unitLabel = unitLabel
        self.granularity = granularity
    }

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
            // Explicit X-axis: without this, a single populated bin
            // collapses the axis to one tick. Backfilled bins (see
            // hourlyBins) ensure the domain spans the full range; this
            // formats the ticks across that domain.
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 6)) { value in
                    AxisGridLine()
                    AxisTick()
                    AxisValueLabel {
                        if let d = value.as(Date.self) {
                            switch granularity {
                            case .minute, .hour: Text(d, format: .dateTime.hour().minute())
                            case .day:           Text(d, format: .dateTime.month(.abbreviated).day())
                            }
                        }
                    }
                }
            }
            .frame(height: 130)
            .padding(.horizontal)
            .padding(.vertical, 4)
        }
    }
}

// MARK: - Bin computation helpers

extension EventTimeHistogram {
    /// Bin width + truncation parameters for a given granularity. Kept
    /// as one place so the truncation idiom (date-from-components) and
    /// the step size stay in sync.
    private static func binParams(_ g: HistogramGranularity)
        -> (components: Set<Calendar.Component>, step: TimeInterval) {
        switch g {
        case .minute: return ([.year, .month, .day, .hour, .minute], 60)
        case .hour:   return ([.year, .month, .day, .hour], 3600)
        case .day:    return ([.year, .month, .day], 86400)
        }
    }

    /// Bin events at the requested granularity over the given window.
    /// Backfills 0-count bins so the X-axis always renders multiple
    /// positions, even with a short / sparse data window.
    static func bins(
        from events: [EventViewModel],
        granularity: HistogramGranularity,
        endingAt: Date = Date(),
        spanSeconds: TimeInterval
    ) -> [EventTimeBin] {
        let cal = Calendar(identifier: .gregorian)
        let (comps, step) = binParams(granularity)
        var counts: [Date: Int] = [:]

        // Count actual events.
        for event in events {
            let bucketComps = cal.dateComponents(comps, from: event.timestamp)
            if let bucket = cal.date(from: bucketComps) {
                counts[bucket, default: 0] += 1
            }
        }

        // Backfill the full window. `default: 0` never overwrites a
        // populated key.
        let startComps = cal.dateComponents(comps, from: endingAt.addingTimeInterval(-spanSeconds))
        let startBin = cal.date(from: startComps) ?? endingAt.addingTimeInterval(-spanSeconds)
        var t = startBin
        while t <= endingAt {
            counts[t, default: 0] = counts[t] ?? 0
            t = t.addingTimeInterval(step)
        }

        return counts
            .map { EventTimeBin(id: $0.key, date: $0.key, count: $0.value) }
            .sorted { $0.date < $1.date }
    }

    /// Back-compat shim. Existing callers can keep calling `hourlyBins`;
    /// new callers should prefer `bins(from:granularity:...)`.
    static func hourlyBins(
        from events: [EventViewModel],
        endingAt: Date = Date(),
        spanSeconds: TimeInterval? = nil
    ) -> [EventTimeBin] {
        bins(from: events, granularity: .hour, endingAt: endingAt, spanSeconds: spanSeconds ?? 86400)
    }

    /// Daily bins from aggregate rows (warm-tier path). When `spanDays`
    /// is non-nil, fills 0-count bins for every day in the window so
    /// the X-axis renders consistently for short ranges.
    static func dailyBins(
        from aggregates: [EventStore.AggregateRow],
        endingAt: Date = Date(),
        spanDays: Int? = nil
    ) -> [EventTimeBin] {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.locale = Locale(identifier: "en_US_POSIX")

        var counts: [Date: Int] = [:]
        for agg in aggregates {
            guard let day = formatter.date(from: agg.day) else { continue }
            counts[day, default: 0] += agg.count
        }

        if let days = spanDays, days > 0 {
            // Floor "endingAt" to its UTC day so the bin keys align
            // with the YYYY-MM-DD strings returned from the aggregate.
            let utc = TimeZone(identifier: "UTC")!
            var cal = Calendar(identifier: .gregorian)
            cal.timeZone = utc
            let endDay = cal.startOfDay(for: endingAt)
            for offset in 0..<days {
                if let day = cal.date(byAdding: .day, value: -offset, to: endDay) {
                    counts[day, default: 0] = counts[day] ?? 0
                }
            }
        }

        return counts
            .map { EventTimeBin(id: $0.key, date: $0.key, count: $0.value) }
            .sorted { $0.date < $1.date }
    }
}
