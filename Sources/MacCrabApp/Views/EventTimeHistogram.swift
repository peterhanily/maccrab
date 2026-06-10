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
///   - minute:    HH:mm ticks, 1-minute bin width (Last Hour view)
///   - tenMinute: HH:mm ticks, 10-minute bin width (Last 6h / sub-day window)
///   - thirtyMin: HH:mm ticks, 30-minute bin width (Last 24h view — gives 48 bins)
///   - hour:      HH:mm ticks, 1-hour bin width
///   - sixHour:   HH:mm ticks, 6-hour bin width (Last 7d → 28 bins)
///   - day:       MMM-d ticks, 1-day bin width (aggregate view)
enum HistogramGranularity {
    case minute, tenMinute, thirtyMin, hour, sixHour, day

    /// Step size in seconds — used by SQL-side histogram queries.
    var stepSeconds: Int {
        switch self {
        case .minute:    return 60
        case .tenMinute: return 600
        case .thirtyMin: return 1800
        case .hour:      return 3600
        case .sixHour:   return 21600
        case .day:       return 86400
        }
    }
}

/// Hourly histogram of event volume across the currently displayed range.
/// Caller computes the bins; this view only renders. Empty state is a
/// 32-pt-tall transparent placeholder so removing it doesn't shift the
/// table layout when the user toggles the histogram off.
struct EventTimeHistogram: View {
    let bins: [EventTimeBin]
    /// "Hour" or "Day" — names the X-axis dimension on the bar marks and
    /// appears in the accessible summary. (v1.18.1: the summary this comment
    /// long claimed actually exists now.)
    let unitLabel: String
    /// Granularity controls X-axis formatting (HH:mm vs MMM-d).
    let granularity: HistogramGranularity

    init(bins: [EventTimeBin], unitLabel: String, granularity: HistogramGranularity = .hour) {
        self.bins = bins
        self.unitLabel = unitLabel
        self.granularity = granularity
    }

    /// v1.8.0 polish: hover-tracked bin index for the tooltip overlay.
    /// Drives the floating "Mon 3:15 PM · 1,234 events" label.
    @State private var hoverBin: EventTimeBin?

    var body: some View {
        if bins.isEmpty {
            Color.clear.frame(height: 32)
        } else {
            Chart(bins) { bin in
                BarMark(
                    x: .value(unitLabel, bin.date),
                    y: .value("Count", bin.count)
                )
                .foregroundStyle(
                    bin.id == hoverBin?.id
                        ? Color.accentColor
                        : Color.accentColor.opacity(0.7)
                )
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
                            Text(d, format: dateFormatStyle(for: granularity))
                        }
                    }
                }
            }
            // Hover overlay (macOS 13 compatible): map continuous mouse
            // position to nearest bin via chartProxy.value(atX:).
            .chartOverlay { proxy in
                GeometryReader { geo in
                    Rectangle().fill(Color.clear).contentShape(Rectangle())
                        .onContinuousHover { phase in
                            switch phase {
                            case .active(let location):
                                let plotFrame = geo[proxy.plotAreaFrame]
                                let xInPlot = location.x - plotFrame.origin.x
                                guard xInPlot >= 0, xInPlot <= plotFrame.size.width else {
                                    hoverBin = nil; return
                                }
                                if let date: Date = proxy.value(atX: xInPlot) {
                                    hoverBin = bins.min(by: {
                                        abs($0.date.timeIntervalSince(date)) < abs($1.date.timeIntervalSince(date))
                                    })
                                }
                            case .ended:
                                hoverBin = nil
                            }
                        }
                }
            }
            // Tooltip caption shown above the chart when hovering. Sits
            // outside the chart frame so it doesn't shift bar positions.
            .overlay(alignment: .topTrailing) {
                if let hover = hoverBin {
                    Text(tooltipText(for: hover))
                        .font(.caption2)
                        .padding(.horizontal, 6).padding(.vertical, 3)
                        .background(.thinMaterial)
                        .cornerRadius(4)
                        .padding(6)
                }
            }
            .frame(height: 130)
            .padding(.horizontal)
            .padding(.vertical, 4)
            // v1.18.1: summary-only accessibility — per-bar traversal of a
            // 100+-bin histogram is worse for VoiceOver than one sentence.
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Self.accessibilitySummary(bins: bins, unitLabel: unitLabel))
        }
    }

    /// One-sentence accessible summary (static so tests can pin it).
    static func accessibilitySummary(bins: [EventTimeBin], unitLabel: String) -> String {
        let total = bins.reduce(0) { $0 + $1.count }
        guard total > 0, let peak = bins.max(by: { $0.count < $1.count }) else {
            return String(localized: "histogram.ax.empty",
                          defaultValue: "Event histogram: no events in range")
        }
        let peakTime = peak.date.formatted(date: .abbreviated, time: .shortened)
        return String(localized: "histogram.ax.summary",
                      defaultValue: "Event histogram: \(total) events across \(bins.count) \(unitLabel.lowercased()) bins, peak \(peak.count) at \(peakTime)")
    }

    private func dateFormatStyle(for g: HistogramGranularity) -> Date.FormatStyle {
        switch g {
        case .minute, .tenMinute, .thirtyMin, .hour, .sixHour:
            return .dateTime.hour().minute()
        case .day:
            return .dateTime.month(.abbreviated).day()
        }
    }

    private func tooltipText(for bin: EventTimeBin) -> String {
        let format = dateFormatStyle(for: granularity)
        let label = bin.date.formatted(format)
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        let count = formatter.string(from: NSNumber(value: bin.count)) ?? "\(bin.count)"
        return "\(label) · \(count) \(unitLabel == "Day" ? "events" : "events")"
    }
}

// MARK: - Bin computation helpers

extension EventTimeHistogram {
    /// Bin width for a given granularity. Step size lives on the enum;
    /// the truncation function below uses floor-by-step rather than
    /// per-granularity Calendar components so a 30-minute or 6-hour
    /// bucket aligns to the bucket boundary regardless of clock drift.
    private static func step(for g: HistogramGranularity) -> TimeInterval {
        TimeInterval(g.stepSeconds)
    }

    /// Floor `date` to the nearest `stepSeconds` boundary. Matches the
    /// SQL-side `CAST(timestamp / step AS INTEGER) * step` expression so
    /// SQL bins and in-memory bins land on the same bucket origins.
    private static func bucketStart(_ date: Date, stepSeconds: Int) -> Date {
        let s = date.timeIntervalSince1970
        let bucket = floor(s / Double(stepSeconds)) * Double(stepSeconds)
        return Date(timeIntervalSince1970: bucket)
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
        let stepSec = granularity.stepSeconds
        let stepInterval = TimeInterval(stepSec)
        var counts: [Date: Int] = [:]

        for event in events {
            let bucket = bucketStart(event.timestamp, stepSeconds: stepSec)
            counts[bucket, default: 0] += 1
        }

        let startBin = bucketStart(endingAt.addingTimeInterval(-spanSeconds), stepSeconds: stepSec)
        var t = startBin
        while t <= endingAt {
            counts[t, default: 0] = counts[t] ?? 0
            t = t.addingTimeInterval(stepInterval)
        }

        return counts
            .map { EventTimeBin(id: $0.key, date: $0.key, count: $0.value) }
            .sorted { $0.date < $1.date }
    }

    /// v1.8.0 polish: build bins from SQL-side counts (returned by
    /// `EventStore.histogramBins`). The DB returns one (bucketDate, count)
    /// per occupied bin; this backfills 0-count bins for empty stretches
    /// of the window so the X-axis renders the full domain.
    static func bins(
        fromSQL rows: [(Date, Int)],
        granularity: HistogramGranularity,
        endingAt: Date = Date(),
        spanSeconds: TimeInterval
    ) -> [EventTimeBin] {
        let stepSec = granularity.stepSeconds
        let stepInterval = TimeInterval(stepSec)
        var counts: [Date: Int] = [:]
        for (date, count) in rows {
            counts[bucketStart(date, stepSeconds: stepSec), default: 0] += count
        }

        let startBin = bucketStart(endingAt.addingTimeInterval(-spanSeconds), stepSeconds: stepSec)
        var t = startBin
        while t <= endingAt {
            counts[t, default: 0] = counts[t] ?? 0
            t = t.addingTimeInterval(stepInterval)
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
