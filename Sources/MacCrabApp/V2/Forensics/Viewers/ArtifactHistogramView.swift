// ArtifactHistogramView — counts-per-time-bucket bar chart for
// any content type that carries a timestamp. Used by Quarantine
// (events per day), KnowledgeC (activity per hour), Safari
// history (visits per day).
//
// Implementation: SwiftUI Charts on macOS 13+. Buckets are
// computed once from chartHint.bucket (minute / hour / day /
// week / month, default hour). A density-aware fallback
// auto-picks the bucket size if the spread is wider than the
// declared bucket would render usefully.

import SwiftUI
import Charts
import MacCrabForensics

struct ArtifactHistogramView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    private var chartHint: ChartHint? { hint.chart }

    private var bucketField: String {
        chartHint?.bucketField
            ?? FieldResolver.field(forRole: .timestamp, in: hint)
            ?? "observed_at"
    }

    private var bucket: HistogramBucket {
        chartHint?.bucket ?? autoBucket()
    }

    private var buckets: [(start: Date, count: Int)] {
        let dates = artifacts.compactMap { a -> Date? in
            FieldResolver.resolve(a, field: bucketField).asDate ?? a.record.observedAt
        }
        guard !dates.isEmpty else { return [] }

        var dict: [Date: Int] = [:]
        for d in dates {
            let b = bucketStart(d, bucket: bucket)
            dict[b, default: 0] += 1
        }
        return dict.keys.sorted().map { ($0, dict[$0]!) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header
            if buckets.isEmpty {
                emptyState
            } else {
                chart
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("\(artifacts.count) event\(artifacts.count == 1 ? "" : "s") · per \(bucketLabel)")
                .scaledSystem(12, weight: .semibold)
            Spacer()
            if let first = buckets.first?.start, let last = buckets.last?.start {
                Text("\(first.formatted(date: .abbreviated, time: .omitted)) → \(last.formatted(date: .abbreviated, time: .omitted))")
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    private var emptyState: some View {
        Text("No timestamped events for this content type.")
            .scaledSystem(11)
            .foregroundStyle(.tertiary)
            .padding(.vertical, 20)
    }

    private var chart: some View {
        Chart {
            ForEach(buckets, id: \.start) { b in
                BarMark(
                    x: .value(bucketLabel, b.start, unit: chartCalendarUnit),
                    y: .value("Count", b.count)
                )
                .foregroundStyle(Color.accentColor.opacity(0.85))
            }
        }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 6))
        }
        .chartYAxis {
            AxisMarks(position: .leading)
        }
        .frame(maxWidth: .infinity, minHeight: 200, idealHeight: 280)
        // v1.18.1: summary-only accessibility (matches EventTimeHistogram).
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(chartAccessibilitySummary)
    }

    private var chartAccessibilitySummary: String {
        guard let peak = buckets.max(by: { $0.count < $1.count }) else {
            return String(localized: "forensics.histogram.ax.empty",
                          defaultValue: "Timeline histogram: no events")
        }
        let peakTime = peak.start.formatted(date: .abbreviated, time: .shortened)
        return String(localized: "forensics.histogram.ax.summary",
                      defaultValue: "Timeline histogram: \(artifacts.count) events per \(bucketLabel), peak \(peak.count) at \(peakTime)")
    }

    // MARK: - Helpers

    private var bucketLabel: String {
        switch bucket {
        case .minute: return "minute"
        case .hour:   return "hour"
        case .day:    return "day"
        case .week:   return "week"
        case .month:  return "month"
        }
    }

    private var chartCalendarUnit: Calendar.Component {
        switch bucket {
        case .minute: return .minute
        case .hour:   return .hour
        case .day:    return .day
        case .week:   return .weekOfYear
        case .month:  return .month
        }
    }

    private func bucketStart(_ date: Date, bucket: HistogramBucket) -> Date {
        let cal = Calendar.current
        switch bucket {
        case .minute: return cal.date(bySetting: .second, value: 0, of: date) ?? date
        case .hour:
            let comps = cal.dateComponents([.year, .month, .day, .hour], from: date)
            return cal.date(from: comps) ?? date
        case .day:    return cal.startOfDay(for: date)
        case .week:
            let comps = cal.dateComponents([.yearForWeekOfYear, .weekOfYear], from: date)
            return cal.date(from: comps) ?? date
        case .month:
            let comps = cal.dateComponents([.year, .month], from: date)
            return cal.date(from: comps) ?? date
        }
    }

    /// Density-aware default bucket: pick the granularity that
    /// gives roughly 20–80 buckets across the date range.
    private func autoBucket() -> HistogramBucket {
        let dates = artifacts.compactMap { a -> Date? in
            FieldResolver.resolve(a, field: bucketField).asDate ?? a.record.observedAt
        }
        guard let first = dates.min(), let last = dates.max() else { return .hour }
        let spanSeconds = last.timeIntervalSince(first)
        let day: Double = 86_400
        if spanSeconds < 7_200      { return .minute }  // < 2h
        if spanSeconds < day * 3    { return .hour }    // < 3 days
        if spanSeconds < day * 60   { return .day }     // < 60 days
        if spanSeconds < day * 365  { return .week }    // < 1 year
        return .month
    }
}
