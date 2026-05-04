// AlertTimelineHistogram.swift
// MacCrabApp
//
// v1.8.0 polish: Overview-tab time-binned activity chart. Severity-stacked
// bars over a configurable window, with campaign-fire markers overlaid as
// flag glyphs above the bar of the hour they fired.
//
// Sibling to EventTimeHistogram. Kept as its own type rather than a
// generalization because the visual structure is meaningfully different —
// stacked bars + scatter overlay vs a single BarMark per bin. If a third
// histogram-shaped view shows up, this is the moment to extract a shared
// `TimeHistogram<BinPayload>` protocol; for two views the duplication is
// cheaper than the abstraction.

import SwiftUI
import Charts

/// One bin in the alert timeline. Counts are exclusive of campaign-prefix
/// alerts — those go to `campaignHours` and render as overlay markers.
struct SeverityTimelineBin: Identifiable {
    let id: Date
    let date: Date
    let critical: Int
    let high: Int
    let medium: Int
    let low: Int

    var total: Int { critical + high + medium + low }
}

/// Severity-stacked bars over the visible window with optional
/// campaign-fire markers. Caller computes both `bins` and
/// `campaignHours`; this view only renders.
struct AlertTimelineHistogram: View {
    let bins: [SeverityTimelineBin]
    /// Hour-truncated dates that had at least one campaign fire.
    let campaignHours: [Date]
    /// Hour vs day axis formatting.
    let granularity: HistogramGranularity

    /// v1.8.0 polish: bin under the cursor (drives the tooltip overlay).
    @State private var hoverBin: SeverityTimelineBin?

    var body: some View {
        if bins.isEmpty || (bins.allSatisfy { $0.total == 0 } && campaignHours.isEmpty) {
            // Match a populated chart's height so toggling between
            // "no alerts" and "alerts arriving" doesn't shift layout.
            HStack {
                Spacer()
                Text("No alerts in this window")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
            }
            .frame(maxWidth: .infinity, minHeight: 110)
        } else {
            Chart {
                // Severity-stacked bars. The order severity-low first
                // through severity-critical last makes "calmer" colors
                // form the base and the dangerous severities crown the
                // bar — visually parallel to the StatCards above which
                // sort critical → low.
                ForEach(bins) { bin in
                    if bin.low > 0 {
                        BarMark(x: .value("Time", bin.date), y: .value("Low", bin.low))
                            .foregroundStyle(MacCrabTheme.severityLow)
                    }
                    if bin.medium > 0 {
                        BarMark(x: .value("Time", bin.date), y: .value("Medium", bin.medium))
                            .foregroundStyle(MacCrabTheme.severityMedium)
                    }
                    if bin.high > 0 {
                        BarMark(x: .value("Time", bin.date), y: .value("High", bin.high))
                            .foregroundStyle(MacCrabTheme.severityHigh)
                    }
                    if bin.critical > 0 {
                        BarMark(x: .value("Time", bin.date), y: .value("Critical", bin.critical))
                            .foregroundStyle(MacCrabTheme.severityCritical)
                    }
                }

                // Campaign markers. Plotted at total+1 so they hover
                // just above the tallest bar at that hour. Annotation
                // carries the visible flag glyph; PointMark itself is
                // rendered tiny because the icon does the work.
                ForEach(campaignHours, id: \.self) { hour in
                    let yPos = (bins.first(where: { $0.date == hour })?.total ?? 0) + 1
                    PointMark(
                        x: .value("Time", hour),
                        y: .value("Campaign", yPos)
                    )
                    .symbolSize(8)
                    .foregroundStyle(.purple)
                    .annotation(position: .top, alignment: .center, spacing: 0) {
                        Image(systemName: "flag.fill")
                            .font(.caption2)
                            .foregroundColor(.purple)
                            .accessibilityLabel("Campaign fired in this hour")
                    }
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3))
            }
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
            .padding(.vertical, 4)
        }
    }

    private func dateFormatStyle(for g: HistogramGranularity) -> Date.FormatStyle {
        switch g {
        case .minute, .tenMinute, .thirtyMin, .hour, .sixHour:
            return .dateTime.hour().minute()
        case .day:
            return .dateTime.month(.abbreviated).day()
        }
    }

    private func tooltipText(for bin: SeverityTimelineBin) -> String {
        let label = bin.date.formatted(dateFormatStyle(for: granularity))
        var parts: [String] = ["\(label) · \(bin.total) alert\(bin.total == 1 ? "" : "s")"]
        if bin.critical > 0 { parts.append("\(bin.critical)C") }
        if bin.high > 0     { parts.append("\(bin.high)H") }
        if bin.medium > 0   { parts.append("\(bin.medium)M") }
        if bin.low > 0      { parts.append("\(bin.low)L") }
        return parts.joined(separator: " · ")
    }
}

// MARK: - Bin computation

extension AlertTimelineHistogram {
    /// Hourly bins from a flat alert list. Filters out campaign-prefix
    /// alerts (`maccrab.campaign.*`) — they're rendered as markers
    /// above the bars via `campaignHours`. Backfills 0-count bins
    /// across the full window so the X-axis renders multiple positions
    /// even when only a recent slice has activity.
    static func hourlyBins(
        from alerts: [AlertViewModel],
        endingAt: Date = Date(),
        spanSeconds: TimeInterval = 86400
    ) -> [SeverityTimelineBin] {
        let cal = Calendar(identifier: .gregorian)
        let cutoff = endingAt.addingTimeInterval(-spanSeconds)
        var bucket: [Date: (c: Int, h: Int, m: Int, l: Int)] = [:]

        for alert in alerts {
            guard !alert.ruleId.hasPrefix("maccrab.campaign."),
                  alert.timestamp >= cutoff,
                  alert.timestamp <= endingAt
            else { continue }
            let comps = cal.dateComponents([.year, .month, .day, .hour], from: alert.timestamp)
            guard let bin = cal.date(from: comps) else { continue }
            var cur = bucket[bin] ?? (0, 0, 0, 0)
            switch alert.severity {
            case .critical:                  cur.c += 1
            case .high:                      cur.h += 1
            case .medium:                    cur.m += 1
            case .low, .informational:       cur.l += 1
            }
            bucket[bin] = cur
        }

        // Backfill empty hours.
        let startHour = cal.date(
            from: cal.dateComponents([.year, .month, .day, .hour], from: cutoff)
        ) ?? cutoff
        var t = startHour
        while t <= endingAt {
            if bucket[t] == nil { bucket[t] = (0, 0, 0, 0) }
            t = t.addingTimeInterval(3600)
        }

        return bucket
            .map { entry in
                SeverityTimelineBin(
                    id: entry.key, date: entry.key,
                    critical: entry.value.c,
                    high: entry.value.h,
                    medium: entry.value.m,
                    low: entry.value.l
                )
            }
            .sorted { $0.date < $1.date }
    }

    /// Hours that had at least one campaign-prefix alert fire. Used as
    /// scatter-marker positions overlaid on the bar histogram.
    static func campaignHours(
        from alerts: [AlertViewModel],
        endingAt: Date = Date(),
        spanSeconds: TimeInterval = 86400
    ) -> [Date] {
        let cal = Calendar(identifier: .gregorian)
        let cutoff = endingAt.addingTimeInterval(-spanSeconds)
        var hours = Set<Date>()
        for alert in alerts where alert.ruleId.hasPrefix("maccrab.campaign.") {
            guard alert.timestamp >= cutoff, alert.timestamp <= endingAt else { continue }
            let comps = cal.dateComponents([.year, .month, .day, .hour], from: alert.timestamp)
            if let h = cal.date(from: comps) { hours.insert(h) }
        }
        return Array(hours).sorted()
    }
}
