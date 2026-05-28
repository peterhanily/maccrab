// ArtifactBarChartView — categorical counts. Plugin declares
// chartHint.groupField (e.g. "domain" for safari history,
// "handle_id" for iMessage), the viewer counts artifacts per
// distinct value, sorts descending, and renders the top-20
// + an "Other" overflow bucket.
//
// Tappable bars route to a future timeline-filtered view (not
// in rc.15 — for now they're a visual summary only).

import SwiftUI
import Charts
import MacCrabForensics

struct ArtifactBarChartView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    private var chartHint: ChartHint? { hint.chart }

    private var groupField: String? {
        chartHint?.groupField
            ?? FieldResolver.field(forRole: .subtitle, in: hint)
            ?? FieldResolver.field(forRole: .title, in: hint)
    }

    private static let topN = 20

    private var buckets: [(label: String, count: Int)] {
        guard let field = groupField else { return [] }
        var dict: [String: Int] = [:]
        for a in artifacts {
            let v = FieldResolver.resolve(a, field: field)
            let key = v.displayString()
            if key.isEmpty { continue }
            dict[key, default: 0] += 1
        }
        let sorted = dict.sorted { $0.value > $1.value }
        let top = Array(sorted.prefix(Self.topN))
        let otherCount = sorted.dropFirst(Self.topN).reduce(0) { $0 + $1.value }
        if otherCount > 0 {
            return top.map { ($0.key, $0.value) } + [("(other)", otherCount)]
        }
        return top.map { ($0.key, $0.value) }
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
            Text("Top \(min(buckets.count, Self.topN)) by \(humanField)")
                .font(.system(size: 12, weight: .semibold))
            Spacer()
            Text("\(artifacts.count) total event\(artifacts.count == 1 ? "" : "s")")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
    }

    private var emptyState: some View {
        Text(groupField == nil
             ? "No groupField declared in this plugin's chart hint."
             : "No data for the declared group field.")
            .font(.system(size: 11))
            .foregroundStyle(.tertiary)
            .padding(.vertical, 20)
    }

    private var chart: some View {
        ScrollView {
            Chart(buckets, id: \.label) { b in
                BarMark(
                    x: .value("Count", b.count),
                    y: .value(humanField, b.label)
                )
                .foregroundStyle(b.label == "(other)" ? Color.gray.opacity(0.5) : Color.accentColor.opacity(0.85))
                .annotation(position: .trailing, alignment: .leading) {
                    Text("\(b.count)")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundStyle(.secondary)
                }
            }
            .chartXAxis {
                AxisMarks(position: .top)
            }
            .frame(maxWidth: .infinity, minHeight: CGFloat(buckets.count) * 22 + 40)
        }
        .frame(maxHeight: .infinity)
    }

    private var humanField: String {
        guard let f = groupField else { return "value" }
        return f.replacingOccurrences(of: "_", with: " ")
    }
}
