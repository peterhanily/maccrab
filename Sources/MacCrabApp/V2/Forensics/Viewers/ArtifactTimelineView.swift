// ArtifactTimelineView — chronological list of artifacts
// grouped by day, with a vertical time spine on the left.
//
// Requires the ViewerHint to declare a field with role
// .timestamp. Falls back to artifact.record.observedAt if no
// data field is declared.

import SwiftUI
import MacCrabForensics

struct ArtifactTimelineView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    private var timestampField: String {
        FieldResolver.field(forRole: .timestamp, in: hint) ?? "observed_at"
    }

    private var titleField: String? {
        FieldResolver.field(forRole: .title, in: hint)
    }

    private var subtitleField: String? {
        FieldResolver.field(forRole: .subtitle, in: hint)
    }

    private var sortedItems: [TimelineItem] {
        artifacts.compactMap { a in
            let ts = FieldResolver.resolve(a, field: timestampField).asDate
                ?? a.record.observedAt
            return TimelineItem(artifact: a, when: ts)
        }
        .sorted { $0.when > $1.when }
    }

    private var grouped: [(day: Date, items: [TimelineItem])] {
        let cal = Calendar.current
        var dict: [Date: [TimelineItem]] = [:]
        for it in sortedItems {
            let day = cal.startOfDay(for: it.when)
            dict[day, default: []].append(it)
        }
        return dict.keys.sorted(by: >).map { ($0, dict[$0]!) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ForEach(grouped, id: \.day) { group in
                    dayBlock(group.day, items: group.items)
                }
                if artifacts.isEmpty {
                    Text("No events for this content type.")
                        .font(.system(size: 11))
                        .foregroundStyle(.tertiary)
                        .padding(20)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 10)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private func dayBlock(_ day: Date, items: [TimelineItem]) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(day.formatted(date: .complete, time: .omitted))
                .font(.system(size: 10, weight: .semibold))
                .foregroundStyle(.tertiary)
                .textCase(.uppercase)
                .padding(.horizontal, 14)
            VStack(spacing: 0) {
                ForEach(items.prefix(200), id: \.artifact.id) { it in
                    eventRow(it)
                }
                if items.count > 200 {
                    Text("+ \(items.count - 200) more on this day")
                        .font(.system(size: 10))
                        .foregroundStyle(.tertiary)
                        .padding(.leading, 60)
                        .padding(.vertical, 4)
                }
            }
        }
    }

    private func eventRow(_ it: TimelineItem) -> some View {
        let sev = FindingHeuristics.severity(for: it.artifact)
        return HStack(alignment: .top, spacing: 10) {
            VStack(spacing: 2) {
                Text(timeOnly(it.when))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundStyle(.secondary)
                Circle()
                    .fill(severityColor(sev))
                    .frame(width: 6, height: 6)
                Rectangle()
                    .fill(Color.secondary.opacity(0.15))
                    .frame(width: 1)
                    .frame(maxHeight: .infinity)
            }
            .frame(width: 50)

            VStack(alignment: .leading, spacing: 2) {
                Text(resolvedTitle(it.artifact))
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(2)
                Text(resolvedSubtitle(it.artifact))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 6)
    }

    /// Title rendered in the timeline row. Falls back through:
    /// (1) hint's title field value, if non-empty; (2) summary,
    /// if non-empty; (3) friendly content-type label. Avoids the
    /// "Chrome by itself with no context" failure case.
    private func resolvedTitle(_ a: CommittedArtifact) -> String {
        if let tf = titleField {
            let v = FieldResolver.resolve(a, field: tf)
            if !v.isEmpty { return v.displayString() }
        }
        if let s = a.record.summary, !s.isEmpty { return s }
        return ScannerDisplay.name(forContentType: a.record.contentType)
    }

    /// Subtitle. Always renders something so the row's right side
    /// isn't blank. Order:
    /// (1) hint's subtitle field value, if non-empty
    /// (2) friendly content-type label (when title already shows
    ///     the field value)
    /// (3) "(no detail)" placeholder
    private func resolvedSubtitle(_ a: CommittedArtifact) -> String {
        if let sf = subtitleField {
            let v = FieldResolver.resolve(a, field: sf)
            if !v.isEmpty { return v.displayString() }
        }
        // If title used the title-role field, surface content-type as
        // secondary context. If title fell back, use the plugin id.
        if let tf = titleField {
            let v = FieldResolver.resolve(a, field: tf)
            if !v.isEmpty { return ScannerDisplay.name(forContentType: a.record.contentType) }
        }
        return ScannerDisplay.name(forPluginID: a.record.pluginID)
    }

    private func timeOnly(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: d)
    }

    private func severityColor(_ s: FindingSeverity) -> Color {
        switch s {
        case .critical:  return .red
        case .attention: return .orange
        case .notable:   return .blue
        case .routine:   return .secondary
        }
    }

    private struct TimelineItem: Equatable {
        let artifact: CommittedArtifact
        let when: Date

        static func == (lhs: TimelineItem, rhs: TimelineItem) -> Bool {
            lhs.artifact.id == rhs.artifact.id
        }
    }
}
