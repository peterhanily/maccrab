// ArtifactCompactPreview.swift
//
// A tiny, chrome-free renderer for ≤3 real artifact rows — the
// store's "Recent output" preview. Unlike ArtifactTableView (search
// bar, sortable header, scrolling, .prefix(500)) this is a bounded
// stack: a decorative severity dot, a one-line title, and a short
// relative timestamp. No ScrollView, capped at 3 rows → bounded
// height for free.
//
// Title rule mirrors ArtifactKeyValueView.rowTitle's hint-less
// fallback: summary ?? a human label for the content type. The
// severity dot is presentation-only (FindingHeuristics is
// documented "heuristics, never decisive").

import SwiftUI
import MacCrabForensics

struct ArtifactCompactPreview: View {
    let artifacts: [CommittedArtifact]
    /// Pre-resolved hint; nil for this store preview (no async hint
    /// resolution for a 3-row thumbnail — the summary fallback is
    /// honest and adequate).
    let hint: ViewerHint?

    var body: some View {
        if artifacts.isEmpty {
            Text(String(localized: "raveDetail.recentOutput.noRows", defaultValue: "No rows"))
                .scaledSystem(11).foregroundStyle(.tertiary)
        } else {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(artifacts.prefix(3), id: \.id) { row(for: $0) }
            }
        }
    }

    @ViewBuilder
    private func row(for a: CommittedArtifact) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(severityColor(FindingHeuristics.severity(for: a)))
                .frame(width: 6, height: 6)
            Text(title(for: a))
                .scaledSystem(11)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 4)
            if let sub = subtitle(for: a) {
                Text(sub)
                    .scaledSystem(10)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    private func title(for a: CommittedArtifact) -> String {
        // Hint-driven title field if one is present (none in this
        // pass); else summary ?? a human content-type label —
        // ArtifactKeyValueView.rowTitle's rule, with the raw
        // content_type swapped for its operator-readable name.
        if let field = FieldResolver.field(forRole: .title, in: hint) {
            let v = FieldResolver.resolve(a, field: field)
            if !v.isEmpty { return v.displayString() }
        }
        if let s = a.record.summary, !s.isEmpty { return s }
        return ScannerDisplay.name(forContentType: a.record.contentType)
    }

    /// Short relative "when observed" — the one scalar that reads
    /// well at thumbnail size for every content type.
    private func subtitle(for a: CommittedArtifact) -> String? {
        Self.relativeFormatter.localizedString(for: a.record.observedAt, relativeTo: Date())
    }

    private func severityColor(_ s: FindingSeverity) -> Color {
        switch s {
        case .critical:  return .red
        case .attention: return .orange
        case .notable:   return .blue
        case .routine:   return .secondary
        }
    }

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f
    }()
}
