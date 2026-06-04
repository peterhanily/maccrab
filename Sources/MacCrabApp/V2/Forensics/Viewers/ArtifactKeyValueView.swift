// ArtifactKeyValueView — split-view: left panel picks an
// artifact, right panel shows all its fields. Used for
// content types where each artifact is rich and worth deep
// inspection one-at-a-time (codesign graph node, plist parse,
// Mach-O analysis).
//
// When there's only one artifact, the left panel collapses
// and the detail panel takes the full width.

import SwiftUI
import MacCrabForensics

struct ArtifactKeyValueView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    @State private var selectedID: Int64? = nil

    private var selected: CommittedArtifact? {
        if let id = selectedID, let a = artifacts.first(where: { $0.id == id }) {
            return a
        }
        return artifacts.first
    }

    var body: some View {
        HStack(spacing: 0) {
            if artifacts.count > 1 {
                picker
                    .frame(width: 240)
                Divider()
            }
            if let a = selected {
                detail(a)
            } else {
                Text("No artifacts.")
                    .foregroundStyle(.tertiary)
                    .padding(20)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var picker: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(artifacts.prefix(200), id: \.id) { a in
                    Button {
                        selectedID = a.id
                    } label: {
                        HStack(spacing: 6) {
                            let sev = FindingHeuristics.severity(for: a)
                            Circle()
                                .fill(severityColor(sev))
                                .frame(width: 6, height: 6)
                            Text(rowTitle(a))
                                .scaledSystem(11)
                                .lineLimit(1)
                            Spacer()
                        }
                        .padding(.horizontal, 10).padding(.vertical, 6)
                        .background(selected?.id == a.id ? Color.accentColor.opacity(0.12) : Color.clear)
                        .foregroundStyle(selected?.id == a.id ? Color.accentColor : .primary)
                    }
                    .buttonStyle(.plain)
                }
                if artifacts.count > 200 {
                    Text("Showing first 200 of \(artifacts.count)")
                        .scaledSystem(9)
                        .foregroundStyle(.tertiary)
                        .padding(8)
                }
            }
        }
    }

    private func detail(_ a: CommittedArtifact) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                detailHeader(a)
                Divider()
                fieldGrid(a)
                if !a.record.data.isEmpty {
                    Divider()
                    rawJSONSection(a)
                }
            }
            .padding(16)
        }
    }

    private func detailHeader(_ a: CommittedArtifact) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(rowTitle(a))
                .font(.headline)
            HStack(spacing: 6) {
                Text(a.record.contentType)
                    .scaledSystem(10, design: .monospaced)
                    .foregroundStyle(.tertiary)
                Text("·")
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
                Text(a.record.observedAt.formatted(date: .abbreviated, time: .standard))
                    .scaledSystem(10)
                    .foregroundStyle(.tertiary)
            }
        }
    }

    /// Render each declared field-role field as a labeled row,
    /// with formatting picked per role.
    private func fieldGrid(_ a: CommittedArtifact) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(orderedFields, id: \.self) { field in
                fieldRow(a, field: field)
            }
            // Unmapped data fields below
            let mapped = Set(hint.fieldRoles.keys)
            let extras = a.record.data.keys.filter { !mapped.contains($0) }.sorted()
            if !extras.isEmpty {
                Text("Other fields")
                    .scaledSystem(9, weight: .semibold)
                    .foregroundStyle(.tertiary)
                    .textCase(.uppercase)
                    .padding(.top, 6)
                ForEach(extras, id: \.self) { field in
                    fieldRow(a, field: field)
                }
            }
        }
    }

    private var orderedFields: [String] {
        let priority: [FieldRole] = [
            .title, .subtitle, .timestamp, .severity, .status,
            .sender, .body, .path, .link, .count, .identifier,
        ]
        var ordered: [String] = []
        for role in priority {
            for (field, mapped) in hint.fieldRoles where mapped == role {
                if !ordered.contains(field) { ordered.append(field) }
            }
        }
        return ordered
    }

    private func fieldRow(_ a: CommittedArtifact, field: String) -> some View {
        let v = FieldResolver.resolve(a, field: field)
        let role = hint.fieldRoles[field]
        return HStack(alignment: .top, spacing: 12) {
            Text(humanFieldName(field))
                .scaledSystem(10, weight: .medium)
                .foregroundStyle(.tertiary)
                .frame(width: 110, alignment: .trailing)
            valueText(v, role: role)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func valueText(_ v: ResolvedValue, role: FieldRole?) -> some View {
        if v.isEmpty {
            Text("—").scaledSystem(11).foregroundStyle(.tertiary)
        } else if case .array(let arr) = v {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(Array(arr.prefix(20).enumerated()), id: \.offset) { _, item in
                    Text(FieldResolver.wrap(item).displayString())
                        .scaledSystem(11, design: .monospaced)
                        .textSelection(.enabled)
                }
                if arr.count > 20 {
                    Text("+ \(arr.count - 20) more")
                        .scaledSystem(10)
                        .foregroundStyle(.tertiary)
                }
            }
        } else {
            Text(v.displayString(format: formatFor(role)))
                .scaledSystem(12, design: role == .path || role == .identifier ? .monospaced : .default)
                .foregroundStyle(role == .link ? Color.accentColor : .primary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func formatFor(_ role: FieldRole?) -> LayoutFormat? {
        switch role {
        case .timestamp: return .date
        case .path:      return .path
        case .link:      return .urlLink
        case .count:     return .integerCount
        default:         return nil
        }
    }

    private func rawJSONSection(_ a: CommittedArtifact) -> some View {
        RawJSONDisclosure(value: .object(a.record.data))
    }

    private func rowTitle(_ a: CommittedArtifact) -> String {
        if let titleField = FieldResolver.field(forRole: .title, in: hint) {
            let v = FieldResolver.resolve(a, field: titleField)
            if !v.isEmpty { return v.displayString() }
        }
        return a.record.summary ?? a.record.contentType
    }

    private func severityColor(_ s: FindingSeverity) -> Color {
        switch s {
        case .critical:  return .red
        case .attention: return .orange
        case .notable:   return .blue
        case .routine:   return .secondary
        }
    }

    private func humanFieldName(_ f: String) -> String {
        let s = f.replacingOccurrences(of: "_", with: " ")
        return s.prefix(1).uppercased() + s.dropFirst()
    }
}

/// Full-block-clickable "Raw data JSON" disclosure. SwiftUI's
/// `DisclosureGroup` only toggles when the chevron itself is clicked;
/// operators expect the whole header row to expand/collapse, so this
/// drives the open state from a Button spanning the entire row.
private struct RawJSONDisclosure: View {
    let value: JSONValue
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: expanded ? "chevron.down" : "chevron.right")
                        .scaledSystem(9, weight: .semibold)
                        .foregroundStyle(.secondary)
                        .frame(width: 10)
                    Text("Raw data JSON")
                        .scaledSystem(11, weight: .semibold)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if expanded {
                JSONNodeView(value: value, depth: 1)
                    .padding(.top, 4)
                    .padding(.leading, 16)
            }
        }
    }
}
