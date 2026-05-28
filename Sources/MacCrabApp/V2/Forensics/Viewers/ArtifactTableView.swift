// ArtifactTableView — sortable, searchable columnar view.
//
// Columns are derived from the ViewerHint:
//   - explicit `columns` array (in order), or
//   - role-driven fallback: timestamp + title + subtitle +
//     status + count + any other declared field-role.
//
// Search box filters rows by any cell value (case-insensitive
// substring match).
//
// Sort: click column header. Default sort = timestamp desc (or
// title asc when no timestamp role).

import SwiftUI
import MacCrabForensics

struct ArtifactTableView: View {
    let artifacts: [CommittedArtifact]
    let hint: ViewerHint

    @State private var query: String = ""
    @State private var sortField: String
    @State private var sortAscending: Bool

    init(artifacts: [CommittedArtifact], hint: ViewerHint) {
        self.artifacts = artifacts
        self.hint = hint
        let columns = Self.columnList(hint: hint)
        // Default sort: timestamp desc, else first column asc.
        if let tsField = FieldResolver.field(forRole: .timestamp, in: hint) {
            self._sortField = State(initialValue: tsField)
            self._sortAscending = State(initialValue: false)
        } else if let first = columns.first {
            self._sortField = State(initialValue: first)
            self._sortAscending = State(initialValue: true)
        } else {
            self._sortField = State(initialValue: "observed_at")
            self._sortAscending = State(initialValue: false)
        }
    }

    private var columns: [String] {
        Self.columnList(hint: hint)
    }

    private var filtered: [CommittedArtifact] {
        let q = query.lowercased()
        let base: [CommittedArtifact]
        if q.isEmpty {
            base = artifacts
        } else {
            base = artifacts.filter { a in
                for col in columns {
                    let v = FieldResolver.resolve(a, field: col)
                    if v.displayString().lowercased().contains(q) {
                        return true
                    }
                }
                return (a.record.summary ?? "").lowercased().contains(q)
            }
        }
        return base.sorted { lhs, rhs in
            let lk = FieldResolver.resolve(lhs, field: sortField).sortKey
            let rk = FieldResolver.resolve(rhs, field: sortField).sortKey
            return sortAscending ? lk < rk : lk > rk
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            searchBar
            Divider()
            headerRow
            Divider()
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(filtered.prefix(500), id: \.id) { a in
                        rowView(a)
                        Divider()
                    }
                    if filtered.count > 500 {
                        Text("Showing first 500 of \(filtered.count). Use search to narrow.")
                            .font(.system(size: 11))
                            .foregroundStyle(.tertiary)
                            .padding(.vertical, 8)
                    }
                }
            }
            .frame(maxHeight: .infinity)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }

    private var searchBar: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 11))
                .foregroundStyle(.tertiary)
            TextField("Search rows", text: $query)
                .textFieldStyle(.plain)
                .font(.system(size: 12))
            Text("\(filtered.count) row\(filtered.count == 1 ? "" : "s")")
                .font(.system(size: 10))
                .foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    private var headerRow: some View {
        HStack(spacing: 8) {
            ForEach(columns, id: \.self) { col in
                Button {
                    if sortField == col {
                        sortAscending.toggle()
                    } else {
                        sortField = col
                        sortAscending = true
                    }
                } label: {
                    HStack(spacing: 3) {
                        Text(humanColumnName(col))
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(.secondary)
                        if sortField == col {
                            Image(systemName: sortAscending ? "chevron.up" : "chevron.down")
                                .font(.system(size: 8))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
    }

    private func rowView(_ a: CommittedArtifact) -> some View {
        HStack(spacing: 8) {
            ForEach(columns, id: \.self) { col in
                cellView(a, field: col)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(rowBackground(a))
    }

    private func cellView(_ a: CommittedArtifact, field: String) -> some View {
        let v = FieldResolver.resolve(a, field: field)
        let role = hint.fieldRoles[field]
        let format: LayoutFormat? = {
            switch role {
            case .timestamp: return .date
            case .path:      return .path
            case .link:      return .urlLink
            default:         return nil
            }
        }()
        return Text(v.displayString(format: format))
            .font(.system(size: 11, design: role == .path || role == .identifier ? .monospaced : .default))
            .foregroundStyle(role == .link ? Color.accentColor : .primary)
            .lineLimit(1)
            .truncationMode(role == .path ? .middle : .tail)
            .textSelection(.enabled)
    }

    private func rowBackground(_ a: CommittedArtifact) -> Color {
        let sev = FindingHeuristics.severity(for: a)
        switch sev {
        case .critical:  return Color.red.opacity(0.08)
        case .attention: return Color.orange.opacity(0.06)
        case .notable:   return Color.blue.opacity(0.04)
        case .routine:   return Color.clear
        }
    }

    // MARK: - Column derivation

    /// Choose which fields to show as columns. Explicit `columns`
    /// in the hint wins; otherwise we follow the role priority.
    static func columnList(hint: ViewerHint) -> [String] {
        if let explicit = hint.columns, !explicit.isEmpty { return explicit }
        var ordered: [String] = []
        let priority: [FieldRole] = [
            .timestamp, .severity, .status, .title, .subtitle, .sender,
            .path, .link, .count, .identifier, .body,
        ]
        for role in priority {
            for (field, mapped) in hint.fieldRoles where mapped == role {
                if !ordered.contains(field) { ordered.append(field) }
            }
        }
        // Any remaining declared field-roles not in the priority list.
        for (field, _) in hint.fieldRoles {
            if !ordered.contains(field) { ordered.append(field) }
        }
        if ordered.isEmpty {
            // No roles declared at all — show observed_at + summary as a
            // minimal table so the operator still sees something.
            ordered = ["observed_at", "summary"]
        }
        return ordered
    }

    private func humanColumnName(_ f: String) -> String {
        // observed_at → "Observed at"; programArguments → "Program arguments"
        let s = f.replacingOccurrences(of: "_", with: " ")
        return s.prefix(1).uppercased() + s.dropFirst()
    }
}
