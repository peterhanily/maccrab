// V2DataTable.swift
// Reusable dense data table for the v2 dashboard surfaces.
// Per spec §5.2: header row, sticky filters, row selection, hover.
//
// Phase 2 scope: column-driven rendering, single-row selection,
// hover background. Column resize / sort / virtualized rows land
// in phase 3 if needed.

import SwiftUI

/// A type-correct sort key for a `V2DataColumn`. Strings compare
/// case-insensitively, numbers/dates compare naturally (so "10" sorts after
/// "9", not before). Also yields a `filterText` so a single per-column closure
/// powers BOTH column sorting and the table's text filter.
public enum V2Sortable: Comparable {
    case text(String)
    case number(Double)
    case date(Date)

    private var rank: Int { switch self { case .text: return 0; case .number: return 1; case .date: return 2 } }

    public static func < (l: V2Sortable, r: V2Sortable) -> Bool {
        switch (l, r) {
        case let (.text(a), .text(b)):     return a.localizedCaseInsensitiveCompare(b) == .orderedAscending
        case let (.number(a), .number(b)): return a < b
        case let (.date(a), .date(b)):     return a < b
        default:                           return l.rank < r.rank
        }
    }

    public var filterText: String {
        switch self {
        case .text(let s):   return s
        case .number(let n): return n == n.rounded() ? String(Int(n)) : String(n)
        case .date(let d):   return V2TimeFormat.short(d)
        }
    }
}

public struct V2DataColumn<Item> {
    public let id: String
    public let title: String
    public let width: V2DataColumn<Item>.Width
    public let alignment: HorizontalAlignment
    public let cell: (Item) -> AnyView
    /// When non-nil the column header becomes a click-to-sort button and the
    /// value participates in the table's text filter. nil = not sortable.
    public let sortKey: ((Item) -> V2Sortable)?

    public enum Width {
        case fixed(CGFloat)
        case flexible(min: CGFloat, max: CGFloat? = nil)
    }

    public init<Cell: View>(
        id: String,
        title: String,
        width: Width = .flexible(min: 80),
        alignment: HorizontalAlignment = .leading,
        sortKey: ((Item) -> V2Sortable)? = nil,
        @ViewBuilder cell: @escaping (Item) -> Cell
    ) {
        self.id = id
        self.title = title
        self.width = width
        self.alignment = alignment
        self.sortKey = sortKey
        self.cell = { AnyView(cell($0)) }
    }
}

public struct V2DataTable<Item: Identifiable & Hashable>: View {
    public let columns: [V2DataColumn<Item>]
    public let items: [Item]
    @Binding public var selection: Item?
    /// When set, a filter field appears above the table that narrows rows by any
    /// sortable column's value. Leave nil for views that already have their own
    /// search box (Alerts, Rules) so there is no duplicate filter.
    public let searchPrompt: String?
    @State private var sortColumnId: String?
    @State private var sortAscending = true
    @State private var filterQuery = ""
    /// v1.18.1: stored, not computed. The computed form re-ran the filter +
    /// O(n log n) sort on EVERY body re-evaluation — including each hover
    /// boundary crossing while hover was table-level state. Recomputed only
    /// when an input actually changes (same discipline as EventStream's
    /// filteredCache).
    @State private var displayCache: [Item] = []

    public init(
        columns: [V2DataColumn<Item>],
        items: [Item],
        selection: Binding<Item?>,
        searchPrompt: String? = nil
    ) {
        self.columns = columns
        self.items = items
        self._selection = selection
        self.searchPrompt = searchPrompt
        // v1.19: seed displayCache synchronously so the FIRST body eval renders
        // rows. Previously it started [] and filled in .onAppear, so the first
        // frame painted an empty table before onAppear ran — a one-frame empty
        // flash on every mount. At init the filter is "" and no sort column is
        // set, so the initial display is just `items` (no filter/sort applied).
        self._displayCache = State(initialValue: Self.computeDisplay(
            items: items, columns: columns,
            filterQuery: "", sortColumnId: nil, sortAscending: true))
    }

    /// Pure filter+sort, used both for the init seed and on every input change.
    /// Filter (by any sortable column's text) then sort (by the active column).
    /// `internal` (not private) so the init-seed contract is unit-testable.
    static func computeDisplay(
        items: [Item],
        columns: [V2DataColumn<Item>],
        filterQuery: String,
        sortColumnId: String?,
        sortAscending: Bool
    ) -> [Item] {
        var result = items
        let q = filterQuery.trimmingCharacters(in: .whitespaces).lowercased()
        if !q.isEmpty {
            let keys = columns.compactMap { $0.sortKey }
            result = result.filter { item in
                keys.contains { $0(item).filterText.lowercased().contains(q) }
            }
        }
        if let sid = sortColumnId,
           let key = columns.first(where: { $0.id == sid })?.sortKey {
            result = result.sorted { a, b in
                sortAscending ? key(a) < key(b) : key(b) < key(a)
            }
        }
        return result
    }

    private func recomputeDisplay() {
        displayCache = Self.computeDisplay(
            items: items, columns: columns,
            filterQuery: filterQuery, sortColumnId: sortColumnId, sortAscending: sortAscending)
    }

    public var body: some View {
        VStack(spacing: 0) {
            if let prompt = searchPrompt {
                filterField(prompt)
                Divider().background(V2Theme.panelBorder)
            }
            headerRow
            Divider().background(V2Theme.panelBorder)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(displayCache) { item in
                        Row(
                            columns: columns,
                            item: item,
                            isSelected: selection?.id == item.id,
                            select: { selection = $0 }
                        )
                    }
                }
            }
        }
        .v2Panel(padding: 0)
        .onAppear { recomputeDisplay() }
        .onChange(of: items) { _ in recomputeDisplay() }
        .onChange(of: filterQuery) { _ in recomputeDisplay() }
        .onChange(of: sortColumnId) { _ in recomputeDisplay() }
        .onChange(of: sortAscending) { _ in recomputeDisplay() }
    }

    private func filterField(_ prompt: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: "line.3.horizontal.decrease.circle")
                .foregroundStyle(V2Theme.mutedText)
            TextField(prompt, text: $filterQuery)
                .textFieldStyle(.plain)
                .font(V2Theme.body())
            if !filterQuery.isEmpty {
                Button { filterQuery = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(V2Theme.mutedText)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(V2Theme.sidebarBackground.opacity(0.4))
    }

    private func toggleSort(_ id: String) {
        if sortColumnId == id { sortAscending.toggle() }
        else { sortColumnId = id; sortAscending = true }
    }

    private var headerRow: some View {
        HStack(spacing: 0) {
            ForEach(columns.indices, id: \.self) { idx in
                let col = columns[idx]
                Self.cell(width: col.width, alignment: col.alignment) {
                    if col.sortKey != nil {
                        Button { toggleSort(col.id) } label: {
                            HStack(spacing: 3) {
                                Text(col.title)
                                    .font(V2Theme.cardTitle())
                                    .foregroundStyle(sortColumnId == col.id ? V2Theme.primaryText : V2Theme.mutedText)
                                    .textCase(.uppercase)
                                if sortColumnId == col.id {
                                    Image(systemName: sortAscending ? "chevron.up" : "chevron.down")
                                        .font(.system(size: 8, weight: .bold))
                                        .foregroundStyle(V2Theme.brand)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("Sort by \(col.title)")
                    } else {
                        Text(col.title)
                            .font(V2Theme.cardTitle())
                            .foregroundStyle(V2Theme.mutedText)
                            .textCase(.uppercase)
                    }
                }
            }
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(V2Theme.sidebarBackground.opacity(0.6))
    }

    /// v1.18.1: hover state lives in the row, not the table. A hover
    /// boundary crossing used to mutate table-level @State and re-evaluate
    /// every visible row; now it re-renders exactly the row under the
    /// pointer.
    private struct Row: View {
        let columns: [V2DataColumn<Item>]
        let item: Item
        let isSelected: Bool
        let select: (Item) -> Void
        @State private var isHovered = false

        var body: some View {
            Button {
                select(item)
            } label: {
                HStack(spacing: 0) {
                    ForEach(columns.indices, id: \.self) { idx in
                        let col = columns[idx]
                        V2DataTable.cell(width: col.width, alignment: col.alignment) {
                            col.cell(item)
                        }
                    }
                }
                .padding(.vertical, 10)
                .padding(.horizontal, 12)
                .background(background)
                .overlay(
                    Rectangle()
                        .fill(isSelected ? V2Theme.brand : .clear)
                        .frame(width: 2),
                    alignment: .leading
                )
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .onHover { isHovered = $0 }
            // VoiceOver: combine the row's cells into a single labelled
            // button so VO doesn't read the row as 5 separate elements
            // ("button", "text", "text", "chip", "text"…). The .combine
            // traversal collapses each cell's text into one announcement.
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : [.isButton])
            .accessibilityHint("Activate to select this row")
            .overlay(
                Rectangle().fill(V2Theme.panelBorder).frame(height: 1),
                alignment: .bottom
            )
        }

        private var background: Color {
            if isSelected { return V2Theme.brand.opacity(0.10) }
            if isHovered  { return V2Theme.hoverBackground }
            return Color.clear
        }
    }

    @ViewBuilder
    private static func cell<C: View>(
        width: V2DataColumn<Item>.Width,
        alignment: HorizontalAlignment,
        @ViewBuilder content: () -> C
    ) -> some View {
        Group {
            switch width {
            case .fixed(let w):
                content()
                    .frame(width: w, alignment: Alignment(horizontal: alignment, vertical: .center))
            case .flexible(let minW, let maxW):
                content()
                    .frame(minWidth: minW, maxWidth: maxW ?? .infinity,
                           alignment: Alignment(horizontal: alignment, vertical: .center))
            }
        }
        .padding(.horizontal, 6)
    }
}

// MARK: - Helpers for table cells

public struct V2TableCellText: View {
    let text: String
    let primary: Bool
    let mono: Bool
    let lineLimit: Int?
    public init(_ text: String, primary: Bool = true, mono: Bool = false, lineLimit: Int? = 1) {
        self.text = text
        self.primary = primary
        self.mono = mono
        self.lineLimit = lineLimit
    }
    public var body: some View {
        Text(text)
            .font(mono ? V2Theme.mono() : V2Theme.body())
            .foregroundStyle(primary ? V2Theme.primaryText : V2Theme.mutedText)
            .lineLimit(lineLimit)
            .truncationMode(.tail)
    }
}
