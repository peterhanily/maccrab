// V2DataTable.swift
// Reusable dense data table for the v2 dashboard surfaces.
// Per spec §5.2: header row, sticky filters, row selection, hover.
//
// Phase 2 scope: column-driven rendering, single-row selection,
// hover background. Column resize / sort / virtualized rows land
// in phase 3 if needed.
//
// v1.21.4: opt-in multi-select mode (a second init taking a
// `Binding<Set<Item.ID>>`). It adds a leading checkbox column for
// bulk selection while the row body still drives the single
// `selection` binding for a detail/inspector pane. The original
// single-select init is unchanged, so every existing caller keeps
// compiling and rendering identically.

import SwiftUI
import AppKit

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
    /// Non-nil only when built via the multi-select init. When present a
    /// leading checkbox column drives this id set; the single `selection`
    /// binding still tracks the row-body click for a detail pane.
    private let multiSelection: Binding<Set<Item.ID>>?
    /// Range-select (shift-click) anchor for multi-select mode.
    @State private var selectionAnchor: Item.ID?
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
    /// v1.19: NO inline default — it is seeded in init() via
    /// State(initialValue:). An inline default here would be discarded by
    /// Xcode 27's @State macro (TN3211), re-introducing the empty-frame flash
    /// the init seed fixes (and pre-release-audit PASS-L2 flags the combo).
    @State private var displayCache: [Item]

    public init(
        columns: [V2DataColumn<Item>],
        items: [Item],
        selection: Binding<Item?>,
        searchPrompt: String? = nil
    ) {
        self.columns = columns
        self.items = items
        self._selection = selection
        self.multiSelection = nil
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

    /// Opt-in multi-select variant. A leading checkbox column toggles
    /// membership in `multiSelection` (with shift-click range extension) for
    /// bulk actions, while a row-body click still sets `selection` so a
    /// detail/inspector pane keeps working. The single-select init above is
    /// untouched, so existing callers are unaffected.
    public init(
        columns: [V2DataColumn<Item>],
        items: [Item],
        selection: Binding<Item?>,
        multiSelection: Binding<Set<Item.ID>>,
        searchPrompt: String? = nil
    ) {
        self.columns = columns
        self.items = items
        self._selection = selection
        self.multiSelection = multiSelection
        self.searchPrompt = searchPrompt
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

    // MARK: - Multi-select (pure selection algebra)

    /// Pure selection-set update for multi-select mode. A plain click toggles
    /// the tapped id and moves the range anchor to it; a range (shift) click
    /// selects the contiguous span between the current anchor and the tapped
    /// id (union with the current set, anchor unchanged). Extracted so the
    /// selection algebra is unit-testable without a SwiftUI view.
    static func updatedMultiSelection(
        current: Set<Item.ID>,
        tapped: Item.ID,
        orderedIDs: [Item.ID],
        anchor: Item.ID?,
        rangeSelect: Bool
    ) -> (selection: Set<Item.ID>, anchor: Item.ID?) {
        if rangeSelect,
           let anchor,
           let a = orderedIDs.firstIndex(of: anchor),
           let b = orderedIDs.firstIndex(of: tapped) {
            let span = orderedIDs[min(a, b)...max(a, b)]
            return (current.union(span), anchor)
        }
        var next = current
        if next.contains(tapped) { next.remove(tapped) } else { next.insert(tapped) }
        return (next, tapped)
    }

    /// Pure "select all displayed" toggle: if every displayed id is already
    /// selected, remove them all; otherwise add them all. Selections for rows
    /// not currently displayed (filtered out) are left untouched.
    static func toggledSelectAll(
        current: Set<Item.ID>,
        displayedIDs: [Item.ID]
    ) -> Set<Item.ID> {
        let displayed = Set(displayedIDs)
        guard !displayed.isEmpty else { return current }
        return displayed.isSubset(of: current)
            ? current.subtracting(displayed)
            : current.union(displayed)
    }

    private var isMulti: Bool { multiSelection != nil }

    private func isChecked(_ item: Item) -> Bool {
        multiSelection?.wrappedValue.contains(item.id) ?? false
    }

    private var allDisplayedChecked: Bool {
        guard let m = multiSelection, !displayCache.isEmpty else { return false }
        return Set(displayCache.map(\.id)).isSubset(of: m.wrappedValue)
    }

    private func toggleCheck(_ item: Item) {
        guard let m = multiSelection else { return }
        let result = Self.updatedMultiSelection(
            current: m.wrappedValue,
            tapped: item.id,
            orderedIDs: displayCache.map(\.id),
            anchor: selectionAnchor,
            rangeSelect: NSEvent.modifierFlags.contains(.shift))
        m.wrappedValue = result.selection
        selectionAnchor = result.anchor
    }

    private func toggleSelectAllDisplayed() {
        guard let m = multiSelection else { return }
        m.wrappedValue = Self.toggledSelectAll(
            current: m.wrappedValue, displayedIDs: displayCache.map(\.id))
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
                            isChecked: isChecked(item),
                            showsCheckbox: isMulti,
                            onSelectRow: { selection = $0 },
                            onToggleCheck: { toggleCheck($0) }
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
            if isMulti {
                Button { toggleSelectAllDisplayed() } label: {
                    Image(systemName: allDisplayedChecked ? "checkmark.square.fill" : "square")
                        .foregroundStyle(allDisplayedChecked ? V2Theme.brand : V2Theme.mutedText)
                        .scaledSystem(14)
                        .frame(width: 36)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .help(allDisplayedChecked ? "Deselect all rows" : "Select all rows")
                .accessibilityLabel(allDisplayedChecked ? "Deselect all rows" : "Select all rows")
            }
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
        /// Multi-select membership. Always false in single-select mode, so the
        /// single path renders identically to phase 2.
        let isChecked: Bool
        /// Whether to render the leading multi-select checkbox.
        let showsCheckbox: Bool
        let onSelectRow: (Item) -> Void
        let onToggleCheck: (Item) -> Void
        @State private var isHovered = false

        var body: some View {
            if showsCheckbox {
                multiRow
            } else {
                singleRow
            }
        }

        /// Single-select row — the whole row is one button that selects the
        /// item. Unchanged from phase 2.
        private var singleRow: some View {
            Button {
                onSelectRow(item)
            } label: {
                cells
                    .padding(.vertical, 10)
                    .padding(.horizontal, 12)
                    .background(background)
                    .overlay(selectionBar, alignment: .leading)
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

        /// Multi-select row — a leading checkbox toggles set membership
        /// (with shift-range at the table level), while the row body still
        /// selects the item for a detail/inspector pane.
        private var multiRow: some View {
            HStack(spacing: 0) {
                Button { onToggleCheck(item) } label: {
                    Image(systemName: isChecked ? "checkmark.square.fill" : "square")
                        .foregroundStyle(isChecked ? V2Theme.brand : V2Theme.mutedText)
                        .scaledSystem(14)
                        .frame(width: 36)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(isChecked ? "Deselect row" : "Select row")
                Button { onSelectRow(item) } label: {
                    cells.contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : [.isButton])
                .accessibilityHint("Activate to open this row")
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 12)
            .background(background)
            .overlay(selectionBar, alignment: .leading)
            .onHover { isHovered = $0 }
            .overlay(
                Rectangle().fill(V2Theme.panelBorder).frame(height: 1),
                alignment: .bottom
            )
        }

        private var cells: some View {
            HStack(spacing: 0) {
                ForEach(columns.indices, id: \.self) { idx in
                    let col = columns[idx]
                    V2DataTable.cell(width: col.width, alignment: col.alignment) {
                        col.cell(item)
                    }
                }
            }
        }

        private var selectionBar: some View {
            Rectangle()
                .fill((isSelected || isChecked) ? V2Theme.brand : .clear)
                .frame(width: 2)
        }

        private var background: Color {
            if isChecked  { return V2Theme.brand.opacity(0.14) }
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
