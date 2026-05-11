// V2DataTable.swift
// Reusable dense data table for the v2 dashboard surfaces.
// Per spec §5.2: header row, sticky filters, row selection, hover.
//
// Phase 2 scope: column-driven rendering, single-row selection,
// hover background. Column resize / sort / virtualized rows land
// in phase 3 if needed.

import SwiftUI

public struct V2DataColumn<Item> {
    public let id: String
    public let title: String
    public let width: V2DataColumn<Item>.Width
    public let alignment: HorizontalAlignment
    public let cell: (Item) -> AnyView

    public enum Width {
        case fixed(CGFloat)
        case flexible(min: CGFloat, max: CGFloat? = nil)
    }

    public init<Cell: View>(
        id: String,
        title: String,
        width: Width = .flexible(min: 80),
        alignment: HorizontalAlignment = .leading,
        @ViewBuilder cell: @escaping (Item) -> Cell
    ) {
        self.id = id
        self.title = title
        self.width = width
        self.alignment = alignment
        self.cell = { AnyView(cell($0)) }
    }
}

public struct V2DataTable<Item: Identifiable & Hashable>: View {
    public let columns: [V2DataColumn<Item>]
    public let items: [Item]
    @Binding public var selection: Item?
    @State private var hoveredId: Item.ID?

    public init(
        columns: [V2DataColumn<Item>],
        items: [Item],
        selection: Binding<Item?>
    ) {
        self.columns = columns
        self.items = items
        self._selection = selection
    }

    public var body: some View {
        VStack(spacing: 0) {
            headerRow
            Divider().background(V2Theme.panelBorder)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(items) { item in
                        rowView(item)
                    }
                }
            }
        }
        .v2Panel(padding: 0)
    }

    private var headerRow: some View {
        HStack(spacing: 0) {
            ForEach(columns.indices, id: \.self) { idx in
                let col = columns[idx]
                cell(width: col.width, alignment: col.alignment) {
                    Text(col.title)
                        .font(V2Theme.cardTitle())
                        .foregroundStyle(V2Theme.mutedText)
                        .textCase(.uppercase)
                }
            }
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(V2Theme.sidebarBackground.opacity(0.6))
    }

    @ViewBuilder
    private func rowView(_ item: Item) -> some View {
        let isSelected = selection?.id == item.id
        let isHovered = hoveredId == item.id

        Button {
            selection = item
        } label: {
            HStack(spacing: 0) {
                ForEach(columns.indices, id: \.self) { idx in
                    let col = columns[idx]
                    cell(width: col.width, alignment: col.alignment) {
                        col.cell(item)
                    }
                }
            }
            .padding(.vertical, 10)
            .padding(.horizontal, 12)
            .background(rowBackground(isSelected: isSelected, isHovered: isHovered))
            .overlay(
                Rectangle()
                    .fill(isSelected ? V2Theme.brand : .clear)
                    .frame(width: 2),
                alignment: .leading
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover in
            hoveredId = hover ? item.id : (hoveredId == item.id ? nil : hoveredId)
        }
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

    private func rowBackground(isSelected: Bool, isHovered: Bool) -> Color {
        if isSelected { return V2Theme.brand.opacity(0.10) }
        if isHovered  { return V2Theme.hoverBackground }
        return Color.clear
    }

    @ViewBuilder
    private func cell<C: View>(
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
