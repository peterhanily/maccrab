// V2FlowGridLayout.swift
// A snapping flow grid for the customizable Overview dashboard. Widgets flow
// left-to-right into a fixed number of columns; each widget occupies a whole
// number of columns (its "span"), wrapping to the next row when it doesn't fit.
// Items in a row share the row's height so the bottoms line up — far more
// robust than free-form pixel resize, and it reflows automatically when a
// widget is resized or reordered.

import SwiftUI

/// Per-subview column span, read by `V2FlowGridLayout`. Default 1.
private struct WidgetSpanKey: LayoutValueKey {
    static let defaultValue: Int = 1
}

extension View {
    /// Declare how many grid columns this widget occupies inside `V2FlowGridLayout`.
    func widgetSpan(_ span: Int) -> some View {
        layoutValue(key: WidgetSpanKey.self, value: span)
    }
}

struct V2FlowGridLayout: Layout {
    var columns: Int = 4
    var spacing: CGFloat = 8        // horizontal gap between columns
    var rowSpacing: CGFloat = 12    // vertical gap between rows

    /// One placed item: which subview, its origin, and the size it was given.
    /// Internal (not private) so the cached layout can be stored in `Cache`.
    struct Placement {
        let index: Int
        let frame: CGRect
    }

    private func columnWidth(for totalWidth: CGFloat) -> CGFloat {
        let gaps = CGFloat(max(0, columns - 1)) * spacing
        return max(1, (totalWidth - gaps) / CGFloat(columns))
    }

    private func width(forSpan span: Int, colWidth: CGFloat) -> CGFloat {
        CGFloat(span) * colWidth + CGFloat(span - 1) * spacing
    }

    /// Pack subviews into rows and resolve every frame for a given total width.
    private func layout(subviews: Subviews, totalWidth: CGFloat) -> (placements: [Placement], totalHeight: CGFloat) {
        let colWidth = columnWidth(for: totalWidth)
        var placements: [Placement] = []
        var y: CGFloat = 0

        var rowStart = 0
        while rowStart < subviews.count {
            // Greedily fill one row.
            var usedCols = 0
            var rowEnd = rowStart
            var rowSpans: [Int] = []
            while rowEnd < subviews.count {
                let span = min(max(1, subviews[rowEnd][WidgetSpanKey.self]), columns)
                if usedCols > 0 && usedCols + span > columns { break }
                rowSpans.append(span)
                usedCols += span
                rowEnd += 1
            }

            // Measure the row (each item sized to its span width), take max height.
            var heights: [CGFloat] = []
            for (offset, span) in rowSpans.enumerated() {
                let w = width(forSpan: span, colWidth: colWidth)
                let h = subviews[rowStart + offset].sizeThatFits(.init(width: w, height: nil)).height
                heights.append(h)
            }
            let rowHeight = heights.max() ?? 0

            // Place the row.
            var x: CGFloat = 0
            for (offset, span) in rowSpans.enumerated() {
                let w = width(forSpan: span, colWidth: colWidth)
                placements.append(Placement(index: rowStart + offset,
                                            frame: CGRect(x: x, y: y, width: w, height: rowHeight)))
                x += w + spacing
            }

            y += rowHeight + rowSpacing
            rowStart = rowEnd
        }

        let totalHeight = max(0, y - rowSpacing)   // trailing rowSpacing not counted
        return (placements, totalHeight)
    }

    /// Remembers the width measured in `sizeThatFits` so `placeSubviews` lays
    /// out against the *same* width — otherwise the height we reported (for the
    /// proposed width) and the arrangement we place (for bounds.width) could
    /// diverge and misalign the grid. It also caches the resolved placements so
    /// `placeSubviews` reuses the measurement `sizeThatFits` already did (each
    /// `layout()` call measures every subview — content cards aren't free), as
    /// long as the width and subview count still match.
    struct Cache { var width: CGFloat?; var count: Int = 0; var placements: [Placement] = [] }

    func makeCache(subviews: Subviews) -> Cache { Cache() }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout Cache) -> CGSize {
        let width = proposal.replacingUnspecifiedDimensions(by: .init(width: 600, height: 0)).width
        let (placements, height) = layout(subviews: subviews, totalWidth: width)
        cache.width = width
        cache.count = subviews.count
        cache.placements = placements
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout Cache) {
        let width = cache.width ?? bounds.width
        let placements: [Placement]
        if cache.width == width, cache.count == subviews.count, !cache.placements.isEmpty {
            placements = cache.placements                                   // reuse sizeThatFits' work
        } else {
            placements = layout(subviews: subviews, totalWidth: width).placements
        }
        for p in placements {
            // Bottom-align within the row cell so items of unequal height (e.g. a
            // fixed-height KPI tile beside a taller card) line up along their
            // bottoms instead of leaving a gap under the shorter one.
            subviews[p.index].place(
                at: CGPoint(x: bounds.minX + p.frame.minX, y: bounds.minY + p.frame.maxY),
                anchor: .bottomLeading,
                proposal: .init(width: p.frame.width, height: p.frame.height)
            )
        }
    }
}
