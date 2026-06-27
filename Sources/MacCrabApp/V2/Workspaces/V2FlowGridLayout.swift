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

    /// Masonry pack: each widget keeps its NATURAL height and drops into the
    /// column-group (its span's worth of adjacent columns) whose current bottom is
    /// lowest — i.e. the shortest gap. Because items aren't forced to a
    /// shared row height, a tall card next to a short one never leaves the dead
    /// space a row-based layout would (the gaps that kept reappearing). A
    /// full-width (span = columns) item lands below everything and resets the
    /// shelf. Order is preserved (we iterate in order, leftmost column wins ties).
    private func layout(subviews: Subviews, totalWidth: CGFloat) -> (placements: [Placement], totalHeight: CGFloat) {
        let colWidth = columnWidth(for: totalWidth)
        var placements: [Placement] = []
        // Running bottom (y just past the last item + rowSpacing) of each column.
        var colBottoms = Array(repeating: CGFloat(0), count: columns)

        for index in subviews.indices {
            let span = min(max(1, subviews[index][WidgetSpanKey.self]), columns)
            // Pick the start column (0...columns-span) that places this item
            // highest. Ties keep the leftmost column (iterate ascending, strict <).
            var bestStart = 0
            var bestTop = CGFloat.greatestFiniteMagnitude
            for start in 0...(columns - span) {
                var top: CGFloat = 0
                for c in start..<(start + span) { top = max(top, colBottoms[c]) }
                if top < bestTop {
                    bestTop = top
                    bestStart = start
                }
            }

            let w = width(forSpan: span, colWidth: colWidth)
            let x = CGFloat(bestStart) * (colWidth + spacing)
            let h = subviews[index].sizeThatFits(.init(width: w, height: nil)).height
            placements.append(Placement(index: index, frame: CGRect(x: x, y: bestTop, width: w, height: h)))
            let newBottom = bestTop + h + rowSpacing
            for c in bestStart..<(bestStart + span) { colBottoms[c] = newBottom }
        }

        let totalHeight = max(0, (colBottoms.max() ?? 0) - rowSpacing)   // trailing rowSpacing not counted
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
            // Top-align at the masonry slot: each item is its own natural height
            // (frame.height), so there is no shared-row stretching and no dead
            // space under a shorter card.
            subviews[p.index].place(
                at: CGPoint(x: bounds.minX + p.frame.minX, y: bounds.minY + p.frame.minY),
                anchor: .topLeading,
                proposal: .init(width: p.frame.width, height: p.frame.height)
            )
        }
    }
}
