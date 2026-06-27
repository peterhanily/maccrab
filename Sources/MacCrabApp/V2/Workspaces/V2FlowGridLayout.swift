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

        // Dense pack (like CSS grid-auto-flow: dense): fill each row left-to-
        // right, pulling the EARLIEST remaining item that fits the leftover
        // columns. This backfills the hole a wide item would otherwise leave
        // when it wraps, so a resize/reorder/window-resize can't strand a ragged
        // gap at any width. Order is preserved except where a later item is
        // pulled up to fill a gap. (Span > columns is clamped, so an empty row
        // always accepts the first remaining item — guaranteed progress.)
        var remaining = Array(subviews.indices)
        while !remaining.isEmpty {
            var rowIdx: [Int] = []
            var rowSpans: [Int] = []
            var usedCols = 0
            var i = 0
            while i < remaining.count && usedCols < columns {
                let span = min(max(1, subviews[remaining[i]][WidgetSpanKey.self]), columns)
                if usedCols + span <= columns {
                    rowIdx.append(remaining[i])
                    rowSpans.append(span)
                    usedCols += span
                    remaining.remove(at: i)   // pulled in; the next item shifts into i
                } else {
                    i += 1                    // doesn't fit here — try a later item
                }
            }

            // If a row still ends short (no remaining item could fill it) AND it
            // holds more than one item, justify it to the full width so there's
            // no ragged edge. A lone tile is left natural (don't balloon it).
            var widths = rowSpans.map { width(forSpan: $0, colWidth: colWidth) }
            if rowSpans.count >= 2, usedCols < columns {
                let gaps = CGFloat(rowSpans.count - 1) * spacing
                let natural = widths.reduce(0, +)
                let target = totalWidth - gaps
                if natural > 0, target > natural {
                    let scale = target / natural
                    widths = widths.map { $0 * scale }
                }
            }

            // Measure the row at the (possibly justified) widths; take max height.
            var heights: [CGFloat] = []
            for (k, w) in widths.enumerated() {
                heights.append(subviews[rowIdx[k]].sizeThatFits(.init(width: w, height: nil)).height)
            }
            let rowHeight = heights.max() ?? 0

            // Place the row.
            var x: CGFloat = 0
            for (k, w) in widths.enumerated() {
                placements.append(Placement(index: rowIdx[k],
                                            frame: CGRect(x: x, y: y, width: w, height: rowHeight)))
                x += w + spacing
            }
            y += rowHeight + rowSpacing
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
