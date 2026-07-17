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
    struct Placement: Equatable {
        let index: Int
        let frame: CGRect
    }

    /// One subview's layout-affecting inputs: its column span and the natural
    /// height it reported at the width its span resolves to. The masonry flow is
    /// a pure function of `(totalWidth, [SubviewMetric])`, so an identical
    /// signature across a re-render yields identical placements — that's the
    /// memo key (see `resolved`). Measuring is the only unavoidable per-pass cost
    /// (SwiftUI caches a subview's ideal size, so an unchanged subview is cheap),
    /// but re-running the pack + reallocating the placement array on every
    /// heartbeat / refresh tick is not — that is what the memo skips.
    struct SubviewMetric: Equatable {
        let span: Int
        let height: CGFloat
    }

    private func columnWidth(for totalWidth: CGFloat) -> CGFloat {
        let gaps = CGFloat(max(0, columns - 1)) * spacing
        return max(1, (totalWidth - gaps) / CGFloat(columns))
    }

    private func width(forSpan span: Int, colWidth: CGFloat) -> CGFloat {
        CGFloat(span) * colWidth + CGFloat(span - 1) * spacing
    }

    /// Measure each subview against the width its span resolves to, producing the
    /// signature the memo compares. Because the measured heights are IN the key,
    /// a cache hit is only taken when the true layout inputs are unchanged — so a
    /// content change that grows a card (e.g. a "recent activity" list) always
    /// re-solves; there is no stale-height class of bug.
    private func metrics(subviews: Subviews, totalWidth: CGFloat) -> [SubviewMetric] {
        let colWidth = columnWidth(for: totalWidth)
        return subviews.indices.map { index in
            let span = min(max(1, subviews[index][WidgetSpanKey.self]), columns)
            let w = width(forSpan: span, colWidth: colWidth)
            let h = subviews[index].sizeThatFits(.init(width: w, height: nil)).height
            return SubviewMetric(span: span, height: h)
        }
    }

    /// Masonry pack (pure — no view access, so it is unit-testable): each widget
    /// keeps its NATURAL height and drops into the column-group (its span's worth
    /// of adjacent columns) whose current bottom is lowest — i.e. the shortest
    /// gap. Because items aren't forced to a shared row height, a tall card next
    /// to a short one never leaves the dead space a row-based layout would. A
    /// full-width (span = columns) item lands below everything and resets the
    /// shelf. Order is preserved (iterate in order, leftmost column wins ties).
    static func solve(metrics: [SubviewMetric], columns: Int, totalWidth: CGFloat,
                      spacing: CGFloat, rowSpacing: CGFloat)
        -> (placements: [Placement], totalHeight: CGFloat) {
        let gaps = CGFloat(max(0, columns - 1)) * spacing
        let colWidth = max(1, (totalWidth - gaps) / CGFloat(columns))
        var placements: [Placement] = []
        placements.reserveCapacity(metrics.count)
        // Running bottom (y just past the last item + rowSpacing) of each column.
        var colBottoms = Array(repeating: CGFloat(0), count: columns)

        for (index, m) in metrics.enumerated() {
            let span = min(max(1, m.span), columns)
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

            let w = CGFloat(span) * colWidth + CGFloat(span - 1) * spacing
            let x = CGFloat(bestStart) * (colWidth + spacing)
            placements.append(Placement(index: index, frame: CGRect(x: x, y: bestTop, width: w, height: m.height)))
            let newBottom = bestTop + m.height + rowSpacing
            for c in bestStart..<(bestStart + span) { colBottoms[c] = newBottom }
        }

        let totalHeight = max(0, (colBottoms.max() ?? 0) - rowSpacing)   // trailing rowSpacing not counted
        return (placements, totalHeight)
    }

    /// Memoizes the resolved masonry pack across re-renders. `width` is the width
    /// `sizeThatFits` measured against, kept so `placeSubviews` lays out against
    /// the *same* width (otherwise the reported height and the placed arrangement
    /// could diverge and misalign the grid). `metrics` is the measured signature
    /// the memo compares to decide "same inputs → reuse the pack".
    struct Cache {
        var width: CGFloat?
        var metrics: [SubviewMetric] = []
        var placements: [Placement] = []
        var totalHeight: CGFloat = 0
    }

    func makeCache(subviews: Subviews) -> Cache { Cache() }

    /// SwiftUI calls this when the subview set changes (add / remove / reorder).
    /// Drop the memo so the next `sizeThatFits` re-measures + re-solves against
    /// the new subviews rather than reusing a stale pack.
    func updateCache(_ cache: inout Cache, subviews: Subviews) {
        cache = Cache()
    }

    /// Resolve placements + height for `totalWidth`, reusing the cached pack when
    /// the measured `(width, metrics)` signature is unchanged — so a re-render
    /// that didn't move or resize any widget pays only the (cheap) measurement,
    /// not another masonry solve + array allocation.
    private func resolved(subviews: Subviews, totalWidth: CGFloat, cache: inout Cache)
        -> (placements: [Placement], totalHeight: CGFloat) {
        let m = metrics(subviews: subviews, totalWidth: totalWidth)
        if cache.width == totalWidth, cache.metrics == m, !cache.placements.isEmpty {
            return (cache.placements, cache.totalHeight)
        }
        let solved = Self.solve(metrics: m, columns: columns, totalWidth: totalWidth,
                                spacing: spacing, rowSpacing: rowSpacing)
        cache.width = totalWidth
        cache.metrics = m
        cache.placements = solved.placements
        cache.totalHeight = solved.totalHeight
        return solved
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout Cache) -> CGSize {
        let width = proposal.replacingUnspecifiedDimensions(by: .init(width: 600, height: 0)).width
        let (_, height) = resolved(subviews: subviews, totalWidth: width, cache: &cache)
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout Cache) {
        // Lay out against the width `sizeThatFits` measured against. When that
        // width is already resolved in the cache (the common sizeThatFits →
        // placeSubviews sequence), reuse its pack directly — no re-measure.
        let width = cache.width ?? bounds.width
        let placements: [Placement]
        if cache.width == width, !cache.placements.isEmpty {
            placements = cache.placements
        } else {
            placements = resolved(subviews: subviews, totalWidth: width, cache: &cache).placements
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
