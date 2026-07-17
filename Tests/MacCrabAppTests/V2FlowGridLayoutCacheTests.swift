// V2FlowGridLayoutCacheTests.swift
// MacCrabAppTests
//
// PERF: V2FlowGridLayout memoizes its masonry pack across re-renders, keyed on
// the measured (width + per-subview span/height) signature — so an unchanged
// re-render (e.g. a 5s refresh tick that didn't move or resize any widget)
// reuses the cached pack instead of re-solving. These pin the pure solver
// (`solve`) that the memo caches: its geometry is correct, it is deterministic
// (identical metrics ⇒ identical placements, which is what makes cache reuse
// safe), and any metric change produces a different pack (which is what forces
// the `cache.metrics == m` guard to re-solve — no stale-height bug).

import Testing
import Foundation
import CoreGraphics
@testable import MacCrabApp

@Suite("V2FlowGridLayout.solve (memoized masonry pack)")
struct V2FlowGridLayoutCacheTests {

    // 4 columns, 8pt gaps: 4*100 + 3*8 = 424 ⇒ colWidth = 100 exactly.
    private let columns = 4
    private let width: CGFloat = 424
    private let spacing: CGFloat = 8
    private let rowSpacing: CGFloat = 12

    private func solve(_ metrics: [V2FlowGridLayout.SubviewMetric])
        -> (placements: [V2FlowGridLayout.Placement], totalHeight: CGFloat) {
        V2FlowGridLayout.solve(metrics: metrics, columns: columns, totalWidth: width,
                               spacing: spacing, rowSpacing: rowSpacing)
    }

    @Test("four span-1 tiles fill row 0 across the four columns")
    func fourAcross() {
        let m = Array(repeating: V2FlowGridLayout.SubviewMetric(span: 1, height: 50), count: 4)
        let out = solve(m)
        #expect(out.placements.count == 4)
        // colWidth 100, column stride = colWidth + spacing = 108.
        for (i, p) in out.placements.enumerated() {
            #expect(p.index == i)
            #expect(p.frame.origin.x == CGFloat(i) * 108)
            #expect(p.frame.origin.y == 0)
            #expect(p.frame.width == 100)
            #expect(p.frame.height == 50)
        }
        // Trailing rowSpacing is not counted in the reported height.
        #expect(out.totalHeight == 50)
    }

    @Test("masonry drops the next tile into the shortest column, leftmost on ties")
    func shortestColumnWins() {
        // col0 tall (100), the other three short (20). A 5th span-1 tile should
        // land in the shortest of col1..3 — all equal (bottom 20) ⇒ leftmost col1.
        let m = [
            V2FlowGridLayout.SubviewMetric(span: 1, height: 100),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 20),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 20),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 20),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 10),
        ]
        let out = solve(m)
        let fifth = out.placements[4]
        #expect(fifth.frame.origin.x == 108)          // column 1
        #expect(fifth.frame.origin.y == 20 + rowSpacing)   // stacked under col1's first tile
    }

    @Test("a full-width tile spans all columns and lands below everything")
    func fullWidthResetsShelf() {
        let m = [
            V2FlowGridLayout.SubviewMetric(span: 1, height: 40),
            V2FlowGridLayout.SubviewMetric(span: 4, height: 30),   // full width
        ]
        let out = solve(m)
        let full = out.placements[1]
        #expect(full.frame.origin.x == 0)
        #expect(full.frame.width == width)             // 4*100 + 3*8 = 424
        #expect(full.frame.origin.y == 40 + rowSpacing)   // below the row-0 tile
    }

    @Test("identical metrics ⇒ identical placements (safe to reuse the cached pack)")
    func deterministicForEqualInputs() {
        let m = [
            V2FlowGridLayout.SubviewMetric(span: 2, height: 124),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 80),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 200),
        ]
        // Equal signatures compare equal (this is the memo hit condition) and
        // re-solving yields byte-identical placements — so reuse is correct.
        #expect(m == m)
        #expect(solve(m).placements == solve(m).placements)
        #expect(solve(m).totalHeight == solve(m).totalHeight)
    }

    @Test("changing one tile's height changes the pack (memo must re-solve)")
    func changedMetricChangesPack() {
        let base = [
            V2FlowGridLayout.SubviewMetric(span: 1, height: 50),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 50),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 50),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 50),
            V2FlowGridLayout.SubviewMetric(span: 1, height: 30),
        ]
        var grown = base
        grown[0] = V2FlowGridLayout.SubviewMetric(span: 1, height: 500)   // col0 grows a lot
        // The signatures differ ⇒ `cache.metrics == m` is false ⇒ re-solve, and
        // the 5th tile now avoids the (very tall) column 0.
        #expect(base != grown)
        #expect(solve(base).placements != solve(grown).placements)
        // With col0 towering, the 5th span-1 tile no longer stacks under col0.
        #expect(solve(grown).placements[4].frame.origin.x != 0)
    }
}
