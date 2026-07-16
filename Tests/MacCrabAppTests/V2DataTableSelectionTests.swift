// V2DataTableSelectionTests.swift
// v1.21.4: V2DataTable gained an opt-in multi-select mode. These tests pin the
// two pure selection helpers that back it — `updatedMultiSelection` (plain
// toggle + move anchor, or shift-range union) and `toggledSelectAll` (select /
// deselect all displayed while preserving off-screen selections). Both are
// value transforms, so they're exercised without standing up a SwiftUI view.

import Testing
@testable import MacCrabApp

@Suite("V2DataTable multi-select algebra (v1.21.4)")
struct V2DataTableSelectionTests {

    private struct Item: Identifiable, Hashable {
        let id: Int
    }

    private let ordered = [1, 2, 3, 4, 5]

    // MARK: - updatedMultiSelection

    @Test("plain click on an unselected id inserts it and moves the anchor")
    func plainClickInserts() {
        let out = V2DataTable<Item>.updatedMultiSelection(
            current: [], tapped: 3, orderedIDs: ordered, anchor: nil, rangeSelect: false)
        #expect(out.selection == [3])
        #expect(out.anchor == 3)
    }

    @Test("plain click on a selected id removes it and moves the anchor")
    func plainClickTogglesOff() {
        let out = V2DataTable<Item>.updatedMultiSelection(
            current: [1, 3], tapped: 3, orderedIDs: ordered, anchor: 1, rangeSelect: false)
        #expect(out.selection == [1])
        #expect(out.anchor == 3)
    }

    @Test("shift click unions the contiguous span between anchor and tap; anchor stays")
    func shiftRangeSelectsSpan() {
        let out = V2DataTable<Item>.updatedMultiSelection(
            current: [], tapped: 4, orderedIDs: ordered, anchor: 2, rangeSelect: true)
        #expect(out.selection == [2, 3, 4])
        #expect(out.anchor == 2, "range-select keeps the original anchor")
    }

    @Test("shift range works when the tap is before the anchor (order-independent)")
    func shiftRangeReversed() {
        let out = V2DataTable<Item>.updatedMultiSelection(
            current: [5], tapped: 1, orderedIDs: ordered, anchor: 3, rangeSelect: true)
        #expect(out.selection == [1, 2, 3, 5], "existing selection is preserved and the span added")
        #expect(out.anchor == 3)
    }

    @Test("shift click with no anchor falls back to a plain toggle")
    func shiftWithoutAnchorTogglesPlainly() {
        let out = V2DataTable<Item>.updatedMultiSelection(
            current: [], tapped: 2, orderedIDs: ordered, anchor: nil, rangeSelect: true)
        #expect(out.selection == [2])
        #expect(out.anchor == 2)
    }

    // MARK: - toggledSelectAll

    @Test("select-all from empty selects every displayed id")
    func selectAllFromEmpty() {
        let out = V2DataTable<Item>.toggledSelectAll(current: [], displayedIDs: ordered)
        #expect(out == Set(ordered))
    }

    @Test("select-all when all displayed are already selected deselects them")
    func selectAllWhenFullDeselects() {
        let out = V2DataTable<Item>.toggledSelectAll(current: Set(ordered), displayedIDs: ordered)
        #expect(out.isEmpty)
    }

    @Test("select-all from a partial selection adds the rest")
    func selectAllFromPartial() {
        let out = V2DataTable<Item>.toggledSelectAll(current: [2], displayedIDs: ordered)
        #expect(out == Set(ordered))
    }

    @Test("select-all preserves selections for rows not currently displayed")
    func selectAllPreservesOffscreen() {
        // 99 isn't in the displayed set (e.g. filtered out) — it must survive.
        let out = V2DataTable<Item>.toggledSelectAll(current: [99], displayedIDs: ordered)
        #expect(out == Set(ordered).union([99]))
    }

    @Test("select-all with nothing displayed is a no-op")
    func selectAllEmptyDisplayedNoop() {
        let out = V2DataTable<Item>.toggledSelectAll(current: [7], displayedIDs: [])
        #expect(out == [7])
    }
}
