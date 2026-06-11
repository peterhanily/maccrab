// V2DataTableInitTests.swift
// v1.19 (S6-5): V2DataTable's displayCache started [] and only filled in
// .onAppear, so the FIRST body eval painted an empty table before onAppear ran
// — a one-frame empty flash on every mount. The fix seeds displayCache
// synchronously in init() via the pure computeDisplay() helper. These tests
// pin computeDisplay's behaviour, including the init-seed case (empty filter,
// no sort column ⇒ the rows are exactly `items` in order).

import Testing
import SwiftUI
@testable import MacCrabApp

@Suite("V2DataTable init-seed / computeDisplay (S6-5)")
struct V2DataTableInitTests {

    private struct Item: Identifiable, Hashable {
        let id: Int
        let name: String
        let count: Int
    }

    private let items = [
        Item(id: 1, name: "charlie", count: 30),
        Item(id: 2, name: "alpha", count: 10),
        Item(id: 3, name: "bravo", count: 20),
    ]

    private var columns: [V2DataColumn<Item>] {
        [
            V2DataColumn(id: "name", title: "Name",
                         sortKey: { .text($0.name) }) { V2TableCellText($0.name) },
            V2DataColumn(id: "count", title: "Count",
                         sortKey: { .number(Double($0.count)) }) { V2TableCellText("\($0.count)") },
        ]
    }

    /// The init seed: empty filter, no sort column ⇒ rows == items, in order.
    /// This is the exact path that fixes the one-frame empty flash: the first
    /// body eval must already have these rows.
    @Test("init-seed (no filter, no sort) returns items unchanged and non-empty")
    func initSeedReturnsItems() {
        let out = V2DataTable<Item>.computeDisplay(
            items: items, columns: columns,
            filterQuery: "", sortColumnId: nil, sortAscending: true)
        #expect(out.count == items.count, "first frame must have all rows, not an empty table")
        #expect(out.map(\.id) == items.map(\.id), "no sort ⇒ original order preserved")
    }

    @Test("empty items ⇒ empty (no spurious rows)")
    func emptyItemsEmpty() {
        let out = V2DataTable<Item>.computeDisplay(
            items: [], columns: columns,
            filterQuery: "", sortColumnId: nil, sortAscending: true)
        #expect(out.isEmpty)
    }

    @Test("filter narrows by any sortable column's text")
    func filterNarrows() {
        let out = V2DataTable<Item>.computeDisplay(
            items: items, columns: columns,
            filterQuery: "alph", sortColumnId: nil, sortAscending: true)
        #expect(out.map(\.name) == ["alpha"])
    }

    @Test("ascending text sort orders by name")
    func sortAscendingByName() {
        let out = V2DataTable<Item>.computeDisplay(
            items: items, columns: columns,
            filterQuery: "", sortColumnId: "name", sortAscending: true)
        #expect(out.map(\.name) == ["alpha", "bravo", "charlie"])
    }

    @Test("descending numeric sort orders by count")
    func sortDescendingByCount() {
        let out = V2DataTable<Item>.computeDisplay(
            items: items, columns: columns,
            filterQuery: "", sortColumnId: "count", sortAscending: false)
        #expect(out.map(\.count) == [30, 20, 10])
    }
}
