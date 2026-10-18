import Testing
@testable import MacCrabApp

@Suite("Data-table accepted snapshot coherence")
struct V2DataTableSnapshotTests {
    private struct Item: Identifiable, Hashable {
        let id: Int
        let payload: Int
    }

    @Test("The default display uses current IDs, payloads and empty results, not a prior cached update")
    func defaultSnapshotIsCurrent() {
        let old = [Item(id: 1, payload: 1), Item(id: 2, payload: 1)]
        for current in [[], [Item(id: 1, payload: 2)], [Item(id: 3, payload: 2), Item(id: 1, payload: 2)]] {
            for noFilter in ["", " ", "\t"] {
                let displayed = V2DataTable<Item>.displayedSnapshot(items: current, cached: old,
                    filterQuery: noFilter, sortColumnId: nil)
                #expect(displayed == current)
            }
        }
    }

    @Test("An active local filter or sort keeps the existing transformed cache exactly")
    func transformedSnapshotIsUnchanged() {
        let current = [Item(id: 1, payload: 2), Item(id: 2, payload: 2)]
        for cached in [[], [Item(id: 2, payload: 1), Item(id: 1, payload: 1)]] {
            for (filter, sort): (String, String?) in [("needle", nil), ("", "column"), ("needle", "column"), ("\n", nil)] {
                let displayed = V2DataTable<Item>.displayedSnapshot(items: current, cached: cached,
                    filterQuery: filter, sortColumnId: sort)
                #expect(displayed == cached)
            }
        }
    }

    @Test("Default display does not evaluate the cache accessor; active transforms evaluate it once")
    func cacheReadIsLazy() {
        let current = [Item(id: 1, payload: 2)]
        let old = [Item(id: 1, payload: 1)]
        var cacheReads = 0
        func readCache() -> [Item] { cacheReads += 1; return old }
        for noFilter in ["", " ", "\t"] {
            let displayed = V2DataTable<Item>.displayedSnapshot(items: current, cached: readCache(),
                filterQuery: noFilter, sortColumnId: nil)
            #expect(displayed == current && cacheReads == 0)
        }
        let filtered = V2DataTable<Item>.displayedSnapshot(items: current, cached: readCache(),
            filterQuery: "needle", sortColumnId: nil)
        #expect(filtered == old && cacheReads == 1)
        let sorted = V2DataTable<Item>.displayedSnapshot(items: current, cached: readCache(),
            filterQuery: "", sortColumnId: "column")
        #expect(sorted == old && cacheReads == 2)
    }

    @Test("Header, range and select-all algebra consume the same current default population")
    func selectionUsesDisplayedSnapshot() {
        let old = [Item(id: 1, payload: 1), Item(id: 2, payload: 1)]
        let current = [Item(id: 3, payload: 2), Item(id: 4, payload: 2), Item(id: 5, payload: 2)]
        let displayed = V2DataTable<Item>.displayedSnapshot(items: current, cached: old,
                                                          filterQuery: "", sortColumnId: nil)
        #expect(!V2DataTable<Item>.allDisplayedSelected(items: displayed, selected: [1, 2]))
        #expect(V2DataTable<Item>.allDisplayedSelected(items: displayed, selected: [3, 4, 5]))
        let all = V2DataTable<Item>.toggledSelectAll(current: [99], displayedIDs: displayed.map(\.id))
        #expect(all == [3, 4, 5, 99])
        let range = V2DataTable<Item>.updatedMultiSelection(current: [], tapped: 5,
            orderedIDs: displayed.map(\.id), anchor: 3, rangeSelect: true)
        #expect(range.selection == [3, 4, 5] && range.anchor == 3)
    }
}
