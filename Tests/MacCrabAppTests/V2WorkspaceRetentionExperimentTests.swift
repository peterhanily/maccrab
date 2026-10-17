import AppKit
import Foundation
import SwiftUI
import Testing
@testable import MacCrabApp

/// A bounded mechanism experiment, not a production cache or navigation SLA.
/// Only synthetic rows and private, unshown windows are used. No AppState,
/// provider, stores, preferences, AX client, timers, network or installed app.
@Suite("Workspace retention experiment", .serialized)
struct V2WorkspaceRetentionExperimentTests {
    private struct Item: Identifiable, Hashable {
        let id: Int
        var title: String { "Synthetic row \(id)" }
    }
    private enum Mode: String { case conditional, retained }
    @MainActor private final class Selection: ObservableObject {
        @Published var page = 0
    }
    @MainActor private final class Owner: ObservableObject {
        let id = UUID()
        let page: Int
        var sentinelTicks = 0
        init(page: Int) { self.page = page }
        // Explicit fixture admission only. This is not a production polling or
        // cancellation oracle; it has no timer or asynchronous work at all.
        func fixtureTick(selected: Int) { if page == selected { sentinelTicks += 1 } }
    }
    @MainActor private final class WeakOwner {
        weak var value: Owner?
        init(_ value: Owner) { self.value = value }
    }
    @MainActor private final class WeakHost {
        weak var value: NSView?
        init(_ value: NSView) { self.value = value }
    }
    @MainActor private final class Observations {
        var owners: [UUID: WeakOwner] = [:]
        var latestOwner: [Int: UUID] = [:]
        var pageMakes = 0
        var pageDismantles = 0
        var rowMakes = 0
        var rowIDs: [UUID: Set<Int>] = [:]
        var probeLayouts = 0
        var hostLayouts = 0
    }
    @MainActor private final class ProbeView: NSView {
        let observations: Observations
        init(_ observations: Observations) {
            self.observations = observations
            super.init(frame: .zero)
        }
        required init?(coder: NSCoder) { fatalError("Fixture is programmatic only") }
        override func layout() {
            observations.probeLayouts += 1
            super.layout()
        }
    }
    @MainActor private struct Probe: NSViewRepresentable {
        let owner: Owner
        let row: Int?
        let observations: Observations
        final class Coordinator {
            let observations: Observations
            let isPage: Bool
            init(_ observations: Observations, isPage: Bool) {
                self.observations = observations
                self.isPage = isPage
            }
        }
        func makeCoordinator() -> Coordinator { Coordinator(observations, isPage: row == nil) }
        func makeNSView(context: Context) -> ProbeView {
            if let row {
                observations.rowMakes += 1
                observations.rowIDs[owner.id, default: []].insert(row)
            } else {
                observations.pageMakes += 1
                observations.owners[owner.id] = WeakOwner(owner)
                observations.latestOwner[owner.page] = owner.id
            }
            return ProbeView(observations)
        }
        func updateNSView(_ view: ProbeView, context: Context) {}
        static func dismantleNSView(_ view: ProbeView, coordinator: Coordinator) {
            if coordinator.isPage { coordinator.observations.pageDismantles += 1 }
        }
    }
    @MainActor private struct Page: View {
        let number: Int
        let observations: Observations
        let items: [Item]
        @StateObject private var owner: Owner
        init(_ number: Int, observations: Observations, items: [Item]) {
            self.number = number
            self.observations = observations
            self.items = items
            _owner = StateObject(wrappedValue: Owner(page: number))
        }
        private var columns: [V2DataColumn<Item>] {
            [
                V2DataColumn(id: "title", title: "Title", width: .flexible(min: 200),
                             sortKey: { .text($0.title) }) { item in
                    V2TableCellText(item.title)
                        .background(Probe(owner: owner, row: item.id, observations: observations))
                },
                V2DataColumn(id: "category", title: "Category", width: .fixed(140)) { _ in
                    V2TableCellText(number == 0 ? "Synthetic rule" : "Synthetic alert")
                },
                V2DataColumn(id: "state", title: "State", width: .fixed(120)) { _ in
                    V2StatusChip("Fixture", kind: .healthy)
                },
                V2DataColumn(id: "count", title: "Count", width: .fixed(100),
                             sortKey: { .number(Double($0.id)) }) { item in
                    V2TableCellText(String(item.id), mono: true)
                }
            ]
        }
        var body: some View {
            Group {
                if number == 2 {
                    Table(items) {
                        TableColumn("Title") { item in
                            Text(item.title)
                                .background(Probe(owner: owner, row: item.id, observations: observations))
                        }
                        TableColumn("Category") { _ in Text("Synthetic event") }
                    }
                } else {
                    V2DataTable(columns: columns, items: items, selection: .constant(nil))
                }
            }
            .background(Probe(owner: owner, row: nil, observations: observations))
        }
    }
    @MainActor private struct ConditionalPages: View {
        @ObservedObject var selection: Selection
        let observations: Observations
        let items: [Item]
        var body: some View {
            ZStack {
                Group {
                    switch selection.page {
                    case 0: Page(0, observations: observations, items: items)
                    case 1: Page(1, observations: observations, items: items)
                    default: Page(2, observations: observations, items: items)
                    }
                }.transition(.identity)
            }.animation(nil, value: selection.page)
        }
    }
    @MainActor private final class Host: NSHostingView<AnyView> {
        let observations: Observations
        init(root: AnyView, observations: Observations) {
            self.observations = observations
            super.init(rootView: root)
        }
        @MainActor required init(rootView: AnyView) { fatalError("Use fixture initializer") }
        @MainActor required dynamic init?(coder: NSCoder) { fatalError("Fixture is programmatic only") }
        override func layout() {
            observations.hostLayouts += 1
            super.layout()
        }
    }
    private struct Metrics {
        let hostCount: Int
        let pageMakes: Int
        let pageDismantles: Int
        let rowMakes: Int
        let maxRealizedRows: Int
        let hostLayouts: Int
        let probeLayouts: Int
        let durations: [UInt64]
    }
    @MainActor private struct Result {
        let metrics: Metrics
        let hosts: [WeakHost]
        let owners: [WeakOwner]
    }

    @MainActor private func settle(_ view: NSView, until complete: () -> Bool) async throws {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        repeat {
            view.layoutSubtreeIfNeeded()
            if complete() { return }
            await Task.yield()
        } while clock.now < deadline
        try #require(complete(), "Private fixture did not reach its lifecycle boundary")
    }

    @MainActor private func run(_ mode: Mode) async throws -> Result {
        let observations = Observations(), selection = Selection()
        let items = (0..<500).map(Item.init)
        let rect = NSRect(x: 0, y: 0, width: 1000, height: 320)
        let container = NSView(frame: rect)
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 1000, height: 320),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = container
        var hosts: [Int: Host] = [:]
        var weakHosts: [WeakHost] = []
        defer {
            container.subviews.forEach { $0.removeFromSuperview() }
            window.contentView = nil
            window.close()
            hosts.removeAll()
        }
        var identities: [Int: UUID] = [:]
        var durations: [UInt64] = []
        for page in [0, 1, 2, 0, 1, 2, 0] {
            let started = DispatchTime.now().uptimeNanoseconds
            let key = mode == .conditional ? -1 : page
            let host: Host
            if let cached = hosts[key] { host = cached }
            else {
                let root: AnyView = mode == .conditional
                    ? AnyView(ConditionalPages(selection: selection, observations: observations, items: items))
                    : AnyView(Page(page, observations: observations, items: items))
                host = Host(root: root, observations: observations)
                host.frame = rect
                host.autoresizingMask = [.width, .height]
                hosts[key] = host
                weakHosts.append(WeakHost(host))
            }
            let oldOwner = identities[page]
            let oldMakes = observations.pageMakes
            if mode == .conditional { selection.page = page }
            if host.superview !== container {
                container.subviews.forEach { $0.removeFromSuperview() }
                container.addSubview(host)
            }
            host.needsLayout = true
            try await settle(host) {
                let visible = observations.owners.values.compactMap(\.value).filter { $0.page == page }
                return visible.contains { !(observations.rowIDs[$0.id] ?? []).isEmpty }
                    && (mode == .retained || oldOwner == nil || observations.pageMakes > oldMakes)
            }
            let currentID = try #require(observations.latestOwner[page])
            let current = try #require(observations.owners[currentID]?.value)
            if let oldOwner {
                #expect((current.id == oldOwner) == (mode == .retained),
                        "Retained page identity must survive; conditional branch must remount")
            }
            identities[page] = current.id
            #expect(container.subviews.count == 1 && container.subviews.first === host)
            #expect(hosts.count <= (mode == .retained ? 3 : 1))
            for (otherKey, other) in hosts where otherKey != key {
                #expect(other.superview == nil && other.window == nil,
                        "Inactive retained hosts must be detached, not hidden overlapping views")
            }
            // Advance every fixture owner, including detached ones: only the
            // explicit selected-page admission may do sentinel work.
            for owner in observations.owners.values.compactMap(\.value) {
                let before = owner.sentinelTicks
                owner.fixtureTick(selected: page)
                #expect(owner.sentinelTicks - before == (owner.page == page ? 1 : 0))
            }
            #expect(!window.isVisible)
            durations.append(DispatchTime.now().uptimeNanoseconds - started)
        }
        let rows = observations.rowIDs.values.map(\.count)
        #expect(rows.count == (mode == .retained ? 3 : 7))
        #expect(rows.allSatisfy { $0 > 0 && $0 < items.count }, "Each viewport must remain lazy")
        #expect(observations.pageMakes == (mode == .retained ? 3 : 7))
        let metrics = Metrics(hostCount: hosts.count, pageMakes: observations.pageMakes,
            pageDismantles: observations.pageDismantles, rowMakes: observations.rowMakes,
            maxRealizedRows: rows.max() ?? 0, hostLayouts: observations.hostLayouts,
            probeLayouts: observations.probeLayouts, durations: durations)
        return Result(metrics: metrics, hosts: weakHosts, owners: Array(observations.owners.values))
    }

    @Test("Actual synthetic tables compare conditional remount with at most three retained hosts")
    @MainActor
    func compareMechanisms() async throws {
        for mode in [Mode.conditional, .retained] {
            let result = try await run(mode)
            // No retained strong fixture handles cross this boundary. Give
            // SwiftUI bounded main-loop opportunities to finish owned cleanup.
            let clock = ContinuousClock(), deadline = clock.now.advanced(by: .seconds(2))
            while result.hosts.contains(where: { $0.value != nil })
                    || result.owners.contains(where: { $0.value != nil }) {
                if clock.now >= deadline { break }
                await Task.yield()
            }
            #expect(result.hosts.allSatisfy { $0.value == nil })
            #expect(result.owners.allSatisfy { $0.value == nil })
            let m = result.metrics
            let record: [String: Any] = ["schema": 1, "experiment": "synthetic_workspace_retention",
                "mode": mode.rawValue, "host_creations": m.hostCount, "page_creations": m.pageMakes,
                "page_dismantles_before_close": m.pageDismantles, "row_creations": m.rowMakes,
                "maximum_realized_rows_per_page": m.maxRealizedRows, "host_layout_callbacks": m.hostLayouts,
                "probe_layout_callbacks": m.probeLayouts, "visit_duration_ns": m.durations,
                "timings_are_navigation_sla": false, "sentinel_proves_product_cancellation": false]
            let encoded = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
            print(try #require(String(data: encoded, encoding: .utf8)))
        }
    }
}
