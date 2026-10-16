import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Detection inventory inspector overlays", .serialized)
struct V2DetectionInspectorOverlayTests {
    enum Layout: String, CaseIterable, Sendable {
        case browser, mcp
        var widths: [CGFloat] { self == .browser ? [200, 100, 90, 110, 80, 80] : [140, 140, 120, 160, 120, 110] }
        var ids: [String] { self == .browser ? ["name", "browser", "version", "perms", "signed", "risk"] : ["name", "host", "tools", "known", "trust", "used"] }
        var flexible: Set<Int> { self == .browser ? [0] : [0, 3] }
        var minimum: CGFloat { widths.reduce(24) { $0 + $1 + 12 } }
        var minimumHeight: CGFloat { self == .browser ? 320 : 280 }
        var selection: String { self == .browser ? "selectedExtension" : "selectedMCP" }
        var inspector: String { self == .browser ? "extensionInspector(ext)" : "mcpInspector(mcp)" }
    }

    @Test("both production tabs keep their complete column lists and move inspectors outside the scroller",
          arguments: Layout.allCases)
    func productionContract(layout: Layout) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabApp/V2/Workspaces/V2DetectionWorkspace.swift"), encoding: .utf8)
        let start = try #require(source.range(of: "    private var \(layout.rawValue)Tab: some View {"))
        let end = try #require(source.range(of: "\n    private func ", range: start.upperBound..<source.endIndex))
        let region = String(source[start.lowerBound..<end.lowerBound])
        #expect(region.contains("ZStack(alignment: .topTrailing) {\n            ScrollView {"))
        #expect(!region.contains("HStack(alignment: .top, spacing: 0)"))
        #expect(region.contains(".padding(16)\n            }\n            if let "))
        #expect(region.contains("selection: $\(layout.selection)"))
        #expect(region.contains(".frame(minHeight: \(Int(layout.minimumHeight)), maxHeight: .infinity)"))
        #expect(region.contains(layout.inspector))
        #expect(region.contains(".transition(V2Motion.inspectorSlide(reduceMotion: reduceMotion))"))
        #expect(region.contains(".animation(V2Motion.inspectorPresent(reduceMotion: reduceMotion), value: \(layout.selection)?.id)"))
        #expect(source.contains("onClose: { \(layout.selection) = nil }"))
        let expression = try NSRegularExpression(pattern:
            #"V2DataColumn\(id: "([^"]+)", title: [^\n]+, width: \.(fixed|flexible)\((?:min: )?([0-9]+)\)"#)
        let ns = region as NSString
        let actual = expression.matches(in: region, range: NSRange(location: 0, length: ns.length)).map {
            "\(ns.substring(with: $0.range(at: 1))):\(ns.substring(with: $0.range(at: 2))):\(ns.substring(with: $0.range(at: 3)))"
        }
        let expected = layout.ids.indices.map {
            "\(layout.ids[$0]):\(layout.flexible.contains($0) ? "flexible" : "fixed"):\(Int(layout.widths[$0]))"
        }
        #expect(actual == expected)
        #expect(layout.minimum == (layout == .browser ? 756 : 886))
    }

    struct Item: Identifiable, Hashable { let id: Int }
    @MainActor private final class State: ObservableObject {
        @Published var selected: Item?
        var closes = 0
        func close() { closes += 1; selected = nil }
    }
    @MainActor private struct Probe: NSViewRepresentable {
        let name: String
        func makeNSView(context: Context) -> NSView {
            let view = NSView()
            view.identifier = NSUserInterfaceItemIdentifier(name)
            return view
        }
        func updateNSView(_ view: NSView, context: Context) {}
    }

    /// Source-bound composition, real table and inspector, entirely inert data.
    /// No AppState, provider, inventory scan, installed files or AX API is used.
    @MainActor private struct Fixture: View {
        let layout: Layout
        @ObservedObject var state: State
        private var columns: [V2DataColumn<Item>] {
            layout.ids.indices.map { index in
                V2DataColumn(id: layout.ids[index], title: layout.ids[index],
                    width: layout.flexible.contains(index) ? .flexible(min: layout.widths[index]) : .fixed(layout.widths[index]),
                    sortKey: { .number(Double($0.id)) }) { item in
                        V2TableCellText("Synthetic \(item.id)")
                    }
            }
        }
        var body: some View {
            ZStack(alignment: .topTrailing) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Synthetic inventory description").frame(height: 80)
                        V2DataTable(columns: columns, items: (0..<40).map { Item(id: $0) },
                                    selection: $state.selected, searchPrompt: "Synthetic filter")
                            .frame(minHeight: layout.minimumHeight, maxHeight: .infinity)
                            .background(Probe(name: "fixture.table"))
                    }
                    .padding(16)
                }
                if let item = state.selected {
                    V2Inspector(title: "Synthetic item \(item.id)", onClose: state.close) {
                        Text("Synthetic inspector details")
                    }
                    .background(Probe(name: "fixture.inspector"))
                    .shadow(color: Color.black.opacity(0.25), radius: 8, x: -4, y: 0)
                    .transition(V2Motion.inspectorSlide(reduceMotion: true))
                }
            }
            .animation(V2Motion.inspectorPresent(reduceMotion: true), value: state.selected?.id)
        }
    }

    @MainActor private func descendants(_ root: NSView) throws -> [NSView] {
        var pending = [root], result: [NSView] = []
        while let view = pending.popLast() {
            try #require(result.count < 4096, "private fixture traversal exceeded its bound")
            result.append(view); pending.append(contentsOf: view.subviews)
        }
        return result
    }
    @MainActor private func probe(_ name: String, host: NSView) throws -> NSView {
        let matches = try descendants(host).filter { $0.identifier?.rawValue == name && !$0.isHiddenOrHasHiddenAncestor }
        try #require(matches.count == 1)
        return matches[0]
    }
    @MainActor private func layoutBoundary(_ host: NSView) async {
        host.needsLayout = true; host.layoutSubtreeIfNeeded()
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        host.layoutSubtreeIfNeeded()
    }
    @MainActor private func change(_ body: () -> Void) {
        var transaction = Transaction(animation: nil)
        transaction.disablesAnimations = true
        withTransaction(transaction, body)
    }

    @Test("opening, scrolling and closing an inspector never shrink the inventory table",
          arguments: Layout.allCases, [false, true])
    @MainActor
    func viewportOverlay(layout: Layout, legacy: Bool) async throws {
        let state = State()
        let host = NSHostingView(rootView: Fixture(layout: layout, state: state))
        // 1180 minimum window minus the default 220 sidebar. The production
        // composition subtracts its own padding and both native scroll gutters.
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 960, height: 360),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.contentView = nil; window.close() }
        host.frame = NSRect(x: 0, y: 0, width: 960, height: 360)
        host.layoutSubtreeIfNeeded()
        let initialViews = try descendants(host)
        for scroll in initialViews.compactMap({ $0 as? NSScrollView }) {
            scroll.scrollerStyle = legacy ? .legacy : .overlay
            scroll.tile()
        }
        window.contentView = host
        await layoutBoundary(host)
        let table = try probe("fixture.table", host: host)
        let before = table.convert(table.bounds, to: host)
        #expect(before.width >= layout.minimum + (legacy ? 17 : 0))
        let outerCandidates = try descendants(host).compactMap { $0 as? NSScrollView }.filter {
            guard let document = $0.documentView else { return false }
            return table.isDescendant(of: document)
        }
        let outer = try #require(outerCandidates.first)
        try #require(outerCandidates.count == 1)
        #expect(outer.scrollerStyle == (legacy ? .legacy : .overlay))

        change { state.selected = Item(id: 0) }
        await layoutBoundary(host)
        let openTable = try probe("fixture.table", host: host)
        let opened = openTable.convert(openTable.bounds, to: host)
        #expect(abs(opened.minX - before.minX) < 0.5 && abs(opened.width - before.width) < 0.5)
        let inspector = try probe("fixture.inspector", host: host)
        let inspectorBefore = inspector.convert(inspector.bounds, to: host)
        #expect(abs(inspectorBefore.width - V2Theme.inspectorWidth) < 0.5)
        #expect(abs(inspectorBefore.maxX - host.bounds.maxX) < 0.5)
        #expect(inspectorBefore.minY >= host.bounds.minY - 0.5 && inspectorBefore.maxY <= host.bounds.maxY + 0.5)
        #expect(inspectorBefore.height > 100)
        #expect(state.selected?.id == 0)

        let originalOffset = outer.contentView.bounds.minY
        outer.contentView.scroll(to: NSPoint(x: 0, y: originalOffset + 40))
        outer.reflectScrolledClipView(outer.contentView)
        await layoutBoundary(host)
        #expect(abs(outer.contentView.bounds.minY - originalOffset) > 1)
        let currentInspector = try probe("fixture.inspector", host: host)
        let inspectorAfter = currentInspector.convert(currentInspector.bounds, to: host)
        #expect(abs(inspectorAfter.minY - inspectorBefore.minY) < 0.5)
        #expect(abs(inspectorAfter.height - inspectorBefore.height) < 0.5)

        // Invoke the same closure supplied to the actual V2Inspector. This is
        // not a packaged accessibility/button-click test; source checks retain
        // each production onClose binding and the shared close control is unchanged.
        change { state.close() }
        await layoutBoundary(host)
        #expect(state.selected == nil && state.closes == 1)
        let remaining = try descendants(host).filter { $0.identifier?.rawValue == "fixture.inspector" }
        #expect(remaining.isEmpty)
        let currentTable = try probe("fixture.table", host: host)
        let closed = currentTable.convert(currentTable.bounds, to: host)
        #expect(abs(closed.minX - before.minX) < 0.5 && abs(closed.width - before.width) < 0.5)
        #expect(!window.isVisible)
    }
}
