import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Data-table shared vertical viewport")
struct V2DataTableViewportTests {
    struct Item: Identifiable, Hashable { let id: Int }
    struct Column {
        let id: String
        let title: String
        let minimum: CGFloat
        let flexible: Bool
        init(_ id: String, _ title: String, _ minimum: CGFloat, flexible: Bool = false) {
            self.id = id; self.title = title; self.minimum = minimum; self.flexible = flexible
        }
        var width: V2DataColumn<Item>.Width { flexible ? .flexible(min: minimum) : .fixed(minimum) }
        var signature: String { "\(id):\(flexible ? "flexible" : "fixed"):\(Int(minimum))" }
    }
    enum Layout: String, CaseIterable, Sendable {
        case rules, history, mcp, feeds
        var columns: [Column] {
            switch self {
            case .rules: return [Column("on", "On", 50), Column("title", "Rule", 160, flexible: true),
                Column("category", "Category", 140), Column("sev", "Severity", 110),
                Column("mitre", "MITRE", 110), Column("fires", "Recorded matches (boot)", 145),
                Column("custom", "Source", 80)]
            case .history: return [Column("sev", "Severity", 96), Column("title", "Alert", 160, flexible: true),
                Column("rule", "Rule", 140, flexible: true), Column("when", "When", 110),
                Column("status", "Status", 120), Column("actions", "Actions", 170)]
            case .mcp: return [Column("name", "Server", 140, flexible: true), Column("host", "Host", 140),
                Column("tools", "Tools (approx)", 120), Column("known", "Known to", 160, flexible: true),
                Column("trust", "Trust", 120), Column("used", "Last used", 110)]
            case .feeds: return [Column("name", "Feed", 150, flexible: true), Column("kind", "Kind", 140),
                Column("entries", "Entries", 110), Column("fetch", "Last fetch", 120),
                Column("status", "Status", 110), Column("error", "Last error", 160, flexible: true)]
            }
        }
        var outerWidth: CGFloat { self == .rules ? 928 : 911 }
        var minimumWidth: CGFloat { columns.reduce(24) { $0 + $1.minimum + 12 } }
        var sourceFile: String {
            switch self {
            case .rules, .mcp: return "V2DetectionWorkspace.swift"
            case .history: return "V2AlertsWorkspace.swift"
            case .feeds: return "V2IntelligenceWorkspace.swift"
            }
        }
    }

    @Test("native fixture specifications bind the actual production widths and order", arguments: Layout.allCases)
    func productionWidthContracts(layout: Layout) throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let file = root.appendingPathComponent("Sources/MacCrabApp/V2/Workspaces/\(layout.sourceFile)")
        let text = try String(contentsOf: file, encoding: .utf8)
        let expression = try NSRegularExpression(pattern:
            #"V2DataColumn\(id: "([^"]+)", title: [^\n]+, width: \.(fixed|flexible)\((?:min: )?([0-9]+)\)"#)
        let ns = text as NSString
        let signatures = expression.matches(in: text, range: NSRange(location: 0, length: ns.length)).map {
            "\(ns.substring(with: $0.range(at: 1))):\(ns.substring(with: $0.range(at: 2))):\(ns.substring(with: $0.range(at: 3)))"
        }
        let expected = layout.columns.map(\.signature)
        try #require(signatures.count >= expected.count)
        let regions = (0...(signatures.count - expected.count)).filter {
            Array(signatures[$0..<($0 + expected.count)]) == expected
        }
        #expect(regions.count == 1, "fixture must match one complete production column list")
        let expectedMinimum: CGFloat = layout == .rules ? 903 : (layout == .history ? 892 : 886)
        #expect(layout.minimumWidth == expectedMinimum)
        #expect(layout.minimumWidth <= layout.outerWidth - 17,
                "default-sidebar minimum window includes the native legacy gutter")
    }

    #if DEBUG
    // Inert values and private unshown windows only: no AppState, app config,
    // preference mutation, engine reader, AX query, event posting or network.
    // Only productionWidthContracts above reads the repository source files.
    @MainActor private final class RealizedRows { var ids: Set<Int> = [] }
    @MainActor private struct Probe: NSViewRepresentable {
        let row: Int
        let column: Int
        let realized: RealizedRows
        func makeNSView(context: Context) -> NSView {
            if row >= 0 { realized.ids.insert(row) }
            let view = NSView()
            view.identifier = NSUserInterfaceItemIdentifier("fixture.\(row).\(column)")
            return view
        }
        func updateNSView(_ view: NSView, context: Context) {}
    }

    @MainActor @ViewBuilder
    private func cell(layout: Layout, definition: Column, item: Item, realized: RealizedRows) -> some View {
        if layout == .rules && definition.id == "title" {
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    V2TableCellText("A deliberately long benign rule title that must truncate rather than hide its status")
                    V2StatusChip("Deprecated", kind: .warning)
                        .background(Probe(row: item.id, column: 99, realized: realized))
                }
                V2TableCellText("maccrab.fixture.long.rule.identifier.\(item.id)", primary: false, mono: true)
            }
        } else if definition.id == "actions" {
            HStack(spacing: 4) {
                Button("Unsuppress") {}.buttonStyle(.plain)
                Button("Delete") {}.buttonStyle(.plain)
            }
        } else if definition.id == "on" {
            Button {} label: { Image(systemName: "circle.fill").frame(width: 24, height: 24) }
                .buttonStyle(.plain)
        } else if ["sev", "status", "trust", "custom"].contains(definition.id) {
            V2StatusChip(definition.id == "sev" ? "Medium" : "Healthy", kind: .healthy)
        } else {
            V2TableCellText("Long inert fixture \(definition.title) value \(item.id)")
        }
    }

    @MainActor private func descendants(_ root: NSView) throws -> [NSView] {
        var result: [NSView] = []; var pending = [root]
        while let view = pending.popLast() {
            try #require(result.count < 4096, "private native traversal exceeded its bound")
            result.append(view); pending.append(contentsOf: view.subviews)
        }
        return result
    }
    @MainActor private func layoutBoundary(_ host: NSView) async {
        host.needsLayout = true
        host.layoutSubtreeIfNeeded()
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        host.layoutSubtreeIfNeeded()
    }
    @MainActor
    private func fixture(layout: Layout, legacy: Bool, width: CGFloat? = nil, count: Int = 500,
                         multiSelection: Binding<Set<Int>>? = nil) async throws ->
        (NSWindow, NSHostingView<V2DataTable<Item>>, NSScrollView, RealizedRows) {
        let realized = RealizedRows()
        let definitions: [V2DataColumn<Item>] = layout.columns.enumerated().map { index, definition in
            V2DataColumn(id: definition.id, title: definition.title, width: definition.width,
                         sortKey: { .number(Double($0.id)) }) { item in
                cell(layout: layout, definition: definition, item: item, realized: realized)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Probe(row: item.id, column: index, realized: realized))
            }
        }
        let items = (0..<count).map(Item.init)
        var table: V2DataTable<Item>
        if let multiSelection {
            table = V2DataTable(columns: definitions, items: items, selection: .constant(nil), multiSelection: multiSelection)
        } else {
            table = V2DataTable(columns: definitions, items: items, selection: .constant(nil))
        }
        table.headerCellProbeForTesting = { index in AnyView(Probe(row: -1, column: index, realized: realized)) }
        let host = NSHostingView(rootView: table)
        let width = width ?? layout.outerWidth
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: width, height: 320),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        var completed = false
        defer { if !completed { window.close() } }
        host.frame = NSRect(x: 0, y: 0, width: width, height: 320)
        host.layoutSubtreeIfNeeded()
        let views = try descendants(host)
        let scrolls = views.compactMap { $0 as? NSScrollView }
        try #require(scrolls.count == 1)
        let scroll = try #require(scrolls.first)
        scroll.scrollerStyle = legacy ? .legacy : .overlay
        scroll.tile()
        window.contentView = host
        await layoutBoundary(host)
        #expect(scroll.scrollerStyle == (legacy ? .legacy : .overlay))
        #expect(!window.isVisible)
        completed = true
        return (window, host, scroll, realized)
    }

    @MainActor private func probe(_ row: Int, _ column: Int, host: NSView,
                                 requireVisible: Bool = true) throws -> NSView {
        let views = try descendants(host)
        let candidate = views.first {
            $0.identifier?.rawValue == "fixture.\(row).\(column)" && !$0.isHiddenOrHasHiddenAncestor
                && (!requireVisible || $0.convert($0.bounds, to: host).intersects(host.bounds))
        }
        if candidate == nil {
            let matches = views.filter { $0.identifier?.rawValue == "fixture.\(row).\(column)" }
            print("missing synthetic probe row=\(row) column=\(column) frames=\(matches.map { $0.convert($0.bounds, to: host) }) host=\(host.bounds)")
        }
        return try #require(candidate, "expected geometry probe must be realized and meet the requested visibility")
    }
    @MainActor private func assertViewport(_ scroll: NSScrollView, host: NSView) throws {
        let document = try #require(scroll.documentView)
        #expect(abs(document.frame.width - scroll.contentView.bounds.width) < 0.5)
        #expect(abs(scroll.contentView.bounds.minX) < 0.5)
        #expect(!scroll.hasHorizontalScroller)
        let clip = scroll.contentView.convert(scroll.contentView.bounds, to: host)
        #expect(clip.minY >= host.bounds.minY - 0.5 && clip.maxY <= host.bounds.maxY + 0.5)
        #expect(scroll.contentView.bounds.height > 0 && scroll.contentView.bounds.height <= 320)
    }
    @MainActor private func assertColumns(_ layout: Layout, row: Int, scroll: NSScrollView, host: NSView) throws {
        for (index, definition) in layout.columns.enumerated() {
            let header = try probe(-1, index, host: host)
            let cell = try probe(row, index, host: host)
            let headerFrame = header.convert(header.bounds, to: scroll.contentView)
            let cellFrame = cell.convert(cell.bounds, to: scroll.contentView)
            #expect(abs(headerFrame.minX + 6 - cellFrame.minX) < 0.5)
            #expect(abs(headerFrame.width - 12 - cellFrame.width) < 0.5)
            #expect(cellFrame.width >= definition.minimum - 0.5)
            if !definition.flexible { #expect(abs(cellFrame.width - definition.minimum) < 0.5) }
            #expect(cellFrame.minX >= scroll.contentView.bounds.minX - 0.5)
            #expect(cellFrame.maxX <= scroll.contentView.bounds.maxX + 0.5)
        }
    }

    @Test("actual minimum-window columns share native clip width, preserve status and stay lazy",
          arguments: Layout.allCases, [false, true])
    @MainActor
    func minimumWindow(layout: Layout, legacy: Bool) async throws {
        let (window, host, scroll, realized) = try await fixture(layout: layout, legacy: legacy)
        defer { window.close() }
        try assertViewport(scroll, host: host)
        #expect(realized.ids.contains(0))
        #expect(realized.ids.count < 500, "initial paint must not realize the full data set")
        try assertColumns(layout, row: 0, scroll: scroll, host: host)
        if layout == .rules {
            let deprecated = try probe(0, 99, host: host)
            let frame = deprecated.convert(deprecated.bounds, to: scroll.contentView)
            #expect(frame.width > 0 && frame.height > 0)
            #expect(frame.maxX <= scroll.contentView.bounds.maxX + 0.5)
        }
        let header = try probe(-1, 0, host: host)
        let beforeY = header.convert(header.bounds, to: host).minY
        scroll.contentView.scroll(to: NSPoint(x: 0, y: 80))
        scroll.reflectScrolledClipView(scroll.contentView)
        await layoutBoundary(host)
        let pinned = try probe(-1, 0, host: host)
        #expect(abs(pinned.convert(pinned.bounds, to: host).minY - beforeY) < 0.5)
        let document = try #require(scroll.documentView)
        // Lazy document estimates can grow when the last row is realized. This
        // checks reachability after one native reveal, not exact initial End-
        // jump placement. Discovery must therefore allow an already-realized
        // offscreen row; the post-reveal lookup and full bounds remain strict.
        // An End jump on a loaded host can land before the estimate settles or
        // before realization is published, so repeat it (bounded) until the
        // last row exists; an unreachable last row still fails below.
        // Bounded by time rather than a count of main-queue hops: under a
        // full-suite load eight hops were not always enough.
        let lastIdentifier = "fixture.499.\(layout.columns.count - 1)"
        let clock = ContinuousClock()
        let realizationDeadline = clock.now.advanced(by: .seconds(5))
        repeat {
            scroll.contentView.scroll(to: NSPoint(x: 0, y: max(0, document.frame.maxY - scroll.contentView.bounds.height)))
            scroll.reflectScrolledClipView(scroll.contentView)
            await layoutBoundary(host)
            if try descendants(host).contains(where: { $0.identifier?.rawValue == lastIdentifier }) { break }
            try await Task.sleep(for: .milliseconds(20))
        } while clock.now < realizationDeadline
        let last = try probe(499, layout.columns.count - 1, host: host, requireVisible: false)
        let before = last.convert(last.bounds, to: scroll.contentView)
        let beforeClip = scroll.contentView.bounds
        let revealed = last.scrollToVisible(last.bounds)
        await layoutBoundary(host)
        let visibleLast = try probe(499, layout.columns.count - 1, host: host)
        #expect(visibleLast === last)
        let final = visibleLast.convert(visibleLast.bounds, to: scroll.contentView)
        let initiallyVisible = before.minY >= beforeClip.minY - 0.5 && before.maxY <= beforeClip.maxY + 0.5
        #expect(initiallyVisible || revealed || abs(scroll.contentView.bounds.minY - beforeClip.minY) > 0.5)
        #expect(final.minY >= scroll.contentView.bounds.minY - 0.5)
        #expect(final.maxY <= scroll.contentView.bounds.maxY + 0.5)
        #expect(final.maxX <= scroll.contentView.bounds.maxX + 0.5)
        #expect(last.convert(last.bounds, to: document).maxY <= document.bounds.maxY + 0.5)
    }

    @Test("vertical resizing retains viewport and multi-selection; empty rows remain visible", arguments: [false, true])
    @MainActor
    func resizingAndEmpty(legacy: Bool) async throws {
        var selected: Set<Int> = [1, 499, 999]
        let binding = Binding(get: { selected }, set: { selected = $0 })
        let (window, host, scroll, _) = try await fixture(layout: .mcp, legacy: legacy, width: 1000, multiSelection: binding)
        defer { window.close() }
        for width in [CGFloat(1200), 1000] {
            window.setContentSize(NSSize(width: width, height: 320))
            await layoutBoundary(host)
            let views = try descendants(host)
            let scrolls = views.compactMap { $0 as? NSScrollView }
            #expect(scrolls.count == 1 && scrolls.first === scroll)
            try assertViewport(scroll, host: host)
            try assertColumns(.mcp, row: 0, scroll: scroll, host: host)
            let first = try probe(0, 0, host: host)
            #expect(abs(first.convert(first.bounds, to: scroll.contentView).minX - 54) < 0.5)
            #expect(selected == [1, 499, 999])
        }
        let (emptyWindow, emptyHost, emptyScroll, realized) = try await fixture(layout: .rules, legacy: legacy, count: 0)
        defer { emptyWindow.close() }
        try assertViewport(emptyScroll, host: emptyHost)
        #expect(realized.ids.isEmpty)
        let header = try probe(-1, 0, host: emptyHost)
        let document = try #require(emptyScroll.documentView)
        #expect(document.frame.height > header.bounds.height)
        #expect(document.frame.height <= emptyScroll.contentView.bounds.height + 0.5)
    }
    #endif
}
