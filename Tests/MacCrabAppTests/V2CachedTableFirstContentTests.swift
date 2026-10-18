import AppKit
import MacCrabCore
import SwiftUI
import Testing
@testable import MacCrabApp

/// Real presentation-model acceptance and real table/representable layout,
/// using only inert values and private, unshown windows. No AppState, provider,
/// store, preferences, installed application, AX calls or native input events.
/// These are fixed-boundary layout oracles, not paint or elapsed-time claims.
@MainActor
@Suite("Cached tables publish their first accepted rows", .serialized)
struct V2CachedTableFirstContentTests {
    enum Page: String, CaseIterable, Sendable { case rules, alerts }
    enum Surface: String, CaseIterable, Sendable { case cached, direct }
    private struct Row: Identifiable, Hashable {
        let id: String
        let text: String
    }
    private final class ProviderIdentity {}
    @MainActor private final class Driver: ObservableObject {
        @Published var visible = true
        @Published var unrelatedRevision = 0
        let provider = ProviderIdentity()
        var rootAssignments = 0
        var expirySchedules = 0
        var ruleIdentity: V2DetectionPresentation.Identity {
            .init(provider: ObjectIdentifier(provider), directory: "/inert-not-read", epoch: 1)
        }
        var alertContext: V2AlertsPresentationContext {
            .init(query: .init(providerID: ObjectIdentifier(provider), timeRange: "7d",
                               windowStart: nil, windowEnd: nil),
                  directory: "/inert-not-read",
                  engine: .init(EngineTelemetryIdentity(pid: 123, startedAtUnix: 100,
                                                       version: "fixture", build: "unit")))
        }
        func makeCache() -> V2TableHostCache {
            V2TableHostCache(observeMemoryPressure: false, now: { 100 }, scheduleExpiry: { [weak self] _, _ in
                self?.expirySchedules += 1
                return V2TableHostExpiry {}
            })
        }
    }

    /// Values live on the currently attached native cells, not in a cumulative
    /// creation registry. An old row's makeNSView cannot satisfy a new snapshot.
    @MainActor private final class CellView: NSView {
        var row = Row(id: "unset", text: "unset")
    }
    @MainActor private struct CellProbe: NSViewRepresentable {
        let row: Row
        func makeNSView(context: Context) -> CellView { CellView() }
        func updateNSView(_ view: CellView, context: Context) { view.row = row }
    }

    @MainActor private struct Fixture: View {
        let page: Page
        let surface: Surface
        let cache: V2TableHostCache
        @ObservedObject var driver: Driver
        @ObservedObject var rules: V2DetectionPresentation
        @ObservedObject var alerts: V2AlertsPresentationModel

        private var rows: [Row] {
            switch page {
            case .rules: return rules.rows(for: driver.ruleIdentity, query: "").map { Row(id: $0.id, text: $0.title) }
            case .alerts: return alerts.rows(for: driver.alertContext).map { Row(id: $0.id, text: $0.title) }
            }
        }
        private var retainable: Bool {
            page == .rules ? rules.canRetainTable(for: driver.ruleIdentity)
                : alerts.canRetainTable(for: driver.alertContext)
        }
        private func table(_ items: [Row], selection: Binding<Row?>) -> some View {
            V2DataTable(columns: [V2DataColumn(id: "text", title: "Text", width: .flexible(min: 200)) {
                V2TableCellText($0.text).background(CellProbe(row: $0))
            }], items: items, selection: selection)
        }
        var body: some View {
            // Snapshot the same model-generation guard used by the workspaces.
            // Freshness is deliberately not a condition for displaying cached rows.
            let items = rows
            let revision = page == .rules ? rules.revision : alerts.readiness.generation
            let isRules = page == .rules
            VStack(spacing: 0) {
                Text("Synthetic heading \(driver.unrelatedRevision)").frame(height: 40)
                if driver.visible {
                    if surface == .cached {
                        V2CachedTableHost(cache: cache, slot: isRules ? .rules : .openAlerts,
                                          key: items, scope: page, retainable: retainable,
                                          isCurrent: {
                            driver.visible && revision == (isRules ? rules.revision : alerts.readiness.generation)
                        }) { lease in
                            let _ = driver.rootAssignments += 1
                            let selection = lease.binding(slot: .selection, Binding<Row?>.constant(nil), fallback: nil)
                            table(items, selection: selection)
                        }
                    } else {
                        // Same actual V2DataTable and model publication, without
                        // the cache, AnyView root replacement or native bridge.
                        table(items, selection: .constant(nil))
                    }
                } else {
                    Color.clear.frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            // Match the production outer-VStack sizing: no direct bridge frame.
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func acceptedRows(_ count: Int, revision: Int = 1) -> [Row] {
        (0..<count).map { Row(id: "fixture-\($0)", text: "Synthetic revision \(revision), row \($0)") }
    }
    private func publish(_ rows: [Row], page: Page, driver: Driver,
                         rules: V2DetectionPresentation, alerts: V2AlertsPresentationModel) async {
        switch page {
        case .rules:
            let values = rows.map { V2MockRule(id: $0.id, title: $0.text, category: "File", severity: .low,
                mitre: [], isEnabled: true, lastFired: nil, firesLastWeek: 0,
                isCustom: false, description: "Inert metadata") }
            await rules.refresh(identity: driver.ruleIdentity) { .success(values) }
            #expect(rules.isCurrent(for: driver.ruleIdentity))
            #expect(rules.rows(for: driver.ruleIdentity, query: "").map(\.id) == rows.map(\.id))
        case .alerts:
            let values = rows.map { V2MockAlert(id: $0.id, title: $0.text, severity: .low, ruleId: "fixture-rule",
                process: "fixture", processPath: "/inert", pid: 1, parent: "fixture", user: "fixture",
                triggeringEventsJson: "", timestamp: Date(timeIntervalSince1970: 1_000), mitre: [],
                category: "File", description: "Inert metadata", actionsTaken: [], suppressed: false) }
            await alerts.refresh(context: driver.alertContext, now: Date(timeIntervalSince1970: 1_000),
                                 isCurrent: { true }) { _, _ in .success(values) }
            #expect(alerts.isFresh(for: driver.alertContext))
            #expect(alerts.rows(for: driver.alertContext).map(\.id) == rows.map(\.id))
        }
    }

    /// Two declared queue/layout turns for nested SwiftUI/native propagation.
    /// No polling, sleep, retry-until-pass, or test-driven table-state mutation.
    private func layoutBoundary(_ root: NSView) async {
        for _ in 0..<2 {
            root.needsLayout = true
            root.layoutSubtreeIfNeeded()
            await withCheckedContinuation { continuation in
                DispatchQueue.main.async { continuation.resume() }
            }
        }
        root.layoutSubtreeIfNeeded()
    }
    private func nativeViews(_ root: NSView) throws -> [NSView] {
        var pending = [root], result: [NSView] = []
        while let view = pending.popLast() {
            try #require(result.count < 4096, "Private table fixture exceeded its traversal bound")
            result.append(view)
            pending.append(contentsOf: view.subviews)
        }
        return result
    }
    private func tableHost(_ root: NSView) throws -> NSHostingView<AnyView> {
        let hosts = try nativeViews(root).compactMap { $0 as? NSHostingView<AnyView> }
        try #require(hosts.count == 1)
        return try #require(hosts.first)
    }
    private func visibleRows(_ root: NSView) throws -> [Row] {
        let views = try nativeViews(root)
        let scrolls = views.compactMap { $0 as? NSScrollView }
        try #require(scrolls.count == 1)
        let scroll = try #require(scrolls.first)
        let clip = scroll.contentView
        try #require(clip.bounds.width > 0 && clip.bounds.height > 0)
        return views.compactMap { $0 as? CellView }.filter { cell in
            cell.window === root.window && !cell.isHiddenOrHasHiddenAncestor
                && !cell.visibleRect.isEmpty && cell.bounds.width > 0 && cell.bounds.height > 0
                && cell.convert(cell.bounds, to: clip).intersects(clip.bounds)
        }.sorted { $0.convert($0.bounds, to: clip).minY < $1.convert($1.bounds, to: clip).minY }
            .map(\.row)
    }
    private func window(_ root: NSView) -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: -10_000, y: -10_000, width: 640, height: 280),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.contentView = root
        return window
    }

    /// Bounded diagnostics contain only this fixture's explicit synthetic
    /// cell IDs/payloads, geometry and fixed stage labels, never native UI text.
    /// Include attached offscreen probes so clipping and stale data differ.
    private func diagnose(_ root: NSView, page: Page, surface: Surface, stage: String,
                          driver: Driver, expectedCount: Int) throws {
        let views = try nativeViews(root)
        let cells = views.compactMap { $0 as? CellView }
        let visible = try visibleRows(root)
        let scroll = try #require(views.compactMap { $0 as? NSScrollView }.first)
        func number(_ value: CGFloat) -> Any { value.isFinite ? Double(value) : NSNull() }
        let attached: [[String: Any]] = cells.prefix(24).map { cell in
            let frame = cell.convert(cell.bounds, to: scroll.contentView)
            return ["id": cell.row.id, "payload": cell.row.text,
                    "x": number(frame.minX), "y": number(frame.minY),
                    "width": number(frame.width), "height": number(frame.height),
                    "visible_rect_empty": cell.visibleRect.isEmpty]
        }
        let record: [String: Any] = [
            "fixture": "table_first_content", "page": page.rawValue, "surface": surface.rawValue,
            "stage": stage, "expected_count": expectedCount, "root_assignments": driver.rootAssignments,
            "attached_count": cells.count, "attached_omitted": max(0, cells.count - attached.count),
            "attached": attached, "visible_count": visible.count,
            "visible": visible.prefix(24).map { ["id": $0.id, "payload": $0.text] },
            "visible_omitted": max(0, visible.count - 24),
            "clip_width": number(scroll.contentView.bounds.width),
            "clip_height": number(scroll.contentView.bounds.height)
        ]
        let data = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }

    @Test("Empty attached tables display accepted IDs and changed payloads without a remount", arguments: Page.allCases)
    func acceptedPopulationReachesNativeCells(page: Page) async throws {
        let driver = Driver(), rules = V2DetectionPresentation(), alerts = V2AlertsPresentationModel()
        let cache = driver.makeCache()
        let root = NSHostingView(rootView: Fixture(page: page, surface: .cached, cache: cache, driver: driver, rules: rules, alerts: alerts))
        let window = window(root)
        defer { rules.leave(); alerts.pause(); cache.removeAll(); window.contentView = nil; window.close() }
        await layoutBoundary(root)
        let originalHost = try tableHost(root)
        try diagnose(root, page: page, surface: .cached, stage: "initial_empty", driver: driver, expectedCount: 0)
        #expect(try visibleRows(root).isEmpty)
        let first = acceptedRows(3)
        await publish(first, page: page, driver: driver, rules: rules, alerts: alerts)
        await layoutBoundary(root)
        try diagnose(root, page: page, surface: .cached, stage: "accepted_three", driver: driver, expectedCount: 3)
        #expect(try tableHost(root) === originalHost)
        #expect(try visibleRows(root) == first)

        // Same IDs, new values: an old realized-row registry is not sufficient.
        let replacement = acceptedRows(3, revision: 2)
        await publish(replacement, page: page, driver: driver, rules: rules, alerts: alerts)
        await layoutBoundary(root)
        try diagnose(root, page: page, surface: .cached, stage: "replacement_same_ids", driver: driver, expectedCount: 3)
        #expect(try tableHost(root) === originalHost)
        #expect(try visibleRows(root) == replacement)
        await publish([], page: page, driver: driver, rules: rules, alerts: alerts)
        await layoutBoundary(root)
        try diagnose(root, page: page, surface: .cached, stage: "accepted_empty", driver: driver, expectedCount: 0)
        #expect(try tableHost(root) === originalHost)
        #expect(try visibleRows(root).isEmpty, "A successful empty replacement must remove old visible rows")
        #expect(driver.expirySchedules == 1)
        #expect(!window.isVisible)
    }

    @Test("Accepted lazy rows survive unrelated root updates and an exact detached revisit", arguments: Page.allCases)
    func acceptedPopulationSurvivesUpdatesAndRevisit(page: Page) async throws {
        let driver = Driver(), rules = V2DetectionPresentation(), alerts = V2AlertsPresentationModel()
        let cache = driver.makeCache()
        let root = NSHostingView(rootView: Fixture(page: page, surface: .cached, cache: cache, driver: driver, rules: rules, alerts: alerts))
        let window = window(root)
        defer { rules.leave(); alerts.pause(); cache.removeAll(); window.contentView = nil; window.close() }
        await layoutBoundary(root)
        let originalHost = try tableHost(root)
        let accepted = acceptedRows(200) // Within the actual 7-day Alerts request limit.
        await publish(accepted, page: page, driver: driver, rules: rules, alerts: alerts)
        await layoutBoundary(root)
        let firstVisible = try visibleRows(root)
        try diagnose(root, page: page, surface: .cached, stage: "accepted_lazy_200", driver: driver, expectedCount: accepted.count)
        try #require(!firstVisible.isEmpty)
        #expect(firstVisible == Array(accepted.prefix(firstVisible.count)))
        #expect(try nativeViews(root).compactMap { $0 as? CellView }.count < accepted.count)
        let beforeAssignments = driver.rootAssignments
        driver.unrelatedRevision += 1
        await layoutBoundary(root)
        #expect(driver.rootAssignments > beforeAssignments, "Exercise a real repeated root assignment")
        #expect(try tableHost(root) === originalHost)
        #expect(try visibleRows(root) == firstVisible)

        if page == .rules { rules.leave() } else { alerts.pause() }
        driver.visible = false
        await layoutBoundary(root)
        #expect(originalHost.superview == nil && originalHost.window == nil)
        #expect(try nativeViews(root).compactMap { $0 as? CellView }.isEmpty)
        driver.visible = true
        await layoutBoundary(root)
        #expect(try tableHost(root) === originalHost)
        #expect(try visibleRows(root) == firstVisible)
        #expect(driver.expirySchedules == 1, "Exact detached reuse must preserve the original host lifetime")
        #expect(!window.isVisible)
    }

    @Test("Direct table control uses the identical publication and queued-layout boundary", arguments: Page.allCases)
    func directTableTransitionControl(page: Page) async throws {
        let driver = Driver(), rules = V2DetectionPresentation(), alerts = V2AlertsPresentationModel()
        let cache = driver.makeCache()
        let root = NSHostingView(rootView: Fixture(page: page, surface: .direct, cache: cache, driver: driver, rules: rules, alerts: alerts))
        let window = window(root)
        defer { rules.leave(); alerts.pause(); cache.removeAll(); window.contentView = nil; window.close() }
        await layoutBoundary(root)
        #expect(try visibleRows(root).isEmpty)
        for (stage, accepted) in [
            ("accepted_three", acceptedRows(3)),
            ("replacement_same_ids", acceptedRows(3, revision: 2)),
            ("accepted_empty", []),
            ("accepted_lazy_200", acceptedRows(200)),
        ] {
            await publish(accepted, page: page, driver: driver, rules: rules, alerts: alerts)
            await layoutBoundary(root)
            try diagnose(root, page: page, surface: .direct, stage: stage, driver: driver, expectedCount: accepted.count)
            let visible = try visibleRows(root)
            if accepted.count <= 3 { #expect(visible == accepted) }
            else {
                #expect(!visible.isEmpty)
                #expect(visible == Array(accepted.prefix(visible.count)))
                #expect(try nativeViews(root).compactMap { $0 as? CellView }.count < accepted.count)
            }
        }
        #expect(driver.rootAssignments == 0 && driver.expirySchedules == 0)
        #expect(!window.isVisible)
    }

    @Test("Initially nonempty positive control validates row extraction without an update hop", arguments: Surface.allCases)
    func initiallyNonemptyControl(surface: Surface) async throws {
        let driver = Driver(), rules = V2DetectionPresentation(), alerts = V2AlertsPresentationModel()
        let cache = driver.makeCache()
        let accepted = acceptedRows(3)
        await publish(accepted, page: .rules, driver: driver, rules: rules, alerts: alerts)
        let root = NSHostingView(rootView: Fixture(page: .rules, surface: surface, cache: cache, driver: driver, rules: rules, alerts: alerts))
        let window = window(root)
        defer { rules.leave(); alerts.pause(); cache.removeAll(); window.contentView = nil; window.close() }
        await layoutBoundary(root)
        try diagnose(root, page: .rules, surface: surface, stage: "initial_nonempty", driver: driver, expectedCount: accepted.count)
        #expect(try visibleRows(root) == accepted)
        #expect(!window.isVisible)
    }
}
