import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Responsive sidebar rendering budget", .serialized)
struct V2SidebarWidthPolicyTests {
    @Test("minimum window preserves the workspace and wider windows restore the stored preference")
    func renderingBudget() {
        let cases: [(CGFloat, CGFloat)] = [(1180, 220), (1240, 280), (1320, 360), (1500, 360), (1180, 220)]
        for (window, expected) in cases {
            let rendered = V2SidebarWidthPolicy.rendered(stored: 360, collapsed: false, availableWidth: window)
            #expect(rendered == expected)
            #expect(window - rendered >= 960)
        }
        #expect(V2SidebarWidthPolicy.rendered(stored: 220, collapsed: false, availableWidth: 1180) == 220)
        #expect(1180 - V2SidebarWidthPolicy.rendered(stored: 360, collapsed: false, availableWidth: 1180) - 32 == 928)
        #expect(V2SidebarWidthPolicy.rendered(stored: 180, collapsed: false, availableWidth: 1180) == 180)
    }

    @Test("collapse and defensive bounds do not rewrite a saved preference")
    func collapseAndBounds() {
        let stored = 360.0
        for width in [CGFloat(0), 1180, 1500] {
            #expect(V2SidebarWidthPolicy.rendered(stored: stored, collapsed: true, availableWidth: width) == 56)
        }
        #expect(V2SidebarWidthPolicy.rendered(stored: stored, collapsed: false, availableWidth: 1320) == 360)
        #expect(V2SidebarWidthPolicy.preference(-100) == 180)
        #expect(V2SidebarWidthPolicy.preference(1000) == 360)
        #expect(V2SidebarWidthPolicy.preference(.nan) == 220)
        #expect(V2SidebarWidthPolicy.preference(.infinity) == 220)
        #expect(V2SidebarWidthPolicy.maximumRendered(availableWidth: .nan) == 180)
        #expect(V2SidebarWidthPolicy.maximumRendered(availableWidth: 0) == 180)
    }

    @Test("cumulative drag translations use one visible start; drag and VoiceOver respect the current cap")
    func explicitResizeSequence() {
        let translations: [CGFloat] = [10, 20, -5]
        let result = translations.map {
            V2SidebarWidthPolicy.resized(startWidth: 220, translation: $0, availableWidth: 1500)
        }
        #expect(result == [230, 240, 215], "translations must not accumulate against earlier writes")
        let visibleStart = V2SidebarWidthPolicy.rendered(stored: 360, collapsed: false, availableWidth: 1180)
        #expect(V2SidebarWidthPolicy.resized(startWidth: visibleStart, translation: -20, availableWidth: 1180) == 200)
        #expect(V2SidebarWidthPolicy.resized(startWidth: visibleStart, translation: 20, availableWidth: 1180) == 220)
        #expect(V2SidebarWidthPolicy.resized(startWidth: visibleStart, translation: -1000, availableWidth: 1180) == 180)
        #expect(V2SidebarWidthPolicy.resized(startWidth: 350, translation: 50, availableWidth: 1500) == 360)
    }

    @Test("shell passes actual width; preference writes remain explicit input only")
    func sourceContract() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        func source(_ path: String) throws -> String {
            try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
                .split(separator: "\n", omittingEmptySubsequences: false)
                .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
        }
        let shell = try source("Sources/MacCrabApp/V2/V2DashboardShell.swift")
        let sidebar = try source("Sources/MacCrabApp/V2/Sidebar/V2Sidebar.swift")
        let app = try source("Sources/MacCrabApp/MacCrabApp.swift")
        #expect(shell.contains("V2SidebarContentLayout(sidebar: { availableWidth in"))
        #expect(shell.contains("appState: appState, availableWidth: availableWidth"))
        #expect(sidebar.contains("@AppStorage(\"v2.sidebar.width\")"))
        #expect(sidebar.contains("V2SidebarWidthPolicy.rendered(stored: storedWidth, collapsed: collapsed,"))
        #expect(sidebar.contains("let start = dragStartWidth ?? resolvedWidth"))
        #expect(sidebar.contains(".onEnded { _ in dragStartWidth = nil }"))
        #expect(sidebar.contains(".accessibilityAdjustableAction"))
        #expect(sidebar.contains(".accessibilityValue(\"\\(Int(resolvedWidth))\")"))
        #expect(sidebar.components(separatedBy: "storedWidth =").count - 1 == 2)
        #expect(!sidebar.contains(".onChange(of: availableWidth)"))
        #expect(app.contains(".frame(minWidth: 1180, minHeight: 760)"))
    }

    @MainActor private final class Model: ObservableObject {
        @Published var stored: Double = 360 { didSet { writes += 1 } }
        @Published var collapsed = false
        private(set) var writes = 0
    }
    @MainActor private struct Probe: NSViewRepresentable {
        let name: String
        func makeNSView(context: Context) -> NSView {
            let view = NSView(); view.identifier = .init(name); return view
        }
        func updateNSView(_ view: NSView, context: Context) {}
    }
    @MainActor private struct Fixture: View {
        @ObservedObject var model: Model
        var body: some View {
            V2SidebarContentLayout(sidebar: { available in
                Probe(name: "sidebar").frame(width: V2SidebarWidthPolicy.rendered(
                    stored: model.stored, collapsed: model.collapsed, availableWidth: available))
            }, content: {
                Probe(name: "workspace").overlay {
                    Probe(name: "table").padding(.horizontal, 16)
                }
            })
        }
    }
    @MainActor private func layoutBoundary(_ host: NSView) async {
        host.needsLayout = true; host.layoutSubtreeIfNeeded()
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        host.layoutSubtreeIfNeeded()
    }
    @MainActor private func probe(_ name: String, host: NSView) throws -> NSView {
        var pending = [host]; var visited = 0; var matches: [NSView] = []
        while let view = pending.popLast() {
            visited += 1
            try #require(visited <= 512)
            if view.identifier?.rawValue == name { matches.append(view) }
            pending.append(contentsOf: view.subviews)
        }
        try #require(matches.count == 1)
        return try #require(matches.first)
    }

    @Test("private native resize/collapse restores width without preference writes or sidebar replacement")
    @MainActor
    func nativeAllocation() async throws {
        // Shared real layout, no V2Sidebar/AppState/AppStorage/provider or real app.
        // The private window is never ordered on screen or made key.
        let model = Model()
        let host = NSHostingView(rootView: Fixture(model: model))
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 1180, height: 760),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.contentView = nil; window.close() }
        window.contentView = host
        await layoutBoundary(host)
        let originalSidebar = try probe("sidebar", host: host)
        for width in [CGFloat(1180), 1320, 1500, 1180] {
            window.setContentSize(NSSize(width: width, height: 760))
            await layoutBoundary(host)
            let sidebar = try probe("sidebar", host: host)
            let workspace = try probe("workspace", host: host)
            let table = try probe("table", host: host)
            let expected = V2SidebarWidthPolicy.rendered(stored: 360, collapsed: false, availableWidth: width)
            #expect(sidebar === originalSidebar)
            #expect(abs(sidebar.bounds.width - expected) < 0.5)
            #expect(abs(workspace.bounds.width - (width - expected)) < 0.5)
            #expect(abs(table.bounds.width - (width - expected - 32)) < 0.5)
            #expect(workspace.convert(workspace.bounds, to: host).maxX <= host.bounds.maxX + 0.5)
            #expect(model.stored == 360 && model.writes == 0)
        }
        model.collapsed = true
        await layoutBoundary(host)
        #expect(abs(originalSidebar.bounds.width - 56) < 0.5)
        model.collapsed = false
        await layoutBoundary(host)
        #expect(abs(originalSidebar.bounds.width - 220) < 0.5)
        #expect(model.stored == 360 && model.writes == 0)
        #expect(!window.isVisible)
    }
}
