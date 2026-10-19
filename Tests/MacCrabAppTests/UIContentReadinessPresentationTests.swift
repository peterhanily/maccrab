import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Readiness metadata without diagnostic UI")
struct UIContentReadinessPresentationTests {
    @Test("No-data notices never turn an incomplete read into success")
    func alertNotices() {
        let expected: [UIContentReadiness.Phase: V2AlertReadNotice] = [
            .loading: .loading, .refreshingCached: .loading, .partial: .partial,
            .deferred: .deferred, .unavailable: .unavailable, .failed: .failed
        ]
        for phase in UIContentReadiness.Phase.allCases {
            #expect(V2AlertReadNotice.resolve(phase: phase, hasSnapshot: false, hasError: false)
                    == expected[phase])
            // These have separate cached/error notices, not duplicate banners.
            #expect(V2AlertReadNotice.resolve(phase: phase, hasSnapshot: true, hasError: false) == nil)
            #expect(V2AlertReadNotice.resolve(phase: phase, hasSnapshot: false, hasError: true)
                    == (phase == .loading || phase == .refreshingCached ? .loading : nil))
            #expect(V2AlertReadNotice.resolve(phase: phase, hasSnapshot: true, hasError: true) == nil)
        }
        #expect(expected[.loadedEmpty] == nil && expected[.loadedNonempty] == nil)
    }

    @Test("Production decorates useful leaves and keeps honest status guards")
    func productionCarriers() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabApp")
        func source(_ path: String) throws -> String {
            try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
        }
        let marker = try source("UIContentReadinessMarker.swift")
        #expect(marker.contains("content.accessibilityIdentifier(readiness.accessibilityIdentifier)"))
        for forbidden in ["NSTextField", "Text(", "accessibilityValue(", "accessibilityLabel(",
                          "accessibilityHidden(", "opacity(", "displayText"] {
            #expect(!marker.contains(forbidden))
        }
        let detection = try source("V2/Workspaces/V2DetectionWorkspace.swift")
        let events = try source("Views/EventStream.swift")
        let alerts = try source("V2/Workspaces/V2AlertsWorkspace.swift")
        for page in [detection, events, alerts] {
            #expect(!page.contains("UIContentReadinessMarker("))
            #expect(!page.contains(".phase.displayText"))
            #expect(!page.contains("Content loaded"))
        }
        #expect(detection.contains(".contentReadiness(presentation.readiness(for: presentationIdentity, query: state.ruleSearchQuery))"))
        #expect(events.contains(".contentReadiness(contentReadinessForDisplay)"))
        #expect(events.contains("ProgressView(EventReadNotice.loading.text)"))
        #expect(events.contains("localized: \"events.cachedIncomplete\""))
        #expect(alerts.components(separatedBy: "timeRangeChips(readiness: readiness)").count - 1 == 2)
        #expect(alerts.components(separatedBy: "timeRangeChips()").count - 1 == 1)
        #expect(alerts.contains(".contentReadiness(on ? readiness : nil)"))
        #expect(alerts.contains(".accessibilityAddTraits(on ? [.isSelected] : [])"))
        #expect(alerts.contains(".forDisplayedContent(isEmpty: visible.isEmpty)"))
        #expect(alerts.contains(".forDisplayedContent(isEmpty: history.isEmpty)"))
        #expect(alerts.contains("ProgressView(notice.text)"))
        #expect(alerts.contains("localized: \"alerts.cachedNotice\""))
        #expect(alerts.contains("Text(V2AlertReadNotice.failed.text)"))
        #expect(alerts.contains("Text(error).textSelection(.enabled)"))
        #expect(alerts.contains("if daemonReporting && presentation.isFresh(for: presentationContext) && !hasOpenAlerts"))
    }

    @MainActor
    private final class State: ObservableObject {
        @Published var readiness: UIContentReadiness
        @Published var selected = "7d"
        @Published var usesMarker = true
        var presses = 0
        init(workspace: UIContentReadiness.Workspace) {
            readiness = UIContentReadiness(workspace: workspace)
        }
    }

    @MainActor
    private struct Fixture: View {
        @ObservedObject var state: State
        let buttons: Bool
        var body: some View {
            VStack {
                if buttons {
                    HStack {
                        ForEach(["24h", "7d", "30d", "all"], id: \.self) { key in
                            Button(key) { state.presses += 1; state.selected = key }
                                .buttonStyle(.plain)
                                .accessibilityLabel("\(key) time range")
                                .accessibilityAddTraits(state.selected == key ? [.isSelected] : [])
                                .contentReadiness(state.usesMarker && state.selected == key ? state.readiness : nil)
                        }
                    }
                } else {
                    Text("Useful fixture heading")
                        .font(.title2)
                        .contentReadiness(state.usesMarker ? state.readiness : nil)
                }
            }
            .environment(\.accessibilityEnabled, true)
        }
    }

    @MainActor
    private func boundary(_ host: NSView) async {
        host.needsLayout = true
        host.layoutSubtreeIfNeeded()
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        host.layoutSubtreeIfNeeded()
    }

    /// SwiftUI's local AccessibilityNode implements the public Objective-C
    /// getters without formally adopting NSAccessibilityProtocol. AnyObject's
    /// checked optional method lookup keeps their declared return types; this
    /// does not use perform(_:), an IMP cast, KVC, or private selectors.
    @MainActor
    private struct LocalElement {
        let object: NSObject
        private var dynamicObject: AnyObject { object }

        func requireAPI(_ names: [String]) throws {
            for name in names {
                try #require(object.responds(to: NSSelectorFromString(name)),
                             "private accessibility object lacks required public method: \(name)")
            }
        }
        func accessibilityChildren() -> [Any]? { dynamicObject.accessibilityChildren?() ?? nil }
        func accessibilityIdentifier() -> String? { dynamicObject.accessibilityIdentifier?() ?? nil }
        func accessibilityRole() -> NSAccessibility.Role? { dynamicObject.accessibilityRole?() ?? nil }
        func accessibilityLabel() -> String? { dynamicObject.accessibilityLabel?() ?? nil }
        func accessibilityValue() -> Any? { dynamicObject.accessibilityValue?() ?? nil }
        func accessibilityFrame() -> NSRect? { dynamicObject.accessibilityFrame?() }
        func isAccessibilityElement() -> Bool? { dynamicObject.isAccessibilityElement?() }
        func isAccessibilitySelected() -> Bool? { dynamicObject.isAccessibilitySelected?() }
        func accessibilityPerformPress() -> Bool? { dynamicObject.accessibilityPerformPress?() }
    }

    /// Local objects belonging only to our unshown fixture. No AXUIElement,
    /// running application, trust/permission request or external AX IPC.
    @MainActor
    private func elements(_ host: NSView) throws -> [LocalElement] {
        var pending: [Any] = [host]
        var visited = Set<ObjectIdentifier>()
        var found: [LocalElement] = []
        var structure: [[String: Any]] = []
        while let next = pending.popLast() {
            let object = next as AnyObject
            guard visited.insert(ObjectIdentifier(object)).inserted else { continue }
            try #require(visited.count <= 256, "private accessibility tree exceeded its bound")
            var record: [String: Any] = [
                "class": String(String(reflecting: type(of: object)).prefix(160)),
                "protocol": next is any NSAccessibilityProtocol,
                "native_subviews": (next as? NSView)?.subviews.count ?? -1
            ]
            let localObject = try #require(next as? NSObject,
                                          "private accessibility tree contains a non-Objective-C object")
            let element = LocalElement(object: localObject)
            try element.requireAPI(["accessibilityChildren", "accessibilityIdentifier",
                                    "accessibilityRole", "isAccessibilityElement",
                                    "accessibilityLabel", "accessibilityValue"])
            record["children_getter"] = true
            record["identifier_getter"] = true
            found.append(element)
            let children = element.accessibilityChildren() ?? []
            try #require(children.count <= 64, "private accessibility children exceeded their bound")
            record["role"] = element.accessibilityRole()?.rawValue ?? "none"
            record["children"] = children.count
            let identifier = element.accessibilityIdentifier()
            record["identifier_kind"] = identifier == nil ? "none"
                : (identifier!.hasPrefix("maccrab.content.v1.") ? "readiness" : "other")
            record["is_element"] = try #require(element.isAccessibilityElement())
            structure.append(record)
            pending.append(contentsOf: children)
        }
        let diagnostic: [String: Any] = ["diagnostic": "private_local_accessibility_structure",
            "nodes": visited.count, "records": Array(structure.prefix(16)),
            "records_omitted": max(0, structure.count - 16),
            "host_width": host.bounds.width, "host_height": host.bounds.height,
            "attached_to_unshown_window": host.window.map { !$0.isVisible } ?? false]
        let bytes = try JSONSerialization.data(withJSONObject: diagnostic, options: [.sortedKeys])
        let text = try #require(String(data: bytes, encoding: .utf8))
        print(text)
        return found
    }

    private func states(_ workspace: UIContentReadiness.Workspace) -> [UIContentReadiness] {
        var result = [UIContentReadiness(workspace: workspace)]
        for cached in [false, true] {
            var state = UIContentReadiness(workspace: workspace)
            state.begin(retainingCachedContent: cached)
            result.append(state)
        }
        for completion in UIContentReadiness.Completion.allCases {
            var state = UIContentReadiness(workspace: workspace)
            let ticket = state.begin(retainingCachedContent: false)
            state.complete(completion, for: ticket)
            result.append(state)
        }
        return result
    }

    @Test("Useful text survives every phase without extra diagnostic content",
          arguments: [UIContentReadiness.Workspace.events, .detection])
    @MainActor
    func textCarrier(workspace: UIContentReadiness.Workspace) async throws {
        try await hostedCarrier(workspace: workspace, buttons: false)
    }

    @Test("Only the active alert range is marked, retaining its label, trait and action")
    @MainActor
    func alertRangeCarrier() async throws {
        try await hostedCarrier(workspace: .alerts, buttons: true)
    }

    @MainActor
    private func hostedCarrier(workspace: UIContentReadiness.Workspace, buttons: Bool) async throws {
        let state = State(workspace: workspace)
        let host = NSHostingView(rootView: Fixture(state: state, buttons: buttons))
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 640, height: 180),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.close() }
        window.contentView = host
        // This direct, task-owned native control distinguishes protocol-reader
        // failure from SwiftUI bridge exposure; it never substitutes for a
        // missing SwiftUI carrier or participates in the marker namespace.
        let control = NSTextField(labelWithString: "Native fixture control")
        control.setAccessibilityElement(true)
        control.setAccessibilityIdentifier("fixture.native.control")
        let controlElements = try elements(control)
        try #require(controlElements.contains { $0.accessibilityIdentifier() == "fixture.native.control" })
        for (index, readiness) in states(workspace).enumerated() {
            state.readiness = readiness
            // Exercise all four selected carriers, including a different
            // descendant when SwiftUI reuses the surrounding HStack.
            state.selected = ["24h", "7d", "30d", "all"][index % 4]
            await boundary(host)
            let all = try elements(host)
            let markers = all.filter { $0.accessibilityIdentifier()?.hasPrefix("maccrab.content.v1.") == true }
            try #require(markers.count == 1, "exactly one real visible leaf must carry readiness")
            let marker = markers[0]
            try marker.requireAPI(["accessibilityFrame"])
            #expect(marker.accessibilityIdentifier() == readiness.accessibilityIdentifier)
            #expect(marker.accessibilityValue() as? String != readiness.phase.rawValue)
            let useful = buttons ? "\(state.selected) time range" : "Useful fixture heading"
            #expect(marker.accessibilityLabel() == useful || marker.accessibilityValue() as? String == useful)
            let markerFrame = try #require(marker.accessibilityFrame())
            #expect(markerFrame.width > 0 && markerFrame.height > 0)
            for element in all {
                #expect(element.accessibilityLabel() != "Workspace content status")
                #expect(element.accessibilityLabel() != readiness.phase.displayText)
                #expect(element.accessibilityValue() as? String != readiness.phase.displayText)
            }
            if buttons {
                try marker.requireAPI(["isAccessibilitySelected", "accessibilityPerformPress"])
                #expect(marker.isAccessibilitySelected() == true)
                let before = state.presses
                let pressed = try #require(marker.accessibilityPerformPress())
                #expect(pressed)
                await boundary(host)
                #expect(state.presses == before + 1)
            }
            #expect(!window.isVisible)
        }
        state.usesMarker = false // Campaigns/other non-carrier siblings.
        await boundary(host)
        let unmarked = try elements(host)
        #expect(!unmarked.contains { $0.accessibilityIdentifier()?.hasPrefix("maccrab.content.v1.") == true })
        #expect(!window.isVisible)
    }
}
