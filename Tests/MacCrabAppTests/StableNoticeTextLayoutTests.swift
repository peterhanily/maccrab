import AppKit
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Stable cached-notice geometry")
struct StableNoticeTextLayoutTests {
    @MainActor
    private final class State: ObservableObject {
        @Published var visibleIndex: Int? = nil
    }

    @MainActor
    private struct Probe: NSViewRepresentable {
        let name: String
        func makeNSView(context: Context) -> NSView {
            let view = NSView()
            view.identifier = NSUserInterfaceItemIdentifier(name)
            return view
        }
        func updateNSView(_ view: NSView, context: Context) {}
    }

    @MainActor
    private struct Fixture: View {
        @ObservedObject var state: State
        var body: some View {
            VStack(alignment: .leading, spacing: 0) {
                StableNoticeText(
                    reservedMessages: [
                        Text(verbatim: "Cached fixture while refreshing."),
                        Text(verbatim: "Cached fixture; the latest read has not completed successfully. This longer synthetic warning must remain fully wrapped.")
                    ],
                    visibleIndex: state.visibleIndex
                )
                .font(.system(size: 13))
                .background(Probe(name: "fixture.notice"))
                Color.clear.frame(height: 24)
                    .background(Probe(name: "fixture.table"))
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
    }

    @MainActor
    private func layoutBoundary(_ host: NSView) async {
        host.needsLayout = true
        host.layoutSubtreeIfNeeded()
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        host.layoutSubtreeIfNeeded()
    }

    @MainActor
    private func frame(_ name: String, in host: NSView) throws -> CGRect {
        var pending = [host]
        var visited = 0
        while let view = pending.popLast() {
            visited += 1
            try #require(visited <= 512, "private fixture view traversal exceeded its bound")
            if view.identifier?.rawValue == name {
                return view.convert(view.bounds, to: host)
            }
            pending.append(contentsOf: view.subviews)
        }
        Issue.record("private fixture geometry probe was not realized")
        throw FixtureError.missingProbe
    }

    private enum FixtureError: Error { case missingProbe }

    @MainActor
    private func fixture(width: CGFloat) async throws -> (NSWindow, NSHostingView<Fixture>, State) {
        let state = State()
        let host = NSHostingView(rootView: Fixture(state: state))
        // Only synthetic text is hosted, never ordered onscreen. No AppState,
        // engine reader, preference, file, network or accessibility API is used.
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: width, height: 320),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        var completed = false
        defer { if !completed { window.close() } }
        window.contentView = host
        await layoutBoundary(host)
        let notice = try frame("fixture.notice", in: host)
        #expect(notice.height > 0)
        #expect(!window.isVisible)
        completed = true
        return (window, host, state)
    }

    @Test("absent, refreshing and incomplete notices keep the same table origin",
          arguments: [CGFloat(240), 800])
    @MainActor
    func visibilityDoesNotMoveTable(width: CGFloat) async throws {
        let (window, host, state) = try await fixture(width: width)
        defer { window.close() }
        let reserved = try frame("fixture.notice", in: host)
        let table = try frame("fixture.table", in: host)
        let states: [Int?] = [0, 1, nil, 0, nil]
        for index in states {
            state.visibleIndex = index
            await layoutBoundary(host)
            let currentNotice = try frame("fixture.notice", in: host)
            let currentTable = try frame("fixture.table", in: host)
            #expect(abs(currentNotice.height - reserved.height) < 0.5)
            #expect(abs(currentNotice.minY - reserved.minY) < 0.5)
            #expect(abs(currentTable.minY - table.minY) < 0.5)
            #expect(currentNotice.width <= host.bounds.width + 0.5)
            #expect(!window.isVisible)
        }
    }

    @Test("reserved notices grow with wrapping instead of using a clipped one-line height")
    @MainActor
    func wrappingIsPreserved() async throws {
        let (wideWindow, wideHost, _) = try await fixture(width: 800)
        defer { wideWindow.close() }
        let (narrowWindow, narrowHost, state) = try await fixture(width: 160)
        defer { narrowWindow.close() }
        let wide = try frame("fixture.notice", in: wideHost)
        let narrow = try frame("fixture.notice", in: narrowHost)
        #expect(narrow.height > wide.height + 1)
        #expect(narrow.height < narrowHost.bounds.height)
        state.visibleIndex = 1
        await layoutBoundary(narrowHost)
        let visible = try frame("fixture.notice", in: narrowHost)
        #expect(abs(visible.height - narrow.height) < 0.5)
    }
}
