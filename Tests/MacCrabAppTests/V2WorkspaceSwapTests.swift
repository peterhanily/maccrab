import AppKit
import Foundation
import SwiftUI
import Testing
@testable import MacCrabApp

@Suite("Immediate workspace swaps", .serialized)
struct V2WorkspaceSwapTests {
    @Test("Shell uses only a workspace-keyed immediate swap and keeps independent motion and owners")
    func shellContract() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent(
            "Sources/MacCrabApp/V2/V2DashboardShell.swift"), encoding: .utf8)
        let code = source.split(separator: "\n", omittingEmptySubsequences: false)
            .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
            .joined(separator: "\n")
        #expect(code.contains("workspaceContent\n                            .transition(.identity)"))
        #expect(code.contains(".animation(nil, value: state.currentWorkspace)"))
        #expect(!code.contains("V2Motion.workspaceTransition") && !code.contains("V2Motion.navigation"))
        #expect(!code.contains("disablesAnimations") && !code.contains(".id(state.currentWorkspace)"))
        for unchanged in [
            "@StateObject private var eventQuerySession: EventQuerySession",
            "@StateObject private var alertsPresentation = V2AlertsPresentationModel()",
            "@StateObject private var detectionPresentation = V2DetectionPresentation()",
            ".animation(V2Motion.overlay(reduceMotion: reduceMotion), value: state.paletteOpen)",
            ".animation(V2Motion.toast(reduceMotion: reduceMotion), value: state.toast?.id)",
            "await state.connectLiveData()", "state.startAutoRefresh()", "state.stopAutoRefresh()",
            "state.goto(url: url)", "state.switchWorkspace(wk)"
        ] {
            #expect(code.contains(unchanged), "Unrelated ownership/navigation/lifecycle/motion must remain wired")
        }
    }

    @MainActor
    private final class Selection: ObservableObject {
        @Published var page = 0
        @Published var detail = 0
    }

    @MainActor
    private final class RetainedOwner: ObservableObject { let id = UUID() }

    @MainActor
    private final class Observations {
        struct Update {
            let page: Int
            let detail: Int
            let owner: UUID
            let animated: Bool
            let animationsDisabled: Bool
        }
        var made: [Int] = []
        var dismantled: [Int] = []
        var updates: [Update] = []
    }

    @MainActor
    private struct Probe: NSViewRepresentable {
        let page: Int
        let detail: Int
        let owner: UUID
        let observations: Observations

        final class Coordinator {
            let page: Int
            let observations: Observations
            init(page: Int, observations: Observations) {
                self.page = page
                self.observations = observations
            }
        }

        func makeCoordinator() -> Coordinator { Coordinator(page: page, observations: observations) }
        func makeNSView(context: Context) -> NSView {
            observations.made.append(page)
            return NSView()
        }
        func updateNSView(_ view: NSView, context: Context) {
            observations.updates.append(.init(page: page, detail: detail, owner: owner,
                animated: context.transaction.animation != nil,
                animationsDisabled: context.transaction.disablesAnimations))
        }
        static func dismantleNSView(_ view: NSView, coordinator: Coordinator) {
            coordinator.observations.dismantled.append(coordinator.page)
        }
    }

    /// The source contract above binds this exact modifier composition to the
    /// shell. The native fixture uses no AppState, provider, preferences, store,
    /// collector or OS service. Its window is never shown or made key.
    @MainActor
    private struct Fixture: View {
        @ObservedObject var selection: Selection
        @StateObject private var owner = RetainedOwner()
        let observations: Observations

        var body: some View {
            ZStack {
                Group {
                    if selection.page == 0 {
                        Probe(page: 0, detail: selection.detail, owner: owner.id, observations: observations)
                    } else {
                        Probe(page: 1, detail: selection.detail, owner: owner.id, observations: observations)
                    }
                }
                .transition(.identity)
            }
            .animation(nil, value: selection.page)
            .frame(width: 320, height: 160)
        }
    }

    @MainActor
    private func settle(_ host: NSView, until complete: () -> Bool) async throws {
        // This deadline only bounds failure/hang detection; correctness is
        // asserted from native transaction/lifecycle callbacks, not elapsed time.
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        repeat {
            host.needsLayout = true
            host.layoutSubtreeIfNeeded()
            if complete() { return }
            await Task.yield()
        } while clock.now < deadline
        try #require(complete(), "Private native fixture did not reach the requested lifecycle boundary")
    }

    @Test("Private native host swaps pages without animation, retains its owner, and permits later local motion")
    @MainActor
    func nativeSwapAndLocalAnimation() async throws {
        let selection = Selection(), observations = Observations()
        let host = NSHostingView(rootView: Fixture(selection: selection, observations: observations))
        let window = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 320, height: 160),
                              styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        defer { window.contentView = nil; window.close() }
        window.contentView = host
        try await settle(host) { observations.updates.contains { $0.page == 0 } }
        let owner = try #require(observations.updates.last?.owner)
        #expect(observations.made == [0])
        #expect(!window.isVisible)

        for page in [1, 0] {
            let firstNewUpdate = observations.updates.count
            let expectedRemoved = page == 1 ? [0] : [0, 1]
            withAnimation(.linear(duration: 0.4)) { selection.page = page }
            try await settle(host) {
                observations.updates.dropFirst(firstNewUpdate).contains { $0.page == page }
                    && observations.dismantled == expectedRemoved
            }
            let updates = observations.updates.dropFirst(firstNewUpdate).filter { $0.page == page }
            #expect(!updates.isEmpty)
            #expect(updates.allSatisfy { !$0.animated && $0.owner == owner })
        }
        #expect(observations.made == [0, 1, 0])
        let firstLocalUpdate = observations.updates.count
        withAnimation(.linear(duration: 0.4)) { selection.detail += 1 }
        try await settle(host) {
            observations.updates.dropFirst(firstLocalUpdate).contains { $0.detail == 1 && $0.animated }
        }
        let local = observations.updates.dropFirst(firstLocalUpdate).filter { $0.detail == 1 }
        #expect(local.contains { $0.animated && !$0.animationsDisabled && $0.owner == owner })
        #expect(observations.made == [0, 1, 0], "An unrelated in-page change must not remount the page")
        #expect(!window.isVisible)
    }
}
