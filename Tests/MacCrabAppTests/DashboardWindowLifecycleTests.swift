import Foundation
import Testing
@testable import MacCrabApp

@MainActor
@Suite("Dashboard window lifecycle")
struct DashboardWindowLifecycleTests {
    private func source() -> V2EngineSource {
        .init(directory: FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-window-lifecycle-\(UUID())").path)
    }

    @Test("leaving one Events window preserves the remaining window's incremental poll")
    func overlappingEventsWindows() {
        let app = AppState(engineSource: source(), startBackgroundWork: false)
        let first = UUID()
        let second = UUID()
        #expect(!app.eventsWorkspaceVisible)

        app.setEventsWorkspaceVisible(true, owner: first)
        app.setEventsWorkspaceVisible(true, owner: second)
        app.setEventsWorkspaceVisible(true, owner: second) // duplicate appearance
        app.setEventsWorkspaceVisible(false, owner: first)
        app.setEventsWorkspaceVisible(false, owner: first) // duplicate disappearance
        app.setEventsWorkspaceVisible(false, owner: UUID()) // unrelated owner
        #expect(app.eventsWorkspaceVisible)

        app.setEventsWorkspaceVisible(false, owner: second)
        #expect(!app.eventsWorkspaceVisible)
        app.setEventsWorkspaceVisible(true, owner: first)
        #expect(app.eventsWorkspaceVisible)
        app.setEventsWorkspaceVisible(false, owner: first)
        #expect(!app.eventsWorkspaceVisible)
    }

    @Test("restarting and closing a dashboard cancels the actual refresh tasks")
    func refreshReplacementAndStop() async throws {
        let state = V2DashboardState(engineSource: source())
        state.startAutoRefresh()
        let first = try #require(state.autoRefreshTask)
        defer { first.cancel(); state.stopAutoRefresh() }
        await Task.yield()

        state.startAutoRefresh()
        let second = try #require(state.autoRefreshTask)
        #expect(first.isCancelled)
        #expect(!second.isCancelled)
        state.stopAutoRefresh()
        state.stopAutoRefresh()
        #expect(second.isCancelled)
        #expect(state.autoRefreshTask == nil)
        // Both handles belong to real Task.sleep loops, not a mock scheduler.
        if first.isCancelled { await first.value }
        if second.isCancelled { await second.value }
        #expect(state.refreshTick == 0)
    }

    @Test("a cancelled connection completion cannot replace a newer window refresh")
    func cancelledConnectionCompletion() async throws {
        let state = V2DashboardState(engineSource: source())
        var releaseConnection: CheckedContinuation<Void, Never>?
        let oldAppearance = Task { @MainActor in
            // Model a store-open operation that returns after task cancellation.
            await withCheckedContinuation { releaseConnection = $0 }
            state.startAutoRefresh()
        }
        defer {
            oldAppearance.cancel()
            releaseConnection?.resume()
            state.stopAutoRefresh()
        }
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(2))
        while releaseConnection == nil, clock.now < deadline {
            await Task.yield()
        }
        try #require(releaseConnection != nil)
        state.stopAutoRefresh()
        oldAppearance.cancel()

        state.startAutoRefresh()
        let current = try #require(state.autoRefreshTask)
        releaseConnection?.resume()
        releaseConnection = nil
        await oldAppearance.value
        #expect(!current.isCancelled,
                "A cancelled older connection must neither replace nor cancel the new loop")
        state.stopAutoRefresh()
        #expect(current.isCancelled)
        if current.isCancelled { await current.value }
    }

    @Test("releasing dashboard state cancels its sleeping refresh without retaining the window")
    func releasedStateCancelsRefresh() async throws {
        var state: V2DashboardState? = V2DashboardState(engineSource: source())
        weak var weakState = state
        state?.startAutoRefresh()
        let task = try #require(state?.autoRefreshTask)
        defer { task.cancel() }
        await Task.yield()
        state = nil
        #expect(weakState == nil, "The periodic sleep must not own the dashboard state")
        #expect(task.isCancelled, "Dropping a Task handle alone does not cancel its loop")
        if task.isCancelled { await task.value }
    }
}
