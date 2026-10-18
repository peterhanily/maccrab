import Foundation
import Testing
import MacCrabCore
@testable import MacCrabApp

#if DEBUG
/// State-only fixtures with injected time, sink and provider boundaries. The
/// state restores ordinary navigation preferences read-only; navigation below
/// uses history application, never goto/persist. No app, store, native API,
/// logging, preference writes, filesystem or network activity is performed.
@MainActor
@Suite("Visit timing state and shell lifecycle")
struct V2VisitTimingLifecycleTests {
    @MainActor private final class Observations {
        var now: UInt64 = 1_000
        var summaries: [V2VisitTiming.Summary] = []
    }

    @MainActor private final class Provider: V2DataProvider {
        let mode: V2DataSourceMode = .live
        let lastErrorDescription: String?
        let dataDir: String?
        init(_ directory: String, error: String? = nil) { dataDir = directory; lastErrorDescription = error }
        func alerts(since: Date, limit: Int) async -> [V2MockAlert] { [] }
        func events(limit: Int) async -> [V2MockEvent] { [] }
        func campaigns(since: Date, limit: Int) async -> [V2MockCampaign] { [] }
        func traces(limit: Int) async -> [V2MockTrace] { [] }
        func rules() async -> [V2MockRule] { [] }
        func feeds() async -> [V2MockFeed] { [] }
        func mcpServers() async -> [V2MockMCP] { [] }
        func collectors() async -> [V2MockCollector] { [] }
        func permissions() async -> [V2MockPermission] { [] }
        func packages() async -> [V2MockPackage] { [] }
        func extensions() async -> [V2MockExtension] { [] }
        func suppressAlert(id: String) async -> Bool { false }
        func unsuppressAlert(id: String) async -> Bool { false }
        func deleteAlert(id: String) async -> Bool { false }
        func suppressAlerts(ids: [String]) async -> Int { 0 }
        func suppressCampaign(id: String) async -> Int { 0 }
        func refreshThreatIntel() async -> Bool { false }
        func suppressions() async -> [V2SuppressionEntry] { [] }
        func liftSuppression(id: String) async -> Bool { false }
        func traceMembers(traceId: String) async -> [V2TraceMember] { [] }
        func traceEdges(traceId: String) async -> [V2TraceEdge] { [] }
        func heartbeat() async -> V2HeartbeatSnapshot? { nil }
        func alertHistogram(rangeKey: String) async -> [V2OverviewBucket] { [] }
        func kpis() async -> V2OverviewKPIs { .zero }
    }

    private func fixture(_ tab: V2WorkspaceTab = .detectionRules) -> (V2DashboardState, Observations) {
        let observations = Observations()
        let timing = V2VisitTiming(now: { observations.now }, emit: { observations.summaries.append($0) })
        let state = V2DashboardState(engineSource: .init(directory: "/synthetic/visit-timing"), visitTiming: timing)
        state.currentWorkspace = tab.workspace
        state.selectedTabs[tab.workspace] = tab
        state.provider = V2OfflineDataProvider()
        state.providerDeferralForTesting = { false }
        state.providerRetirementForTesting = { _ in }
        state.providerFactoryForTesting = { _ in
            Issue.record("Unexpected provider opening in a state-only fixture")
            return nil
        }
        return (state, observations)
    }

    /// Exercises the real applyDestination path without UserDefaults writes.
    private func accept(_ destination: V2NavigationDestination, in state: V2DashboardState) {
        state.history = V2NavigationHistory()
        state.history.push(destination)
        state.history.push(.init(workspace: state.currentWorkspace, tab: state.currentTab()))
        state.goBack()
    }

    @Test("Initial restored visit starts once; refresh and no-op navigation cannot restart it")
    func initialAndNoOp() throws {
        let (state, observations) = fixture()
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        let ticket = try #require(state.visitTiming.currentTicket(for: .detection))
        observations.now += 20
        state.refreshTick += 1
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        accept(.init(workspace: .detection, tab: .detectionRules, entityId: "synthetic-inspector"), in: state)
        state.reconcileVisitTimingContext()
        #expect(state.visitTiming.currentTicket(for: .detection) == ticket)
        #expect(observations.summaries.isEmpty)
        state.stopVisitTiming(.windowClosed)
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        #expect(state.visitTiming.currentTicket(for: .detection) == nil)
        #expect(observations.summaries.count == 1 && observations.summaries[0].elapsedNS == 20)
    }

    @Test("Accepted navigation precedes initial shell task and carries exact applied filters privately")
    func acceptedNavigationBeforeAppearance() throws {
        let (state, observations) = fixture(.alertsHistory)
        accept(.init(workspace: .alerts, tab: .alertsOpen, filters: ["q": "private synthetic query"]), in: state)
        let ticket = try #require(state.visitTiming.currentTicket(for: .alerts))
        #expect(state.alertSearchQuery == "private synthetic query")
        observations.now += 7
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        #expect(state.visitTiming.currentTicket(for: .alerts) == ticket)
        state.stopVisitTiming(.windowClosed)
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        #expect(observations.summaries.count == 1)
        #expect(!observations.summaries[0].logLine.contains("private synthetic query"))
    }

    @Test("First matching deep link starts the restored page visit, repeated matching links do not restart it")
    func initialMatchingLink() throws {
        let (state, observations) = fixture()
        let destination = V2NavigationDestination(workspace: .detection, tab: .detectionRules)
        accept(destination, in: state)
        let ticket = try #require(state.visitTiming.currentTicket(for: .detection))
        observations.now += 9
        accept(destination, in: state)
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        #expect(state.visitTiming.currentTicket(for: .detection) == ticket)
        #expect(observations.summaries.isEmpty)
        state.stopVisitTiming(.windowClosed)
        #expect(observations.summaries.count == 1 && observations.summaries[0].elapsedNS == 9)
    }

    @Test("Supported navigation supersedes, unsupported navigation retires, neither makes a completed visit recur")
    func navigationBoundaries() throws {
        let (state, observations) = fixture()
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        let old = try #require(state.visitTiming.currentTicket(for: .detection))
        accept(.init(workspace: .alerts, tab: .alertsOpen), in: state)
        let current = try #require(state.visitTiming.currentTicket(for: .alerts))
        #expect(current != old)
        #expect(observations.summaries.map(\.terminal) == [.superseded])
        state.reconcileVisitTimingContext() // delayed shell observer sees accepted context
        #expect(state.visitTiming.currentTicket(for: .alerts) == current)
        accept(.init(workspace: .alerts, tab: .alertsHistory), in: state)
        #expect(state.visitTiming.currentTicket(for: .alerts) == nil)
        #expect(observations.summaries.map(\.terminal) == [.superseded, .contextChanged])
    }

    @Test("Changed user filters retire the old visit before an accepted input exists", arguments: 0..<5)
    func filterChanges(_ field: Int) throws {
        let (state, observations) = fixture(field == 0 ? .detectionRules : .alertsOpen)
        let workspace: V2VisitTiming.Workspace = field == 0 ? .detection : .alerts
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        let ticket = try #require(state.currentVisitTimingTicket(for: workspace))
        switch field {
        case 0: state.ruleSearchQuery = "synthetic rule"
        case 1: state.alertSearchQuery = "synthetic alert"
        case 2: state.alertTimeRange = "24h"
        case 3: state.alertSeverityFilter = .critical
        default: state.pendingAlertsWindow = .init(start: .init(timeIntervalSince1970: 1), end: .init(timeIntervalSince1970: 2))
        }
        // This is the exact setter-before-shell-onChange boundary: the raw
        // recorder is still pending, but no builder/layout/failure callback
        // may acquire its ticket for the new context. The lookup is pure.
        #expect(state.visitTiming.currentTicket(for: workspace) == ticket)
        #expect(state.currentVisitTimingTicket(for: workspace) == nil)
        #expect(observations.summaries.isEmpty)
        state.reconcileVisitTimingContext()
        state.reconcileVisitTimingContext()
        #expect(observations.summaries.map(\.terminal) == [.contextChanged])
    }

    @Test("Inactive first appearance or subsequent focus cannot fabricate a navigation interval")
    func activityBoundaries() {
        let (state, observations) = fixture()
        state.setForegroundActive(false)
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        state.setForegroundActive(true)
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        #expect(state.visitTiming.currentTicket(for: .detection) == nil)
        #expect(observations.summaries.isEmpty)
        accept(.init(workspace: .alerts, tab: .alertsOpen), in: state)
        state.setForegroundActive(false)
        state.setForegroundActive(true)
        #expect(state.visitTiming.currentTicket(for: .alerts) == nil)
        #expect(observations.summaries.map(\.terminal) == [.windowInactive])
    }

    @Test("Initial deferral and release preserve the cold visit through healthy adoption")
    func coldStartup() async throws {
        let (state, observations) = fixture()
        defer { state.dismissToast() }
        var deferred = true
        state.providerDeferralForTesting = { deferred }
        var opens = 0
        state.providerFactoryForTesting = { source in opens += 1; return Provider(source.directory) }
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        let ticket = try #require(state.visitTiming.currentTicket(for: .detection))
        state.reconcileVisitTimingBackend(epoch: 1, deferred: true)
        await state.connectLiveData()
        #expect(opens == 0 && !state.didProbeLiveData)
        #expect(state.visitTiming.currentTicket(for: .detection) == ticket)
        deferred = false
        observations.now += 50
        await state.resumeProviderAfterStartup()
        // Delayed SwiftUI observation of the release must not cancel an
        // already-adopted healthy initial provider's visit.
        state.reconcileVisitTimingBackend(epoch: 2, deferred: false)
        #expect(opens == 1 && state.didProbeLiveData)
        #expect(state.visitTiming.currentTicket(for: .detection) == ticket)
        state.stopVisitTiming(.windowClosed)
        let summary = try #require(observations.summaries.first)
        #expect(summary.providerReadyNS == 50 && summary.readAcceptedNS == nil)
        #expect(summary.terminal == .windowClosed && observations.summaries.count == 1)
    }

    @Test("Completed missing, wrong-source or degraded probes are terminal, never provider-ready", arguments: 0..<3)
    func failedProviders(_ kind: Int) async throws {
        let (state, observations) = fixture()
        defer { state.dismissToast() }
        state.providerFactoryForTesting = { source in
            if kind == 0 { return nil }
            return Provider(kind == 1 ? source.directory + "/wrong" : source.directory,
                            error: kind == 2 ? "Synthetic partial open" : nil)
        }
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        await state.connectLiveData()
        let summary = try #require(observations.summaries.first)
        #expect(summary.terminal == (kind == 2 ? .readFailed : .readUnavailable))
        #expect(summary.providerReadyNS == nil && summary.nativeTableLayoutNS == nil)
        #expect(observations.summaries.count == 1)
    }

    @Test("Only healthy adoption supplies readiness; ignored reprobe failure preserves the current provider")
    func retainedHealthyProvider() async throws {
        let (state, observations) = fixture(.alertsHistory)
        defer { state.dismissToast() }
        state.providerFactoryForTesting = { Provider($0.directory) }
        await state.connectLiveData()
        accept(.init(workspace: .alerts, tab: .alertsOpen), in: state)
        let ticket = try #require(state.visitTiming.currentTicket(for: .alerts))
        state.providerFactoryForTesting = { _ in nil }
        await state.reconnectLiveDataIfStale()
        #expect(state.visitTiming.currentTicket(for: .alerts) == ticket)
        state.stopVisitTiming(.windowClosed)
        #expect(observations.summaries.count == 1 && observations.summaries[0].providerReadyNS == 0)
    }

    @Test("Post-adoption epoch change terminates, while duplicate epoch observations do nothing")
    func epochBoundaries() async throws {
        let (state, observations) = fixture()
        defer { state.dismissToast() }
        state.providerFactoryForTesting = { Provider($0.directory) }
        state.beginInitialVisitTiming(epoch: 0, deferred: false)
        await state.connectLiveData()
        let ticket = try #require(state.visitTiming.currentTicket(for: .detection))
        state.reconcileVisitTimingBackend(epoch: 0, deferred: false)
        #expect(state.visitTiming.currentTicket(for: .detection) == ticket)
        state.reconcileVisitTimingBackend(epoch: 1, deferred: false)
        #expect(observations.summaries.map(\.terminal) == [.contextChanged])
    }

    @Test("Actual engine replacement terminates even during initial startup deferral")
    func engineReplacement() async {
        let (state, observations) = fixture()
        state.providerDeferralForTesting = { true }
        state.beginInitialVisitTiming(epoch: 0, deferred: true)
        await state.onEngineIdentity(.init(pid: 1, startedAtUnix: 1, version: "synthetic", build: "1"))
        #expect(observations.summaries.isEmpty)
        await state.onEngineIdentity(.init(pid: 2, startedAtUnix: 2, version: "synthetic", build: "1"))
        #expect(observations.summaries.map(\.terminal) == [.contextChanged])
    }
}
#endif
