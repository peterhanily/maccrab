import Foundation
import Testing
import MacCrabCore
@testable import MacCrabApp

#if DEBUG
@MainActor
@Suite("Dashboard provider connection ownership")
struct DashboardProviderConnectionTests {
    /// No filesystem, store, process or network operations. The production
    /// state still restores its ordinary read-only navigation preferences.
    private final class Provider: V2DataProvider {
        let mode: V2DataSourceMode = .live
        let lastErrorDescription: String?
        let dataDir: String?
        init(directory: String, error: String? = nil) { dataDir = directory; lastErrorDescription = error }
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

    @MainActor private final class Opens {
        let directory = "/synthetic/provider-connection/\(UUID())"
        let gates = (0..<3).map { _ in DashboardReadTestGate() }
        let retirementGates = (0..<3).map { _ in DashboardReadTestGate() }
        var unavailable: Set<Int> = []
        var degraded: Set<Int> = []
        var wrongSource: Set<Int> = []
        var deferred = false
        lazy var candidates = (0..<3).map { index in
            Provider(directory: wrongSource.contains(index) ? directory + "/other" : directory,
                     error: degraded.contains(index) ? "Synthetic incomplete store set" : nil)
        }
        var starts = 0
        var active = 0
        var maximumActive = 0
        var retired: [ObjectIdentifier] = []

        func state() -> V2DashboardState {
            let state = V2DashboardState(engineSource: .init(directory: directory))
            state.provider = V2OfflineDataProvider()
            state.providerDeferralForTesting = { [self] in deferred }
            state.providerFactoryForTesting = { [self] source in
                #expect(source.directory == directory)
                let index = starts
                starts += 1
                guard gates.indices.contains(index) else {
                    Issue.record("Unexpected extra synthetic provider open")
                    return nil
                }
                active += 1
                maximumActive = max(maximumActive, active)
                defer { active -= 1 }
                await gates[index].pause() // deliberately returns after cancellation
                return unavailable.contains(index) ? nil : candidates[index]
            }
            state.providerRetirementForTesting = { [self] candidate in
                retired.append(ObjectIdentifier(candidate))
                if let index = candidates.firstIndex(where: { $0 === candidate }) { retirementGates[index].release() }
            }
            return state
        }

        func releaseAll() { for gate in gates + retirementGates { gate.release() } }
    }

    @Test("Initial connect, ready edge and focus share one usable provider open")
    func overlappingInitialReadyAndFocus() async {
        let opens = Opens()
        let state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        let initial = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        let readyArrived = DashboardReadTestGate()
        let focusArrived = DashboardReadTestGate()
        defer { readyArrived.release(); focusArrived.release() }
        let ready = Task { @MainActor in
            readyArrived.release()
            await state.onSysextBootPhase("ready")
        }
        await readyArrived.pause()
        let focus = Task { @MainActor in
            focusArrived.release()
            await state.reconnectLiveDataIfStale()
        }
        await focusArrived.pause()
        // Each arrival continues synchronously into the state until it reaches
        // the occupied read. No elapsed-time or scheduler-speed pass oracle.
        #expect(opens.starts == 1)
        #expect(opens.maximumActive == 1)
        opens.gates[0].release()
        await initial.value
        #expect(state.provider === opens.candidates[0],
                "A later equivalent request must not invalidate the first usable result")
        opens.releaseAll() // also drains the known old-behavior duplicate opens
        await ready.value
        await focus.value
        #expect(opens.starts == 1 && opens.maximumActive == 1)
        #expect(state.provider === opens.candidates[0])
        #expect(state.didProbeLiveData)
        #expect(!opens.retired.contains(ObjectIdentifier(opens.candidates[0])))
    }

    @Test("A sole cancelled connection cannot publish a late non-cooperative result")
    func cancelledOwnerDoesNotAdopt() async {
        let opens = Opens()
        let state = opens.state()
        let original = state.provider
        defer { opens.releaseAll(); state.dismissToast() }
        let request = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        request.cancel()
        opens.gates[0].release()
        await request.value
        await opens.retirementGates[0].pause()
        #expect(state.provider === original)
        #expect(!state.didProbeLiveData)
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[0]) }.count == 1)
    }

    @Test("Cancelling an equivalent focus waiter cannot supersede the active initial consumer")
    func cancelledJoinerDoesNotPoisonOwner() async {
        let opens = Opens()
        let state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        let owner = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        let arrived = DashboardReadTestGate()
        defer { arrived.release() }
        let joiner = Task { @MainActor in
            arrived.release()
            await state.reconnectLiveDataIfStale()
        }
        await arrived.pause()
        joiner.cancel()
        opens.releaseAll()
        await owner.value
        await joiner.value
        #expect(opens.starts == 1)
        #expect(state.provider === opens.candidates[0])
        #expect(!opens.retired.contains(ObjectIdentifier(opens.candidates[0])))
    }

    @Test("Cancellation recorded at delivery rejects adoption before queued actor cleanup can run")
    func cancellationAtDelivery() async {
        let opens = Opens(), state = opens.state()
        let original = state.provider
        var request: Task<Void, Never>?
        var deliveries = 0
        state.providerWillDeliverForTesting = {
            deliveries += 1
            request?.cancel()
        }
        defer { opens.releaseAll(); state.providerWillDeliverForTesting = nil; state.dismissToast() }
        request = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        opens.gates[0].release()
        await request?.value
        await opens.retirementGates[0].pause()
        #expect(deliveries == 1 && state.provider === original && !state.didProbeLiveData)
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[0]) }.count == 1)
    }

    @Test("The last cancelled waiter releases state before a non-cooperative open returns")
    func cancelledWindowDoesNotRetainState() async {
        let opens = Opens()
        var state: V2DashboardState? = opens.state()
        weak let releasedState = state
        let request = Task { @MainActor [state] in await state?.connectLiveData() }
        defer { opens.releaseAll() }
        await opens.gates[0].waitUntilPaused()
        request.cancel()
        await request.value // Must finish while the backend gate remains closed.
        state = nil
        #expect(releasedState == nil, "The occupied worker must not keep a closed window's state alive")
        opens.gates[0].release()
        await opens.retirementGates[0].pause()
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[0]) }.count == 1)
    }

    @Test("Only the latest forced engine epoch opens after the invalidated predecessor unwinds")
    func forcedEpochsKeepOneOccupiedOpen() async {
        let opens = Opens(), state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        func engine(_ pid: Int) -> EngineTelemetryIdentity {
            .init(pid: pid, startedAtUnix: Double(pid), version: "fixture", build: "unit")
        }
        await state.onEngineIdentity(engine(100))
        let initial = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        let firstArrived = DashboardReadTestGate(), lastArrived = DashboardReadTestGate()
        defer { firstArrived.release(); lastArrived.release() }
        let superseded = Task { @MainActor in
            firstArrived.release()
            await state.onEngineIdentity(engine(101))
        }
        await firstArrived.pause()
        await initial.value
        let latest = Task { @MainActor in
            lastArrived.release()
            await state.onEngineIdentity(engine(102))
        }
        await lastArrived.pause()
        await superseded.value
        #expect(opens.starts == 1 && opens.active == 1 && state.provider.mode == .offline)
        opens.gates[0].release()
        await opens.gates[1].waitUntilPaused()
        #expect(opens.starts == 2 && opens.maximumActive == 1)
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[0]) }.count == 1)
        opens.gates[1].release()
        await latest.value
        #expect(state.provider === opens.candidates[1] && state.didProbeLiveData)
        #expect(!opens.retired.contains(ObjectIdentifier(opens.candidates[1])))
    }

    @Test("Startup invalidation rejects a late result and ready recovery waits for the same occupied slot")
    func startupDuringOpen() async {
        let opens = Opens(), state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        let old = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        opens.deferred = true
        await state.onSysextBootPhase("upgrading_store")
        await old.value
        #expect(state.provider.mode == .offline && !state.didProbeLiveData)
        #expect(opens.starts == 1)
        opens.deferred = false
        let arrived = DashboardReadTestGate()
        defer { arrived.release() }
        let ready = Task { @MainActor in
            arrived.release()
            await state.onSysextBootPhase("ready")
        }
        await arrived.pause()
        #expect(opens.starts == 1)
        opens.gates[0].release()
        await opens.gates[1].waitUntilPaused()
        #expect(opens.maximumActive == 1)
        opens.gates[1].release()
        await ready.value
        #expect(state.provider === opens.candidates[1])
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[0]) }.count == 1)
    }

    @Test("Disconnect drains waiters without allowing the old open to revive the provider")
    func disconnectRejectsLateResult() async {
        let opens = Opens(), state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        let old = Task { @MainActor in await state.connectLiveData() }
        await opens.gates[0].waitUntilPaused()
        state.disconnectLiveData()
        let disconnected = state.provider
        await old.value
        opens.gates[0].release()
        await opens.retirementGates[0].pause()
        #expect(state.provider === disconnected && !state.didProbeLiveData)
        #expect(opens.starts == 1)
    }

    @Test("Missing then partial startup probes remain retryable; a healthy probe settles recovery")
    func missingAndPartialRecovery() async {
        let opens = Opens()
        opens.unavailable = [0]
        opens.degraded = [1]
        let state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        for gate in opens.gates { gate.release() }
        await state.onSysextBootPhase("ready")
        #expect(opens.starts == 1 && state.provider.mode == .offline && state.didProbeLiveData)
        await state.resumeProviderAfterStartup()
        #expect(opens.starts == 2 && state.provider === opens.candidates[1])
        #expect(state.provider.lastErrorDescription != nil)
        await state.resumeProviderAfterStartup()
        #expect(opens.starts == 3 && state.provider === opens.candidates[2])
        await state.resumeProviderAfterStartup()
        await state.onSysextBootPhase("ready")
        #expect(opens.starts == 3 && opens.maximumActive == 1)
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[1]) }.count == 1)
    }

    @Test("Wrong-source results cannot replace current state; a healthy provider is retained on ordinary reprobe")
    func sourceAndHealthyAdoption() async {
        let opens = Opens()
        opens.wrongSource = [0]
        let state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        for gate in opens.gates { gate.release() }
        let original = state.provider
        await state.connectLiveData()
        #expect(state.provider === original)
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[0]) }.count == 1)
        await state.connectLiveData()
        #expect(state.provider === opens.candidates[1])
        await state.reconnectLiveDataIfStale()
        #expect(state.provider === opens.candidates[1])
        #expect(opens.retired.filter { $0 == ObjectIdentifier(opens.candidates[2]) }.count == 1)
    }

    @Test("Already-cancelled callers perform no external dependency work")
    func cancelledBeforeEntry() async {
        let opens = Opens(), state = opens.state()
        defer { opens.releaseAll(); state.dismissToast() }
        state.providerDeferralForTesting = { Issue.record("Cancelled request checked heartbeat"); return false }
        let request = Task { @MainActor in await state.connectLiveData() }
        request.cancel()
        await request.value
        #expect(opens.starts == 0 && !state.didProbeLiveData)
    }
}
#endif
