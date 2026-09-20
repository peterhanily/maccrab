import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@MainActor
@Suite("Dashboard automatic startup recovery")
struct DashboardStartupRecoveryTests {
    private let engineStartedAt = Date().addingTimeInterval(-60)

    private func writeHeartbeat(_ phase: String, to directory: URL) throws {
        let now = Date()
        let heartbeat: [String: Any] = [
            "engine_pid": 101,
            "engine_started_at_unix": engineStartedAt.timeIntervalSince1970,
            "engine_version": "1.22.1", "engine_build": "fixture",
            "written_at_unix": now.timeIntervalSince1970,
            "boot_phase": phase, "liveness": phase == "ready",
        ]
        try JSONSerialization.data(withJSONObject: heartbeat)
            .write(to: directory.appendingPathComponent("heartbeat.json"), options: .atomic)
    }

    @Test("Completing an upgrade reconnects an inactive dashboard without a focus edge")
    func inactiveReadyReconnect() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-dashboard-recovery-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let events = try EventStore(directory: directory.path)
        let alerts = try AlertStore(directory: directory.path)
        defer { withExtendedLifetime((events, alerts)) {} }
        let state = V2DashboardState(engineSource: .init(directory: directory.path))
        state.setWindowActivity(.inactive)
        let tick = state.refreshTick
        try writeHeartbeat("upgrading_store", to: directory)
        await state.connectLiveData()
        #expect(state.provider.mode == .offline)

        try writeHeartbeat("ready", to: directory)
        await state.onSysextBootPhase("ready")
        #expect(state.provider.mode == .live)
        #expect(state.provider.dataDir == directory.path)
        #expect(state.provider.lastErrorDescription == nil)
        #expect(state.refreshTick == tick,
                "Recovering the connection must not resume periodic background refresh ticks")
    }

    @Test("The refresh loop recovers after ready even when no AppState phase callback arrives")
    func readyWithoutObservedEdge() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-dashboard-recovery-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let events = try EventStore(directory: directory.path)
        let alerts = try AlertStore(directory: directory.path)
        defer { withExtendedLifetime((events, alerts)) {} }
        let state = V2DashboardState(engineSource: .init(directory: directory.path))
        state.setWindowActivity(.inactive)
        try writeHeartbeat("upgrading_store", to: directory)
        await state.connectLiveData()
        await state.resumeProviderAfterStartup()
        #expect(state.provider.mode == .offline)
        try writeHeartbeat("ready", to: directory)
        // The periodic loop uses the selected source directly; AppState polling
        // and controlActiveState need not deliver another edge to this window.
        await state.resumeProviderAfterStartup()
        #expect(state.provider.mode == .live)
        #expect(state.provider.lastErrorDescription == nil)
        #expect(state.refreshTick == 0)
    }

    @Test("A missing startup probe remains retryable after the only ready edge")
    func missingProbeRetries() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-dashboard-recovery-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let state = V2DashboardState(engineSource: .init(directory: directory.path))
        state.setWindowActivity(.inactive)
        try writeHeartbeat("upgrading_store", to: directory)
        await state.connectLiveData()
        // A ready edge can race a temporarily unavailable source. The probe
        // returns nil; this must not consume the recovery request forever.
        try FileManager.default.removeItem(at: directory.appendingPathComponent("heartbeat.json"))
        await state.onSysextBootPhase("ready")
        #expect(state.provider.mode == .offline)
        let events = try EventStore(directory: directory.path)
        let alerts = try AlertStore(directory: directory.path)
        defer { withExtendedLifetime((events, alerts)) {} }
        try writeHeartbeat("ready", to: directory)
        await state.resumeProviderAfterStartup()
        #expect(state.provider.mode == .live)
        #expect(state.provider.dataDir == directory.path)
        #expect(state.provider.lastErrorDescription == nil)
        let recovered = state.provider
        await state.resumeProviderAfterStartup()
        await state.onSysextBootPhase("ready")
        #expect(state.provider === recovered)
        #expect(state.refreshTick == 0)
    }

    @Test("A partial startup provider retries and a new startup retires its readers")
    func partialProbeRetriesAndRetires() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-dashboard-recovery-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let events = try EventStore(directory: directory.path)
        defer { withExtendedLifetime(events) {} }
        let state = V2DashboardState(engineSource: .init(directory: directory.path))
        state.setWindowActivity(.inactive)
        try writeHeartbeat("upgrading_store", to: directory)
        await state.connectLiveData()
        try writeHeartbeat("ready", to: directory)
        await state.onSysextBootPhase("ready")
        #expect(state.provider.mode == .live)
        #expect(state.provider.lastErrorDescription != nil,
                "The missing mandatory alert store must keep recovery unresolved")
        let partial = state.provider
        try writeHeartbeat("upgrading_store", to: directory)
        await state.onSysextBootPhase("upgrading_store")
        #expect(state.provider.mode == .offline,
                "Pending recovery must not leave a partial live reader attached during another startup")
        try writeHeartbeat("ready", to: directory)
        await state.onSysextBootPhase("ready")
        #expect(state.provider.mode == .live)
        #expect(state.provider.lastErrorDescription != nil)
        let alerts = try AlertStore(directory: directory.path)
        defer { withExtendedLifetime(alerts) {} }
        try writeHeartbeat("ready", to: directory)
        await state.resumeProviderAfterStartup()
        #expect(state.provider.mode == .live)
        #expect(state.provider.lastErrorDescription == nil)
        #expect(state.provider !== partial)
        #expect(state.refreshTick == 0)
    }

    @Test("Explicit disconnect cancels an unresolved startup recovery")
    func disconnectCancelsRecovery() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-dashboard-recovery-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let events = try EventStore(directory: directory.path)
        let alerts = try AlertStore(directory: directory.path)
        defer { withExtendedLifetime((events, alerts)) {} }
        let state = V2DashboardState(engineSource: .init(directory: directory.path))
        state.setWindowActivity(.inactive)
        try writeHeartbeat("upgrading_store", to: directory)
        await state.connectLiveData()
        state.disconnectLiveData()
        let disconnected = state.provider
        try writeHeartbeat("ready", to: directory)
        await state.resumeProviderAfterStartup()
        #expect(state.provider === disconnected)
        #expect(state.provider.mode != .live)
        #expect(state.refreshTick == 0)
    }
}
