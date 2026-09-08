import Foundation
import Testing
@testable import MacCrabApp

@MainActor
@Suite("System health before database readiness")
struct SystemStartupPresentationTests {
    private func writeHeartbeat(_ phase: String, pid: Int, to directory: URL) throws {
        let now = Date()
        let raw: [String: Any] = [
            "engine_pid": pid,
            "engine_started_at_unix": now.addingTimeInterval(-5).timeIntervalSince1970,
            "engine_version": "1.22.0", "engine_build": "fixture",
            "written_at_unix": now.timeIntervalSince1970,
            "boot_phase": phase, "liveness": phase == "ready",
        ]
        try JSONSerialization.data(withJSONObject: raw)
            .write(to: directory.appendingPathComponent("heartbeat.json"), options: .atomic)
    }

    @Test("System and sidebar retain startup and failure status while providers are deferred")
    func deferredProviderStatus() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-system-startup-\(UUID())")
        let selected = root.appendingPathComponent("selected")
        let other = root.appendingPathComponent("other")
        try FileManager.default.createDirectory(at: selected, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: other, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try writeHeartbeat("starting", pid: 101, to: selected)
        try writeHeartbeat("ready", pid: 202, to: other)
        let source = V2EngineSource.select(systemDirectory: selected.path, userDirectory: other.path)
        let state = V2DashboardState(engineSource: source)
        let app = AppState(engineSource: source, startBackgroundWork: false)
        await state.connectLiveData()
        #expect(state.provider.mode == .offline)
        #expect(await state.provider.heartbeat() == nil,
                "The deferred provider cannot supply the engine's startup status")

        for (index, phase) in ["starting", "stores_ready", "rules_loaded", "collectors_started", "storage_not_ready"].enumerated() {
            try writeHeartbeat(phase, pid: 101, to: selected)
            // Advance the AppState parse-cache input deterministically even on
            // filesystems whose modification timestamps have coarse precision.
            try FileManager.default.setAttributes(
                [.modificationDate: Date(timeIntervalSince1970: 1_780_000_000 + Double(index))],
                ofItemAtPath: selected.appendingPathComponent("heartbeat.json").path)
            let snapshot = try #require(await V2SystemWorkspace.readSelectedHeartbeat(source: source))
            #expect(snapshot.engineIdentity?.pid == 101)
            #expect(snapshot.bootPhase == phase)
            #expect(!snapshot.isReady)
            app.refreshHeartbeat()
            let sidebar = V2Sidebar(state: state, appState: app, onProtectionTap: {})
            #expect(sidebar.protectionStatus == (phase == "storage_not_ready" ? .unavailable : .starting))
        }
        #expect(state.provider.mode == .offline)
        #expect(try FileManager.default.contentsOfDirectory(atPath: selected.path) == ["heartbeat.json"],
                "Health reads must not initialize or open database files during startup")

        // Losing the selected status must not borrow another engine's newer
        // ready heartbeat, nor keep displaying the previous startup phase.
        try FileManager.default.removeItem(at: selected.appendingPathComponent("heartbeat.json"))
        #expect(await V2SystemWorkspace.readSelectedHeartbeat(source: source) == nil)
        let absentApp = AppState(engineSource: source, startBackgroundWork: false)
        absentApp.refreshHeartbeat()
        let absentSidebar = V2Sidebar(state: state, appState: absentApp, onProtectionTap: {})
        #expect(absentSidebar.protectionStatus == .inactive)
    }
}
