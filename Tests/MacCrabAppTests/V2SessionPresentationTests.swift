import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("Selected engine and recovery presentation")
struct V2SessionPresentationTests {
    private func heartbeat(pid: Int, started: Date, written: Date, phase: String = "ready") -> [String: Any] {
        ["engine_pid": pid, "engine_started_at_unix": started.timeIntervalSince1970,
         "engine_version": "1.22.0", "engine_build": "test", "written_at_unix": written.timeIntervalSince1970,
         "boot_phase": phase, "liveness": phase == "ready", "rules_loaded": 10,
         "collector_health": [["name": "DNSCollector", "state": "healthy", "healthy": true]]]
    }

    @Test("provider heartbeat stays with its stores while another engine writes newer data")
    @MainActor
    func sourceIsolation() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-source-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let system = root.appendingPathComponent("system")
        let user = root.appendingPathComponent("user")
        try FileManager.default.createDirectory(at: user, withIntermediateDirectories: true)
        let store = try AlertStore(directory: system.path)
        let now = Date()
        func write(_ raw: [String: Any], to directory: URL) throws {
            try JSONSerialization.data(withJSONObject: raw).write(to: directory.appendingPathComponent("heartbeat.json"))
        }
        try write(heartbeat(pid: 101, started: now.addingTimeInterval(-60), written: now), to: system)
        try write(heartbeat(pid: 202, started: now.addingTimeInterval(-40), written: now.addingTimeInterval(1)), to: user)
        let source = V2EngineSource.select(systemDirectory: system.path, userDirectory: user.path)
        let provider = try #require(await V2LiveDataProvider(source: source))
        #expect(provider.dataDir == system.path)
        #expect(await provider.heartbeat()?.engineIdentity?.pid == 101)
        try write(heartbeat(pid: 202, started: now.addingTimeInterval(-40), written: now.addingTimeInterval(2)), to: user)
        #expect(source.heartbeat()?.engineIdentity?.pid == 101)
        #expect(await provider.heartbeat()?.engineIdentity?.pid == 101)
        withExtendedLifetime(store) {}
    }

    @Test("suppression snapshot reads and removal requests stay on the selected source")
    @MainActor
    func suppressionSnapshotAndRequest() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-suppression-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let now = Date()
        try JSONSerialization.data(withJSONObject: heartbeat(pid: 101, started: now.addingTimeInterval(-60), written: now))
            .write(to: root.appendingPathComponent("heartbeat.json"))
        let provider = try #require(await V2LiveDataProvider(source: .init(directory: root.path)))
        #expect(await provider.suppressions().isEmpty)
        #expect(provider.suppressionReadError != nil)
        let entry = Suppression(scope: .rule("fixture"), source: .ui, reason: "Fixture")
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(SuppressionFile(version: 2, entries: [entry]))
            .write(to: root.appendingPathComponent("suppressions_snapshot.json"))
        #expect(await provider.suppressions().map(\.id) == [entry.id])
        #expect(provider.suppressionReadError == nil)
        #expect(await provider.liftSuppression(id: entry.id))
        let request = root.appendingPathComponent("inbox/remove-suppression-\(entry.id).json")
        let payload = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: request)) as? [String: Any])
        #expect(payload["id"] as? String == entry.id)
        #expect(await provider.suppressions().map(\.id) == [entry.id], "Queue acceptance does not remove a saved row")
    }

    @Test("first run and startup reports select one expected source without a database")
    func startupSource() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-source-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let system = root.appendingPathComponent("system")
        let user = root.appendingPathComponent("user")
        try FileManager.default.createDirectory(at: system, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: user, withIntermediateDirectories: true)
        #expect(V2EngineSource.select(systemDirectory: system.path, userDirectory: user.path).directory == system.path)
        try Data("{}".utf8).write(to: user.appendingPathComponent("heartbeat.json"))
        let selectedUser = V2EngineSource.select(systemDirectory: system.path, userDirectory: user.path)
        #expect(selectedUser.directory == user.path)
        try Data("{}".utf8).write(to: system.appendingPathComponent("last_crash.json"))
        #expect(selectedUser.directory == user.path, "an already selected session does not switch")
        #expect(V2EngineSource.select(systemDirectory: system.path, userDirectory: user.path).directory == system.path)
    }

    @Test("structured startup reports preserve classifications without raw diagnostics")
    func sanitizedReportAndExport() throws {
        let now = Date()
        let raw: [String: Any] = ["schema_version": 2, "occurred_at_unix": now.timeIntervalSince1970,
            "database": "events.db", "reason": "storage_pressure", "preservation_outcome": "preserved",
            "error": "PRIVATE_DIAGNOSTIC_TEXT", "recovery_action": "/Users/private-owner/private-store"]
        let report = V2StartupFailure.decode(raw)
        #expect(report.reason == .storagePressure)
        #expect(report.preservation == .preserved)
        let hb = V2HeartbeatSnapshot.decode(raw: heartbeat(pid: 101, started: now.addingTimeInterval(-60), written: now))
        let export = try V2DiagnosticsExport.make(source: .init(directory: "/Users/private-owner/MacCrab"),
            mode: "Live", heartbeat: hb, failure: report, permissions: [], providerReadFailed: true)
        let text = String(decoding: export.data, as: UTF8.self)
        #expect(!text.contains("PRIVATE_DIAGNOSTIC_TEXT"))
        #expect(!text.contains("private-owner"))
        let object = try #require(JSONSerialization.jsonObject(with: export.data) as? [String: Any])
        #expect((object["startup_failure"] as? [String: Any])?["preservation_outcome"] as? String == "preserved")
        #expect(object["provider_read_failed"] as? Bool == true)
    }

    @Test("legacy and malformed reports never assert an unverified preservation outcome")
    func legacyAndUnreadableReports() throws {
        let legacy = V2StartupFailure.decode(["error": "EventStore keychain encryption key unavailable", "recovery_action": "recovery failed"])
        #expect(legacy.database == "events.db")
        #expect(legacy.reason == .keyUnavailable)
        #expect(legacy.preservation == .unverified)
        let unknown = V2StartupFailure.decode(["schema_version": 2, "database": "private-path", "reason": "custom", "preservation_outcome": "maybe"])
        #expect(unknown.database == "unknown")
        #expect(unknown.preservation == .unverified)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-report-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        #expect(V2StartupFailure.read(directory: root.path) == nil)
        try Data("{unfinished".utf8).write(to: root.appendingPathComponent("last_crash.json"))
        #expect(V2StartupFailure.read(directory: root.path)?.reason == .reportUnavailable)
        try Data(repeating: 32, count: 65_537).write(to: root.appendingPathComponent("last_crash.json"))
        #expect(V2StartupFailure.read(directory: root.path)?.reason == .reportUnavailable)
    }

    @Test("a retained report becomes historical only after a newer ready boot")
    func reportAcrossRestart() {
        let now = Date()
        let report = V2StartupFailure.decode(["schema_version": 2, "occurred_at_unix": now.addingTimeInterval(-20).timeIntervalSince1970,
            "database": "events.db", "reason": "integrity_failure", "preservation_outcome": "quarantined"])
        #expect(!report.isHistorical(heartbeat: nil))
        let starting = V2HeartbeatSnapshot.decode(raw: heartbeat(pid: 2, started: now.addingTimeInterval(-10), written: now, phase: "starting"))
        #expect(!report.isHistorical(heartbeat: starting))
        let previousBoot = V2HeartbeatSnapshot.decode(raw: heartbeat(pid: 1, started: now.addingTimeInterval(-60), written: now))
        #expect(!report.isHistorical(heartbeat: previousBoot))
        let ready = V2HeartbeatSnapshot.decode(raw: heartbeat(pid: 2, started: now.addingTimeInterval(-10), written: now))
        #expect(report.isHistorical(heartbeat: ready))
    }

    @Test("onboarding refresh clears readiness and rules when the engine becomes unavailable")
    func onboardingTransitions() {
        let now = Date()
        let ready = WelcomeHealthSnapshot(heartbeat: V2HeartbeatSnapshot.decode(raw: heartbeat(pid: 1, started: now.addingTimeInterval(-60), written: now)), fda: .granted)
        #expect(ready.engineReady && ready.rulesLoaded == 10)
        let missing = WelcomeHealthSnapshot(heartbeat: nil, fda: .unknown)
        #expect(!missing.engineReady && missing.rulesLoaded == 0 && missing.fda == .unknown)
    }

    @Test("actionable notices survive replacement and dismiss by identity")
    @MainActor
    func persistentNotices() {
        let state = V2DashboardState(engineSource: .init(directory: "/fixture"))
        let action = V2Toast(kind: .success, title: "Saved", action: .init(title: "Undo") {})
        let error = V2Toast(kind: .error, title: "Failed")
        let informational = V2Toast(kind: .info, title: "Refreshed")
        #expect(action.requiresDismissal)
        #expect(error.requiresDismissal)
        #expect(!informational.requiresDismissal)
        state.showToast(action)
        state.showToast(error)
        state.showToast(informational)
        #expect(state.noticeHistory.map(\.id) == [action.id, error.id])
        state.dismissToast(id: action.id)
        #expect(state.noticeHistory.map(\.id) == [error.id])
        #expect(state.toast?.id == informational.id)
        state.dismissToast()
    }

    @Test("a new engine epoch invalidates readers even in the same directory")
    func engineEpochTransition() {
        let first = EngineTelemetryIdentity(pid: 10, startedAtUnix: 100, version: "1.22.0", build: "1")
        let restarted = EngineTelemetryIdentity(pid: 11, startedAtUnix: 200, version: "1.22.0", build: "1")
        #expect(!V2DashboardState.engineEpochChanged(previous: nil, next: first))
        #expect(!V2DashboardState.engineEpochChanged(previous: first, next: first))
        #expect(V2DashboardState.engineEpochChanged(previous: first, next: restarted))
        var remembered: EngineTelemetryIdentity? = first
        let gapChanged = V2DashboardState.updateEngineIdentity(&remembered, next: nil)
        #expect(!gapChanged)
        #expect(remembered == first)
        let restartChanged = V2DashboardState.updateEngineIdentity(&remembered, next: restarted)
        #expect(restartChanged)
        #expect(remembered == restarted)
    }

    @Test("AppState clears retained alert rows and badges after a heartbeat gap and restart")
    @MainActor
    func retainedAlertEpochTransition() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-app-epoch-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
        let now = Date()
        let path = directory.appendingPathComponent("heartbeat.json")
        func write(pid: Int, start: Date) throws {
            try JSONSerialization.data(withJSONObject: heartbeat(pid: pid, started: start, written: now))
                .write(to: path)
        }
        try write(pid: 101, start: now.addingTimeInterval(-60))
        app.refreshHeartbeat()
        let row = AlertViewModel(id: "fixture", timestamp: now, ruleId: "fixture", ruleTitle: "Fixture",
                                 severity: .high, processName: "fixture", processPath: "/fixture", description: "Fixture",
                                 mitreTechniques: "", suppressed: false)
        app.dashboardAlerts = [row]
        app.recentAlerts = [row]
        app.aiAnalysisAlerts = [row]
        app.totalAlerts = 1
        app.eventsPerSecond = 15
        app.hasMoreAlerts = true
        app.hasMoreEvents = true
        app.refreshHeartbeat()
        #expect(app.dashboardAlerts == [row], "The same verified epoch retains current rows")
        try FileManager.default.removeItem(at: path)
        app.refreshHeartbeat()
        #expect(app.dashboardAlerts == [row], "An unavailable heartbeat alone does not erase saved rows")
        try write(pid: 102, start: now.addingTimeInterval(-5))
        app.refreshHeartbeat()
        #expect(app.dashboardAlerts.isEmpty)
        #expect(app.recentAlerts.isEmpty)
        #expect(app.aiAnalysisAlerts.isEmpty)
        #expect(app.totalAlerts == 0)
        #expect(app.eventsPerSecond == 0)
        #expect(!app.hasMoreAlerts)
        #expect(!app.hasMoreEvents)
    }

    @Test("DNS diagnostics distinguish packet statistics from parsed-query loss")
    func dnsScopeCounters() {
        let capture = V2DNSCaptureStatus(["available": true, "interface": "en1",
            "kernel_statistics_available": false, "kernel_received_total": UInt64(12),
            "kernel_dropped_total": UInt64(3), "stream_offered_total": UInt64(5),
            "stream_dropped_total": UInt64(1), "stream_terminated_total": UInt64(0)])
        #expect(capture.interface == "en1")
        #expect(!capture.kernelStatisticsAvailable)
        #expect(capture.kernelDropped == 3)
        #expect(capture.streamDropped == 1)
        #expect(capture.diagnosticDictionary["scope"] as? String == "primary_ipv4_ethernet_udp_53")
    }
}
