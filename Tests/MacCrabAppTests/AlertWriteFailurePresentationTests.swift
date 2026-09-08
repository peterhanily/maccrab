import Foundation
import Testing
@testable import MacCrabApp
import MacCrabCore

@Suite("Alert write failure presentation", .serialized)
struct AlertWriteFailurePresentationTests {
    @Test("Exact reported attempts survive both heartbeat decoders; older fields remain compatible")
    func counterDecoding() throws {
        for count in [0, 1, 2_530, Int.max] {
            let raw: [String: Any] = ["alert_insert_errors_total": count]
            let data = try JSONSerialization.data(withJSONObject: raw)
            let core = try JSONDecoder().decode(MacCrabCore.HeartbeatSnapshot.self, from: data)
            let ui = V2HeartbeatSnapshot.decode(raw: raw)
            #expect(core.alertInsertErrorsTotal == count)
            #expect(ui.alertInsertErrorsTotal == count)
            #expect(ui.alertWritesRequireAttention == (count > 0))
        }
        let coreLegacy = try JSONDecoder().decode(MacCrabCore.HeartbeatSnapshot.self, from: Data("{}".utf8))
        #expect(coreLegacy.alertInsertErrorsTotal == nil, "The shared DTO preserves its honest-absent contract")
        let uiLegacy = V2HeartbeatSnapshot.decode(raw: [:])
        #expect(uiLegacy.alertInsertErrorsTotal == 0)
        #expect(!uiLegacy.alertWritesRequireAttention)
    }

    @Test("Invalid present counters cannot clear the alert persistence warning")
    func invalidCounterDecoding() {
        let invalid: [Any] = [-1, "2530", true, false, NSNull(), 1.5, UInt64.max, ["count": 0]]
        for value in invalid {
            let ui = V2HeartbeatSnapshot.decode(raw: ["alert_insert_errors_total": value])
            #expect(ui.alertInsertErrorsTotal == nil)
            #expect(ui.alertWritesRequireAttention)
        }
    }

    private func ready(_ now: Date, pid: Int = 101) -> [String: Any] {
        ["engine_pid": pid, "engine_started_at_unix": now.addingTimeInterval(-5).timeIntervalSince1970,
         "engine_version": "1.22.0-rc.5", "engine_build": "1.22.0.1127",
         "boot_phase": "ready", "liveness": true, "written_at_unix": now.timeIntervalSince1970,
         "rules_loaded": 1,
         "collector_health": [["name": "ESCollector", "healthy": true, "state": "healthy",
                               "enabled": true, "expected_interval_seconds": 30]]]
    }

    private var recoveredEvidence: [String: Any] {
        ["alerts_family_blocked": false, "alerts_family_reason": "",
         "legacy_transition_measurement_failed": false,
         "capture_offered_total": 2, "capture_completed_total": 2,
         "capture_failures_total": 0, "capture_shed_total": 0,
         "capture_pending": 0, "capture_in_flight": 0,
         "capture_oldest_outstanding_age_seconds": 0, "capture_active_operation_age_seconds": 0,
         "capture_queue_capacity": 256, "capture_accepting": true, "capture_conserved": true]
    }

    @Test("Recovered admission and an expired transient warning cannot hide recent alert write failures")
    @MainActor
    func recoveredAdmission() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-alert-health-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date()
        let minimal = ready(now)
        try JSONSerialization.data(withJSONObject: minimal)
            .write(to: directory.appendingPathComponent("heartbeat.json"))
        let values: [Any] = [0, 2_530, -1, "invalid"]
        for value in values {
            var rich = minimal
            rich["alert_insert_errors_total"] = value
            rich["alert_evidence_budget"] = recoveredEvidence
            try JSONSerialization.data(withJSONObject: rich)
                .write(to: directory.appendingPathComponent("heartbeat_rich.json"), options: .atomic)
            let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
            app.refreshHeartbeat()
            app.rulesLoaded = 1
            app.isConnected = true
            let oldError = AppState.StorageErrorSnapshot(alertInsertErrors: 2_530, eventInsertErrors: 0,
                lastErrorMessage: "fixture", lastErrorKind: "alert_insert", lastErrorAt: now.addingTimeInterval(-300))
            app.storageErrors = oldError
            #expect(!app.hasConcerningStorageError(oldError))
            let ui = try #require(V2HeartbeatSnapshot.read(directory: directory.path, now: now))
            #expect(ui.alertEvidenceBudget?.alertsFamilyBlocked == false)
            #expect(ui.alertEvidenceBudget?.captureDegraded == false)
            #expect(app.heartbeat?.alertEvidenceBudgetDegraded == false)
            #expect(app.heartbeat?.alertInsertErrorsTotal == ui.alertInsertErrorsTotal)
            #expect(app.isProtectionDegraded == ui.alertWritesRequireAttention)
            #expect(V2ProtectionStatus.resolve(providerLive: true, heartbeatPresent: true,
                heartbeatStale: false, readiness: .ready, degraded: app.isProtectionDegraded)
                == (ui.alertWritesRequireAttention ? .degraded : .active))
        }
    }

    @Test("The previous engine's failure count cannot contaminate a new ready process")
    @MainActor
    func selectedEngineEpoch() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-alert-epoch-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let now = Date()
        var previous = ready(now, pid: 101)
        previous["alert_insert_errors_total"] = 2_530
        try JSONSerialization.data(withJSONObject: previous)
            .write(to: directory.appendingPathComponent("heartbeat_rich.json"))
        try JSONSerialization.data(withJSONObject: ready(now, pid: 102))
            .write(to: directory.appendingPathComponent("heartbeat.json"))
        let app = AppState(engineSource: .init(directory: directory.path), startBackgroundWork: false)
        app.refreshHeartbeat()
        app.isConnected = true
        app.rulesLoaded = 1
        #expect(app.heartbeat?.alertInsertErrorsTotal == 0)
        #expect(!app.isProtectionDegraded)
        let ui = try #require(V2HeartbeatSnapshot.read(directory: directory.path, now: now))
        #expect(ui.alertInsertErrorsTotal == 0)
        #expect(!ui.alertWritesRequireAttention)
    }
}
