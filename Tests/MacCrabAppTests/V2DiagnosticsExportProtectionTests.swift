import Foundation
import Testing
@testable import MacCrabApp

@Suite("Diagnostics export explains the protection verdict")
struct V2DiagnosticsExportProtectionTests {
    private func ready(_ now: Date) -> [String: Any] {
        ["engine_pid": 101, "engine_started_at_unix": now.addingTimeInterval(-5).timeIntervalSince1970,
         "engine_version": "1.22.5", "engine_build": "1.22.5.1300",
         "boot_phase": "ready", "liveness": true, "written_at_unix": now.timeIntervalSince1970,
         "rules_loaded": 438,
         "collector_health": [["name": "ESCollector", "healthy": true, "state": "healthy",
                               "enabled": true, "expected_interval_seconds": 30],
                              ["name": "ClipboardMonitor", "healthy": true, "state": "disabled",
                               "enabled": false, "expected_interval_seconds": 3]]]
    }

    private func export(_ raw: [String: Any]) throws -> [String: Any] {
        let heartbeat = V2HeartbeatSnapshot.decode(raw: raw)
        let export = try V2DiagnosticsExport.make(
            source: .init(directory: "/Library/Application Support/MacCrab"), mode: "Live",
            heartbeat: heartbeat, failure: nil, permissions: [], providerReadFailed: false)
        return try #require(JSONSerialization.jsonObject(with: export.data) as? [String: Any])
    }

    @Test("A healthy engine exports an active verdict with no reasons, at schema 4")
    func healthy() throws {
        let object = try export(ready(Date()))
        #expect(object["schema_version"] as? Int == 4)
        let protection = try #require(object["protection"] as? [String: Any])
        #expect(protection["resolved_from_heartbeat"] as? String == "active")
        #expect((protection["reasons"] as? [String]) == [])
        #expect(protection["collectors_enabled"] as? Int == 1)
        #expect((protection["collectors_not_healthy"] as? [String]) == [])
        #expect(protection["alert_write_failure_current"] as? Bool == false)
    }

    @Test("Every hidden input that can degrade protection is named in the reasons")
    func degradedReasons() throws {
        var raw = ready(Date())
        raw["alert_insert_errors_total"] = 3
        raw["alert_insert_failure_recent"] = true
        raw["tracegraph_storage_admission"] = ["enabled": true, "blocked": true, "store_available": false,
                                               "reason": "initialization_failed"]
        raw["sequence_checkpoint"] = ["restore_status": "rejected"]
        let protection = try #require(try export(raw)["protection"] as? [String: Any])
        #expect(protection["resolved_from_heartbeat"] as? String == "degraded")
        let reasons = try #require(protection["reasons"] as? [String])
        #expect(reasons.contains("alert_write_failure_recent"))
        #expect(reasons.contains("tracegraph_evidence_unavailable"))
        #expect(reasons.contains("sequence_checkpoint_degraded"))
        let tracegraph = try #require(protection["tracegraph"] as? [String: Any])
        #expect(tracegraph["reason"] as? String == "initialization_failed")
        #expect(tracegraph["evidence_unavailable"] as? Bool == true)
        let checkpoint = try #require(protection["sequence_checkpoint"] as? [String: Any])
        #expect(checkpoint["restore_status"] as? String == "rejected")
    }

    @Test("An old alert write failure is reported as history, not as a current reason")
    func historicalFailure() throws {
        var raw = ready(Date())
        raw["alert_insert_errors_total"] = 2_530
        raw["alert_insert_failure_recent"] = false
        raw["alert_insert_last_error_at_unix"] = 1_790_000_000.0
        let protection = try #require(try export(raw)["protection"] as? [String: Any])
        #expect(protection["resolved_from_heartbeat"] as? String == "active")
        #expect((protection["reasons"] as? [String]) == [])
        #expect(protection["alert_insert_errors_total"] as? Int == 2_530)
        #expect(protection["alert_insert_failure_recent"] as? Bool == false)
        #expect(protection["alert_insert_last_error_at_unix"] as? Double == 1_790_000_000)
    }

    @Test("Free-text engine details never reach the export")
    func redaction() throws {
        var raw = ready(Date())
        raw["es_sensor_degraded"] = true
        raw["es_sensor_degraded_detail"] = "PRIVATE_DETAIL /Users/private-owner/secret"
        raw["sequence_checkpoint"] = ["restore_status": "rejected", "restore_detail": "PRIVATE_RESTORE_DETAIL",
                                      "last_failure": "PRIVATE_FAILURE"]
        let heartbeat = V2HeartbeatSnapshot.decode(raw: raw)
        let export = try V2DiagnosticsExport.make(
            source: .init(directory: "/Library/Application Support/MacCrab"), mode: "Live",
            heartbeat: heartbeat, failure: nil, permissions: [], providerReadFailed: false)
        let text = String(decoding: export.data, as: UTF8.self)
        #expect(text.contains("es_sensor_degraded"))
        #expect(!text.contains("PRIVATE_"))
        #expect(!text.contains("private-owner"))
    }
}
