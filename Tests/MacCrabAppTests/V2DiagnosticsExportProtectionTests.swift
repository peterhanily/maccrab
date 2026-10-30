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

    @Test("A recent content-scan shed degrades protection and is named in the reasons")
    func contentScanShed() throws {
        var raw = ready(Date())
        raw["content_scan_work_lifecycle"] = [
            "accepting": true, "offered_handlers_total": 40, "accepted_handlers_total": 32,
            "completed_handlers_total": 32, "rejected_handlers_total": 8,
            "closed_rejected_handlers_total": 0, "overload_shed_handlers_total": 8,
            "coalesced_handlers_total": 0, "coalesced_by_label": [String: Int](),
            "rejected_by_label": ["file-injection-scan": 8], "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": [String: Int](), "in_flight_handlers": 0,
            "maximum_in_flight_handlers": 4096, "conserves_accepted_handlers": true,
            "conserves_offered_handlers": true, "loss_last_at_unix": 1_793_300_000.0,
            "loss_recent": true,
        ] as [String: Any]
        let protection = try #require(try export(raw)["protection"] as? [String: Any])
        #expect(protection["resolved_from_heartbeat"] as? String == "degraded")
        #expect((protection["reasons"] as? [String])?.contains("content_scan_degraded") == true)
        #expect(protection["content_scan_degraded"] as? Bool == true)
        // Once the shed is no longer recent the warning clears.
        var plane = try #require(raw["content_scan_work_lifecycle"] as? [String: Any])
        plane["loss_recent"] = false
        raw["content_scan_work_lifecycle"] = plane
        let cleared = try #require(try export(raw)["protection"] as? [String: Any])
        #expect((cleared["reasons"] as? [String])?.contains("content_scan_degraded") == false)
        #expect(cleared["content_scan_degraded"] as? Bool == false)
    }

    @Test("A shed notarization follow-up degrades protection and is named in the reasons")
    func notarizationFollowUpShed() throws {
        var raw = ready(Date())
        raw["notarization_follow_up_lifecycle"] = [
            "accepting": true, "offered_handlers_total": 40, "accepted_handlers_total": 32,
            "completed_handlers_total": 32, "rejected_handlers_total": 0,
            "closed_rejected_handlers_total": 0, "overload_shed_handlers_total": 8,
            "coalesced_handlers_total": 0, "coalesced_by_label": [String: Int](),
            "rejected_by_label": [String: Int](), "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": [String: Int](), "in_flight_handlers": 0,
            "maximum_in_flight_handlers": 32, "conserves_accepted_handlers": true,
            "conserves_offered_handlers": true,
        ] as [String: Any]
        let protection = try #require(try export(raw)["protection"] as? [String: Any])
        #expect(protection["resolved_from_heartbeat"] as? String == "degraded")
        #expect((protection["reasons"] as? [String])?.contains("notarization_follow_up_degraded") == true)
        #expect(protection["notarization_follow_up_degraded"] as? Bool == true)
        // The menu bar's own heartbeat read counts it the same way.
        let shed = try #require(raw["notarization_follow_up_lifecycle"] as? [String: Any])
        #expect(AppState.detectionProtectionDegraded(in: ["notarization_follow_up_lifecycle": shed]) == true)
        var healthy = shed
        healthy["overload_shed_handlers_total"] = 0
        healthy["offered_handlers_total"] = 32
        #expect(AppState.detectionProtectionDegraded(in: ["notarization_follow_up_lifecycle": healthy,
                                                          "detection_work_lifecycle": healthy]) == false)
        #expect(AppState.detectionProtectionDegraded(in: [:]) == nil)
        // A recent content-scan shed is a skipped scan; an earlier one is history.
        var recentScanShed = shed
        recentScanShed["loss_recent"] = true
        #expect(AppState.detectionProtectionDegraded(in: ["content_scan_work_lifecycle": recentScanShed,
                                                          "detection_work_lifecycle": healthy]) == true)
        var earlierScanShed = shed
        earlierScanShed["loss_recent"] = false
        #expect(AppState.detectionProtectionDegraded(in: ["content_scan_work_lifecycle": earlierScanShed,
                                                          "detection_work_lifecycle": healthy]) == false)
        // Both heartbeat payloads the menu bar reads go through it.
        let appState = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabApp/AppState.swift"), encoding: .utf8)
        #expect(appState.contains("var richDetectionWorkLifecycleDegraded: Bool? = Self.detectionProtectionDegraded(in: json)"))
        #expect(appState.contains("if let degraded = Self.detectionProtectionDegraded(in: richJSON) {"))
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
