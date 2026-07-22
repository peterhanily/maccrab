// HeartbeatSnapshotTests.swift
// assessment-framework (P0): pins the shared Core heartbeat DTO — full
// schema-5 decode, honest-absent semantics (missing key → nil, never a
// fabricated zero/healthy), and the clock-injected staleness helpers.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Assessment: HeartbeatSnapshot DTO")
struct HeartbeatSnapshotTests {

    /// A representative schema-5 heartbeat carrying every top-level key plus
    /// fully-populated nested blocks.
    private static let fullJSON = """
    {
      "schema_version": 5,
      "written_at_unix": 1700000000.5,
      "uptime_seconds": 3600,
      "alerts_emitted": 12,
      "events_processed": 8377,
      "events_dropped": 4,
      "rules_loaded": 486,
      "rules_active": 98,
      "collector_health": [
        { "name": "ESCollector", "healthy": true, "last_tick_unix": 1700000000.0,
          "event_count": 5000, "error_count": 0 },
        { "name": "DNSCollector", "healthy": false, "event_count": 3,
          "error_count": 2, "last_error": "bpf attach failed" }
      ],
      "llm": { "configured": true, "provider": "ollama", "model": "llama3.1:8b",
               "last_success_unix": 1699999999.0, "consecutive_failures": 0,
               "circuit_open": false, "healthy": true },
      "prevention": {
        "sinkhole": { "enabled": true, "count": 7 },
        "network_blocker": { "enabled": false, "count": 0 },
        "persistence_guard": { "enabled": true, "count": 3 }
      },
      "trace_registry": { "enabled": true, "live_bindings": 5, "cap": 4096,
                          "pid_recycle_rejected": 1, "cap_evictions": 0, "ttl_evictions": 2 },
      "es_kernel_dropped_total": 0,
      "es_kernel_dropped_by_type": { "exec": 0, "write": 3 },
      "es_processed_by_type": { "exec": 4000, "write": 4377 },
      "es_copy_backpressure_dropped_total": 6931,
      "es_stream_yield_dropped_total": 0,
      "eslogger_dropped_total": 0,
      "merged_priority_dropped_total": 0,
      "merged_file_dropped_total": 12,
      "detection_input_dropped_total": 12,
      "events_storage_write_dropped_total": 3605,
      "payload_truncated_total": 1,
      "event_insert_errors_total": 0,
      "event_insert_error_rate_per_min": 0,
      "last_event_insert_error_kind": "",
      "es_sensor_degraded": false,
      "es_sensor_degraded_detail": "nominal",
      "es_sensor_degraded_severity": "none",
      "es_client_split_degraded": false,
      "db_tamper_decrypt_failures": 0,
      "fda_checked_at_unix": 1699999000.0,
      "sysext_has_fda": true
    }
    """

    private func decode(_ s: String) throws -> HeartbeatSnapshot {
        try JSONDecoder().decode(HeartbeatSnapshot.self, from: Data(s.utf8))
    }

    @Test("Full schema-5 heartbeat decodes every top-level field")
    func fullDecode() throws {
        let h = try decode(Self.fullJSON)
        #expect(h.schemaVersion == 5)
        #expect(h.writtenAtUnix == 1700000000.5)
        #expect(h.uptimeSeconds == 3600)
        #expect(h.alertsEmitted == 12)
        #expect(h.eventsProcessed == 8377)
        #expect(h.eventsDropped == 4)
        #expect(h.rulesLoaded == 486)
        #expect(h.rulesActive == 98)
        // Drop-attribution gauges — the exact fields the app decoder omitted.
        #expect(h.esKernelDroppedTotal == 0)
        #expect(h.esKernelDroppedByType?["write"] == 3)
        #expect(h.esProcessedByType?["exec"] == 4000)
        #expect(h.esCopyBackpressureDroppedTotal == 6931)
        #expect(h.esStreamYieldDroppedTotal == 0)
        #expect(h.esloggerDroppedTotal == 0)
        #expect(h.mergedPriorityDroppedTotal == 0)
        #expect(h.mergedFileDroppedTotal == 12)
        #expect(h.detectionInputDroppedTotal == 12)
        #expect(h.eventsStorageWriteDroppedTotal == 3605)
        #expect(h.payloadTruncatedTotal == 1)
        // Storage-error + degraded + self-defense + FDA.
        #expect(h.eventInsertErrorsTotal == 0)
        #expect(h.eventInsertErrorRatePerMin == 0)
        #expect(h.lastEventInsertErrorKind == "")
        #expect(h.esSensorDegraded == false)
        #expect(h.esSensorDegradedDetail == "nominal")
        #expect(h.esSensorDegradedSeverity == "none")
        #expect(h.esClientSplitDegraded == false)
        #expect(h.dbTamperDecryptFailures == 0)
        #expect(h.fdaCheckedAtUnix == 1699999000.0)
        #expect(h.sysextHasFDA == true)
    }

    @Test("Nested blocks decode fully")
    func nestedBlocks() throws {
        let h = try decode(Self.fullJSON)
        #expect(h.collectorHealth?.count == 2)
        let es = h.collectorHealth?.first { $0.name == "ESCollector" }
        #expect(es?.healthy == true)
        #expect(es?.lastTick == 1700000000.0)
        #expect(es?.eventCount == 5000)
        // DNSCollector omitted last_tick_unix → honestly nil, not epoch-0.
        let dns = h.collectorHealth?.first { $0.name == "DNSCollector" }
        #expect(dns?.healthy == false)
        #expect(dns?.lastTick == nil)
        #expect(dns?.lastError == "bpf attach failed")
        #expect(h.llm?.provider == "ollama")
        #expect(h.llm?.circuitOpen == false)
        #expect(h.prevention?.sinkhole?.enabled == true)
        #expect(h.prevention?.networkBlocker?.count == 0)
        #expect(h.traceRegistry?.liveBindings == 5)
        #expect(h.traceRegistry?.ttlEvictions == 2)
    }

    @Test("Missing drop-attribution keys decode as nil, never zero (honest-absent)")
    func honestAbsent() throws {
        // An older-schema heartbeat missing the drop-attribution gauges.
        let minimal = """
        { "schema_version": 3, "written_at_unix": 1700000000.0,
          "events_processed": 100, "rules_loaded": 400 }
        """
        let h = try decode(minimal)
        #expect(h.eventsProcessed == 100)
        // The absent gauges must be nil (unknown), NOT 0 — a consumer must be
        // able to distinguish "no drops" from "this engine didn't report drops".
        #expect(h.esKernelDroppedTotal == nil)
        #expect(h.mergedPriorityDroppedTotal == nil)
        #expect(h.detectionInputDroppedTotal == nil)
        #expect(h.collectorHealth == nil)
        #expect(h.sysextHasFDA == nil)
    }

    @Test("ageSeconds / isStale use the injected clock and fail safe")
    func staleness() throws {
        let h = try decode(Self.fullJSON)   // written_at_unix = 1700000000.5
        #expect(h.ageSeconds(now: 1700000010.5) == 10.0)
        #expect(h.isStale(now: 1700000010.5, maxAge: 300) == false)
        #expect(h.isStale(now: 1700000400.5, maxAge: 300) == true)
        // A heartbeat with no write time: age unknown → reported stale, never fresh.
        let noTime = try decode("{ \"schema_version\": 5 }")
        #expect(noTime.ageSeconds(now: 1700000000) == nil)
        #expect(noTime.isStale(now: 1700000000, maxAge: 300) == true)
    }

    @Test("readFreshest picks the newer heartbeat by written_at_unix")
    func readFreshest() throws {
        let fm = FileManager.default
        let older = fm.temporaryDirectory.appendingPathComponent("hb-old-\(UUID().uuidString)")
        let newer = fm.temporaryDirectory.appendingPathComponent("hb-new-\(UUID().uuidString)")
        try fm.createDirectory(at: older, withIntermediateDirectories: true)
        try fm.createDirectory(at: newer, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: older); try? fm.removeItem(at: newer) }
        try #"{ "schema_version": 5, "written_at_unix": 100.0, "rules_active": 1 }"#
            .write(to: older.appendingPathComponent("heartbeat_rich.json"), atomically: true, encoding: .utf8)
        try #"{ "schema_version": 5, "written_at_unix": 200.0, "rules_active": 2 }"#
            .write(to: newer.appendingPathComponent("heartbeat_rich.json"), atomically: true, encoding: .utf8)
        let picked = HeartbeatSnapshot.readFreshest(supportDirs: [older.path, newer.path])
        #expect(picked?.writtenAtUnix == 200.0)
        #expect(picked?.rulesActive == 2)
    }
}
