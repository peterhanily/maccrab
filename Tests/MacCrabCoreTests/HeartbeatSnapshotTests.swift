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
      "engine_pid": 4242,
      "engine_started_at_unix": 1699996400.25,
      "engine_version": "1.21.6-rc.5",
      "engine_build": "1210605",
      "alerts_emitted": 12,
      "events_processed": 8377,
      "events_dropped": 4,
      "event_pipeline": {
        "offered_by_source": { "ESCollector": 100, "UnifiedLogCollector": 40 },
        "offered_by_source_and_lane": {
          "ESCollector": { "priority": 10, "file": 90 },
          "UnifiedLogCollector": { "priority": 5, "file": 35 }
        },
        "dropped_by_source_and_lane": {
          "ESCollector": { "priority": 0, "file": 1 },
          "UnifiedLogCollector": { "priority": 1, "file": 0 }
        },
        "terminated_by_source_and_lane": {
          "ESCollector": { "priority": 1, "file": 0 }
        },
        "collector_offered_by_source_and_lane": {
          "ESCollector": { "priority": 11, "file": 91 }
        },
        "upstream_dropped_by_source_and_lane": {
          "ESCollector": { "priority": 0, "file": 1 }
        },
        "upstream_terminated_by_source_and_lane": {
          "ESCollector": { "priority": 1, "file": 0 }
        },
        "merged_dropped_by_source_and_lane": {
          "UnifiedLogCollector": { "priority": 1, "file": 0 }
        },
        "merged_terminated_by_source_and_lane": {
          "ESCollector": { "priority": 0, "file": 0 }
        },
        "offered_by_lane": { "priority": 90, "file": 50 },
        "dequeued_by_lane": { "priority": 86, "file": 49 },
        "rule_evaluation_reached_by_lane_and_category": {
          "priority": { "process": 80, "file": 5, "network": 1 },
          "file": { "file": 49 }
        },
        "rule_evaluation_completed_by_lane_and_category": {
          "priority": { "process": 79, "file": 5, "network": 1 },
          "file": { "file": 49 }
        },
        "completed_by_lane": { "priority": 85, "file": 49 },
        "backlog_estimate_by_lane": { "priority": 3, "file": 0 },
        "in_flight_by_lane": { "priority": 1, "file": 0 },
        "processing_p99_us_by_lane": { "priority": 4000, "file": 1000 },
        "latency_sample_count_by_lane": { "priority": 85, "file": 49 },
        "upstream_dropped_by_lane": { "priority": 0, "file": 1 },
        "upstream_terminated_by_lane": { "priority": 1, "file": 0 },
        "merged_dropped_by_lane": { "priority": 1, "file": 1 },
        "merged_terminated_by_lane": { "priority": 0, "file": 0 },
        "collector_capacity_by_source": { "ESCollector": 100000 },
        "pre_buffer_dropped_by_source": { "ESCollector": 7 },
        "detection_input_dropped_total": 10,
        "capacity_by_lane": { "priority": 100000, "file": 100000 },
        "collector_buffer": {
          "unified_log_normalized_total": 42,
          "unified_log_stream_yield_dropped_total": 2,
          "unified_log_capacity": 512
        }
      },
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
      "tracegraph_storage_admission": {
        "enabled": true, "blocked": true, "reason": "footprint_limit",
        "store_available": true, "startup_blocked": false,
        "shed_mutations_total": 73, "max_footprint_bytes": 262144000,
        "admission_threshold_bytes": 195035136, "resume_below_bytes": 195035136,
        "transaction_reserve_bytes": 67108864, "footprint_bytes": 224395952,
        "free_space_bytes": 8589934592, "free_space_floor_bytes": 1073741824,
        "pinned_reader": false, "recovering": false
      },
      "traces_storage_admission": {
        "enabled": true, "blocked": true, "reason": "low_free_space",
        "store_available": true, "startup_blocked": false,
        "shed_mutations_total": 19, "max_footprint_bytes": 104857600,
        "admission_threshold_bytes": 96468992,
        "transaction_reserve_bytes": 8388608, "footprint_bytes": 95158272,
        "free_space_bytes": 805306368, "free_space_floor_bytes": 1073741824,
        "pinned_reader": false, "recovering": true
      },
      "browser_inventory": {
        "coverage_known": true, "complete": false, "degraded": true,
        "reason": "directory_budget_exhausted",
        "last_scan_was_truncated": true,
        "scans_total": 9, "truncated_scans_total": 2,
        "inspected_directory_entries_total": 200123,
        "truncated_directories_total": 2, "truncated_homes_total": 2,
        "last_scan_completed_at_unix": 1785686400.5,
        "last_scan_homes": 2,
        "last_scan_inspected_directory_entries": 100123,
        "last_scan_truncated_directory_count": 1,
        "last_scan_truncated_home_count": 1,
        "per_home_directory_entry_budget": 100000
      },
      "es_kernel_dropped_total": 0,
      "es_kernel_dropped_by_type": { "exec": 0, "write": 3 },
      "es_processed_by_type": { "exec": 4000, "write": 4377 },
      "es_intentionally_filtered_before_worker_by_type": { "open": 60000, "close": 4000 },
      "es_normalized_yielded_by_type": { "exec": 3999, "write": 4370 },
      "es_copy_backpressure_dropped_total": 6931,
      "es_stream_yield_dropped_total": 0,
      "eslogger_dropped_total": 0,
      "merged_priority_dropped_total": 0,
      "merged_file_dropped_total": 12,
      "merged_priority_terminated_total": 1,
      "merged_file_terminated_total": 2,
      "detection_input_dropped_total": 12,
      "events_storage_write_dropped_total": 3605,
      "events_storage_write_persisted_total": 4700,
      "events_storage_write_retried_total": 17,
      "events_storage_write_buffer_depth": 55,
      "events_storage_write_in_flight_depth": 400,
      "events_insert_filter_dropped_total": 200,
      "events_insert_filter_passed_total": 8305,
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
        #expect(h.enginePID == 4242)
        #expect(h.engineStartedAtUnix == 1699996400.25)
        #expect(h.engineVersion == "1.21.6-rc.5")
        #expect(h.engineBuild == "1210605")
        #expect(h.alertsEmitted == 12)
        #expect(h.eventsProcessed == 8377)
        #expect(h.eventsDropped == 4)
        #expect(h.rulesLoaded == 486)
        #expect(h.rulesActive == 98)
        #expect(h.eventPipeline?.offeredBySource?["ESCollector"] == 100)
        #expect(h.eventPipeline?.offeredBySourceAndLane?["UnifiedLogCollector"]?["file"] == 35)
        #expect(h.eventPipeline?.droppedBySourceAndLane?["ESCollector"]?["file"] == 1)
        #expect(h.eventPipeline?.terminatedBySourceAndLane?["ESCollector"]?["priority"] == 1)
        #expect(h.eventPipeline?.upstreamDroppedByLane?["file"] == 1)
        #expect(h.eventPipeline?.mergedDroppedBySourceAndLane?["UnifiedLogCollector"]?["priority"] == 1)
        #expect(h.eventPipeline?.collectorCapacityBySource?["ESCollector"] == 100_000)
        #expect(h.eventPipeline?.preBufferDroppedBySource?["ESCollector"] == 7)
        #expect(h.eventPipeline?.detectionInputDroppedTotal == 10)
        #expect(h.eventPipeline?.backlogEstimateByLane?["priority"] == 3)
        #expect(h.eventPipeline?.inFlightByLane?["priority"] == 1)
        #expect(h.eventPipeline?.ruleEvaluationReachedByLaneAndCategory?["priority"]?["process"] == 80)
        #expect(h.eventPipeline?.ruleEvaluationCompletedByLaneAndCategory?["priority"]?["process"] == 79)
        #expect(h.eventPipeline?.ruleEvaluationCompletedByLaneAndCategory?["file"]?["file"] == 49)
        #expect(h.eventPipeline?.processingP99MicrosByLane?["priority"] == 4_000)
        #expect(h.eventPipeline?.latencySampleCountByLane?["file"] == 49)
        #expect(h.eventPipeline?.collectorBuffer?["unified_log_stream_yield_dropped_total"] == 2)
        // Drop-attribution gauges — the exact fields the app decoder omitted.
        #expect(h.esKernelDroppedTotal == 0)
        #expect(h.esKernelDroppedByType?["write"] == 3)
        #expect(h.esProcessedByType?["exec"] == 4000)
        #expect(h.esIntentionallyFilteredBeforeWorkerByType?["open"] == 60_000)
        #expect(h.esNormalizedYieldedByType?["write"] == 4_370)
        #expect(h.esCopyBackpressureDroppedTotal == 6931)
        #expect(h.esStreamYieldDroppedTotal == 0)
        #expect(h.esloggerDroppedTotal == 0)
        #expect(h.mergedPriorityDroppedTotal == 0)
        #expect(h.mergedFileDroppedTotal == 12)
        #expect(h.mergedPriorityTerminatedTotal == 1)
        #expect(h.mergedFileTerminatedTotal == 2)
        #expect(h.detectionInputDroppedTotal == 12)
        #expect(h.eventsStorageWriteDroppedTotal == 3605)
        #expect(h.eventsStorageWritePersistedTotal == 4700)
        #expect(h.eventsStorageWriteRetriedTotal == 17)
        #expect(h.eventsStorageWriteBufferDepth == 55)
        #expect(h.eventsStorageWriteInFlightDepth == 400)
        #expect(h.eventsInsertFilterDroppedTotal == 200)
        #expect(h.eventsInsertFilterPassedTotal == 8305)
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
        #expect(h.traceGraphStorageAdmission?.enabled == true)
        #expect(h.traceGraphStorageAdmission?.blocked == true)
        #expect(h.traceGraphStorageAdmission?.storeAvailable == true)
        #expect(h.traceGraphStorageAdmission?.startupBlocked == false)
        #expect(h.traceGraphStorageAdmission?.reason == "footprint_limit")
        #expect(h.traceGraphStorageAdmission?.shedMutationsTotal == 73)
        #expect(h.traceGraphStorageAdmission?.maxFootprintBytes == 262_144_000)
        #expect(h.traceGraphStorageAdmission?.transactionReserveBytes == 67_108_864)
        #expect(h.traceGraphStorageAdmission?.pinnedReader == false)
        #expect(h.traceStoreStorageAdmission?.enabled == true)
        #expect(h.traceStoreStorageAdmission?.blocked == true)
        #expect(h.traceStoreStorageAdmission?.reason == "low_free_space")
        #expect(h.traceStoreStorageAdmission?.shedMutationsTotal == 19)
        #expect(h.traceStoreStorageAdmission?.maxFootprintBytes == 104_857_600)
        #expect(h.traceStoreStorageAdmission?.recovering == true)
        #expect(h.browserInventory?.coverageKnown == true)
        #expect(h.browserInventory?.complete == false)
        #expect(h.browserInventory?.degraded == true)
        #expect(h.browserInventory?.reason == "directory_budget_exhausted")
        #expect(h.browserInventory?.lastScanWasTruncated == true)
        #expect(h.browserInventory?.scansTotal == 9)
        #expect(h.browserInventory?.truncatedScansTotal == 2)
        #expect(h.browserInventory?.lastScanInspectedDirectoryEntries == 100_123)
        #expect(h.browserInventory?.lastScanTruncatedHomeCount == 1)
        #expect(h.browserInventory?.perHomeDirectoryEntryBudget == 100_000)
    }

    @Test("Startup admission remains distinct from a live blocked store")
    func startupAdmissionDecode() throws {
        let h = try decode("""
        {
          "schema_version": 5,
          "tracegraph_storage_admission": {
            "enabled": true,
            "blocked": true,
            "store_available": false,
            "startup_blocked": true,
            "reason": "low_free_space",
            "free_space_bytes": 104857600,
            "free_space_floor_bytes": 1073741824
          }
        }
        """)
        #expect(h.traceGraphStorageAdmission?.storeAvailable == false)
        #expect(h.traceGraphStorageAdmission?.startupBlocked == true)
        #expect(h.traceGraphStorageAdmission?.blocked == true)
        #expect(h.traceGraphStorageAdmission?.reason == "low_free_space")
        #expect(h.traceGraphStorageAdmission?.freeSpaceBytes == 104_857_600)
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
        #expect(h.mergedPriorityTerminatedTotal == nil)
        #expect(h.detectionInputDroppedTotal == nil)
        #expect(h.collectorHealth == nil)
        #expect(h.eventPipeline == nil)
        #expect(h.enginePID == nil)
        #expect(h.engineStartedAtUnix == nil)
        #expect(h.engineVersion == nil)
        #expect(h.engineBuild == nil)
        #expect(h.esIntentionallyFilteredBeforeWorkerByType == nil)
        #expect(h.eventsStorageWritePersistedTotal == nil)
        #expect(h.eventsStorageWriteInFlightDepth == nil)
        #expect(h.eventsInsertFilterDroppedTotal == nil)
        #expect(h.traceGraphStorageAdmission == nil)
        #expect(h.traceStoreStorageAdmission == nil)
        #expect(h.browserInventory == nil)
        #expect(h.sysextHasFDA == nil)
    }

    @Test("build_channel decodes, and is never defaulted to release")
    func buildChannel() throws {
        #expect(try decode("""
        { "schema_version": 5, "build_channel": "dev" }
        """).buildChannel == "dev")

        #expect(try decode("""
        { "schema_version": 5, "build_channel": "release" }
        """).buildChannel == "release")

        // An engine too old to carry the Info.plist marker reports "unknown".
        #expect(try decode("""
        { "schema_version": 5, "build_channel": "unknown" }
        """).buildChannel == "unknown")

        // A heartbeat predating the field decodes as nil. Neither this nor
        // "unknown" may be read as "release": a consumer deciding whether a
        // host's measurements count as production evidence has to be able to
        // tell a shipped build apart from an undetermined one.
        let old = try decode("""
        { "schema_version": 5, "events_processed": 1 }
        """)
        #expect(old.buildChannel == nil)
        #expect(old.buildChannel != "release")
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
