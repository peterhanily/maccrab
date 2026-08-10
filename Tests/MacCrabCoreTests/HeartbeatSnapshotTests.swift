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
      "timer_lifecycle": { "accepting": true, "offered_handlers_total": 10,
               "accepted_handlers_total": 10, "completed_handlers_total": 9,
               "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
               "overload_shed_handlers_total": 0, "coalesced_handlers_total": 0,
               "coalesced_by_label": {}, "rejected_by_label": {},
               "inline_fallback_handlers_total": 0, "inline_fallbacks_by_label": {},
               "in_flight_handlers": 1, "maximum_in_flight_handlers": 256,
               "conserves_accepted_handlers": true, "conserves_offered_handlers": true },
      "liveness_timer_lifecycle": { "accepting": true, "offered_handlers_total": 5,
               "accepted_handlers_total": 4, "completed_handlers_total": 3,
               "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
               "overload_shed_handlers_total": 0, "coalesced_handlers_total": 1,
               "coalesced_by_label": {"liveness-heartbeat": 1}, "rejected_by_label": {},
               "inline_fallback_handlers_total": 0, "inline_fallbacks_by_label": {},
               "in_flight_handlers": 1, "maximum_in_flight_handlers": 1,
               "conserves_accepted_handlers": true, "conserves_offered_handlers": true },
      "startup_work_lifecycle": { "accepting": true, "offered_handlers_total": 3,
               "accepted_handlers_total": 3, "completed_handlers_total": 3,
               "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
               "overload_shed_handlers_total": 0, "coalesced_handlers_total": 0,
               "coalesced_by_label": {}, "rejected_by_label": {},
               "inline_fallback_handlers_total": 0, "inline_fallbacks_by_label": {},
               "in_flight_handlers": 0, "maximum_in_flight_handlers": 64,
               "conserves_accepted_handlers": true, "conserves_offered_handlers": true },
      "detection_work_lifecycle": { "accepting": true, "offered_handlers_total": 5,
               "accepted_handlers_total": 4, "completed_handlers_total": 4,
               "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
               "overload_shed_handlers_total": 0, "coalesced_handlers_total": 0,
               "coalesced_by_label": {}, "rejected_by_label": {},
               "inline_fallback_handlers_total": 1,
               "inline_fallbacks_by_label": {"active-defense": 1},
               "in_flight_handlers": 0, "maximum_in_flight_handlers": 256,
               "conserves_accepted_handlers": true, "conserves_offered_handlers": true },
      "advisory_work_lifecycle": { "accepting": true, "offered_handlers_total": 4,
               "accepted_handlers_total": 3, "completed_handlers_total": 3,
               "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
               "overload_shed_handlers_total": 0, "coalesced_handlers_total": 1,
               "coalesced_by_label": {"campaign-llm": 1}, "rejected_by_label": {},
               "inline_fallback_handlers_total": 0, "inline_fallbacks_by_label": {},
               "in_flight_handlers": 0, "maximum_in_flight_handlers": 64,
               "conserves_accepted_handlers": true, "conserves_offered_handlers": true },
      "output_work_lifecycle": { "accepting": true, "offered_handlers_total": 2,
               "accepted_handlers_total": 2, "completed_handlers_total": 2,
               "rejected_handlers_total": 0, "closed_rejected_handlers_total": 0,
               "overload_shed_handlers_total": 0, "coalesced_handlers_total": 0,
               "coalesced_by_label": {}, "rejected_by_label": {},
               "inline_fallback_handlers_total": 0, "inline_fallbacks_by_label": {},
               "in_flight_handlers": 0, "maximum_in_flight_handlers": 128,
               "conserves_accepted_handlers": true, "conserves_offered_handlers": true },
      "otlp_receiver_lifecycle": {
               "accepting_listeners": true, "listeners_accepted_total": 1,
               "listeners_completed_total": 0,
               "listeners_rejected_after_seal_total": 0,
               "active_listeners": 1, "ready_listeners": 1,
               "listeners_conserved": true,
               "accepting_connections": true, "connections_accepted_total": 5,
               "connections_completed_total": 4,
               "connections_rejected_after_seal_total": 0,
               "connections_rejected_at_capacity_total": 0,
               "active_connections": 1, "connections_conserved": true,
               "accepting_body_tasks": true, "body_tasks_accepted_total": 3,
               "body_tasks_completed_total": 2, "body_tasks_cancelled_total": 0,
               "body_tasks_rejected_total": 0,
               "body_task_cancellation_requests_total": 0,
               "body_tasks_in_flight": 1, "maximum_body_tasks": 64,
               "body_tasks_conserved": true,
               "accepting_callback_tasks": true,
               "callback_tasks_accepted_total": 2,
               "callback_tasks_completed_total": 1,
               "callback_tasks_cancelled_total": 0,
               "callback_tasks_rejected_total": 0,
               "callback_task_cancellation_requests_total": 0,
               "callback_tasks_in_flight": 1,
               "maximum_callback_tasks": 256,
               "callback_tasks_conserved": true,
               "lifecycle_operations_in_progress": 0,
               "shutdown_timeouts_total": 0,
               "cleanly_stopped": false },
      "alert_evidence_budget": {
        "events_family_effective_cap_bytes": 440401920,
        "events_family_steady_state_cap_bytes": 335544320,
        "alerts_family_combined_cap_bytes": 209715200,
        "events_and_alerts_total_cap_bytes": 650117120,
        "events_and_alerts_steady_state_total_cap_bytes": 545259520,
        "legacy_transition_reserve_bytes": 104857600,
        "legacy_transition_max_bytes": 104857600,
        "legacy_transition_measurement_failed": false,
        "capture_offered_total": 1, "capture_completed_total": 0,
        "capture_failures_total": 0, "capture_shed_total": 0,
        "capture_pending": 0, "capture_in_flight": 1,
        "capture_queue_capacity": 256, "capture_accepting": true,
        "capture_conserved": true, "allocated_bytes_exact": true,
        "mutation_generation": 7, "full_refreshes_total": 1
      },
      "prevention": {
        "sinkhole": { "enabled": true, "count": 7 },
        "network_blocker": { "enabled": false, "count": 0 },
        "persistence_guard": { "enabled": true, "count": 3 }
      },
      "trace_registry": { "enabled": true, "live_bindings": 5, "cap": 4096,
                          "pid_recycle_rejected": 1, "cap_evictions": 0, "ttl_evictions": 2 },
      "sequence_checkpoint": {
        "restore_status": "restored",
        "restore_detail": "restored 17 partial(s), 2 pending step(s)",
        "last_restore_at_unix": 1699996400.5,
        "last_attempt_at_unix": 1700000000.0,
        "last_success_at_unix": 1700000000.0,
        "checkpoint_captured_at_unix": 1699999999.9,
        "checkpoint_age_seconds": 0.6,
        "checkpoint_bytes": 8192,
        "durable_carrier_valid": true,
        "dirty": false,
        "current_semantic_digest": "current-digest",
        "durable_semantic_digest": "current-digest",
        "current_generation": 44,
        "durable_generation": 44,
        "configured_crash_rpo_seconds": 30.0,
        "crash_rpo_bound_currently_maintained": true,
        "periodic_writes_last_hour": 14,
        "periodic_bytes_last_hour": 114688,
        "writes_total": 21,
        "bytes_written_total": 172032,
        "unchanged_skips_total": 3,
        "budget_deferrals_total": 0,
        "conservation": {
          "offered": 24, "completed": 23, "queued": 0,
          "in_flight": 1, "explicitly_shed": 0
        },
        "orphan_files_current": 0,
        "orphan_bytes_current": 0,
        "orphan_files_removed_total": 2,
        "orphan_bytes_removed_total": 4096,
        "orphan_cleanup_scan_truncated": false,
        "last_orphan_cleanup_at_unix": 1699999998.0,
        "carrier_invalidations_total": 1,
        "last_carrier_invalidation_reason": "integrity_mismatch",
        "last_carrier_invalidation_at_unix": 1699999997.0
      },
      "sequence_journal_conservation": {
        "offered": 12, "completed": 10, "queued": 2,
        "in_flight": 0, "explicitly_shed": 0
      },
      "sequence_journal_conservation_by_rule": {
        "stable-rule": {
          "offered": 12, "completed": 10, "queued": 2,
          "in_flight": 0, "explicitly_shed": 0
        }
      },
      "sequence_partials_evicted_total": 0,
      "sequence_partials_in_flight": 17,
      "sequence_pending_steps_current": 2,
      "sequence_pending_steps_evicted_total": 0,
      "sequence_checkpoint_state_weight_bytes": 4096,
      "sequence_checkpoint_state_weight_recomputed_bytes": 4096,
      "sequence_checkpoint_state_weight_limit_bytes": 8388608,
      "sequence_state_continuity_maintained": true,
      "sequence_state_continuity_detail": "nominal",
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
        "pinned_reader": false, "recovering": true,
        "ingest_conservation": {
          "offered": 29, "completed": 7, "queued": 3,
          "in_flight": 4, "explicitly_shed": 15
        }
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
      "events_storage_write_offered_by_lane": { "priority": 3000, "file": 5765 },
      "events_storage_write_dropped_by_lane": { "priority": 0, "file": 3605 },
      "events_storage_write_persisted_total": 4700,
      "events_storage_write_persisted_by_lane": { "priority": 2600, "file": 2100 },
      "events_storage_write_filtered_total": 5,
      "events_storage_write_filtered_by_lane": { "priority": 0, "file": 5 },
      "events_storage_write_retried_total": 17,
      "events_storage_write_retried_by_lane": { "priority": 7, "file": 10 },
      "events_storage_write_buffer_depth": 55,
      "events_storage_write_buffer_depth_by_lane": { "priority": 0, "file": 55 },
      "events_storage_write_in_flight_depth": 400,
      "events_storage_write_in_flight_depth_by_lane": { "priority": 400, "file": 0 },
      "events_retention_budget": {
        "state": "degraded_budget_unmet",
        "reason": "post_sweep_above_target",
        "sticky": true,
        "forensic_floor_minutes": 15,
        "observed_footprint_bytes": 440401921,
        "target_bytes": 373293056,
        "proactive_boundary_bytes": 373293056,
        "nominal_cap_bytes": 440401920,
        "evaluated_at_unix": 1700000000.25
      },
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
        #expect(h.eventsStorageWriteOfferedByLane?["priority"] == 3000)
        #expect(h.eventsStorageWriteOfferedByLane?["file"] == 5765)
        #expect(h.eventsStorageWriteDroppedByLane?["file"] == 3605)
        #expect(h.eventsStorageWritePersistedTotal == 4700)
        #expect(h.eventsStorageWritePersistedByLane?["priority"] == 2600)
        #expect(h.eventsStorageWriteFilteredTotal == 5)
        #expect(h.eventsStorageWriteFilteredByLane?["file"] == 5)
        #expect(h.eventsStorageWriteRetriedTotal == 17)
        #expect(h.eventsStorageWriteRetriedByLane?["priority"] == 7)
        #expect(h.eventsStorageWriteBufferDepth == 55)
        #expect(h.eventsStorageWriteBufferDepthByLane?["file"] == 55)
        #expect(h.eventsStorageWriteInFlightDepth == 400)
        #expect(h.eventsStorageWriteInFlightDepthByLane?["priority"] == 400)
        #expect(h.eventsRetentionBudget?.state == "degraded_budget_unmet")
        #expect(h.eventsRetentionBudget?.reason == "post_sweep_above_target")
        #expect(h.eventsRetentionBudget?.sticky == true)
        #expect(h.eventsRetentionBudget?.forensicFloorMinutes == 15)
        #expect(h.eventsRetentionBudget?.observedFootprintBytes == 440_401_921)
        #expect(h.eventsRetentionBudget?.targetBytes == 373_293_056)
        #expect(h.eventsRetentionBudget?.evaluatedAtUnix == 1700000000.25)
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
        #expect(h.timerLifecycle?.inFlightHandlers == 1)
        #expect(h.timerLifecycle?.degraded == false)
        #expect(h.timerLifecycle?.conservationMaintained == true)
        #expect(h.livenessTimerLifecycle?.coalescedHandlersTotal == 1)
        #expect(h.livenessTimerLifecycle?.degraded == false)
        #expect(h.startupWorkLifecycle?.acceptedHandlersTotal == 3)
        #expect(h.detectionWorkLifecycle?.inlineFallbackHandlersTotal == 1)
        #expect(h.detectionWorkLifecycle?.detectionProtectionDegraded == false)
        #expect(h.advisoryWorkLifecycle?.coalescedByLabel?["campaign-llm"] == 1)
        #expect(h.advisoryWorkLifecycle?.featureDegraded == false)
        #expect(h.outputWorkLifecycle?.acceptedHandlersTotal == 2)
        #expect(h.otlpReceiverLifecycle?.readyListeners == 1)
        #expect(h.otlpReceiverLifecycle?.callbackTasksInFlight == 1)
        #expect(h.otlpReceiverLifecycle?.lifecycleOperationsInProgress == 0)
        #expect(h.otlpReceiverLifecycle?.activeConnections == 1)
        #expect(h.otlpReceiverLifecycle?.conservationMaintained == true)
        #expect(h.otlpReceiverLifecycle?.featureDegraded == false)
        #expect(h.alertEvidenceBudget?.eventsAndAlertsTotalCapBytes == Int64(620) * 1_048_576)
        #expect(h.alertEvidenceBudget?.eventsAndAlertsSteadyStateTotalCapBytes == Int64(520) * 1_048_576)
        #expect(h.alertEvidenceBudget?.captureDegraded == false)
        #expect(h.prevention?.sinkhole?.enabled == true)
        #expect(h.prevention?.networkBlocker?.count == 0)
        #expect(h.traceRegistry?.liveBindings == 5)
        #expect(h.traceRegistry?.ttlEvictions == 2)
        #expect(h.sequenceCheckpoint?.restoreStatus == "restored")
        #expect(h.sequenceCheckpoint?.restoreDetail?.contains("17 partial") == true)
        #expect(h.sequenceCheckpoint?.checkpointBytes == 8_192)
        #expect(h.sequenceCheckpoint?.durableCarrierValid == true)
        #expect(h.sequenceCheckpoint?.dirty == false)
        #expect(h.sequenceCheckpoint?.currentGeneration == 44)
        #expect(h.sequenceCheckpoint?.durableGeneration == 44)
        #expect(h.sequenceCheckpoint?.crashRPOBoundCurrentlyMaintained == true)
        #expect(h.sequenceCheckpoint?.periodicWritesLastHour == 14)
        #expect(h.sequenceCheckpoint?.writesTotal == 21)
        #expect(h.sequenceCheckpoint?.conservation?.conservationMaintained == true)
        #expect(h.sequenceCheckpoint?.conservation?.inFlight == 1)
        #expect(h.sequenceCheckpoint?.orphanFilesRemovedTotal == 2)
        #expect(h.sequenceCheckpoint?.carrierInvalidationsTotal == 1)
        #expect(h.sequenceCheckpoint?.lastCarrierInvalidationReason == "integrity_mismatch")
        #expect(h.sequencePartialsEvictedTotal == 0)
        #expect(h.sequencePartialsInFlight == 17)
        #expect(h.sequencePendingStepsCurrent == 2)
        #expect(h.sequencePendingStepsEvictedTotal == 0)
        #expect(h.sequenceJournalConservation?.conservationMaintained == true)
        #expect(h.sequenceJournalConservation?.queued == 2)
        #expect(h.sequenceJournalConservationByRule?["stable-rule"]?
            .conservationMaintained == true)
        #expect(h.sequenceCheckpointStateWeightBytes == 4_096)
        #expect(h.sequenceCheckpointStateWeightRecomputedBytes == 4_096)
        #expect(h.sequenceCheckpointStateWeightLimitBytes == 8_388_608)
        #expect(h.sequenceStateContinuityMaintained == true)
        #expect(h.sequenceStateContinuityDetail == "nominal")
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
        #expect(h.traceStoreStorageAdmission?.ingestConservation?.offered == 29)
        #expect(h.traceStoreStorageAdmission?.ingestConservation?.completed == 7)
        #expect(h.traceStoreStorageAdmission?.ingestConservation?.queued == 3)
        #expect(h.traceStoreStorageAdmission?.ingestConservation?.inFlight == 4)
        #expect(h.traceStoreStorageAdmission?.ingestConservation?.explicitlyShed == 15)
        #expect(h.traceStoreStorageAdmission?.ingestConservation?
            .conservationMaintained == true)
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

    @Test("Active TraceGraph admission cannot hide a failed conserving batch")
    func traceGraphFailedBatchHealth() throws {
        let h = try decode("""
        {
          "schema_version": 5,
          "tracegraph_storage_admission": {
            "enabled": true, "blocked": false, "store_available": true,
            "startup_blocked": false, "reason": "",
            "ingest_events_total": 2,
            "ingest_events_committed_total": 0,
            "ingest_events_failed_total": 2,
            "ingest_events_in_flight": 0,
            "ingest_events_pending": 0,
            "entity_observations_total": 2,
            "edge_observations_total": 0,
            "relevance_suppressed_file_events_total": 0,
            "relevance_suppressed_rows_total": 0,
            "write_attempts_total": 1,
            "write_batches_committed_total": 0,
            "write_batches_failed_total": 1,
            "write_batches_in_flight": 0,
            "write_rows_attempted_total": 1,
            "write_rows_committed_total": 0,
            "write_rows_failed_total": 1,
            "write_rows_in_flight": 0,
            "coalesced_noop_rows_total": 1,
            "pending_entity_rows": 0,
            "pending_edge_rows": 0
          }
        }
        """)
        let storage = try #require(h.traceGraphStorageAdmission)
        #expect(storage.ingestConservationMaintained == true)
        #expect(storage.writeBatchConservationMaintained == true)
        #expect(storage.writeRowConservationMaintained == true)
        #expect(storage.observationConservationMaintained == true)
        #expect(storage.writeConservationMaintained == true)
        #expect(storage.hasStickyWriteFailure == true)
        #expect(storage.hasOutstandingBacklog == false)
        #expect(storage.graphWriteDegraded)

        let drift = try decode("""
        {"tracegraph_storage_admission":{
          "ingest_events_total":2,"ingest_events_committed_total":2,
          "ingest_events_failed_total":1,"ingest_events_in_flight":0,
          "ingest_events_pending":0,"entity_observations_total":0,
          "edge_observations_total":0,"write_attempts_total":0,
          "write_batches_committed_total":0,"write_batches_failed_total":0,
          "write_batches_in_flight":0,"write_rows_attempted_total":0,
          "write_rows_committed_total":0,"write_rows_failed_total":0,
          "write_rows_in_flight":0,"coalesced_noop_rows_total":0,
          "pending_entity_rows":0,"pending_edge_rows":0}}
        """)
        #expect(drift.traceGraphStorageAdmission?.writeConservationMaintained == false)
        #expect(drift.traceGraphStorageAdmission?.graphWriteDegraded == true)

        let partial = try decode("""
        {"tracegraph_storage_admission":{"enabled":true,"blocked":false,
        "store_available":true,"ingest_events_total":1}}
        """)
        #expect(partial.traceGraphStorageAdmission?.writeTelemetryPresent == true)
        #expect(partial.traceGraphStorageAdmission?.writeTelemetryComplete == false)
        #expect(partial.traceGraphStorageAdmission?.graphWriteDegraded == true)
    }

    @Test("transition-aware evidence and timer ledgers remain fail-visible")
    func evidenceAndTimerHealth() throws {
        let h = try decode("""
        {
          "alert_evidence_budget": {
            "events_family_effective_cap_bytes": 440401920,
            "events_family_steady_state_cap_bytes": 335544320,
            "alerts_family_combined_cap_bytes": 209715200,
            "events_and_alerts_total_cap_bytes": 650117120,
            "events_and_alerts_steady_state_total_cap_bytes": 545259520,
            "legacy_transition_reserve_bytes": 104857600,
            "legacy_transition_max_bytes": 104857600,
            "legacy_transition_measurement_failed": true,
            "legacy_row_count": 42,
            "legacy_charged_bytes": 73400320,
            "capture_offered_total": 8,
            "capture_completed_total": 5,
            "capture_failures_total": 1,
            "capture_shed_total": 1,
            "capture_pending": 1,
            "capture_in_flight": 0,
            "capture_queue_capacity": 256,
            "capture_accepting": true,
            "capture_conserved": true,
            "allocated_bytes_exact": false,
            "mutation_generation": 19,
            "full_refreshes_total": 3
          },
          "timer_lifecycle": {
            "accepting": true,
            "offered_handlers_total": 11,
            "accepted_handlers_total": 10,
            "completed_handlers_total": 8,
            "rejected_handlers_total": 1,
            "closed_rejected_handlers_total": 0,
            "overload_shed_handlers_total": 1,
            "coalesced_handlers_total": 0,
            "coalesced_by_label": {},
            "rejected_by_label": {"retention": 1},
            "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": {},
            "in_flight_handlers": 1,
            "maximum_in_flight_handlers": 256,
            "conserves_accepted_handlers": false,
            "conserves_offered_handlers": true
          },
          "liveness_timer_lifecycle": {
            "accepting": true,
            "offered_handlers_total": 2,
            "accepted_handlers_total": 1,
            "completed_handlers_total": 0,
            "rejected_handlers_total": 0,
            "closed_rejected_handlers_total": 0,
            "overload_shed_handlers_total": 0,
            "coalesced_handlers_total": 1,
            "coalesced_by_label": {"liveness": 1},
            "rejected_by_label": {},
            "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": {},
            "in_flight_handlers": 1,
            "maximum_in_flight_handlers": 1,
            "conserves_accepted_handlers": true,
            "conserves_offered_handlers": true
          },
          "detection_work_lifecycle": {
            "accepting": false,
            "offered_handlers_total": 4,
            "accepted_handlers_total": 3,
            "completed_handlers_total": 3,
            "rejected_handlers_total": 1,
            "closed_rejected_handlers_total": 1,
            "overload_shed_handlers_total": 0,
            "coalesced_handlers_total": 0,
            "coalesced_by_label": {},
            "rejected_by_label": {"active-defense": 1},
            "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": {},
            "in_flight_handlers": 0,
            "maximum_in_flight_handlers": 256,
            "conserves_accepted_handlers": true,
            "conserves_offered_handlers": true
          },
          "advisory_work_lifecycle": {
            "accepting": true,
            "offered_handlers_total": 6,
            "accepted_handlers_total": 5,
            "completed_handlers_total": 5,
            "rejected_handlers_total": 1,
            "closed_rejected_handlers_total": 0,
            "overload_shed_handlers_total": 1,
            "coalesced_handlers_total": 0,
            "coalesced_by_label": {},
            "rejected_by_label": {"campaign-llm": 1},
            "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": {},
            "in_flight_handlers": 0,
            "maximum_in_flight_handlers": 64,
            "conserves_accepted_handlers": true,
            "conserves_offered_handlers": true
          },
          "output_work_lifecycle": {
            "accepting": false,
            "offered_handlers_total": 3,
            "accepted_handlers_total": 3,
            "completed_handlers_total": 2,
            "rejected_handlers_total": 0,
            "closed_rejected_handlers_total": 0,
            "overload_shed_handlers_total": 0,
            "coalesced_handlers_total": 0,
            "coalesced_by_label": {},
            "rejected_by_label": {},
            "inline_fallback_handlers_total": 0,
            "inline_fallbacks_by_label": {},
            "in_flight_handlers": 1,
            "maximum_in_flight_handlers": 128,
            "conserves_accepted_handlers": true,
            "conserves_offered_handlers": true
          },
          "otlp_receiver_lifecycle": {
            "accepting_listeners": false,
            "listeners_accepted_total": 2,
            "listeners_completed_total": 1,
            "listeners_rejected_after_seal_total": 1,
            "active_listeners": 1,
            "ready_listeners": 1,
            "listeners_conserved": true,
            "accepting_connections": false,
            "connections_accepted_total": 2,
            "connections_completed_total": 1,
            "connections_rejected_after_seal_total": 1,
            "connections_rejected_at_capacity_total": 0,
            "active_connections": 1,
            "connections_conserved": true,
            "accepting_body_tasks": false,
            "body_tasks_accepted_total": 1,
            "body_tasks_completed_total": 0,
            "body_tasks_cancelled_total": 0,
            "body_tasks_rejected_total": 1,
            "body_task_cancellation_requests_total": 1,
            "body_tasks_in_flight": 1,
            "maximum_body_tasks": 64,
            "body_tasks_conserved": true,
            "accepting_callback_tasks": false,
            "callback_tasks_accepted_total": 2,
            "callback_tasks_completed_total": 1,
            "callback_tasks_cancelled_total": 0,
            "callback_tasks_rejected_total": 1,
            "callback_task_cancellation_requests_total": 1,
            "callback_tasks_in_flight": 1,
            "maximum_callback_tasks": 256,
            "callback_tasks_conserved": true,
            "lifecycle_operations_in_progress": 1,
            "shutdown_timeouts_total": 1,
            "cleanly_stopped": false,
            "last_shutdown_clean": false
          }
        }
        """)
        let budget = try #require(h.alertEvidenceBudget)
        #expect(budget.eventsFamilyEffectiveCapBytes == Int64(420) * 1_048_576)
        #expect(budget.eventsFamilySteadyStateCapBytes == Int64(320) * 1_048_576)
        #expect(budget.eventsAndAlertsTotalCapBytes == Int64(620) * 1_048_576)
        #expect(budget.eventsAndAlertsSteadyStateTotalCapBytes == Int64(520) * 1_048_576)
        #expect(budget.legacyTransitionReserveBytes == Int64(100) * 1_048_576)
        #expect(budget.legacyTransitionMeasurementFailed == true)
        #expect(budget.captureConserved == true)
        #expect(budget.captureConservationMaintained == true)
        #expect(budget.captureDegraded)
        #expect(budget.transitionDegraded)
        #expect(budget.allocatedBytesExact == false)
        #expect(budget.mutationGeneration == 19)

        let timer = try #require(h.timerLifecycle)
        #expect(timer.inFlightHandlers == 1)
        #expect(timer.degradedWhileRunning)
        #expect(timer.offeredHandlersTotal == 11)
        #expect(timer.conservationMaintained == false)
        #expect(h.livenessTimerLifecycle?.losslessPressureObserved == true)
        #expect(h.livenessTimerLifecycle?.degraded == false)
        #expect(h.detectionWorkLifecycle?.closedRejectedHandlersTotal == 1)
        #expect(h.detectionWorkLifecycle?.detectionProtectionDegraded == true)
        #expect(h.advisoryWorkLifecycle?.overloadShedHandlersTotal == 1)
        #expect(h.advisoryWorkLifecycle?.featureDegraded == true)
        #expect(h.outputWorkLifecycle?.uncleanOutstandingAfterClose == true)
        #expect(h.otlpReceiverLifecycle?.uncleanShutdown == true)
        #expect(h.otlpReceiverLifecycle?.advisoryInputShed == true)
        #expect(h.otlpReceiverLifecycle?.sealedWorkInFlight == true)
        #expect(h.otlpReceiverLifecycle?.lifecycleOperationLeftInProgress == true)
        #expect(h.otlpReceiverLifecycle?.featureDegraded == true)

        let normal = try decode("""
        {"timer_lifecycle":{"accepting":true,"offered_handlers_total":10,
        "accepted_handlers_total":10,
        "completed_handlers_total":9,"rejected_handlers_total":0,
        "closed_rejected_handlers_total":0,"overload_shed_handlers_total":0,
        "coalesced_handlers_total":0,"inline_fallback_handlers_total":0,
        "in_flight_handlers":1,"maximum_in_flight_handlers":256,
        "conserves_accepted_handlers":true,"conserves_offered_handlers":true}}
        """)
        #expect(normal.timerLifecycle?.degradedWhileRunning == false)

        let incomplete = try decode("""
        {"detection_work_lifecycle":{"offered_handlers_total":1},
         "otlp_receiver_lifecycle":{"accepting_connections":true}}
        """)
        #expect(incomplete.detectionWorkLifecycle?.telemetryIncomplete == true)
        #expect(incomplete.detectionWorkLifecycle?.detectionProtectionDegraded == true)
        #expect(incomplete.otlpReceiverLifecycle?.telemetryPresent == true)
        #expect(incomplete.otlpReceiverLifecycle?.telemetryComplete == false)
        #expect(incomplete.otlpReceiverLifecycle?.featureDegraded == true)

        let incompleteLegacyTimer = try decode("""
        {"timer_lifecycle":{"accepting":true}}
        """)
        #expect(incompleteLegacyTimer.timerLifecycle?.telemetryIncomplete == true)
        #expect(incompleteLegacyTimer.timerLifecycle?.featureDegraded == true)

        let cleanOTLPStop = try decode("""
        {"otlp_receiver_lifecycle":{"accepting_listeners":false,
        "listeners_accepted_total":1,"listeners_completed_total":1,
        "listeners_rejected_after_seal_total":0,"active_listeners":0,
        "ready_listeners":0,"listeners_conserved":true,
        "accepting_connections":false,
        "connections_accepted_total":1,"connections_completed_total":1,
        "connections_rejected_after_seal_total":0,
        "connections_rejected_at_capacity_total":0,"active_connections":0,
        "connections_conserved":true,"accepting_body_tasks":false,
        "body_tasks_accepted_total":1,"body_tasks_completed_total":0,
        "body_tasks_cancelled_total":1,"body_tasks_rejected_total":0,
        "body_task_cancellation_requests_total":1,"body_tasks_in_flight":0,
        "maximum_body_tasks":64,"body_tasks_conserved":true,
        "accepting_callback_tasks":false,"callback_tasks_accepted_total":1,
        "callback_tasks_completed_total":0,"callback_tasks_cancelled_total":1,
        "callback_tasks_rejected_total":0,
        "callback_task_cancellation_requests_total":1,
        "callback_tasks_in_flight":0,"maximum_callback_tasks":256,
        "callback_tasks_conserved":true,"lifecycle_operations_in_progress":0,
        "shutdown_timeouts_total":0,"cleanly_stopped":true,
        "last_shutdown_clean":true}}
        """)
        #expect(cleanOTLPStop.otlpReceiverLifecycle?.uncleanShutdown == false)
        #expect(cleanOTLPStop.otlpReceiverLifecycle?.advisoryInputShed == false)
        #expect(cleanOTLPStop.otlpReceiverLifecycle?.featureDegraded == false)

        let legacy = try decode("""
        {"derived_work_lifecycle":{"accepting":false,
        "accepted_handlers_total":2,"completed_handlers_total":1,
        "rejected_handlers_total":0,"in_flight_handlers":1,
        "maximum_in_flight_handlers":64,
        "conserves_accepted_handlers":true}}
        """)
        #expect(legacy.legacyDerivedWorkLifecycle?.uncleanOutstandingAfterClose == true)
        #expect(legacy.detectionWorkLifecycle == nil)

        let partialCapture = try decode("""
        {"alert_evidence_budget":{"capture_offered_total":1}}
        """)
        #expect(partialCapture.alertEvidenceBudget?.captureTelemetryPresent == true)
        #expect(partialCapture.alertEvidenceBudget?.captureConservationMaintained == nil)
        #expect(partialCapture.alertEvidenceBudget?.captureDegraded == true)
    }

    @Test("OTLP listener and callback ledgers distinguish live work from loss")
    func otlpListenerAndCallbackHealth() throws {
        func lifecycle(
            overriding overrides: [String: Any] = [:]
        ) throws -> HeartbeatSnapshot.OTLPReceiverLifecycle {
            var block: [String: Any] = [
                "accepting_listeners": true,
                "listeners_accepted_total": 1,
                "listeners_completed_total": 0,
                "listeners_rejected_after_seal_total": 0,
                "active_listeners": 1,
                "ready_listeners": 1,
                "listeners_conserved": true,
                "accepting_connections": true,
                "connections_accepted_total": 1,
                "connections_completed_total": 0,
                "connections_rejected_after_seal_total": 0,
                "connections_rejected_at_capacity_total": 0,
                "active_connections": 1,
                "connections_conserved": true,
                "accepting_body_tasks": true,
                "body_tasks_accepted_total": 1,
                "body_tasks_completed_total": 0,
                "body_tasks_cancelled_total": 0,
                "body_tasks_rejected_total": 0,
                "body_task_cancellation_requests_total": 0,
                "body_tasks_in_flight": 1,
                "maximum_body_tasks": 64,
                "body_tasks_conserved": true,
                "accepting_callback_tasks": true,
                "callback_tasks_accepted_total": 1,
                "callback_tasks_completed_total": 0,
                "callback_tasks_cancelled_total": 0,
                "callback_tasks_rejected_total": 0,
                "callback_task_cancellation_requests_total": 0,
                "callback_tasks_in_flight": 1,
                "maximum_callback_tasks": 256,
                "callback_tasks_conserved": true,
                "lifecycle_operations_in_progress": 0,
                "shutdown_timeouts_total": 0,
                "cleanly_stopped": false,
            ]
            for (key, value) in overrides { block[key] = value }
            let data = try JSONSerialization.data(
                withJSONObject: ["otlp_receiver_lifecycle": block]
            )
            return try #require(
                JSONDecoder().decode(HeartbeatSnapshot.self, from: data)
                    .otlpReceiverLifecycle
            )
        }

        let open = try lifecycle()
        #expect(open.telemetryComplete)
        #expect(open.conservationMaintained == true)
        #expect(!open.sealedWorkInFlight)
        #expect(!open.featureDegraded)

        #expect(try lifecycle(overriding: [
            "listeners_rejected_after_seal_total": 1,
        ]).featureDegraded)
        #expect(try lifecycle(overriding: [
            "listeners_conserved": false,
        ]).featureDegraded)
        #expect(try lifecycle(overriding: [
            "accepting_listeners": false,
        ]).sealedWorkInFlight)
        #expect(try lifecycle(overriding: [
            "callback_tasks_rejected_total": 1,
        ]).featureDegraded)
        #expect(try lifecycle(overriding: [
            "callback_tasks_conserved": false,
        ]).featureDegraded)
        #expect(try lifecycle(overriding: [
            "accepting_callback_tasks": false,
        ]).sealedWorkInFlight)
        #expect(try lifecycle(overriding: [
            "lifecycle_operations_in_progress": 1,
        ]).lifecycleOperationLeftInProgress)
        #expect(try lifecycle(overriding: [
            "last_shutdown_clean": false,
        ]).featureDegraded)
    }

    @Test("LLM runtime ledger decodes fixed outcomes, attribution, and semantic validation")
    func llmRuntimeTelemetryHealth() throws {
        func counters(
            requested: Int = 0,
            success: Int = 0,
            cache: Int = 0,
            admitted: Int = 0,
            accepted: Int = 0,
            retries: Int = 0,
            finalRejections: Int = 0
        ) -> [String: Any] {
            [
                "requestedTotal": requested,
                "currentInFlight": 0,
                "admittedBackendTotal": admitted,
                "currentAdmittedBackendRequests": 0,
                "backendCallsStartedTotal": admitted,
                "cancellationsAfterAdmissionTotal": 0,
                "outcomes": [
                    "success": success, "cacheHit": cache,
                    "backendFailure": 0, "circuitRejection": 0,
                    "privacyRejection": 0, "admissionShed": 0,
                    "cancellation": 0, "responseOversize": 0,
                ],
                "circuitRecoveryProbesStartedTotal": 0,
                "currentCircuitRecoveryProbes": 0,
                "circuitRecoveryProbesSucceededTotal": 0,
                "circuitRecoveryProbesDidNotRecoverTotal": 0,
                "downstreamValidation": [
                    "operationsStartedTotal": accepted + finalRejections,
                    "currentOperations": 0,
                    "accepted": accepted,
                    "retryRequested": retries,
                    "finalRejection": finalRejections,
                ],
                "requestLatencyBuckets": [[
                    "upperBoundMilliseconds": 120_000,
                    "completedRequests": requested,
                ]],
                "requestedInputUTF8BytesTotal": 0,
                "backendInputUTF8BytesTotal": 0,
                "backendOutputUTF8BytesTotal": 0,
                "returnedOutputUTF8BytesTotal": 0,
                "estimatedBackendInputTokensTotal": 0,
                "estimatedBackendOutputTokensTotal": 0,
                "estimatedReturnedOutputTokensTotal": 0,
                "conservationMaintained": true,
                "backendAdmissionConservationMaintained": true,
                "circuitRecoveryConservationMaintained": true,
            ]
        }

        let perFeature: [[String: Any]] = LLMRuntimeFeature.allCases.map { feature in
            let value: [String: Any]
            switch feature {
            case .unspecified:
                value = counters(requested: 1, cache: 1)
            case .alertInvestigation:
                value = counters(
                    requested: 2, success: 2, admitted: 2,
                    accepted: 1, retries: 1, finalRejections: 1
                )
            default:
                value = counters()
            }
            return ["feature": feature.rawValue, "counters": value]
        }
        let heartbeat: [String: Any] = [
            "schema_version": 5,
            "llm": [
                "configured": true,
                "provider": "fixture",
                "model": "content-free",
                "healthy": true,
                "runtime_telemetry": [
                    "schemaVersion": 2,
                    "capturedAtUnix": 1_700_000_000.0,
                    "totals": counters(
                        requested: 3, success: 2, cache: 1, admitted: 2,
                        accepted: 1, retries: 1, finalRejections: 1
                    ),
                    "perFeature": perFeature,
                    "alertInvestigationRejections": [
                        "observedAttemptsTotal": 2,
                        "terminalRejectionsTotal": 1,
                        "byReason": LLMAlertInvestigationRejectionReason.allCases.map {
                            reason in
                            [
                                "reason": reason.rawValue,
                                "observedAttempts": reason == .mitreGrounding ? 2 : 0,
                                "terminalRejections": reason == .mitreGrounding ? 1 : 0,
                            ]
                        },
                    ],
                ],
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: heartbeat)
        let h = try JSONDecoder().decode(HeartbeatSnapshot.self, from: data)
        #expect(h.llm?.runtimeTelemetry?.totals.requestedTotal == 3)
        #expect(h.llm?.runtimeConservationMaintained == true)
        #expect(h.llm?.unspecifiedRequestsTotal == 1)
        #expect(h.llm?.runtimeTelemetry?.totals.downstreamValidation.retryRequested == 1)
        #expect(h.llm?.runtimeTelemetry?.totals.downstreamValidation.finalRejection == 1)
        #expect(h.llm?.runtimeTelemetry?.alertInvestigationRejections?
            .counts(for: .mitreGrounding)?.observedAttempts == 2)
        #expect(h.llm?.runtimeTelemetryDegraded == true)
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
        #expect(h.eventsStorageWriteOfferedByLane == nil)
        #expect(h.eventsStorageWriteFilteredTotal == nil)
        #expect(h.eventsStorageWriteInFlightDepth == nil)
        #expect(h.eventsRetentionBudget == nil)
        #expect(h.eventsInsertFilterDroppedTotal == nil)
        #expect(h.traceGraphStorageAdmission == nil)
        #expect(h.traceStoreStorageAdmission == nil)
        #expect(h.browserInventory == nil)
        #expect(h.sequenceCheckpoint == nil)
        #expect(h.timerLifecycle == nil)
        #expect(h.livenessTimerLifecycle == nil)
        #expect(h.startupWorkLifecycle == nil)
        #expect(h.detectionWorkLifecycle == nil)
        #expect(h.advisoryWorkLifecycle == nil)
        #expect(h.outputWorkLifecycle == nil)
        #expect(h.legacyDerivedWorkLifecycle == nil)
        #expect(h.otlpReceiverLifecycle == nil)
        #expect(h.alertEvidenceBudget == nil)
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
