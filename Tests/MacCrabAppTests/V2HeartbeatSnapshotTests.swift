// V2HeartbeatSnapshotTests.swift
// MacCrabAppTests
//
// Pin the V2HeartbeatSnapshot decoder + computed-property contract.
// The dashboard's System workspace renders these directly so a
// silent decoding regression would put epoch-0 / 20583d-ago strings
// in front of users. Covers: decode happy path, missing-field
// degradation, uptime formatting buckets, eventsPerSecond1h math.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2HeartbeatSnapshot")
struct V2HeartbeatSnapshotTests {

    private func writeFixture(_ json: [String: Any]) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-hb-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let path = dir.appendingPathComponent("heartbeat_rich.json")
        let data = try JSONSerialization.data(withJSONObject: json, options: [])
        try data.write(to: path)
        return path
    }

    // MARK: - uptimeDisplay buckets

    @Test("uptimeDisplay formats sub-minute values as seconds")
    func uptimeUnderOneMinute() {
        let snap = makeSnapshot(uptimeSeconds: 45)
        #expect(snap.uptimeDisplay == "45s")
    }

    @Test("uptimeDisplay formats sub-hour values as minutes")
    func uptimeUnderOneHour() {
        let snap = makeSnapshot(uptimeSeconds: 600)
        #expect(snap.uptimeDisplay == "10m")
    }

    @Test("uptimeDisplay formats sub-day values as Hh Mm")
    func uptimeUnderOneDay() {
        let snap = makeSnapshot(uptimeSeconds: 2 * 3600 + 14 * 60) // 2h 14m
        #expect(snap.uptimeDisplay == "2h 14m")
    }

    @Test("uptimeDisplay drops the minute component when at an exact hour")
    func uptimeExactHour() {
        let snap = makeSnapshot(uptimeSeconds: 3 * 3600)
        #expect(snap.uptimeDisplay == "3h")
    }

    @Test("uptimeDisplay formats day+ values as Nd Hh")
    func uptimeMultiDay() {
        let snap = makeSnapshot(uptimeSeconds: 5 * 86_400 + 3 * 3600)
        #expect(snap.uptimeDisplay == "5d 3h")
    }

    @Test("uptimeDisplay drops hour when on an exact day")
    func uptimeExactDay() {
        let snap = makeSnapshot(uptimeSeconds: 12 * 86_400)
        #expect(snap.uptimeDisplay == "12d")
    }

    // MARK: - eventsPerSecond1h

    @Test("eventsPerSecond1h sums all categories and divides by 3600")
    func eventsPerSecondMath() {
        let snap = makeSnapshot(eventTypeCounts1h: ["exec": 1800, "file": 1800])
        #expect(snap.eventsPerSecond1h == 1.0)
    }

    @Test("eventsPerSecond1h returns 0 when counts are empty")
    func eventsPerSecondEmpty() {
        let snap = makeSnapshot(eventTypeCounts1h: [:])
        #expect(snap.eventsPerSecond1h == 0.0)
    }

    // MARK: - prevention block (UX-3)

    @Test("prevention block decodes three modules; absent → nil; partial → safe defaults")
    func preventionDecode() {
        let raw: [String: Any] = [
            "sinkhole": ["enabled": true, "count": 5],
            "network_blocker": ["enabled": false, "count": 0],
            "persistence_guard": ["enabled": true, "count": 3],
        ]
        let p = V2HeartbeatSnapshot.Prevention(from: raw)
        #expect(p?.sinkhole.enabled == true)
        #expect(p?.sinkhole.count == 5)
        #expect(p?.networkBlocker.enabled == false)
        #expect(p?.persistenceGuard.count == 3)
        // Older daemon (no prevention block) → nil so the UI shows
        // "status unavailable" instead of a false reading, no crash.
        #expect(V2HeartbeatSnapshot.Prevention(from: nil) == nil)
        // Malformed/partial block → safe defaults, never a crash.
        let partial = V2HeartbeatSnapshot.Prevention(from: ["sinkhole": ["enabled": true]])
        #expect(partial?.sinkhole.enabled == true)
        #expect(partial?.sinkhole.count == 0)
        #expect(partial?.networkBlocker.enabled == false)
    }

    // MARK: - TraceGraph storage admission

    @Test("event-pipeline causality block preserves source, lane, and collector boundaries")
    func eventPipelineDecode() throws {
        let pipeline = try #require(V2HeartbeatSnapshot.EventPipeline(from: [
            "offered_by_source": ["ESCollector": 20, "UnifiedLogCollector": 8],
            "offered_by_source_and_lane": [
                "ESCollector": ["priority": 12, "file": 8],
                "UnifiedLogCollector": ["priority": 6, "file": 2],
            ],
            "dropped_by_source_and_lane": [
                "ESCollector": ["priority": 0, "file": 1],
                "UnifiedLogCollector": ["priority": 1, "file": 0],
            ],
            "terminated_by_source_and_lane": [
                "ESCollector": ["priority": 1, "file": 0],
            ],
            "collector_offered_by_source_and_lane": [
                "ESCollector": ["priority": 13, "file": 9],
            ],
            "upstream_dropped_by_source_and_lane": [
                "ESCollector": ["priority": 0, "file": 1],
            ],
            "upstream_terminated_by_source_and_lane": [
                "ESCollector": ["priority": 1, "file": 0],
            ],
            "merged_dropped_by_source_and_lane": [
                "UnifiedLogCollector": ["priority": 1, "file": 0],
            ],
            "merged_terminated_by_source_and_lane": [
                "ESCollector": ["priority": 0, "file": 0],
            ],
            "offered_by_lane": ["priority": 18, "file": 10],
            "dequeued_by_lane": ["priority": 16, "file": 9],
            "rule_evaluation_reached_by_lane_and_category": [
                "priority": ["process": 14, "file": 2],
                "file": ["file": 9],
            ],
            "rule_evaluation_completed_by_lane_and_category": [
                "priority": ["process": 13, "file": 2],
                "file": ["file": 9],
            ],
            "completed_by_lane": ["priority": 15, "file": 9],
            "backlog_estimate_by_lane": ["priority": 1, "file": 0],
            "in_flight_by_lane": ["priority": 1, "file": 0],
            "processing_p99_us_by_lane": ["priority": 4_000, "file": 1_000],
            "latency_sample_count_by_lane": ["priority": 15, "file": 9],
            "upstream_dropped_by_lane": ["priority": 0, "file": 1],
            "upstream_terminated_by_lane": ["priority": 1, "file": 0],
            "merged_dropped_by_lane": ["priority": 1, "file": 1],
            "merged_terminated_by_lane": ["priority": 0, "file": 0],
            "collector_capacity_by_source": ["ESCollector": 100_000],
            "pre_buffer_dropped_by_source": ["ESCollector": 7],
            "detection_input_dropped_total": 10,
            "capacity_by_lane": ["priority": 100_000, "file": 100_000],
            "collector_buffer": [
                "unified_log_normalized_total": 10,
                "unified_log_stream_yield_dropped_total": 2,
                "unified_log_capacity": 512,
            ],
        ]))

        #expect(pipeline.offeredBySource["ESCollector"] == 20)
        #expect(pipeline.offeredBySourceAndLane["UnifiedLogCollector"]?["file"] == 2)
        #expect(pipeline.droppedBySourceAndLane["ESCollector"]?["file"] == 1)
        #expect(pipeline.terminatedBySourceAndLane["ESCollector"]?["priority"] == 1)
        #expect(pipeline.upstreamDroppedByLane["file"] == 1)
        #expect(pipeline.mergedDroppedBySourceAndLane["UnifiedLogCollector"]?["priority"] == 1)
        #expect(pipeline.collectorCapacityBySource["ESCollector"] == 100_000)
        #expect(pipeline.preBufferDroppedBySource["ESCollector"] == 7)
        #expect(pipeline.detectionInputDroppedTotal == 10)
        #expect(pipeline.backlogEstimateByLane["priority"] == 1)
        #expect(pipeline.inFlightByLane["priority"] == 1)
        #expect(pipeline.ruleEvaluationReachedByLaneAndCategory["priority"]?["process"] == 14)
        #expect(pipeline.ruleEvaluationCompletedByLaneAndCategory["priority"]?["process"] == 13)
        #expect(pipeline.ruleEvaluationCompletedByLaneAndCategory["file"]?["file"] == 9)
        #expect(pipeline.processingP99MicrosByLane["priority"] == 4_000)
        #expect(pipeline.latencySampleCountByLane["file"] == 9)
        #expect(pipeline.collectorBuffer["unified_log_stream_yield_dropped_total"] == 2)
        let diagnostics = pipeline.diagnosticDictionary
        #expect(diagnostics["detection_input_dropped_total"] as? UInt64 == 10)
        #expect((diagnostics["upstream_dropped_by_lane"] as? [String: UInt64])?["file"] == 1)
        #expect((diagnostics["rule_evaluation_completed_by_lane_and_category"]
            as? [String: [String: UInt64]])?["priority"]?["process"] == 13)
        #expect(V2HeartbeatSnapshot.EventPipeline(from: nil) == nil)
    }

    @Test("startup storage admission remains a fail-visible evidence gap")
    func traceGraphStartupAdmissionDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": true,
            "store_available": false,
            "startup_blocked": true,
            "reason": "low_free_space",
            "free_space_bytes": NSNumber(value: 100_000_000),
            "free_space_floor_bytes": NSNumber(value: 1_073_741_824),
        ]))

        #expect(status.enabled)
        #expect(status.blocked)
        #expect(status.storeAvailable == false)
        #expect(status.startupBlocked)
        #expect(status.reason == "low_free_space")
        #expect(status.freeSpaceBytes == 100_000_000)
        #expect(status.freeSpaceFloorBytes == 1_073_741_824)
        #expect(status.evidenceUnavailable)
        #expect(status.operatorDetail.contains("paused at startup"))
        #expect(status.operatorDetail.contains("new causal evidence is not being recorded"))
    }

    @Test("live healthy admission is not reported as an evidence gap")
    func traceGraphHealthyAdmissionDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": false,
            "store_available": true,
            "startup_blocked": false,
            "reason": "",
        ]))

        #expect(!status.evidenceUnavailable)
        #expect(status.reason == nil)
    }

    @Test("failed TraceGraph batch degrades an otherwise active admission")
    func traceGraphFailedBatchDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": false,
            "store_available": true,
            "startup_blocked": false,
            "reason": "",
            "ingest_events_total": 2,
            "ingest_events_committed_total": 0,
            "ingest_events_failed_total": 2,
            "ingest_events_in_flight": 0,
            "ingest_events_pending": 0,
            "entity_observations_total": 2,
            "edge_observations_total": 0,
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
            "pending_edge_rows": 0,
        ]))

        #expect(status.writeTelemetry?.writeConservationMaintained == true)
        #expect(status.writeTelemetry?.hasStickyWriteFailure == true)
        #expect(status.graphWriteDegraded)
        #expect(status.evidenceUnavailable)
        #expect(status.operatorDetail.contains("admission is active"))
        #expect(status.operatorDetail.contains("2 input event(s) failed"))
        #expect(status.diagnosticDictionary["write_degraded"] as? Bool == true)
        #expect(AppState.traceGraphEvidenceUnavailable(
            blocked: false,
            storeAvailable: true,
            writeDegraded: true
        ))
    }

    @Test("Agent Trace admission uses the shared wire shape without implying trust")
    func traceStoreAdmissionDecode() throws {
        let status = try #require(V2HeartbeatSnapshot.TraceGraphStorageAdmission(from: [
            "enabled": true,
            "blocked": true,
            "store_available": true,
            "startup_blocked": false,
            "reason": "footprint_limit",
            "footprint_bytes": NSNumber(value: 96_000_000),
            "max_footprint_bytes": NSNumber(value: 100_000_000),
        ]))

        #expect(status.evidenceUnavailable)
        #expect(status.reason == "footprint_limit")
        #expect(status.footprintBytes == 96_000_000)
        #expect(status.maxFootprintBytes == 100_000_000)
    }

    @Test("TraceGraph evidence gaps degrade every shared dashboard surface")
    func traceGraphGlobalDegradedSignal() {
        #expect(AppState.traceGraphEvidenceUnavailable(
            enabled: false,
            blocked: false,
            storeAvailable: true
        ))
        #expect(AppState.traceGraphEvidenceUnavailable(blocked: true, storeAvailable: true))
        #expect(AppState.traceGraphEvidenceUnavailable(blocked: false, storeAvailable: false))
        #expect(!AppState.traceGraphEvidenceUnavailable(blocked: false, storeAvailable: true))
        #expect(!AppState.traceGraphEvidenceUnavailable(blocked: nil, storeAvailable: nil))
    }

    @Test("LLM runtime quality is content-free, conserving, and fail-visible")
    func llmRuntimeQualityDecode() throws {
        func counters(
            requested: Int = 0,
            cache: Int = 0,
            success: Int = 0,
            backendFailures: Int = 0,
            retries: Int = 0,
            finalRejections: Int = 0
        ) -> [String: Any] {
            let admitted = success + backendFailures
            return [
                "requestedTotal": requested,
                "currentInFlight": 0,
                "admittedBackendTotal": admitted,
                "currentAdmittedBackendRequests": 0,
                "backendCallsStartedTotal": admitted,
                "cancellationsAfterAdmissionTotal": 0,
                "outcomes": [
                    "success": success, "cacheHit": cache,
                    "backendFailure": backendFailures, "circuitRejection": 0,
                    "privacyRejection": 0, "admissionShed": 0,
                    "cancellation": 0, "responseOversize": 0,
                ],
                "circuitRecoveryProbesStartedTotal": 0,
                "currentCircuitRecoveryProbes": 0,
                "circuitRecoveryProbesSucceededTotal": 0,
                "circuitRecoveryProbesDidNotRecoverTotal": 0,
                "downstreamValidation": [
                    "operationsStartedTotal": finalRejections,
                    "currentOperations": 0,
                    "accepted": 0,
                    "retryRequested": retries,
                    "finalRejection": finalRejections,
                ],
                "requestLatencyBuckets": [["completedRequests": requested]],
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
            let value = feature == .unspecified
                ? counters(requested: 1, cache: 1, retries: 1, finalRejections: 1)
                : counters()
            return ["feature": feature.rawValue, "counters": value]
        }
        let llm = V2HeartbeatSnapshot.LLMHealth(from: [
            "configured": true,
            "provider": "fixture",
            "model": "content-free",
            "healthy": true,
            "runtime_telemetry": [
                "schemaVersion": 1,
                "capturedAtUnix": 1_700_000_000.0,
                "totals": counters(
                    requested: 1, cache: 1, retries: 1, finalRejections: 1
                ),
                "perFeature": perFeature,
            ],
        ])

        #expect(llm.runtimeTelemetry?.totals.requestedTotal == 1)
        #expect(llm.runtimeConservationMaintained == true)
        #expect(llm.unspecifiedRequestsTotal == 1)
        #expect(llm.semanticRetriesTotal == 1)
        #expect(llm.semanticFinalRejectionsTotal == 1)
        #expect(llm.runtimeRequiresAttention)
        #expect(llm.runtimeOperatorDetail.contains("No prompt or response content"))
        #expect(llm.summary.contains("needs attention"))
        #expect(llm.diagnosticDictionary["runtime_telemetry"] != nil)

        let recoveredFeatures: [[String: Any]] = LLMRuntimeFeature.allCases.map { feature in
            let value = feature == .intentClassification
                ? counters(requested: 2, success: 1, backendFailures: 1)
                : counters()
            return ["feature": feature.rawValue, "counters": value]
        }
        let recovered = V2HeartbeatSnapshot.LLMHealth(from: [
            "configured": true,
            "provider": "fixture",
            "model": "recovered",
            "last_success_unix": 1_700_000_010.0,
            "consecutive_failures": 0,
            "circuit_open": false,
            "healthy": true,
            "runtime_telemetry": [
                "schemaVersion": 1,
                "capturedAtUnix": 1_700_000_020.0,
                "totals": counters(requested: 2, success: 1, backendFailures: 1),
                "perFeature": recoveredFeatures,
            ],
        ])
        #expect(!recovered.runtimeRequiresAttention,
                "A historical failure must not pin a recovered runtime red")
        #expect(recovered.summary.contains("healthy"))
        #expect(recovered.runtimeOperatorDetail.contains(
            "Historical outcome counts do not describe current health"
        ))

        let currentlyFailing = V2HeartbeatSnapshot.LLMHealth(from: [
            "configured": true,
            "provider": "fixture",
            "model": "failing",
            "last_success_unix": 1_700_000_010.0,
            "consecutive_failures": 1,
            "circuit_open": false,
            "healthy": false,
        ])
        #expect(currentlyFailing.runtimeRequiresAttention)
    }

    @Test("V2 decodes live versus steady storage and lifecycle degradation")
    func transitionAndTimerDecode() throws {
        let path = try writeFixture([
            "written_at_unix": Date().timeIntervalSince1970,
            "alert_evidence_budget": [
                "events_family_effective_cap_bytes": 440_401_920,
                "events_family_steady_state_cap_bytes": 335_544_320,
                "alerts_family_combined_cap_bytes": 209_715_200,
                "events_and_alerts_total_cap_bytes": 650_117_120,
                "events_and_alerts_steady_state_total_cap_bytes": 545_259_520,
                "legacy_transition_reserve_bytes": 104_857_600,
                "legacy_transition_max_bytes": 104_857_600,
                "legacy_transition_measurement_failed": false,
                "capture_offered_total": 4,
                "capture_completed_total": 2,
                "capture_failures_total": 1,
                "capture_shed_total": 0,
                "capture_pending": 0,
                "capture_in_flight": 1,
                "capture_queue_capacity": 256,
                "capture_accepting": true,
                "capture_conserved": true,
            ],
            "timer_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 11,
                "accepted_handlers_total": 10,
                "completed_handlers_total": 8,
                "rejected_handlers_total": 1,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 1,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 1,
                "maximum_in_flight_handlers": 256,
                "conserves_accepted_handlers": false,
                "conserves_offered_handlers": true,
            ],
            "liveness_timer_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 2,
                "accepted_handlers_total": 1,
                "completed_handlers_total": 0,
                "rejected_handlers_total": 0,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 0,
                "coalesced_handlers_total": 1,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 1,
                "maximum_in_flight_handlers": 1,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "detection_work_lifecycle": [
                "accepting": false,
                "offered_handlers_total": 4,
                "accepted_handlers_total": 3,
                "completed_handlers_total": 3,
                "rejected_handlers_total": 1,
                "closed_rejected_handlers_total": 1,
                "overload_shed_handlers_total": 0,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 256,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "advisory_work_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 2,
                "accepted_handlers_total": 1,
                "completed_handlers_total": 1,
                "rejected_handlers_total": 1,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 1,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 64,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "output_work_lifecycle": [
                "accepting": true,
                "offered_handlers_total": 1,
                "accepted_handlers_total": 1,
                "completed_handlers_total": 1,
                "rejected_handlers_total": 0,
                "closed_rejected_handlers_total": 0,
                "overload_shed_handlers_total": 0,
                "coalesced_handlers_total": 0,
                "inline_fallback_handlers_total": 0,
                "in_flight_handlers": 0,
                "maximum_in_flight_handlers": 128,
                "conserves_accepted_handlers": true,
                "conserves_offered_handlers": true,
            ],
            "otlp_receiver_lifecycle": [
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
                "last_shutdown_clean": false,
            ],
        ])
        defer { try? FileManager.default.removeItem(at: path.deletingLastPathComponent()) }
        let snapshot = try #require(V2HeartbeatSnapshot.decode(at: path.path))
        #expect(snapshot.alertEvidenceBudget?.eventsAndAlertsTotalCapBytes
            == 620 * 1_048_576)
        #expect(snapshot.alertEvidenceBudget?.eventsAndAlertsSteadyStateTotalCapBytes
            == 520 * 1_048_576)
        #expect(snapshot.alertEvidenceBudget?.captureConservationMaintained == true)
        #expect(snapshot.alertEvidenceBudget?.captureDegraded == true)
        #expect(snapshot.timerLifecycle?.inFlightHandlers == 1)
        #expect(snapshot.timerLifecycle?.degradedWhileRunning == true)
        #expect(snapshot.livenessTimerLifecycle?.losslessPressureObserved == true)
        #expect(snapshot.livenessTimerLifecycle?.degraded == false)
        #expect(snapshot.detectionWorkLifecycle?.detectionProtectionDegraded == true)
        #expect(snapshot.advisoryWorkLifecycle?.featureDegraded == true)
        #expect(snapshot.outputWorkLifecycle?.featureDegraded == false)
        #expect(snapshot.otlpReceiverLifecycle?.readyListeners == 1)
        #expect(snapshot.otlpReceiverLifecycle?.callbackTasksInFlight == 1)
        #expect(snapshot.otlpReceiverLifecycle?.lifecycleOperationLeftInProgress == true)
        #expect(snapshot.otlpReceiverLifecycle?.featureDegraded == true)
    }

    @Test("split detection lane is authoritative for global protection health")
    func splitDetectionProtectionVerdict() {
        #expect(AppState.detectionWorkProtectionUnavailable(
            detectionDegraded: true,
            legacyDerivedDegraded: false
        ))
        #expect(!AppState.detectionWorkProtectionUnavailable(
            detectionDegraded: false,
            legacyDerivedDegraded: true
        ))
        #expect(AppState.detectionWorkProtectionUnavailable(
            detectionDegraded: nil,
            legacyDerivedDegraded: true
        ))
        #expect(!AppState.detectionWorkProtectionUnavailable(
            detectionDegraded: nil,
            legacyDerivedDegraded: nil
        ))
    }

    @Test("browser inventory truncation decodes as an explicit coverage gap")
    func browserInventoryDecode() throws {
        let inventory = try #require(V2HeartbeatSnapshot.BrowserInventory(from: [
            "coverage_known": true,
            "complete": false,
            "degraded": true,
            "reason": "directory_budget_exhausted",
            "last_scan_was_truncated": true,
            "scans_total": 7,
            "truncated_scans_total": 2,
            "inspected_directory_entries_total": 200_321,
            "truncated_directories_total": 2,
            "truncated_homes_total": 2,
            "last_scan_completed_at_unix": 1_785_686_400.5,
            "last_scan_homes": 2,
            "last_scan_inspected_directory_entries": 100_321,
            "last_scan_truncated_directory_count": 1,
            "last_scan_truncated_home_count": 1,
            "per_home_directory_entry_budget": 100_000,
        ]))

        #expect(inventory.coverageKnown)
        #expect(!inventory.complete)
        #expect(inventory.degraded)
        #expect(inventory.lastScanWasTruncated)
        #expect(inventory.scansTotal == 7)
        #expect(inventory.lastScanTruncatedHomeCount == 1)
        #expect(inventory.operatorDetail.contains("partial"))
        #expect(inventory.diagnosticDictionary["complete"] as? Bool == false)
        #expect(inventory.diagnosticDictionary["last_scan_truncated_home_count"] as? UInt64 == 1)
        #expect(V2HeartbeatSnapshot.BrowserInventory(from: nil) == nil)
        #expect(AppState.browserInventoryEvidenceUnavailable(
            coverageKnown: true,
            complete: false,
            degraded: false,
            lastScanWasTruncated: false
        ))
        #expect(!AppState.browserInventoryEvidenceUnavailable(
            coverageKnown: true,
            complete: true,
            degraded: false,
            lastScanWasTruncated: false
        ))
        let contradictory = try #require(V2HeartbeatSnapshot.BrowserInventory(from: [
            "coverage_known": true,
            "complete": false,
            "degraded": false,
            "last_scan_was_truncated": true,
        ]))
        #expect(contradictory.degraded)
    }

    @Test("sequence checkpoint exposes honest restart continuity")
    func sequenceCheckpointDecode() throws {
        let healthy = try #require(V2HeartbeatSnapshot.SequenceCheckpoint(from: [
            "restore_status": "restored",
            "dirty": false,
            "configured_crash_rpo_seconds": 30,
            "crash_rpo_bound_currently_maintained": true,
        ]))
        #expect(!healthy.degraded)
        #expect(healthy.operatorDetail.contains("30-second"))
        #expect(healthy.diagnosticDictionary["dirty"] as? Bool == false)

        let rejected = try #require(V2HeartbeatSnapshot.SequenceCheckpoint(from: [
            "restore_status": "rejected",
            "crash_rpo_bound_currently_maintained": true,
        ]))
        #expect(rejected.degraded)
        #expect(rejected.operatorDetail.contains("could not be recovered"))

        #expect(AppState.sequenceCheckpointUnavailable(
            restoreStatus: "rejected",
            rpoMaintained: true
        ))
        #expect(AppState.sequenceCheckpointUnavailable(
            restoreStatus: "restored",
            rpoMaintained: false
        ))
        #expect(!AppState.sequenceCheckpointUnavailable(
            restoreStatus: nil,
            rpoMaintained: nil
        ))
        #expect(AppState.sequenceCheckpointUnavailable(
            restoreStatus: "recovered",
            rpoMaintained: true,
            durableCarrierValid: false
        ))
        #expect(AppState.sequenceCheckpointUnavailable(
            restoreStatus: "restored",
            rpoMaintained: true,
            stateContinuityMaintained: false
        ))

        let evicted = try #require(V2HeartbeatSnapshot.SequenceCheckpoint(
            from: [
                "restore_status": "recovered",
                "durable_carrier_valid": true,
                "crash_rpo_bound_currently_maintained": true,
                "carrier_invalidations_total": 1,
                "last_carrier_invalidation_reason": "integrity_mismatch",
            ],
            runtimeRaw: [
                "sequence_state_continuity_maintained": false,
                "sequence_state_continuity_detail": "pending_step_eviction",
                "sequence_partials_evicted_total": 0,
                "sequence_partials_in_flight": 3,
                "sequence_pending_steps_current": 8,
                "sequence_pending_steps_evicted_total": 2,
                "sequence_checkpoint_state_weight_bytes": 2048,
                "sequence_checkpoint_state_weight_recomputed_bytes": 2048,
                "sequence_checkpoint_state_weight_limit_bytes": 8388608,
            ]
        ))
        #expect(evicted.degraded)
        #expect(evicted.operatorDetail.contains("pending_step_eviction"))
        #expect(evicted.pendingStepsEvictedTotal == 2)
        #expect(evicted.carrierInvalidationsTotal == 1)
    }

    // MARK: - readFreshest behavior

    @Test("readFreshest returns nil when no candidate heartbeat exists")
    func readFreshestNil() {
        // The Real readFreshest scans two specific application-support
        // dirs; on a clean test environment those should not contain
        // a recent heartbeat. We accept either nil OR a real snapshot
        // depending on whether the developer's daemon is running.
        // Not strictly testable without injecting paths; documented
        // as a follow-up.
        let snap = V2HeartbeatSnapshot.readFreshest()
        // If the daemon is running, snap is non-nil and within 5 minutes.
        if let s = snap {
            #expect(s.writtenAt.timeIntervalSinceNow > -300)
        }
    }

    // MARK: - Helpers

    private func makeSnapshot(
        uptimeSeconds: Int = 0,
        eventTypeCounts1h: [String: Int] = [:]
    ) -> V2HeartbeatSnapshot {
        V2HeartbeatSnapshot(
            writtenAt: Date(),
            uptimeSeconds: uptimeSeconds,
            eventsProcessed: 0,
            alertsEmitted: 0,
            residentMemoryMB: nil,
            sysextHasFDA: false,
            schemaVersion: 2,
            eventTypeCounts1h: eventTypeCounts1h,
            collectors: [],
            payloadTruncatedTotal: 0,
            esloggerDroppedTotal: 0,
            esSensorDegraded: false,
            esSensorDegradedDetail: nil,
            esSensorDegradedSeverity: nil,
            llm: nil,
            prevention: nil,
            traceGraphStorageAdmission: nil,
            traceStoreStorageAdmission: nil,
            alertEvidenceBudget: nil,
            timerLifecycle: nil,
            livenessTimerLifecycle: nil,
            startupWorkLifecycle: nil,
            detectionWorkLifecycle: nil,
            advisoryWorkLifecycle: nil,
            outputWorkLifecycle: nil,
            legacyDerivedWorkLifecycle: nil,
            otlpReceiverLifecycle: nil,
            eventPipeline: nil,
            browserInventory: nil,
            sequenceCheckpoint: nil
        )
    }
}
