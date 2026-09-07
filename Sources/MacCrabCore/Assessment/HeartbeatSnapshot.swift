// HeartbeatSnapshot.swift
// assessment-framework (P0): shared, versioned DTO that decodes the FULL
// schema-5 rich heartbeat written by `MacCrabAgentKit/DaemonTimers.swift`
// (`<support-dir>/heartbeat_rich.json`, `schema_version: 5`).
//
// assessment-framework (P0): before this type the ONLY decoder was
// `V2HeartbeatSnapshot` in the SwiftUI app target, and it omitted the
// drop-attribution gauges (es_kernel_dropped_*, merged_*_dropped_total,
// detection_input_dropped_total, events_storage_write_dropped_total, …).
// A consumer that cannot see those counters can report a green engine while
// detection input is being silently dropped — a false-green the assessment
// framework must make structurally impossible. This Core DTO decodes every
// top-level schema-5 key so the MCP server and the assessment harness read
// the same health the daemon actually reports.
//
// assessment-framework (P0): honesty invariants baked into the type —
//   1. EVERY field is Optional. A key absent from an older-schema heartbeat
//      decodes to `nil` (honest-unknown), NEVER to a default "healthy"/zero.
//   2. Nothing here reads the clock. `ageSeconds(now:)` / `isStale(now:)`
//      take `now` as a parameter so callers are deterministic and testable.
//   3. There is no force-unwrap anywhere in this file.

import Foundation

/// Full schema-5 rich-heartbeat snapshot, decoded from `heartbeat_rich.json`.
///
/// All fields are optional so that a heartbeat written by an older engine
/// (missing newer keys) still decodes — with the missing fields honestly
/// reported as `nil` rather than a fabricated default.
public struct HeartbeatSnapshot: Codable, Sendable, Equatable {
    // MARK: Identity / liveness
    public let schemaVersion: Int?
    /// Unix seconds the heartbeat was written. Written as a `Double`
    /// (`Date().timeIntervalSince1970`) by the daemon — decoded as `Double`.
    public let writtenAtUnix: Double?
    public let uptimeSeconds: Int?
    /// Stable process-epoch identity copied into each heartbeat. Consumers must
    /// not compute cumulative-counter deltas across a change in any epoch field.
    public let enginePID: Int?
    public let engineStartedAtUnix: Double?
    public let engineVersion: String?
    public let engineBuild: String?
    /// Build channel of the RUNNING engine: `"release"`, `"dev"`, or
    /// `"unknown"` when the executing bundle predates the marker. `nil` when
    /// the heartbeat itself predates this field.
    ///
    /// Deliberately never defaulted to `"release"` at either end. A consumer
    /// deciding whether a host's measurements count as production evidence
    /// must be able to tell "this is a shipped build" apart from "I could not
    /// determine what this is" — collapsing those is how a dev candidate's
    /// numbers get quoted as if they came from the shipped product.
    public let buildChannel: String?

    // MARK: Throughput counters
    public let alertsEmitted: Int?
    public let eventsProcessed: Int?
    /// Every known detection-input loss plus non-pipeline CollectorRegistry
    /// loss. Storage-writer drops remain separate because detection completed.
    public let eventsDropped: Int?

    // MARK: Rule coverage
    public let rulesLoaded: Int?
    public let rulesActive: Int?
    /// Immutable boot-time observation from the signed bundled-rule
    /// synchronizer. Missing means the running engine predates this evidence.
    public let ruleSync: RuleSync?
    /// Immutable pre-producer rc.12 -> rc.13 journal migration result.
    public let eventJournalRecovery: EventJournalRecovery?
    /// Current sparse-search projection coverage for the heartbeat's one-hour
    /// observation window. An unavailable query is never represented as zero.
    public let eventSearchProjection: EventSearchProjection?

    // MARK: Nested health blocks
    public let collectorHealth: [CollectorHealth]?
    public let llm: LLMHealth?
    /// Joinable dispatch-timer task plane. Missing on older engines means
    /// lifecycle accounting is unknown, not zero work.
    public let timerLifecycle: TimerLifecycle?
    /// The dedicated liveness writer is isolated from slower maintenance
    /// timers so a blocked sweep cannot hide that the process is alive.
    public let livenessTimerLifecycle: TimerLifecycle?
    /// One-shot boot hydration and long-lived startup workers.
    public let startupWorkLifecycle: TimerLifecycle?
    /// Security decisions spawned by the event loop. Rejection or an unclean
    /// close here is a protection gap, unlike shedding in advisory/output
    /// planes where deterministic detection has already completed.
    public let detectionWorkLifecycle: TimerLifecycle?
    /// Optional model-backed analysis. Loss is feature degradation, not loss of
    /// the deterministic detector that produced the underlying alert/event.
    public let advisoryWorkLifecycle: TimerLifecycle?
    /// Notification and external-output fan-out. Loss means delivery may be
    /// incomplete while alert detection and local persistence continue.
    public let outputWorkLifecycle: TimerLifecycle?
    /// Compatibility only for pre-split engines. New lanes are never filled
    /// from this aggregate because doing so would hide which class lost work.
    public let legacyDerivedWorkLifecycle: TimerLifecycle?
    /// Exact listener/connection/callback/body-task ownership for the loopback
    /// OTLP receiver.
    /// OTLP data is unauthenticated/self-reported advisory evidence; lifecycle
    /// failure must remain visible without being called kernel protection loss.
    public let otlpReceiverLifecycle: OTLPReceiverLifecycle?
    public let prevention: Prevention?
    public let traceRegistry: TraceRegistry?
    public let traceGraphStorageAdmission: TraceGraphStorageAdmission?
    /// OTLP `traces.db` admission. Separate from TraceGraph: this store holds
    /// unauthenticated/self-reported spans, and a block means those advisory
    /// records are being shed while kernel detection continues.
    public let traceStoreStorageAdmission: TraceStoreStorageAdmission?
    /// Causality counters around the bounded collector and merged-stream
    /// stages. Missing on pre-instrumentation engines means unknown, not zero.
    public let eventPipeline: EventPipeline?
    /// Completeness of the privileged, bounded browser-extension inventory.
    /// Missing on older engines means unknown. A present degraded block means
    /// returned rows are partial and must not be interpreted as a clean census.
    public let browserInventory: BrowserInventory?
    /// Sticky post-sweep events.db budget truth. A degraded value cannot clear
    /// merely because a later sampling tick catches a transient size dip.
    public let eventsRetentionBudget: EventsRetentionBudget?
    /// Evidence ownership and the effective post-split event/alert SQLite
    /// family caps. Missing on engines predating schema-v8 evidence ownership.
    public let alertEvidenceBudget: AlertEvidenceBudget?
    /// Durable continuity for in-flight multi-event sequence detections.
    /// Missing means the running engine predates checkpoint integration; a
    /// present dirty/degraded block must never be rendered as restart-safe.
    public let sequenceCheckpoint: SequenceCheckpoint?
    /// Exact producer-owned accounting for the bounded pending-step journal.
    /// Missing on older engines means unknown, never an inferred zero.
    public let sequenceJournalConservation: SequenceConservationTelemetry?
    /// Per-rule attribution for the same exact ledger. Keys are trusted rule
    /// IDs, not event-derived labels. Missing means the producer predates it.
    public let sequenceJournalConservationByRule: [String: SequenceConservationTelemetry]?
    /// Live temporal-correlation state. Eviction or accounting drift is a
    /// detection-continuity loss even if the checkpoint carrier itself is
    /// current and writable.
    public let sequencePartialsEvictedTotal: Int?
    public let sequencePartialsInFlight: Int?
    public let sequencePendingStepsCurrent: Int?
    public let sequencePendingStepsEvictedTotal: Int?
    public let sequenceCheckpointStateWeightBytes: Int?
    public let sequenceCheckpointStateWeightRecomputedBytes: Int?
    public let sequenceCheckpointStateWeightLimitBytes: Int?
    public let sequenceStateContinuityMaintained: Bool?
    public let sequenceStateContinuityDetail: String?

    // MARK: Drop attribution (the gauges the app decoder omitted)
    /// Native ES per-client kernel ingest-drops. Distinct from `eventsDropped`
    /// (userspace AsyncStream eviction) — the kernel/userspace split is the
    /// whole point of the drop-attribution methodology.
    public let esKernelDroppedTotal: Int?
    public let esKernelDroppedByType: [String: Int]?
    public let esProcessedByType: [String: Int]?
    public let esIntentionallyFilteredBeforeWorkerByType: [String: Int]?
    public let esNormalizedYieldedByType: [String: Int]?
    public let esCopyBackpressureDroppedTotal: Int?
    public let esStreamYieldDroppedTotal: Int?
    public let esloggerDroppedTotal: Int?
    /// Merged priority-stream detection-input drops (lost exec/process events).
    public let mergedPriorityDroppedTotal: Int?
    /// Merged file-stream detection-input drops (file-noise flood).
    public let mergedFileDroppedTotal: Int?
    public let mergedPriorityTerminatedTotal: Int?
    public let mergedFileTerminatedTotal: Int?
    /// Aggregate pre-buffer, collector-buffer and merged-buffer input loss.
    /// A subset of `eventsDropped`, which also includes registry-only losses.
    public let detectionInputDroppedTotal: Int?
    /// Batched-writer storage-layer drop — a storage loss, NOT a detection gap.
    public let eventsStorageWriteDroppedTotal: Int?
    /// Exact storage hand-off/result ledgers keyed by the fixed `priority` and
    /// `file` lanes. For each lane and one process epoch:
    /// offered = persisted + filtered + dropped + buffer + in-flight.
    public let eventsStorageWriteOfferedByLane: [String: Int]?
    public let eventsStorageWriteDroppedByLane: [String: Int]?
    /// Rows reported committed at write time. Historical commits are not
    /// subtracted if a later corruption recovery replaces the active database.
    public let eventsStorageWritePersistedTotal: Int?
    public let eventsStorageWritePersistedByLane: [String: Int]?
    public let eventsStorageWriteFilteredTotal: Int?
    public let eventsStorageWriteFilteredByLane: [String: Int]?
    /// Retry attempts, not unique rows; one row may be counted more than once.
    public let eventsStorageWriteRetriedTotal: Int?
    public let eventsStorageWriteRetriedByLane: [String: Int]?
    /// Rows queued in the writer actor, excluding a batch currently inside the
    /// asynchronous database insert call.
    public let eventsStorageWriteBufferDepth: Int?
    public let eventsStorageWriteBufferDepthByLane: [String: Int]?
    /// Rows detached from the writer queue and currently inside the asynchronous
    /// database insert call. `buffer + inFlight` is the complete outstanding
    /// writer backlog for one process epoch.
    public let eventsStorageWriteInFlightDepth: Int?
    public let eventsStorageWriteInFlightDepthByLane: [String: Int]?
    /// EventStore policy-filter decisions across both batch and direct inserts.
    /// Passing rows may be evaluated again after a writer retry, so these are
    /// decision counts rather than unique-event counts.
    public let eventsInsertFilterDroppedTotal: Int?
    public let eventsInsertFilterPassedTotal: Int?
    public let payloadTruncatedTotal: Int?

    // MARK: Storage-error accounting
    public let eventInsertErrorsTotal: Int?
    /// Written by the daemon as an integer (`ratePerMin: Int`), not a rate float.
    public let eventInsertErrorRatePerMin: Int?
    /// The daemon writes `""` (not JSON null) when no insert error since boot.
    public let lastEventInsertErrorKind: String?

    // MARK: Sensor-degraded advisory
    public let esSensorDegraded: Bool?
    public let esSensorDegradedDetail: String?
    public let esSensorDegradedSeverity: String?
    public let esClientSplitDegraded: Bool?

    // MARK: Self-defense
    /// Invalid ENC2 envelopes / AES-GCM authentication failures — non-zero
    /// means encrypted database corruption or tamper.
    public let dbTamperDecryptFailures: Int?

    // MARK: Full Disk Access probe
    public let fdaCheckedAtUnix: Double?
    public let sysextHasFDA: Bool?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case writtenAtUnix = "written_at_unix"
        case uptimeSeconds = "uptime_seconds"
        case enginePID = "engine_pid"
        case engineStartedAtUnix = "engine_started_at_unix"
        case engineVersion = "engine_version"
        case engineBuild = "engine_build"
        case buildChannel = "build_channel"
        case alertsEmitted = "alerts_emitted"
        case eventsProcessed = "events_processed"
        case eventsDropped = "events_dropped"
        case rulesLoaded = "rules_loaded"
        case rulesActive = "rules_active"
        case ruleSync = "rule_sync"
        case eventJournalRecovery = "event_journal_recovery"
        case eventSearchProjection = "event_search_projection"
        case collectorHealth = "collector_health"
        case llm
        case timerLifecycle = "timer_lifecycle"
        case livenessTimerLifecycle = "liveness_timer_lifecycle"
        case startupWorkLifecycle = "startup_work_lifecycle"
        case detectionWorkLifecycle = "detection_work_lifecycle"
        case advisoryWorkLifecycle = "advisory_work_lifecycle"
        case outputWorkLifecycle = "output_work_lifecycle"
        case legacyDerivedWorkLifecycle = "derived_work_lifecycle"
        case otlpReceiverLifecycle = "otlp_receiver_lifecycle"
        case prevention
        case traceRegistry = "trace_registry"
        case traceGraphStorageAdmission = "tracegraph_storage_admission"
        case traceStoreStorageAdmission = "traces_storage_admission"
        case eventPipeline = "event_pipeline"
        case browserInventory = "browser_inventory"
        case eventsRetentionBudget = "events_retention_budget"
        case alertEvidenceBudget = "alert_evidence_budget"
        case sequenceCheckpoint = "sequence_checkpoint"
        case sequenceJournalConservation = "sequence_journal_conservation"
        case sequenceJournalConservationByRule = "sequence_journal_conservation_by_rule"
        case sequencePartialsEvictedTotal = "sequence_partials_evicted_total"
        case sequencePartialsInFlight = "sequence_partials_in_flight"
        case sequencePendingStepsCurrent = "sequence_pending_steps_current"
        case sequencePendingStepsEvictedTotal = "sequence_pending_steps_evicted_total"
        case sequenceCheckpointStateWeightBytes = "sequence_checkpoint_state_weight_bytes"
        case sequenceCheckpointStateWeightRecomputedBytes = "sequence_checkpoint_state_weight_recomputed_bytes"
        case sequenceCheckpointStateWeightLimitBytes = "sequence_checkpoint_state_weight_limit_bytes"
        case sequenceStateContinuityMaintained = "sequence_state_continuity_maintained"
        case sequenceStateContinuityDetail = "sequence_state_continuity_detail"
        case esKernelDroppedTotal = "es_kernel_dropped_total"
        case esKernelDroppedByType = "es_kernel_dropped_by_type"
        case esProcessedByType = "es_processed_by_type"
        case esIntentionallyFilteredBeforeWorkerByType = "es_intentionally_filtered_before_worker_by_type"
        case esNormalizedYieldedByType = "es_normalized_yielded_by_type"
        case esCopyBackpressureDroppedTotal = "es_copy_backpressure_dropped_total"
        case esStreamYieldDroppedTotal = "es_stream_yield_dropped_total"
        case esloggerDroppedTotal = "eslogger_dropped_total"
        case mergedPriorityDroppedTotal = "merged_priority_dropped_total"
        case mergedFileDroppedTotal = "merged_file_dropped_total"
        case mergedPriorityTerminatedTotal = "merged_priority_terminated_total"
        case mergedFileTerminatedTotal = "merged_file_terminated_total"
        case detectionInputDroppedTotal = "detection_input_dropped_total"
        case eventsStorageWriteDroppedTotal = "events_storage_write_dropped_total"
        case eventsStorageWriteOfferedByLane = "events_storage_write_offered_by_lane"
        case eventsStorageWriteDroppedByLane = "events_storage_write_dropped_by_lane"
        case eventsStorageWritePersistedTotal = "events_storage_write_persisted_total"
        case eventsStorageWritePersistedByLane = "events_storage_write_persisted_by_lane"
        case eventsStorageWriteFilteredTotal = "events_storage_write_filtered_total"
        case eventsStorageWriteFilteredByLane = "events_storage_write_filtered_by_lane"
        case eventsStorageWriteRetriedTotal = "events_storage_write_retried_total"
        case eventsStorageWriteRetriedByLane = "events_storage_write_retried_by_lane"
        case eventsStorageWriteBufferDepth = "events_storage_write_buffer_depth"
        case eventsStorageWriteBufferDepthByLane = "events_storage_write_buffer_depth_by_lane"
        case eventsStorageWriteInFlightDepth = "events_storage_write_in_flight_depth"
        case eventsStorageWriteInFlightDepthByLane = "events_storage_write_in_flight_depth_by_lane"
        case eventsInsertFilterDroppedTotal = "events_insert_filter_dropped_total"
        case eventsInsertFilterPassedTotal = "events_insert_filter_passed_total"
        case payloadTruncatedTotal = "payload_truncated_total"
        case eventInsertErrorsTotal = "event_insert_errors_total"
        case eventInsertErrorRatePerMin = "event_insert_error_rate_per_min"
        case lastEventInsertErrorKind = "last_event_insert_error_kind"
        case esSensorDegraded = "es_sensor_degraded"
        case esSensorDegradedDetail = "es_sensor_degraded_detail"
        case esSensorDegradedSeverity = "es_sensor_degraded_severity"
        case esClientSplitDegraded = "es_client_split_degraded"
        case dbTamperDecryptFailures = "db_tamper_decrypt_failures"
        case fdaCheckedAtUnix = "fda_checked_at_unix"
        case sysextHasFDA = "sysext_has_fda"
    }

    // MARK: - Nested blocks

    public struct RuleSync: Codable, Sendable, Equatable {
        public let status: String?
        public let version: String?
        public let reason: String?
        public let bundledTampered: Bool?
        public let installedTampered: Bool?
        public let installedCorpusVerified: Bool?
        public let installedManifestSHA256: String?
        public let installedManifestHashEntryCount: Int?

        private enum CodingKeys: String, CodingKey {
            case status
            case version
            case reason
            case bundledTampered = "bundled_tampered"
            case installedTampered = "installed_tampered"
            case installedCorpusVerified = "installed_corpus_verified"
            case installedManifestSHA256 = "installed_manifest_sha256"
            case installedManifestHashEntryCount =
                "installed_manifest_hash_entry_count"
        }
    }

    public struct EventJournalRecovery: Codable, Sendable, Equatable {
        public let sourceEvents: Int?
        public let migratedEvents: Int?
        public let rolledExpiredEvents: Int?
        public let corruptPreservedEvents: Int?
        public let remainingEvents: Int?
        public let complete: Bool?
        public let conserved: Bool?

        private enum CodingKeys: String, CodingKey {
            case sourceEvents = "source_events"
            case migratedEvents = "migrated_events"
            case rolledExpiredEvents = "rolled_expired_events"
            case corruptPreservedEvents = "corrupt_preserved_events"
            case remainingEvents = "remaining_events"
            case complete
            case conserved
        }
    }

    public struct EventSearchProjection: Codable, Sendable, Equatable {
        public let queryAvailable: Bool?
        public let mutationGeneration: UInt64?
        public let requestedDurationSeconds: Int?
        public let effectiveDurationSeconds: Int?
        public let requestedWindowComplete: Bool?
        public let projectionConsidered: Int?
        public let projectionMaterialized: Int?
        public let projectionOmittedQuota: Int?
        public let projectionOmittedReplaced: Int?
        public let projectionOmittedPhysical: Int?
        public let projectionOmittedExternal: Int?
        public let projectionOmittedMigration: Int?
        public let projectionPending: Int?
        public let projectionOmittedTotal: Int?
        public let canonicalPoisonRecords: Int?
        public let corruptLegacyRecords: Int?
        public let inheritedLegacyLossRecords: Int?
        public let resourceLimitedRecords: Int?
        public let gapRecordsTotal: Int?
        public let complete: Bool?

        private enum CodingKeys: String, CodingKey {
            case queryAvailable = "query_available"
            case mutationGeneration = "mutation_generation"
            case requestedDurationSeconds = "requested_duration_seconds"
            case effectiveDurationSeconds = "effective_duration_seconds"
            case requestedWindowComplete = "requested_window_complete"
            case projectionConsidered = "projection_considered"
            case projectionMaterialized = "projection_materialized"
            case projectionOmittedQuota = "projection_omitted_quota"
            case projectionOmittedReplaced = "projection_omitted_replaced"
            case projectionOmittedPhysical = "projection_omitted_physical"
            case projectionOmittedExternal = "projection_omitted_external"
            case projectionOmittedMigration = "projection_omitted_migration"
            case projectionPending = "projection_pending"
            case projectionOmittedTotal = "projection_omitted_total"
            case canonicalPoisonRecords = "canonical_poison_records"
            case corruptLegacyRecords = "corrupt_legacy_records"
            case inheritedLegacyLossRecords = "inherited_legacy_loss_records"
            case resourceLimitedRecords = "resource_limited_records"
            case gapRecordsTotal = "gap_records_total"
            case complete
        }
    }

    /// Per-collector liveness (the `collector_health` array). Mirrors the
    /// shape `V2HeartbeatSnapshot.Collector` reads; `expected_interval_seconds`
    /// is written by the daemon but intentionally not modelled here.
    public struct CollectorHealth: Codable, Sendable, Equatable, Hashable {
        public let name: String
        public let healthy: Bool
        /// `last_tick_unix` — nil when the collector has never ticked. The
        /// daemon OMITS the key in that case, so it stays honestly nil rather
        /// than decoding to epoch-0.
        public let lastTick: Double?
        public let eventCount: Int?
        public let errorCount: Int?
        public let lastError: String?
        /// v1.21.6-rc.45: why the collector is in this state, in operator
        /// words. Optional so older heartbeats still decode.
        public let reason: String?

        private enum CodingKeys: String, CodingKey {
            case name
            case healthy
            case reason
            case lastTick = "last_tick_unix"
            case eventCount = "event_count"
            case errorCount = "error_count"
            case lastError = "last_error"
        }
    }

    /// Fixed-cardinality event-flow telemetry. Maps are keyed only by the
    /// daemon's compile-time source/lane names.
    public struct EventPipeline: Codable, Sendable, Equatable {
        public let offeredBySource: [String: UInt64]?
        public let offeredBySourceAndLane: [String: [String: UInt64]]?
        public let droppedBySourceAndLane: [String: [String: UInt64]]?
        public let terminatedBySourceAndLane: [String: [String: UInt64]]?
        public let collectorOfferedBySourceAndLane: [String: [String: UInt64]]?
        public let upstreamDroppedBySourceAndLane: [String: [String: UInt64]]?
        public let upstreamTerminatedBySourceAndLane: [String: [String: UInt64]]?
        public let mergedDroppedBySourceAndLane: [String: [String: UInt64]]?
        public let mergedTerminatedBySourceAndLane: [String: [String: UInt64]]?
        public let offeredByLane: [String: UInt64]?
        public let dequeuedByLane: [String: UInt64]?
        public let ruleEvaluationReachedByLaneAndCategory: [String: [String: UInt64]]?
        public let ruleEvaluationCompletedByLaneAndCategory: [String: [String: UInt64]]?
        public let completedByLane: [String: UInt64]?
        public let backlogEstimateByLane: [String: UInt64]?
        public let inFlightByLane: [String: UInt64]?
        public let processingP99MicrosByLane: [String: UInt64]?
        public let latencySampleCountByLane: [String: UInt64]?
        public let upstreamDroppedByLane: [String: UInt64]?
        public let upstreamTerminatedByLane: [String: UInt64]?
        public let mergedDroppedByLane: [String: UInt64]?
        public let mergedTerminatedByLane: [String: UInt64]?
        public let collectorCapacityBySource: [String: UInt64]?
        public let preBufferDroppedBySource: [String: UInt64]?
        public let detectionInputDroppedTotal: UInt64?
        public let capacityByLane: [String: UInt64]?
        public let collectorBuffer: [String: UInt64]?

        private enum CodingKeys: String, CodingKey {
            case offeredBySource = "offered_by_source"
            case offeredBySourceAndLane = "offered_by_source_and_lane"
            case droppedBySourceAndLane = "dropped_by_source_and_lane"
            case terminatedBySourceAndLane = "terminated_by_source_and_lane"
            case collectorOfferedBySourceAndLane = "collector_offered_by_source_and_lane"
            case upstreamDroppedBySourceAndLane = "upstream_dropped_by_source_and_lane"
            case upstreamTerminatedBySourceAndLane = "upstream_terminated_by_source_and_lane"
            case mergedDroppedBySourceAndLane = "merged_dropped_by_source_and_lane"
            case mergedTerminatedBySourceAndLane = "merged_terminated_by_source_and_lane"
            case offeredByLane = "offered_by_lane"
            case dequeuedByLane = "dequeued_by_lane"
            case ruleEvaluationReachedByLaneAndCategory = "rule_evaluation_reached_by_lane_and_category"
            case ruleEvaluationCompletedByLaneAndCategory = "rule_evaluation_completed_by_lane_and_category"
            case completedByLane = "completed_by_lane"
            case backlogEstimateByLane = "backlog_estimate_by_lane"
            case inFlightByLane = "in_flight_by_lane"
            case processingP99MicrosByLane = "processing_p99_us_by_lane"
            case latencySampleCountByLane = "latency_sample_count_by_lane"
            case upstreamDroppedByLane = "upstream_dropped_by_lane"
            case upstreamTerminatedByLane = "upstream_terminated_by_lane"
            case mergedDroppedByLane = "merged_dropped_by_lane"
            case mergedTerminatedByLane = "merged_terminated_by_lane"
            case collectorCapacityBySource = "collector_capacity_by_source"
            case preBufferDroppedBySource = "pre_buffer_dropped_by_source"
            case detectionInputDroppedTotal = "detection_input_dropped_total"
            case capacityByLane = "capacity_by_lane"
            case collectorBuffer = "collector_buffer"
        }
    }

    public struct BrowserInventory: Codable, Sendable, Equatable {
        public let coverageKnown: Bool?
        public let complete: Bool?
        public let degraded: Bool?
        public let reason: String?
        public let lastScanWasTruncated: Bool?
        public let scansTotal: UInt64?
        public let truncatedScansTotal: UInt64?
        public let inspectedDirectoryEntriesTotal: UInt64?
        public let truncatedDirectoriesTotal: UInt64?
        public let truncatedHomesTotal: UInt64?
        public let lastScanCompletedAtUnix: Double?
        public let lastScanHomes: Int?
        public let lastScanInspectedDirectoryEntries: UInt64?
        public let lastScanTruncatedDirectoryCount: UInt64?
        public let lastScanTruncatedHomeCount: UInt64?
        public let perHomeDirectoryEntryBudget: Int?

        private enum CodingKeys: String, CodingKey {
            case coverageKnown = "coverage_known"
            case complete
            case degraded
            case reason
            case lastScanWasTruncated = "last_scan_was_truncated"
            case scansTotal = "scans_total"
            case truncatedScansTotal = "truncated_scans_total"
            case inspectedDirectoryEntriesTotal = "inspected_directory_entries_total"
            case truncatedDirectoriesTotal = "truncated_directories_total"
            case truncatedHomesTotal = "truncated_homes_total"
            case lastScanCompletedAtUnix = "last_scan_completed_at_unix"
            case lastScanHomes = "last_scan_homes"
            case lastScanInspectedDirectoryEntries = "last_scan_inspected_directory_entries"
            case lastScanTruncatedDirectoryCount = "last_scan_truncated_directory_count"
            case lastScanTruncatedHomeCount = "last_scan_truncated_home_count"
            case perHomeDirectoryEntryBudget = "per_home_directory_entry_budget"
        }
    }

    public struct EventsRetentionBudget: Codable, Sendable, Equatable {
        public let state: String?
        public let reason: String?
        public let sticky: Bool?
        public let forensicFloorMinutes: Int?
        public let observedFootprintBytes: Int64?
        public let targetBytes: Int64?
        public let proactiveBoundaryBytes: Int64?
        public let nominalCapBytes: Int64?
        public let evaluatedAtUnix: Double?

        private enum CodingKeys: String, CodingKey {
            case state
            case reason
            case sticky
            case forensicFloorMinutes = "forensic_floor_minutes"
            case observedFootprintBytes = "observed_footprint_bytes"
            case targetBytes = "target_bytes"
            case proactiveBoundaryBytes = "proactive_boundary_bytes"
            case nominalCapBytes = "nominal_cap_bytes"
            case evaluatedAtUnix = "evaluated_at_unix"
        }
    }

    public struct AlertEvidenceBudget: Codable, Sendable, Equatable {
        public let eventsFamilyEffectiveCapBytes: Int64?
        public let eventsFamilySteadyStateCapBytes: Int64?
        public let eventsLegacyEnvelopeBytes: Int64?
        public let alertRowsMaxBytes: Int64?
        public let evidenceMaxBytes: Int64?
        public let alertsFamilyCombinedCapBytes: Int64?
        public let eventsAndAlertsTotalCapBytes: Int64?
        public let eventsAndAlertsSteadyStateTotalCapBytes: Int64?
        public let legacyTransitionReserveBytes: Int64?
        public let legacyTransitionMaxBytes: Int64?
        public let legacyTransitionMeasurementFailed: Bool?
        public let legacyRowCount: Int?
        public let legacyChargedBytes: Int64?
        public let rowCount: Int?
        public let logicalBytes: Int64?
        public let allocatedBytes: Int64?
        public let chargedBytes: Int64?
        public let overBudget: Bool?
        public let captureRowsTotal: Int?
        public let capturePrunedRowsTotal: Int?
        public let captureOfferedTotal: Int?
        public let captureCompletedTotal: Int?
        public let captureFailuresTotal: Int?
        public let captureShedTotal: Int?
        public let capturePending: Int?
        public let captureInFlight: Int?
        public let captureQueueCapacity: Int?
        public let captureAccepting: Bool?
        public let captureConserved: Bool?
        public let allocatedBytesExact: Bool?
        public let mutationGeneration: UInt64?
        public let fullRefreshesTotal: UInt64?
        public let alertsFamilyFootprintBytes: Int64?
        public let alertsFamilyAdmissionCapBytes: Int64?
        public let alertsFamilyTransactionReserveBytes: Int64?
        public let alertsFamilyAdmissionBoundaryBytes: Int64?
        public let alertsFamilyRecoveryTargetBytes: Int64?
        public let alertsFamilyBlocked: Bool?
        public let alertsFamilyReason: String?

        private enum CodingKeys: String, CodingKey {
            case eventsFamilyEffectiveCapBytes = "events_family_effective_cap_bytes"
            case eventsFamilySteadyStateCapBytes = "events_family_steady_state_cap_bytes"
            case eventsLegacyEnvelopeBytes = "events_legacy_envelope_bytes"
            case alertRowsMaxBytes = "alert_rows_max_bytes"
            case evidenceMaxBytes = "evidence_max_bytes"
            case alertsFamilyCombinedCapBytes = "alerts_family_combined_cap_bytes"
            case eventsAndAlertsTotalCapBytes = "events_and_alerts_total_cap_bytes"
            case eventsAndAlertsSteadyStateTotalCapBytes = "events_and_alerts_steady_state_total_cap_bytes"
            case legacyTransitionReserveBytes = "legacy_transition_reserve_bytes"
            case legacyTransitionMaxBytes = "legacy_transition_max_bytes"
            case legacyTransitionMeasurementFailed = "legacy_transition_measurement_failed"
            case legacyRowCount = "legacy_row_count"
            case legacyChargedBytes = "legacy_charged_bytes"
            case rowCount = "row_count"
            case logicalBytes = "logical_bytes"
            case allocatedBytes = "allocated_bytes"
            case chargedBytes = "charged_bytes"
            case overBudget = "over_budget"
            case captureRowsTotal = "capture_rows_total"
            case capturePrunedRowsTotal = "capture_pruned_rows_total"
            case captureOfferedTotal = "capture_offered_total"
            case captureCompletedTotal = "capture_completed_total"
            case captureFailuresTotal = "capture_failures_total"
            case captureShedTotal = "capture_shed_total"
            case capturePending = "capture_pending"
            case captureInFlight = "capture_in_flight"
            case captureQueueCapacity = "capture_queue_capacity"
            case captureAccepting = "capture_accepting"
            case captureConserved = "capture_conserved"
            case allocatedBytesExact = "allocated_bytes_exact"
            case mutationGeneration = "mutation_generation"
            case fullRefreshesTotal = "full_refreshes_total"
            case alertsFamilyFootprintBytes = "alerts_family_footprint_bytes"
            case alertsFamilyAdmissionCapBytes = "alerts_family_admission_cap_bytes"
            case alertsFamilyTransactionReserveBytes = "alerts_family_transaction_reserve_bytes"
            case alertsFamilyAdmissionBoundaryBytes = "alerts_family_admission_boundary_bytes"
            case alertsFamilyRecoveryTargetBytes = "alerts_family_recovery_target_bytes"
            case alertsFamilyBlocked = "alerts_family_blocked"
            case alertsFamilyReason = "alerts_family_reason"
        }

        /// A single in-flight post-commit capture is normal. Failures, shedding,
        /// accounting drift, or pending work observed on a slow heartbeat are
        /// fail-visible; repeated pending snapshots prove a stuck worker.
        public var captureTelemetryPresent: Bool {
            [
                captureOfferedTotal,
                captureCompletedTotal,
                captureFailuresTotal,
                captureShedTotal,
                capturePending,
                captureInFlight,
                captureQueueCapacity,
            ].contains { $0 != nil }
                || captureAccepting != nil
                || captureConserved != nil
        }

        /// Recompute the producer's exact equation instead of trusting its
        /// boolean in isolation:
        ///
        /// offered = completed + failures + shed + pending + in-flight.
        ///
        /// Once any capture telemetry is present, a partial block is unknown
        /// rather than healthy. A completely absent block remains compatible
        /// with older engines that predate this worker ledger.
        public var captureConservationMaintained: Bool? {
            guard captureTelemetryPresent,
                  let offered = captureOfferedTotal,
                  let completed = captureCompletedTotal,
                  let failures = captureFailuresTotal,
                  let shed = captureShedTotal,
                  let pending = capturePending,
                  let inFlight = captureInFlight,
                  let capacity = captureQueueCapacity,
                  captureAccepting != nil,
                  let producerVerdict = captureConserved,
                  [offered, completed, failures, shed, pending, inFlight].allSatisfy({ $0 >= 0 }),
                  capacity > 0,
                  let terminalAndOutstanding = Self.safeSum(
                      [completed, failures, shed, pending, inFlight]
                  ) else { return nil }
            return producerVerdict && offered == terminalAndOutstanding
        }

        public var captureDegraded: Bool {
            guard captureTelemetryPresent else { return false }
            return captureConservationMaintained != true
                || (captureFailuresTotal ?? 0) > 0
                || (captureShedTotal ?? 0) > 0
                || (capturePending ?? 0) > 0
        }

        public var transitionDegraded: Bool {
            legacyTransitionMeasurementFailed == true
        }

        private static func safeSum(_ values: [Int]) -> Int? {
            var total = 0
            for value in values {
                let (next, overflow) = total.addingReportingOverflow(value)
                guard !overflow else { return nil }
                total = next
            }
            return total
        }
    }

    /// Engine-side LLM health (the `llm` block). When the engine has no LLM
    /// backend the daemon writes only `{"configured": false}`, so every other
    /// field is honestly absent (nil) — never a fabricated "healthy".
    public struct LLMHealth: Codable, Sendable, Equatable {
        public let configured: Bool?
        public let provider: String?
        public let model: String?
        public let lastSuccessUnix: Double?
        public let consecutiveFailures: Int?
        public let circuitOpen: Bool?
        public let healthy: Bool?
        /// Fixed-cardinality process-lifetime accounting. nil on older engines
        /// or when the backend is not configured.
        public let runtimeTelemetry: LLMRuntimeTelemetrySnapshot?
        /// The daemon could not encode the typed content-free ledger. A present
        /// true value is an observability failure, not permission to infer zero
        /// requests or healthy accounting.
        public let runtimeTelemetryEncodingFailed: Bool?

        private enum CodingKeys: String, CodingKey {
            case configured
            case provider
            case model
            case lastSuccessUnix = "last_success_unix"
            case consecutiveFailures = "consecutive_failures"
            case circuitOpen = "circuit_open"
            case healthy
            case runtimeTelemetry = "runtime_telemetry"
            case runtimeTelemetryEncodingFailed = "runtime_telemetry_encoding_failed"
        }

        /// All three exact runtime ledgers must conserve globally and for every
        /// fixed feature. `nil` keeps older heartbeats honestly unknown.
        public var runtimeConservationMaintained: Bool? {
            guard let telemetry = runtimeTelemetry else {
                return runtimeTelemetryEncodingFailed == true ? false : nil
            }
            let expectedFeatures = Set(LLMRuntimeFeature.allCases)
            let observedFeatures = telemetry.perFeature.map(\.feature)
            guard observedFeatures.count == expectedFeatures.count,
                  Set(observedFeatures) == expectedFeatures,
                  Self.featureTotalsMatch(telemetry),
                  Self.alertInvestigationReasonsConserve(telemetry) else {
                return false
            }
            let counters = [telemetry.totals] + telemetry.perFeature.map(\.counters)
            return counters.allSatisfy(Self.countersConserve)
        }

        /// Schema-1 heartbeats predate reason attribution and remain honestly
        /// decodable. A schema-2 producer must emit the exhaustive reason set,
        /// and every retry/final alert-investigation rejection must have exactly
        /// one fixed content-free reason.
        private static func alertInvestigationReasonsConserve(
            _ telemetry: LLMRuntimeTelemetrySnapshot
        ) -> Bool {
            guard let reasons = telemetry.alertInvestigationRejections else {
                return telemetry.schemaVersion == 1
            }
            guard reasons.conservationMaintained,
                  let investigation = telemetry.counters(for: .alertInvestigation)?
                    .downstreamValidation else {
                return false
            }
            let (expectedObserved, overflow) = investigation.retryRequested
                .addingReportingOverflow(reasons.terminalRejectionsTotal)
            return !overflow
                && reasons.observedAttemptsTotal == expectedObserved
                && reasons.terminalRejectionsTotal == investigation.finalRejection
        }

        /// Requests that reached the public API without a fixed feature label.
        /// Non-zero means the product cannot yet attribute AI cost/reliability
        /// to the feature that caused it; this is intentionally not hidden in an
        /// "other" bucket.
        public var unspecifiedRequestsTotal: UInt64? {
            runtimeTelemetry?.counters(for: .unspecified)?.requestedTotal
        }

        /// A configured runtime is degraded when its telemetry cannot be
        /// encoded, any conservation equation drifts, or calls escape feature
        /// attribution. Semantic rejection counts remain visible separately:
        /// fail-closed rejection is a feature-quality signal, not ledger drift.
        public var runtimeTelemetryDegraded: Bool {
            runtimeTelemetryEncodingFailed == true
                || runtimeConservationMaintained == false
                || (unspecifiedRequestsTotal ?? 0) > 0
        }

        /// Cross-check the aggregate ledger against the exhaustive fixed
        /// feature ledgers. Per-ledger equations can each conserve while a
        /// missed feature update still makes their aggregate disagree.
        private static func featureTotalsMatch(
            _ telemetry: LLMRuntimeTelemetrySnapshot
        ) -> Bool {
            let features = telemetry.perFeature.map(\.counters)
            let totals = telemetry.totals
            func sum(_ values: [UInt64]) -> UInt64? {
                var result: UInt64 = 0
                for value in values {
                    let (next, overflow) = result.addingReportingOverflow(value)
                    guard !overflow else { return nil }
                    result = next
                }
                return result
            }
            func sum(_ values: [Int]) -> Int? {
                var result = 0
                for value in values {
                    let (next, overflow) = result.addingReportingOverflow(value)
                    guard !overflow else { return nil }
                    result = next
                }
                return result
            }
            return sum(features.map(\.requestedTotal)) == totals.requestedTotal
                && sum(features.map(\.currentInFlight)) == totals.currentInFlight
                && sum(features.map(\.admittedBackendTotal)) == totals.admittedBackendTotal
                && sum(features.map(\.currentAdmittedBackendRequests))
                    == totals.currentAdmittedBackendRequests
                && sum(features.map(\.backendCallsStartedTotal))
                    == totals.backendCallsStartedTotal
                && sum(features.map(\.cancellationsAfterAdmissionTotal))
                    == totals.cancellationsAfterAdmissionTotal
                && sum(features.map(\.circuitRecoveryProbesStartedTotal))
                    == totals.circuitRecoveryProbesStartedTotal
                && sum(features.map(\.currentCircuitRecoveryProbes))
                    == totals.currentCircuitRecoveryProbes
                && sum(features.map(\.circuitRecoveryProbesSucceededTotal))
                    == totals.circuitRecoveryProbesSucceededTotal
                && sum(features.map(\.circuitRecoveryProbesDidNotRecoverTotal))
                    == totals.circuitRecoveryProbesDidNotRecoverTotal
                && sum(features.map { $0.outcomes.success }) == totals.outcomes.success
                && sum(features.map { $0.outcomes.cacheHit }) == totals.outcomes.cacheHit
                && sum(features.map { $0.outcomes.backendFailure })
                    == totals.outcomes.backendFailure
                && sum(features.map { $0.outcomes.circuitRejection })
                    == totals.outcomes.circuitRejection
                && sum(features.map { $0.outcomes.privacyRejection })
                    == totals.outcomes.privacyRejection
                && sum(features.map { $0.outcomes.admissionShed })
                    == totals.outcomes.admissionShed
                && sum(features.map { $0.outcomes.cancellation })
                    == totals.outcomes.cancellation
                && sum(features.map { $0.outcomes.responseOversize })
                    == totals.outcomes.responseOversize
                && sum(features.map { $0.downstreamValidation.accepted })
                    == totals.downstreamValidation.accepted
                && sum(features.map { $0.downstreamValidation.operationsStartedTotal })
                    == totals.downstreamValidation.operationsStartedTotal
                && sum(features.map { $0.downstreamValidation.currentOperations })
                    == totals.downstreamValidation.currentOperations
                && sum(features.map { $0.downstreamValidation.retryRequested })
                    == totals.downstreamValidation.retryRequested
                && sum(features.map { $0.downstreamValidation.finalRejection })
                    == totals.downstreamValidation.finalRejection
                && sum(features.map(\.requestedInputUTF8BytesTotal))
                    == totals.requestedInputUTF8BytesTotal
                && sum(features.map(\.backendInputUTF8BytesTotal))
                    == totals.backendInputUTF8BytesTotal
                && sum(features.map(\.backendOutputUTF8BytesTotal))
                    == totals.backendOutputUTF8BytesTotal
                && sum(features.map(\.returnedOutputUTF8BytesTotal))
                    == totals.returnedOutputUTF8BytesTotal
                && sum(features.map(\.estimatedBackendInputTokensTotal))
                    == totals.estimatedBackendInputTokensTotal
                && sum(features.map(\.estimatedBackendOutputTokensTotal))
                    == totals.estimatedBackendOutputTokensTotal
                && sum(features.map(\.estimatedReturnedOutputTokensTotal))
                    == totals.estimatedReturnedOutputTokensTotal
                && Self.latencyBucketsMatch(telemetry)
        }

        /// Recompute every conserving equation from the decoded counters. The
        /// producer verdicts are still required to agree, but cannot turn a
        /// malformed or stale counter set green by themselves.
        private static func countersConserve(
            _ counters: LLMRuntimeCountersSnapshot
        ) -> Bool {
            guard counters.currentInFlight >= 0,
                  counters.currentAdmittedBackendRequests >= 0,
                  counters.currentCircuitRecoveryProbes >= 0,
                  counters.downstreamValidation.currentOperations >= 0,
                  let requestTerminal = sum([
                      counters.outcomes.success,
                      counters.outcomes.cacheHit,
                      counters.outcomes.backendFailure,
                      counters.outcomes.circuitRejection,
                      counters.outcomes.privacyRejection,
                      counters.outcomes.admissionShed,
                      counters.outcomes.cancellation,
                      counters.outcomes.responseOversize,
                  ]),
                  let requestAccounted = sum([
                      requestTerminal,
                      UInt64(counters.currentInFlight),
                  ]),
                  let backendTerminal = sum([
                      counters.outcomes.success,
                      counters.outcomes.backendFailure,
                      counters.outcomes.responseOversize,
                      counters.cancellationsAfterAdmissionTotal,
                  ]),
                  let backendAccounted = sum([
                      backendTerminal,
                      UInt64(counters.currentAdmittedBackendRequests),
                  ]),
                  let recoveryAccounted = sum([
                      counters.circuitRecoveryProbesSucceededTotal,
                      counters.circuitRecoveryProbesDidNotRecoverTotal,
                      UInt64(counters.currentCircuitRecoveryProbes),
                  ]),
                  let semanticAccounted = sum([
                      counters.downstreamValidation.accepted,
                      counters.downstreamValidation.finalRejection,
                      UInt64(counters.downstreamValidation.currentOperations),
                  ]),
                  let latencyTerminal = sum(
                      counters.requestLatencyBuckets.map(\.completedRequests)
                  ) else { return false }
            return counters.conservationMaintained
                && counters.backendAdmissionConservationMaintained
                && counters.circuitRecoveryConservationMaintained
                && counters.requestedTotal == requestAccounted
                && counters.admittedBackendTotal == backendAccounted
                && counters.circuitRecoveryProbesStartedTotal == recoveryAccounted
                && counters.downstreamValidation.operationsStartedTotal
                    == semanticAccounted
                && requestTerminal == latencyTerminal
        }

        private static func latencyBucketsMatch(
            _ telemetry: LLMRuntimeTelemetrySnapshot
        ) -> Bool {
            let totalBuckets = telemetry.totals.requestLatencyBuckets
            let featureBuckets = telemetry.perFeature.map {
                $0.counters.requestLatencyBuckets
            }
            guard featureBuckets.allSatisfy({ $0.count == totalBuckets.count })
            else { return false }
            for index in totalBuckets.indices {
                guard featureBuckets.allSatisfy({
                    $0[index].upperBoundMilliseconds
                        == totalBuckets[index].upperBoundMilliseconds
                }), let sum = sum(featureBuckets.map {
                    $0[index].completedRequests
                }), sum == totalBuckets[index].completedRequests else {
                    return false
                }
            }
            return true
        }

        private static func sum(_ values: [UInt64]) -> UInt64? {
            var total: UInt64 = 0
            for value in values {
                let (next, overflow) = total.addingReportingOverflow(value)
                guard !overflow else { return nil }
                total = next
            }
            return total
        }
    }

    /// Live prevention-module state (the `prevention` block).
    public struct Prevention: Codable, Sendable, Equatable {
        public struct Module: Codable, Sendable, Equatable {
            public let enabled: Bool?
            public let count: Int?
            /// The daemon currently emits COUNTS only; `entries` stays nil until
            /// the writer adds a per-module `entries` array.
            public let entries: [String]?
        }
        public let sinkhole: Module?
        public let networkBlocker: Module?
        public let persistenceGuard: Module?

        private enum CodingKeys: String, CodingKey {
            case sinkhole
            case networkBlocker = "network_blocker"
            case persistenceGuard = "persistence_guard"
        }
    }

    /// TraceRegistry telemetry (the `trace_registry` block). When agent-trace
    /// binding is inactive the daemon writes only `{"enabled": false}`.
    public struct TraceRegistry: Codable, Sendable, Equatable {
        public let enabled: Bool?
        public let liveBindings: Int?
        public let cap: Int?
        public let pidRecycleRejected: Int?
        public let capEvictions: Int?
        public let ttlEvictions: Int?

        private enum CodingKeys: String, CodingKey {
            case enabled
            case liveBindings = "live_bindings"
            case cap
            case pidRecycleRejected = "pid_recycle_rejected"
            case capEvictions = "cap_evictions"
            case ttlEvictions = "ttl_evictions"
        }
    }

    /// Conservation for one joinable work plane. In-flight work, coalescing and
    /// detection's inline overload fallback are owned outcomes, not loss.
    /// Rejection, explicit overload shedding, accounting drift, or work left
    /// after close are fail-visible and interpreted according to the lane.
    public struct TimerLifecycle: Codable, Sendable, Equatable {
        public let accepting: Bool?
        public let offeredHandlersTotal: UInt64?
        public let acceptedHandlersTotal: UInt64?
        public let completedHandlersTotal: UInt64?
        public let rejectedHandlersTotal: UInt64?
        public let closedRejectedHandlersTotal: UInt64?
        public let overloadShedHandlersTotal: UInt64?
        public let coalescedHandlersTotal: UInt64?
        public let coalescedByLabel: [String: UInt64]?
        public let rejectedByLabel: [String: UInt64]?
        public let inlineFallbackHandlersTotal: UInt64?
        public let inlineFallbacksByLabel: [String: UInt64]?
        public let inFlightHandlers: Int?
        public let maximumInFlightHandlers: Int?
        public let conservesAcceptedHandlers: Bool?
        public let conservesOfferedHandlers: Bool?

        private enum CodingKeys: String, CodingKey {
            case accepting
            case offeredHandlersTotal = "offered_handlers_total"
            case acceptedHandlersTotal = "accepted_handlers_total"
            case completedHandlersTotal = "completed_handlers_total"
            case rejectedHandlersTotal = "rejected_handlers_total"
            case closedRejectedHandlersTotal = "closed_rejected_handlers_total"
            case overloadShedHandlersTotal = "overload_shed_handlers_total"
            case coalescedHandlersTotal = "coalesced_handlers_total"
            case coalescedByLabel = "coalesced_by_label"
            case rejectedByLabel = "rejected_by_label"
            case inlineFallbackHandlersTotal = "inline_fallback_handlers_total"
            case inlineFallbacksByLabel = "inline_fallbacks_by_label"
            case inFlightHandlers = "in_flight_handlers"
            case maximumInFlightHandlers = "maximum_in_flight_handlers"
            case conservesAcceptedHandlers = "conserves_accepted_handlers"
            case conservesOfferedHandlers = "conserves_offered_handlers"
        }

        public var conservationMaintained: Bool? {
            guard let accepted = conservesAcceptedHandlers,
                  let offered = conservesOfferedHandlers else { return nil }
            return accepted && offered
        }

        /// Old aggregate timer heartbeats predate the offered-outcome ledger.
        /// Once any extended scalar appears, require the complete scalar
        /// equation; a partially encoded new block must not render green.
        public var extendedTelemetryPresent: Bool {
            offeredHandlersTotal != nil
                || closedRejectedHandlersTotal != nil
                || overloadShedHandlersTotal != nil
                || coalescedHandlersTotal != nil
                || inlineFallbackHandlersTotal != nil
                || conservesOfferedHandlers != nil
        }

        public var extendedTelemetryComplete: Bool {
            guard extendedTelemetryPresent else { return false }
            return offeredHandlersTotal != nil
                && acceptedHandlersTotal != nil
                && completedHandlersTotal != nil
                && rejectedHandlersTotal != nil
                && closedRejectedHandlersTotal != nil
                && overloadShedHandlersTotal != nil
                && coalescedHandlersTotal != nil
                && inlineFallbackHandlersTotal != nil
                && inFlightHandlers != nil
                && maximumInFlightHandlers != nil
                && conservesAcceptedHandlers != nil
                && conservesOfferedHandlers != nil
        }

        public var telemetryPresent: Bool {
            accepting != nil
                || acceptedHandlersTotal != nil
                || completedHandlersTotal != nil
                || rejectedHandlersTotal != nil
                || inFlightHandlers != nil
                || conservesAcceptedHandlers != nil
                || extendedTelemetryPresent
        }

        public var telemetryComplete: Bool {
            guard telemetryPresent else { return false }
            let baseComplete = accepting != nil
                && acceptedHandlersTotal != nil
                && completedHandlersTotal != nil
                && rejectedHandlersTotal != nil
                && inFlightHandlers != nil
                && maximumInFlightHandlers != nil
                && conservesAcceptedHandlers != nil
            return baseComplete
                && (!extendedTelemetryPresent || extendedTelemetryComplete)
        }

        public var telemetryIncomplete: Bool {
            telemetryPresent && !telemetryComplete
        }

        /// While a lane accepts work, explicit loss or conservation failure is
        /// degraded. Reaching the capacity gauge alone is not: the detection
        /// lane runs inline and liveness may intentionally coalesce a duplicate.
        public var degradedWhileRunning: Bool {
            return accepting == true
                && (conservesAcceptedHandlers == false
                    || conservesOfferedHandlers == false
                    || telemetryIncomplete
                    || (rejectedHandlersTotal ?? 0) > 0
                    || (overloadShedHandlersTotal ?? 0) > 0)
        }

        public var uncleanOutstandingAfterClose: Bool {
            accepting == false
                && ((inFlightHandlers ?? 0) > 0
                    || conservesAcceptedHandlers == false
                    || conservesOfferedHandlers == false
                    || telemetryIncomplete)
        }

        /// Generic lifecycle/feature verdict. Security surfaces should use
        /// ``detectionProtectionDegraded`` for the detection plane so their
        /// wording explicitly names the protection consequence.
        public var degraded: Bool {
            degradedWhileRunning || uncleanOutstandingAfterClose
        }

        /// Security-plane verdict: every rejection (including a late
        /// post-seal producer) is a dropped security decision. Inline fallback
        /// and coalescing are independently measured owned outcomes, not loss.
        public var detectionProtectionDegraded: Bool {
            degraded
                || telemetryIncomplete
                || (rejectedHandlersTotal ?? 0) > 0
                || (closedRejectedHandlersTotal ?? 0) > 0
                || (overloadShedHandlersTotal ?? 0) > 0
        }

        /// Advisory/output verdict. This deliberately says "feature" rather
        /// than "protection": deterministic detection has already completed.
        public var featureDegraded: Bool {
            degraded
                || telemetryIncomplete
                || (rejectedHandlersTotal ?? 0) > 0
                || (closedRejectedHandlersTotal ?? 0) > 0
                || (overloadShedHandlersTotal ?? 0) > 0
        }

        public var losslessPressureObserved: Bool {
            (coalescedHandlersTotal ?? 0) > 0
                || (inlineFallbackHandlersTotal ?? 0) > 0
        }
    }

    /// Exact ownership of the loopback OTLP receiver's Network.framework
    /// listener, connection, callback, and body-processing planes. Current work
    /// is normal while its plane is open and conserving; only loss, broken
    /// conservation, sealed in-flight work, a stuck lifecycle operation, or an
    /// unclean shutdown degrades the Agent Traces feature.
    public struct OTLPReceiverLifecycle: Codable, Sendable, Equatable {
        public let acceptingListeners: Bool?
        public let listenersAcceptedTotal: UInt64?
        public let listenersCompletedTotal: UInt64?
        public let listenersRejectedAfterSealTotal: UInt64?
        public let activeListeners: Int?
        public let readyListeners: Int?
        public let listenersConserved: Bool?
        public let acceptingConnections: Bool?
        public let connectionsAcceptedTotal: UInt64?
        public let connectionsCompletedTotal: UInt64?
        public let connectionsRejectedAfterSealTotal: UInt64?
        public let connectionsRejectedAtCapacityTotal: UInt64?
        public let activeConnections: Int?
        public let connectionsConserved: Bool?
        public let acceptingBodyTasks: Bool?
        public let bodyTasksAcceptedTotal: UInt64?
        public let bodyTasksCompletedTotal: UInt64?
        public let bodyTasksCancelledTotal: UInt64?
        public let bodyTasksRejectedTotal: UInt64?
        public let bodyTaskCancellationRequestsTotal: UInt64?
        public let bodyTasksInFlight: Int?
        public let maximumBodyTasks: Int?
        public let bodyTasksConserved: Bool?
        public let acceptingCallbackTasks: Bool?
        public let callbackTasksAcceptedTotal: UInt64?
        public let callbackTasksCompletedTotal: UInt64?
        public let callbackTasksCancelledTotal: UInt64?
        public let callbackTasksRejectedTotal: UInt64?
        public let callbackTaskCancellationRequestsTotal: UInt64?
        public let callbackTasksInFlight: Int?
        public let maximumCallbackTasks: Int?
        public let callbackTasksConserved: Bool?
        public let lifecycleOperationsInProgress: Int?
        public let shutdownTimeoutsTotal: UInt64?
        public let cleanlyStopped: Bool?
        public let lastShutdownClean: Bool?

        private enum CodingKeys: String, CodingKey {
            case acceptingListeners = "accepting_listeners"
            case listenersAcceptedTotal = "listeners_accepted_total"
            case listenersCompletedTotal = "listeners_completed_total"
            case listenersRejectedAfterSealTotal = "listeners_rejected_after_seal_total"
            case activeListeners = "active_listeners"
            case readyListeners = "ready_listeners"
            case listenersConserved = "listeners_conserved"
            case acceptingConnections = "accepting_connections"
            case connectionsAcceptedTotal = "connections_accepted_total"
            case connectionsCompletedTotal = "connections_completed_total"
            case connectionsRejectedAfterSealTotal = "connections_rejected_after_seal_total"
            case connectionsRejectedAtCapacityTotal = "connections_rejected_at_capacity_total"
            case activeConnections = "active_connections"
            case connectionsConserved = "connections_conserved"
            case acceptingBodyTasks = "accepting_body_tasks"
            case bodyTasksAcceptedTotal = "body_tasks_accepted_total"
            case bodyTasksCompletedTotal = "body_tasks_completed_total"
            case bodyTasksCancelledTotal = "body_tasks_cancelled_total"
            case bodyTasksRejectedTotal = "body_tasks_rejected_total"
            case bodyTaskCancellationRequestsTotal = "body_task_cancellation_requests_total"
            case bodyTasksInFlight = "body_tasks_in_flight"
            case maximumBodyTasks = "maximum_body_tasks"
            case bodyTasksConserved = "body_tasks_conserved"
            case acceptingCallbackTasks = "accepting_callback_tasks"
            case callbackTasksAcceptedTotal = "callback_tasks_accepted_total"
            case callbackTasksCompletedTotal = "callback_tasks_completed_total"
            case callbackTasksCancelledTotal = "callback_tasks_cancelled_total"
            case callbackTasksRejectedTotal = "callback_tasks_rejected_total"
            case callbackTaskCancellationRequestsTotal = "callback_task_cancellation_requests_total"
            case callbackTasksInFlight = "callback_tasks_in_flight"
            case maximumCallbackTasks = "maximum_callback_tasks"
            case callbackTasksConserved = "callback_tasks_conserved"
            case lifecycleOperationsInProgress = "lifecycle_operations_in_progress"
            case shutdownTimeoutsTotal = "shutdown_timeouts_total"
            case cleanlyStopped = "cleanly_stopped"
            case lastShutdownClean = "last_shutdown_clean"
        }

        public var conservationMaintained: Bool? {
            guard let listenersConserved,
                  let connectionsConserved,
                  let bodyTasksConserved,
                  let callbackTasksConserved else {
                return nil
            }
            return listenersConserved
                && connectionsConserved
                && bodyTasksConserved
                && callbackTasksConserved
        }

        public var telemetryPresent: Bool {
            acceptingListeners != nil
                || listenersAcceptedTotal != nil
                || acceptingConnections != nil
                || connectionsAcceptedTotal != nil
                || acceptingBodyTasks != nil
                || bodyTasksAcceptedTotal != nil
                || acceptingCallbackTasks != nil
                || callbackTasksAcceptedTotal != nil
                || lifecycleOperationsInProgress != nil
        }

        public var telemetryComplete: Bool {
            guard telemetryPresent else { return false }
            return acceptingListeners != nil
                && listenersAcceptedTotal != nil
                && listenersCompletedTotal != nil
                && listenersRejectedAfterSealTotal != nil
                && activeListeners != nil
                && readyListeners != nil
                && listenersConserved != nil
                && acceptingConnections != nil
                && connectionsAcceptedTotal != nil
                && connectionsCompletedTotal != nil
                && connectionsRejectedAfterSealTotal != nil
                && connectionsRejectedAtCapacityTotal != nil
                && activeConnections != nil
                && connectionsConserved != nil
                && acceptingBodyTasks != nil
                && bodyTasksAcceptedTotal != nil
                && bodyTasksCompletedTotal != nil
                && bodyTasksCancelledTotal != nil
                && bodyTasksRejectedTotal != nil
                && bodyTaskCancellationRequestsTotal != nil
                && bodyTasksInFlight != nil
                && maximumBodyTasks != nil
                && bodyTasksConserved != nil
                && acceptingCallbackTasks != nil
                && callbackTasksAcceptedTotal != nil
                && callbackTasksCompletedTotal != nil
                && callbackTasksCancelledTotal != nil
                && callbackTasksRejectedTotal != nil
                && callbackTaskCancellationRequestsTotal != nil
                && callbackTasksInFlight != nil
                && maximumCallbackTasks != nil
                && callbackTasksConserved != nil
                && lifecycleOperationsInProgress != nil
                && shutdownTimeoutsTotal != nil
                && cleanlyStopped != nil
        }

        /// A sealed plane retaining owned work cannot accept the callback that
        /// would normally drive that work to its terminal accounting state.
        public var sealedWorkInFlight: Bool {
            (acceptingListeners == false
                && ((activeListeners ?? 0) > 0 || (readyListeners ?? 0) > 0))
                || (acceptingConnections == false && (activeConnections ?? 0) > 0)
                || (acceptingBodyTasks == false && (bodyTasksInFlight ?? 0) > 0)
                || (acceptingCallbackTasks == false && (callbackTasksInFlight ?? 0) > 0)
        }

        public var lifecycleOperationLeftInProgress: Bool {
            (lifecycleOperationsInProgress ?? 0) > 0
        }

        public var uncleanShutdown: Bool {
            if (shutdownTimeoutsTotal ?? 0) > 0 || lastShutdownClean == false {
                return true
            }
            return sealedWorkInFlight
        }

        public var advisoryInputShed: Bool {
            (listenersRejectedAfterSealTotal ?? 0) > 0
                || (connectionsRejectedAfterSealTotal ?? 0) > 0
                || (connectionsRejectedAtCapacityTotal ?? 0) > 0
                || (bodyTasksRejectedTotal ?? 0) > 0
                || (callbackTasksRejectedTotal ?? 0) > 0
        }

        /// Advisory feature health only. A true value must not be promoted to
        /// a claim that kernel-backed detection is degraded.
        public var featureDegraded: Bool {
            (telemetryPresent && !telemetryComplete)
                || listenersConserved == false
                || connectionsConserved == false
                || bodyTasksConserved == false
                || callbackTasksConserved == false
                || lifecycleOperationLeftInProgress
                || uncleanShutdown
                || advisoryInputShed
        }
    }

    /// Integrity/fingerprint-bound sequence recovery telemetry. Wall-clock
    /// timestamps remain diagnostic; `crashRPOBoundCurrentlyMaintained` is the
    /// coordinator's monotonic health verdict and is the authoritative gate.
    public struct SequenceCheckpoint: Codable, Sendable, Equatable {
        public let restoreStatus: String?
        public let restoreDetail: String?
        public let lastRestoreAtUnix: Double?
        public let lastAttemptAtUnix: Double?
        public let lastSuccessAtUnix: Double?
        public let lastFailureAtUnix: Double?
        public let lastFailure: String?
        public let checkpointCapturedAtUnix: Double?
        public let checkpointAgeSeconds: Double?
        public let checkpointBytes: Int?
        public let durableCarrierValid: Bool?
        public let dirty: Bool?
        public let currentSemanticDigest: String?
        public let durableSemanticDigest: String?
        public let currentGeneration: UInt64?
        public let durableGeneration: UInt64?
        public let configuredCrashRPOSeconds: Double?
        public let crashRPOBoundCurrentlyMaintained: Bool?
        public let periodicWritesLastHour: Int?
        public let periodicBytesLastHour: Int?
        public let writesTotal: UInt64?
        public let bytesWrittenTotal: UInt64?
        public let unchangedSkipsTotal: UInt64?
        public let budgetDeferralsTotal: UInt64?
        public let conservation: SequenceConservationTelemetry?
        public let orphanFilesCurrent: Int?
        public let orphanBytesCurrent: Int?
        public let orphanFilesRemovedTotal: UInt64?
        public let orphanBytesRemovedTotal: UInt64?
        public let orphanCleanupScanTruncated: Bool?
        public let lastOrphanCleanupAtUnix: Double?
        public let carrierInvalidationsTotal: UInt64?
        public let lastCarrierInvalidationReason: String?
        public let lastCarrierInvalidationAtUnix: Double?

        private enum CodingKeys: String, CodingKey {
            case restoreStatus = "restore_status"
            case restoreDetail = "restore_detail"
            case lastRestoreAtUnix = "last_restore_at_unix"
            case lastAttemptAtUnix = "last_attempt_at_unix"
            case lastSuccessAtUnix = "last_success_at_unix"
            case lastFailureAtUnix = "last_failure_at_unix"
            case lastFailure = "last_failure"
            case checkpointCapturedAtUnix = "checkpoint_captured_at_unix"
            case checkpointAgeSeconds = "checkpoint_age_seconds"
            case checkpointBytes = "checkpoint_bytes"
            case durableCarrierValid = "durable_carrier_valid"
            case dirty
            case currentSemanticDigest = "current_semantic_digest"
            case durableSemanticDigest = "durable_semantic_digest"
            case currentGeneration = "current_generation"
            case durableGeneration = "durable_generation"
            case configuredCrashRPOSeconds = "configured_crash_rpo_seconds"
            case crashRPOBoundCurrentlyMaintained = "crash_rpo_bound_currently_maintained"
            case periodicWritesLastHour = "periodic_writes_last_hour"
            case periodicBytesLastHour = "periodic_bytes_last_hour"
            case writesTotal = "writes_total"
            case bytesWrittenTotal = "bytes_written_total"
            case unchangedSkipsTotal = "unchanged_skips_total"
            case budgetDeferralsTotal = "budget_deferrals_total"
            case conservation
            case orphanFilesCurrent = "orphan_files_current"
            case orphanBytesCurrent = "orphan_bytes_current"
            case orphanFilesRemovedTotal = "orphan_files_removed_total"
            case orphanBytesRemovedTotal = "orphan_bytes_removed_total"
            case orphanCleanupScanTruncated = "orphan_cleanup_scan_truncated"
            case lastOrphanCleanupAtUnix = "last_orphan_cleanup_at_unix"
            case carrierInvalidationsTotal = "carrier_invalidations_total"
            case lastCarrierInvalidationReason = "last_carrier_invalidation_reason"
            case lastCarrierInvalidationAtUnix = "last_carrier_invalidation_at_unix"
        }
    }

    /// Exact TraceStore span-ingest conservation. Missing means the heartbeat
    /// predates this ledger; a present but incomplete ledger remains unknown,
    /// never silently green.
    public struct TraceStoreIngestConservation: Codable, Sendable, Equatable {
        public let offered: Int64?
        public let completed: Int64?
        public let queued: Int64?
        public let inFlight: Int64?
        public let explicitlyShed: Int64?

        private enum CodingKeys: String, CodingKey {
            case offered
            case completed
            case queued
            case inFlight = "in_flight"
            case explicitlyShed = "explicitly_shed"
        }

        public var conservationMaintained: Bool? {
            guard let offered, let completed, let queued, let inFlight,
                  let explicitlyShed else { return nil }
            guard offered >= 0, completed >= 0, queued >= 0, inFlight >= 0,
                  explicitlyShed >= 0 else { return false }
            var accounted: Int64 = 0
            for value in [completed, queued, inFlight, explicitlyShed] {
                let (next, overflow) = accounted.addingReportingOverflow(value)
                guard !overflow else { return false }
                accounted = next
            }
            return offered == accounted
        }
    }

    /// Authoritative SQLite actor admission state. A blocked store represents a
    /// deliberate forensic-evidence gap while detection continues in memory.
    public struct TraceGraphStorageAdmission: Codable, Sendable, Equatable {
        public let enabled: Bool?
        /// True when a foreground graph mutation can enter SQLite now or join
        /// the actor's bounded recovery handoff queue. Recovery is orthogonal:
        /// a recovering store remains accepting until that queue is saturated.
        public let acceptingMutations: Bool?
        public let blocked: Bool?
        /// False when the daemon could not construct the TraceGraph store at
        /// boot. Missing means the heartbeat predates this fail-visible field.
        public let storeAvailable: Bool?
        /// True only when a typed storage-admission refusal happened before the
        /// store actor existed (distinct from a live actor shedding mutations).
        public let startupBlocked: Bool?
        public let reason: String?
        public let shedMutationsTotal: Int64?
        public let maxFootprintBytes: Int64?
        public let admissionThresholdBytes: Int64?
        public let resumeBelowBytes: Int64?
        public let transactionReserveBytes: Int64?
        public let footprintBytes: Int64?
        public let freeSpaceBytes: Int64?
        public let freeSpaceFloorBytes: Int64?
        public let pinnedReader: Bool?
        public let recovering: Bool?
        public let recoveryMutationWaiters: Int?
        public let recoveryMutationWaiterLimit: Int?
        public let recoveryMutationQueueSaturated: Bool?
        public let recoveryMutationWaiterHighWatermark: Int?
        public let recoveryMutationWaitsTotal: Int64?
        public let recoveryMutationWaitReleasesTotal: Int64?
        public let recoveryMutationWaitCancellationsTotal: Int64?
        public let recoveryMutationWaitClosedTotal: Int64?
        public let recoveryMutationWaitSaturationsTotal: Int64?
        public let recoveryMutationWaitNanosecondsTotal: Int64?
        public let recoveryMutationMaxWaitNanoseconds: Int64?
        public let recoveryMutationOldestWaitNanoseconds: Int64?
        public let recoveryWriterPreemptionsTotal: Int64?
        public let autoVacuumMode: Int?
        public let footprintLatchTripsTotal: Int64?
        public let footprintLatchClearsTotal: Int64?
        public let recoveryRunsTotal: Int64?
        public let recoveryTracesDeletedTotal: Int64?
        public let recoveryTraceChildRowsDeletedTotal: Int64?
        public let recoveryEdgesDeletedTotal: Int64?
        public let recoveryEntitiesDeletedTotal: Int64?
        public let recoveryVacuumPagesReclaimedTotal: Int64?
        public let recoveryNoPhysicalProgressTotal: Int64?
        public let lastRecoveryFootprintBeforeBytes: Int64?
        public let lastRecoveryFootprintAfterBytes: Int64?
        public let proactiveRecoveryThresholdBytes: Int64?
        public let recoveryDeficitBytes: Int64?
        public let lastRecoveryEligibleBacklogRemaining: Bool?
        public let ingestConservation: TraceStoreIngestConservation?

        // Exact rolling-graph persistence accounting. These counters are
        // cumulative for one process epoch; failed totals therefore remain
        // sticky even if the SQLite admission latch later returns to Active.
        public let ingestEventsTotal: Int64?
        public let ingestEventsCommittedTotal: Int64?
        public let ingestEventsFailedTotal: Int64?
        public let ingestEventsInFlight: Int?
        public let ingestEventsPending: Int?
        public let entityObservationsTotal: Int64?
        public let edgeObservationsTotal: Int64?
        public let relevanceSuppressedFileEventsTotal: Int64?
        public let relevanceSuppressedRowsTotal: Int64?
        public let physicalWriteSuppressedEventsTotal: Int64?
        public let physicalWriteSuppressedRowsTotal: Int64?
        public let writeAttemptsTotal: Int64?
        public let writeBatchesCommittedTotal: Int64?
        public let writeBatchesFailedTotal: Int64?
        public let writeBatchesInFlight: Int?
        public let writeRowsAttemptedTotal: Int64?
        public let writeRowsCommittedTotal: Int64?
        public let writeRowsFailedTotal: Int64?
        public let writeRowsInFlight: Int?
        public let coalescedNoopRowsTotal: Int64?
        public let pendingEntityRows: Int?
        public let pendingEdgeRows: Int?

        private enum CodingKeys: String, CodingKey {
            case enabled
            case acceptingMutations = "accepting_mutations"
            case blocked
            case storeAvailable = "store_available"
            case startupBlocked = "startup_blocked"
            case reason
            case shedMutationsTotal = "shed_mutations_total"
            case maxFootprintBytes = "max_footprint_bytes"
            case admissionThresholdBytes = "admission_threshold_bytes"
            case resumeBelowBytes = "resume_below_bytes"
            case transactionReserveBytes = "transaction_reserve_bytes"
            case footprintBytes = "footprint_bytes"
            case freeSpaceBytes = "free_space_bytes"
            case freeSpaceFloorBytes = "free_space_floor_bytes"
            case pinnedReader = "pinned_reader"
            case recovering
            case recoveryMutationWaiters = "recovery_mutation_waiters"
            case recoveryMutationWaiterLimit = "recovery_mutation_waiter_limit"
            case recoveryMutationQueueSaturated = "recovery_mutation_queue_saturated"
            case recoveryMutationWaiterHighWatermark = "recovery_mutation_waiter_high_watermark"
            case recoveryMutationWaitsTotal = "recovery_mutation_waits_total"
            case recoveryMutationWaitReleasesTotal = "recovery_mutation_wait_releases_total"
            case recoveryMutationWaitCancellationsTotal = "recovery_mutation_wait_cancellations_total"
            case recoveryMutationWaitClosedTotal = "recovery_mutation_wait_closed_total"
            case recoveryMutationWaitSaturationsTotal = "recovery_mutation_wait_saturations_total"
            case recoveryMutationWaitNanosecondsTotal = "recovery_mutation_wait_nanoseconds_total"
            case recoveryMutationMaxWaitNanoseconds = "recovery_mutation_max_wait_nanoseconds"
            case recoveryMutationOldestWaitNanoseconds = "recovery_mutation_oldest_wait_nanoseconds"
            case recoveryWriterPreemptionsTotal = "recovery_writer_preemptions_total"
            case autoVacuumMode = "auto_vacuum_mode"
            case footprintLatchTripsTotal = "footprint_latch_trips_total"
            case footprintLatchClearsTotal = "footprint_latch_clears_total"
            case recoveryRunsTotal = "recovery_runs_total"
            case recoveryTracesDeletedTotal = "recovery_traces_deleted_total"
            case recoveryTraceChildRowsDeletedTotal = "recovery_trace_child_rows_deleted_total"
            case recoveryEdgesDeletedTotal = "recovery_edges_deleted_total"
            case recoveryEntitiesDeletedTotal = "recovery_entities_deleted_total"
            case recoveryVacuumPagesReclaimedTotal = "recovery_vacuum_pages_reclaimed_total"
            case recoveryNoPhysicalProgressTotal = "recovery_no_physical_progress_total"
            case lastRecoveryFootprintBeforeBytes = "last_recovery_footprint_before_bytes"
            case lastRecoveryFootprintAfterBytes = "last_recovery_footprint_after_bytes"
            case proactiveRecoveryThresholdBytes = "proactive_recovery_threshold_bytes"
            case recoveryDeficitBytes = "recovery_deficit_bytes"
            case lastRecoveryEligibleBacklogRemaining = "last_recovery_eligible_backlog_remaining"
            case ingestConservation = "ingest_conservation"
            case ingestEventsTotal = "ingest_events_total"
            case ingestEventsCommittedTotal = "ingest_events_committed_total"
            case ingestEventsFailedTotal = "ingest_events_failed_total"
            case ingestEventsInFlight = "ingest_events_in_flight"
            case ingestEventsPending = "ingest_events_pending"
            case entityObservationsTotal = "entity_observations_total"
            case edgeObservationsTotal = "edge_observations_total"
            case relevanceSuppressedFileEventsTotal = "relevance_suppressed_file_events_total"
            case relevanceSuppressedRowsTotal = "relevance_suppressed_rows_total"
            case physicalWriteSuppressedEventsTotal = "physical_write_suppressed_events_total"
            case physicalWriteSuppressedRowsTotal = "physical_write_suppressed_rows_total"
            case writeAttemptsTotal = "write_attempts_total"
            case writeBatchesCommittedTotal = "write_batches_committed_total"
            case writeBatchesFailedTotal = "write_batches_failed_total"
            case writeBatchesInFlight = "write_batches_in_flight"
            case writeRowsAttemptedTotal = "write_rows_attempted_total"
            case writeRowsCommittedTotal = "write_rows_committed_total"
            case writeRowsFailedTotal = "write_rows_failed_total"
            case writeRowsInFlight = "write_rows_in_flight"
            case coalescedNoopRowsTotal = "coalesced_noop_rows_total"
            case pendingEntityRows = "pending_entity_rows"
            case pendingEdgeRows = "pending_edge_rows"
        }

        /// input = committed + failed + in-flight + pending.
        public var ingestConservationMaintained: Bool? {
            guard let input = ingestEventsTotal,
                  let committed = ingestEventsCommittedTotal,
                  let failed = ingestEventsFailedTotal,
                  let inFlight = ingestEventsInFlight,
                  let pending = ingestEventsPending else { return nil }
            return Self.conserves(
                total: input,
                terms: [committed, failed, Int64(inFlight), Int64(pending)]
            )
        }

        /// Every recovery waiter has exactly one terminal outcome, or remains
        /// in the actor-owned queue at this snapshot.
        public var recoveryMutationWaitConservationMaintained: Bool? {
            guard let waits = recoveryMutationWaitsTotal,
                  let current = recoveryMutationWaiters,
                  let releases = recoveryMutationWaitReleasesTotal,
                  let cancellations = recoveryMutationWaitCancellationsTotal,
                  let closed = recoveryMutationWaitClosedTotal else { return nil }
            return Self.conserves(
                total: waits,
                terms: [Int64(current), releases, cancellations, closed]
            )
        }

        /// Barrier telemetry is all-or-nothing for a current TraceGraph
        /// heartbeat. Absence remains compatible with older engines, while a
        /// partial block is fail-visible instead of being treated as healthy.
        public var recoveryMutationTelemetryPresent: Bool {
            let int64Values: [Int64?] = [
                recoveryMutationWaitsTotal,
                recoveryMutationWaitReleasesTotal,
                recoveryMutationWaitCancellationsTotal,
                recoveryMutationWaitClosedTotal,
                recoveryMutationWaitSaturationsTotal,
                recoveryMutationWaitNanosecondsTotal,
                recoveryMutationMaxWaitNanoseconds,
                recoveryMutationOldestWaitNanoseconds,
                recoveryWriterPreemptionsTotal,
            ]
            let intValues: [Int?] = [
                recoveryMutationWaiters,
                recoveryMutationWaiterLimit,
                recoveryMutationWaiterHighWatermark,
            ]
            return acceptingMutations != nil
                || recoveryMutationQueueSaturated != nil
                || int64Values.contains { $0 != nil }
                || intValues.contains { $0 != nil }
        }

        public var recoveryMutationTelemetryComplete: Bool {
            guard recoveryMutationTelemetryPresent else { return false }
            return acceptingMutations != nil
                && recoveryMutationWaiters != nil
                && recoveryMutationWaiterLimit != nil
                && recoveryMutationQueueSaturated != nil
                && recovering != nil
                && recoveryMutationWaiterHighWatermark != nil
                && recoveryMutationWaitsTotal != nil
                && recoveryMutationWaitReleasesTotal != nil
                && recoveryMutationWaitCancellationsTotal != nil
                && recoveryMutationWaitClosedTotal != nil
                && recoveryMutationWaitSaturationsTotal != nil
                && recoveryMutationWaitNanosecondsTotal != nil
                && recoveryMutationMaxWaitNanoseconds != nil
                && recoveryMutationOldestWaitNanoseconds != nil
                && recoveryWriterPreemptionsTotal != nil
        }

        /// A foreground queue can be occupied during healthy recovery. The
        /// degraded cases are loss/admission signals: it stopped accepting,
        /// saturated at least once, exceeded its fixed bound, or broke its
        /// exact waiter ledger.
        public var recoveryMutationBarrierDegraded: Bool {
            guard recoveryMutationTelemetryPresent else { return false }
            guard recoveryMutationTelemetryComplete,
                  let accepting = acceptingMutations,
                  let current = recoveryMutationWaiters,
                  let limit = recoveryMutationWaiterLimit,
                  let saturated = recoveryMutationQueueSaturated,
                  let recovering = recovering,
                  let highWatermark = recoveryMutationWaiterHighWatermark,
                  let saturations = recoveryMutationWaitSaturationsTotal,
                  let totalWait = recoveryMutationWaitNanosecondsTotal,
                  let maxWait = recoveryMutationMaxWaitNanoseconds,
                  let oldestWait = recoveryMutationOldestWaitNanoseconds else {
                return true
            }
            return !accepting
                || saturated
                || current < 0
                || limit <= 0
                || current > limit
                || highWatermark < current
                || highWatermark > limit
                || saturated != (recovering && current >= limit)
                || saturations != 0
                || totalWait < 0
                || maxWait < 0
                || maxWait > totalWait
                || oldestWait < 0
                || (current == 0 && oldestWait != 0)
                || recoveryMutationWaitConservationMaintained != true
        }

        /// attempts = committed batches + failed batches + in-flight batches.
        public var writeBatchConservationMaintained: Bool? {
            guard let attempts = writeAttemptsTotal,
                  let committed = writeBatchesCommittedTotal,
                  let failed = writeBatchesFailedTotal,
                  let inFlight = writeBatchesInFlight else { return nil }
            return Self.conserves(
                total: attempts,
                terms: [committed, failed, Int64(inFlight)]
            )
        }

        /// attempted rows = committed + failed + in-flight rows.
        public var writeRowConservationMaintained: Bool? {
            guard let attempted = writeRowsAttemptedTotal,
                  let committed = writeRowsCommittedTotal,
                  let failed = writeRowsFailedTotal,
                  let inFlight = writeRowsInFlight else { return nil }
            return Self.conserves(
                total: attempted,
                terms: [committed, failed, Int64(inFlight)]
            )
        }

        /// entity + edge observations = attempted + coalesced + deliberately
        /// suppressed physical rows + pending rows.
        public var observationConservationMaintained: Bool? {
            guard let entities = entityObservationsTotal,
                  let edges = edgeObservationsTotal,
                  let attempted = writeRowsAttemptedTotal,
                  let coalesced = coalescedNoopRowsTotal,
                  let pendingEntities = pendingEntityRows,
                  let pendingEdges = pendingEdgeRows else { return nil }
            guard let observations = Self.safeSum([entities, edges]) else { return false }
            return Self.conserves(
                total: observations,
                terms: [
                    attempted,
                    coalesced,
                    physicalWriteSuppressedRowsTotal ?? 0,
                    Int64(pendingEntities),
                    Int64(pendingEdges),
                ]
            )
        }

        /// Exact accounting is known only when all four equations are present.
        public var writeConservationMaintained: Bool? {
            let equations = [
                ingestConservationMaintained,
                writeBatchConservationMaintained,
                writeRowConservationMaintained,
                observationConservationMaintained,
            ]
            guard equations.allSatisfy({ $0 != nil }) else { return nil }
            return equations.allSatisfy { $0 == true }
        }

        /// Cumulative failures are deliberately sticky for the process epoch.
        public var hasStickyWriteFailure: Bool? {
            Self.anyPositive([
                ingestEventsFailedTotal,
                writeBatchesFailedTotal,
                writeRowsFailedTotal,
            ])
        }

        /// Coalescing normally drains within 250 ms. Pending work caught by the
        /// much slower heartbeat remains fail-visible; repeated snapshots prove
        /// it is stuck. In-flight work alone is an active write, not a backlog.
        public var hasOutstandingBacklog: Bool? {
            guard let events = ingestEventsPending,
                  let entities = pendingEntityRows,
                  let edges = pendingEdgeRows else { return nil }
            return events < 0 || entities < 0 || edges < 0
                || events > 0 || entities > 0 || edges > 0
        }

        /// The SQLite admission block and the rolling writer are independent.
        /// A green admission latch cannot override failed/dropped work, pending
        /// backlog, or accounting drift.
        public var writeTelemetryPresent: Bool {
            let int64Values: [Int64?] = [
                ingestEventsTotal,
                ingestEventsCommittedTotal,
                ingestEventsFailedTotal,
                entityObservationsTotal,
                edgeObservationsTotal,
                relevanceSuppressedFileEventsTotal,
                relevanceSuppressedRowsTotal,
                physicalWriteSuppressedEventsTotal,
                physicalWriteSuppressedRowsTotal,
                writeAttemptsTotal,
                writeBatchesCommittedTotal,
                writeBatchesFailedTotal,
                writeRowsAttemptedTotal,
                writeRowsCommittedTotal,
                writeRowsFailedTotal,
                coalescedNoopRowsTotal,
            ]
            let intValues: [Int?] = [
                ingestEventsInFlight,
                ingestEventsPending,
                writeBatchesInFlight,
                writeRowsInFlight,
                pendingEntityRows,
                pendingEdgeRows,
            ]
            return int64Values.contains { $0 != nil }
                || intValues.contains { $0 != nil }
        }

        /// The running producer emits the whole fixed ledger atomically. If a
        /// newer heartbeat contains only part of it, no operator surface may
        /// turn the missing counters into a green "Active" verdict.
        public var writeTelemetryComplete: Bool {
            let int64Values: [Int64?] = [
                ingestEventsTotal,
                ingestEventsCommittedTotal,
                ingestEventsFailedTotal,
                entityObservationsTotal,
                edgeObservationsTotal,
                relevanceSuppressedFileEventsTotal,
                relevanceSuppressedRowsTotal,
                writeAttemptsTotal,
                writeBatchesCommittedTotal,
                writeBatchesFailedTotal,
                writeRowsAttemptedTotal,
                writeRowsCommittedTotal,
                writeRowsFailedTotal,
                coalescedNoopRowsTotal,
            ]
            let intValues: [Int?] = [
                ingestEventsInFlight,
                ingestEventsPending,
                writeBatchesInFlight,
                writeRowsInFlight,
                pendingEntityRows,
                pendingEdgeRows,
            ]
            return int64Values.allSatisfy { $0 != nil }
                && intValues.allSatisfy { $0 != nil }
        }

        public var graphWriteDegraded: Bool {
            if recoveryMutationBarrierDegraded { return true }
            guard writeTelemetryPresent else { return false }
            return !writeTelemetryComplete
                || hasStickyWriteFailure != false
                || hasOutstandingBacklog == true
                || writeConservationMaintained != true
        }

        private static func anyPositive(_ values: [Int64?]) -> Bool? {
            if values.contains(where: { ($0 ?? 0) > 0 }) { return true }
            guard values.allSatisfy({ $0 != nil }) else { return nil }
            return values.contains(where: { ($0 ?? 0) < 0 }) ? true : false
        }

        private static func conserves(total: Int64, terms: [Int64]) -> Bool {
            guard total >= 0, terms.allSatisfy({ $0 >= 0 }),
                  let sum = safeSum(terms) else { return false }
            return total == sum
        }

        private static func safeSum(_ values: [Int64]) -> Int64? {
            var total: Int64 = 0
            for value in values {
                let (next, overflow) = total.addingReportingOverflow(value)
                guard !overflow else { return nil }
                total = next
            }
            return total
        }
    }

    /// Same wire shape as TraceGraph admission, emitted under a distinct key.
    public typealias TraceStoreStorageAdmission = TraceGraphStorageAdmission

    // MARK: - Reading / freshness

    /// assessment-framework (P0): reads `<dir>/heartbeat_rich.json` from each
    /// candidate support dir, JSON-decodes it, and returns the one with the
    /// greatest `writtenAtUnix`. Does NOT read the clock — staleness is a
    /// separate, clock-injected decision via `isStale(now:maxAge:)`, so this
    /// function is deterministic. A heartbeat that fails to decode, or whose
    /// `written_at_unix` is absent, is simply not selected over a valid one.
    public static func readFreshest(supportDirs: [String]) -> HeartbeatSnapshot? {
        let decoder = JSONDecoder()
        let snapshots: [HeartbeatSnapshot] = supportDirs.compactMap { dir in
            let path = dir + "/heartbeat_rich.json"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  let snap = try? decoder.decode(HeartbeatSnapshot.self, from: data)
            else { return nil }
            return snap
        }
        return snapshots.max { ($0.writtenAtUnix ?? 0) < ($1.writtenAtUnix ?? 0) }
    }

    /// Seconds between `now` (unix seconds, injected) and when this heartbeat
    /// was written. `nil` when the heartbeat has no `written_at_unix` — the age
    /// is genuinely unknown, so we refuse to invent one.
    public func ageSeconds(now: Double) -> Double? {
        guard let w = writtenAtUnix else { return nil }
        return now - w
    }

    /// assessment-framework (P0): staleness with an INJECTED clock so it is
    /// deterministic. Fail-safe: a heartbeat with no known write time is
    /// reported as stale (`true`), never as fresh — the framework must never
    /// present an unknown as a live/green engine.
    public func isStale(now: Double, maxAge: Double) -> Bool {
        guard let age = ageSeconds(now: now), age.isFinite, maxAge.isFinite, maxAge >= 0 else { return true }
        return age < 0 || age > maxAge
    }
}
