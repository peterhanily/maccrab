// V2HeartbeatSnapshot.swift
// View model derived from the daemon's `heartbeat_rich.json` file
// (written every 30s by `Sources/MacCrabAgentKit/DaemonTimers.swift`).
// Used by the System workspace to replace hardcoded health metrics
// with real ones.

import Foundation
import MacCrabCore

public struct V2HeartbeatSnapshot: Sendable, Equatable {
    public let writtenAt: Date
    public var bootPhase: String? = nil
    public var liveness: Bool? = nil
    public var rulesLoaded: Int? = nil
    public var engineIdentity: EngineTelemetryIdentity? = nil
    var dnsCapture: V2DNSCaptureStatus? = nil
    public var engineStartedAt: Date? { engineIdentity.map { Date(timeIntervalSince1970: $0.startedAtUnix) } }
    var readiness: V2EngineReadiness {
        V2EngineReadiness(bootPhase: bootPhase, liveness: liveness)
    }
    public var isReady: Bool { readiness == .ready }

    /// v1.21.4: canonical staleness threshold — MUST match
    /// AppState.HeartbeatSnapshot.staleThreshold (120s) so every workspace
    /// agrees on "live vs degraded". `readFreshest()` only nils heartbeats
    /// older than 300s, so a 120–300s-old heartbeat is returned NON-nil and
    /// callers that treated non-nil as "live" (System "Daemon: Running",
    /// Prevention "on" chips) falsely reassured during a 2–5 min outage. Gate
    /// live/green state on `!isStale`, not merely on the snapshot existing.
    public static let staleThreshold: TimeInterval = 120
    public var isStale: Bool {
        let age = Date().timeIntervalSince(writtenAt)
        return age < 0 || age > Self.staleThreshold
    }
    /// Whole seconds since the daemon last wrote a heartbeat (for "N m ago").
    public var ageSeconds: Int { max(0, Int(Date().timeIntervalSince(writtenAt))) }
    public let uptimeSeconds: Int
    public let eventsProcessed: Int
    public let alertsEmitted: Int
    public let residentMemoryMB: Int?
    public let sysextHasFDA: Bool
    public let schemaVersion: Int
    /// Exact admission-time counts paired with the daemon's retained-window
    /// proof. Unlike the compatibility `_1h` alias, this remains populated
    /// when only a shorter interval is provable.
    public let eventTypeCounts: [String: Int]
    public let eventTypeCountWindow: EventTypeCountWindow?
    /// Compatibility payload from older daemons, or from a new daemon only
    /// when it proved the complete requested hour.
    public let eventTypeCounts1h: [String: Int]
    public let collectors: [Collector]
    // v1.12.6 Wave 9O: Wave-9K added these counters to
    // heartbeat_rich.json but pre-9O the dashboard snapshot didn't
    // decode them. Wired now so the System workspace can surface
    // payload-cap-firing rate and ES-collector drop rate.
    public let payloadTruncatedTotal: Int
    public let esloggerDroppedTotal: Int
    /// v1.21.4 Phase-1 D2: ES sensor-degraded advisory. True when a file-event
    /// flood is spiking above baseline while the kernel is dropping messages
    /// (possible telemetry-drop evasion). `esSensorDegradedDetail` carries the
    /// drop counts + rates; `esSensorDegradedSeverity` is "high" or "low"
    /// (low = attributed to a known-benign high-I/O signer). Advisory only.
    public let esSensorDegraded: Bool
    public let esSensorDegradedDetail: String?
    public let esSensorDegradedSeverity: String?
    /// v1.18: engine-side LLM health (from the `llm` block). nil when the
    /// heartbeat predates this field. `configured == false` means the engine
    /// has no LLM backend wired; configured-but-not-healthy means enabled
    /// yet unreachable/misconfigured — previously invisible.
    public let llm: LLMHealth?
    /// UX-3: live prevention-module state from the `prevention` block.
    /// nil when the heartbeat predates this field (older daemon) → the
    /// Prevention tab shows "status unavailable" rather than a false reading.
    public let prevention: Prevention?
    /// TraceGraph persistence health. A present blocked/unavailable value is a
    /// forensic-evidence gap even while event detection continues normally.
    /// nil means the running daemon predates this heartbeat block.
    public let traceGraphStorageAdmission: TraceGraphStorageAdmission?
    /// traces.db persistence health. These OTLP spans are always
    /// unauthenticated/self-reported and advisory, but a blocked store still
    /// needs to be visible so an empty trace panel is not read as "no spans".
    public let traceStoreStorageAdmission: TraceGraphStorageAdmission?
    /// Live transition-aware alerts/events caps and the steady-state envelope.
    public let alertEvidenceBudget: MacCrabCore.HeartbeatSnapshot.AlertEvidenceBudget?
    /// Recent failed alert write attempts, independent of current admission.
    /// Zero is the compatibility default for an absent older-engine field;
    /// nil means a present count could not be trusted.
    public let alertInsertErrorsTotal: Int?
    public var alertWritesRequireAttention: Bool { alertInsertErrorsTotal != 0 }
    /// Joinable timer-handler lifecycle accounting. One in-flight heartbeat
    /// handler is normal; conservation/rejection while accepting is not.
    public let timerLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    public let livenessTimerLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    public let startupWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    public let detectionWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    public let advisoryWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    public let outputWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    /// Pre-split compatibility only; never projected into one of the typed
    /// lanes because that would hide which class actually shed work.
    public let legacyDerivedWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle?
    /// Lifecycle health for unauthenticated/self-reported loopback OTLP input.
    /// A degraded value is an Agent Traces feature gap, not kernel protection.
    public let otlpReceiverLifecycle: MacCrabCore.HeartbeatSnapshot.OTLPReceiverLifecycle?
    /// Fixed-cardinality event-flow diagnostics. Nil means the running engine
    /// predates the causality block; absence must not be read as zero drops.
    public let eventPipeline: EventPipeline?
    /// Bounded browser inventory coverage. A degraded value means rows shown in
    /// Detection > Browser are partial, not a clean inventory.
    public let browserInventory: BrowserInventory?
    /// Durable continuity for in-flight multi-event sequence detections.
    /// Missing means an older engine. A rejected restore or an explicit false
    /// crash-RPO verdict is a real detection-continuity gap, not merely a
    /// storage diagnostic.
    public let sequenceCheckpoint: SequenceCheckpoint?

    public struct Collector: Sendable, Equatable, Hashable {
        public let name: String
        public let eventCount: Int
        public let healthy: Bool
        /// Optional. Nil when the collector has never ticked (event-
        /// driven collector waiting for its first event, or non-event-
        /// driven collector that has not yet completed a poll
        /// iteration). Pre-fix the daemon omitted `last_tick_unix`
        /// from heartbeat.json in this case but the dashboard
        /// fallback `as? Double ?? 0` produced epoch-0 dates that
        /// rendered as "20583d ago".
        public let lastTickUnix: Double?
        public var reason: String? = nil
        public var state: String? = nil
        public var enabled: Bool? = nil
        public var lastError: String? = nil

        public var resolvedState: V2CollectorState {
            .resolve(state: state, enabled: enabled, healthy: healthy,
                     reason: reason, lastError: lastError)
        }

        public var lastTick: Date? {
            lastTickUnix.map(Date.init(timeIntervalSince1970:))
        }
    }

    public struct EventTypeCountWindow: Sendable, Equatable {
        public let queryAvailable: Bool
        public let requestedDurationSeconds: Int
        public let effectiveDurationSeconds: Int
        public let requestedWindowComplete: Bool
        public let complete: Bool
        public let gapRecords: Int

        fileprivate init?(from raw: [String: Any]?) {
            guard let raw else { return nil }
            self.queryAvailable = raw["query_available"] as? Bool ?? false
            self.requestedDurationSeconds = max(
                0,
                raw["requested_duration_seconds"] as? Int ?? 0
            )
            self.effectiveDurationSeconds = max(
                0,
                raw["effective_duration_seconds"] as? Int ?? 0
            )
            self.requestedWindowComplete =
                raw["requested_window_complete"] as? Bool ?? false
            self.complete = raw["complete"] as? Bool ?? false
            self.gapRecords = max(0, raw["gap_records"] as? Int ?? 0)
        }
    }

    /// Live prevention state parsed from the heartbeat `prevention` block.
    public struct Prevention: Sendable, Equatable {
        public struct Module: Sendable, Equatable {
            public let enabled: Bool
            public let count: Int
            /// v1.21.4 (view/manage scaffold): the actual blocked / sinkholed /
            /// guarded entries, when the daemon reports them. The current daemon
            /// heartbeat emits COUNTS only — the DNSSinkhole / NetworkBlocker /
            /// PersistenceGuard actors keep their entry sets private and expose
            /// no list accessor, so the writer can't include them without a
            /// daemon-side (MacCrabCore) change. Defaults to `[]` and stays empty
            /// until the daemon adds an `entries: [String]` array per module —
            /// at which point the Prevention tab list renders automatically.
            public let entries: [String]
        }
        public let sinkhole: Module
        public let networkBlocker: Module
        public let persistenceGuard: Module

        init?(from raw: [String: Any]?) {
            guard let raw else { return nil }
            func module(_ key: String) -> Module {
                let m = raw[key] as? [String: Any]
                return Module(enabled: m?["enabled"] as? Bool ?? false,
                              count: m?["count"] as? Int ?? 0,
                              entries: (m?["entries"] as? [String]) ?? [])
            }
            sinkhole = module("sinkhole")
            networkBlocker = module("network_blocker")
            persistenceGuard = module("persistence_guard")
        }
    }

    public struct TraceGraphStorageAdmission: Sendable, Equatable {
        public let enabled: Bool
        public let acceptingMutations: Bool?
        public let blocked: Bool
        public let storeAvailable: Bool?
        public let startupBlocked: Bool
        public let reason: String?
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
        public let footprintBytes: Int64?
        public let freeSpaceBytes: Int64?
        public let maxFootprintBytes: Int64?
        public let freeSpaceFloorBytes: Int64?
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
        /// Shared typed decoder for the exact ingest/write ledgers carried in
        /// this same block. Keeping the equations in Core prevents the app, CLI,
        /// and MCP surfaces from drifting on what "Active" means.
        public let writeTelemetry: MacCrabCore.HeartbeatSnapshot.TraceGraphStorageAdmission?

        init?(from raw: [String: Any]?) {
            guard let raw else { return nil }
            enabled = raw["enabled"] as? Bool ?? false
            acceptingMutations = raw["accepting_mutations"] as? Bool
            blocked = raw["blocked"] as? Bool ?? false
            storeAvailable = raw["store_available"] as? Bool
            startupBlocked = raw["startup_blocked"] as? Bool ?? false
            reason = (raw["reason"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            recovering = raw["recovering"] as? Bool
            recoveryMutationWaiters = Self.int(raw["recovery_mutation_waiters"])
            recoveryMutationWaiterLimit = Self.int(raw["recovery_mutation_waiter_limit"])
            recoveryMutationQueueSaturated = raw["recovery_mutation_queue_saturated"] as? Bool
            recoveryMutationWaiterHighWatermark = Self.int(raw["recovery_mutation_waiter_high_watermark"])
            recoveryMutationWaitsTotal = Self.int64(raw["recovery_mutation_waits_total"])
            recoveryMutationWaitReleasesTotal = Self.int64(raw["recovery_mutation_wait_releases_total"])
            recoveryMutationWaitCancellationsTotal = Self.int64(raw["recovery_mutation_wait_cancellations_total"])
            recoveryMutationWaitClosedTotal = Self.int64(raw["recovery_mutation_wait_closed_total"])
            recoveryMutationWaitSaturationsTotal = Self.int64(raw["recovery_mutation_wait_saturations_total"])
            recoveryMutationWaitNanosecondsTotal = Self.int64(raw["recovery_mutation_wait_nanoseconds_total"])
            recoveryMutationMaxWaitNanoseconds = Self.int64(raw["recovery_mutation_max_wait_nanoseconds"])
            recoveryMutationOldestWaitNanoseconds = Self.int64(raw["recovery_mutation_oldest_wait_nanoseconds"])
            recoveryWriterPreemptionsTotal = Self.int64(raw["recovery_writer_preemptions_total"])
            footprintBytes = Self.int64(raw["footprint_bytes"])
            freeSpaceBytes = Self.int64(raw["free_space_bytes"])
            maxFootprintBytes = Self.int64(raw["max_footprint_bytes"])
            freeSpaceFloorBytes = Self.int64(raw["free_space_floor_bytes"])
            autoVacuumMode = Self.int(raw["auto_vacuum_mode"])
            footprintLatchTripsTotal = Self.int64(raw["footprint_latch_trips_total"])
            footprintLatchClearsTotal = Self.int64(raw["footprint_latch_clears_total"])
            recoveryRunsTotal = Self.int64(raw["recovery_runs_total"])
            recoveryTracesDeletedTotal = Self.int64(raw["recovery_traces_deleted_total"])
            recoveryTraceChildRowsDeletedTotal = Self.int64(raw["recovery_trace_child_rows_deleted_total"])
            recoveryEdgesDeletedTotal = Self.int64(raw["recovery_edges_deleted_total"])
            recoveryEntitiesDeletedTotal = Self.int64(raw["recovery_entities_deleted_total"])
            recoveryVacuumPagesReclaimedTotal = Self.int64(raw["recovery_vacuum_pages_reclaimed_total"])
            recoveryNoPhysicalProgressTotal = Self.int64(raw["recovery_no_physical_progress_total"])
            lastRecoveryFootprintBeforeBytes = Self.int64(raw["last_recovery_footprint_before_bytes"])
            lastRecoveryFootprintAfterBytes = Self.int64(raw["last_recovery_footprint_after_bytes"])
            writeTelemetry = Self.decodeWriteTelemetry(raw)
        }

        public var evidenceUnavailable: Bool {
            !enabled
                || acceptingMutations == false
                || blocked
                || storeAvailable == false
                || graphWriteDegraded
        }

        public var graphWriteDegraded: Bool {
            writeTelemetry?.graphWriteDegraded ?? true
        }

        public var operatorDetail: String {
            let rawReason = reason ?? "unknown reason"
            let readableReason = rawReason.replacingOccurrences(of: "_", with: " ")
            if startupBlocked {
                return "The TraceGraph store was paused at startup (\(readableReason)). Detection continues, but new causal evidence is not being recorded. Free disk space or adjust the TraceGraph storage limit, then restart MacCrab."
            }
            if storeAvailable == false {
                return "The TraceGraph store is unavailable (\(readableReason)). Detection continues, but new causal evidence is not being recorded."
            }
            if !enabled {
                return "TraceGraph persistence is disabled (\(readableReason)). Detection continues, but new causal evidence is not being recorded."
            }
            if blocked {
                return "TraceGraph hard storage admission is blocked (\(readableReason)). Detection continues, but new causal evidence is being shed until bounded maintenance restores write headroom."
            }
            if acceptingMutations == false {
                if recoveryMutationQueueSaturated == true {
                    return "TraceGraph recovery is still running, but its bounded foreground mutation queue is saturated. New causal evidence cannot currently enter the store; queued \(recoveryMutationWaiters ?? -1) of \(recoveryMutationWaiterLimit ?? -1), with \(recoveryMutationWaitSaturationsTotal ?? -1) saturation refusal(s) since boot."
                }
                return "TraceGraph is not accepting new causal mutations even though no hard storage block was reported. The recovery handoff or writer handle is degraded."
            }
            if let telemetry = writeTelemetry, telemetry.graphWriteDegraded {
                var failures: [String] = []
                if telemetry.recoveryMutationWaitConservationMaintained == false {
                    failures.append("the recovery-wait ledger does not conserve")
                }
                if (telemetry.recoveryMutationWaitSaturationsTotal ?? 0) > 0 {
                    failures.append("the bounded recovery queue saturated")
                }
                if let events = telemetry.ingestEventsFailedTotal, events > 0 {
                    failures.append("\(events) input event(s) failed")
                }
                if let batches = telemetry.writeBatchesFailedTotal, batches > 0 {
                    failures.append("\(batches) batch(es) failed")
                }
                if telemetry.writeConservationMaintained == false {
                    failures.append("persistence accounting does not conserve")
                }
                if telemetry.hasOutstandingBacklog == true {
                    let age = telemetry.oldestOutstandingAgeSeconds ?? 0
                    failures.append(
                        "the oldest pending or in-flight batch has waited "
                            + String(format: "%.2f", age)
                            + " seconds (live persistence deadline: "
                            + String(format: "%.2f", CausalGraphWriteResponsiveness.maximumOutstandingAgeSeconds)
                            + " seconds)"
                    )
                } else if telemetry.hasOutstandingBacklog == nil {
                    failures.append("pending-write timing is missing or invalid")
                }
                let detail = failures.isEmpty
                    ? "rolling-graph persistence health is degraded"
                    : failures.joined(separator: "; ")
                return "TraceGraph admission is active, but new causal evidence is not fully durable: \(detail). Failed totals remain visible for this engine run. Pending work is degraded only when its measured age exceeds the live persistence deadline or its timing cannot be verified."
            }
            if writeTelemetry == nil {
                return "TraceGraph persistence telemetry is unreadable. Current causal evidence durability cannot be verified."
            }
            return "TraceGraph evidence persistence is active."
        }

        public var diagnosticDictionary: [String: Any] {
            var value: [String: Any] = [
                "enabled": enabled,
                "blocked": blocked,
                "startup_blocked": startupBlocked,
                "write_degraded": graphWriteDegraded,
            ]
            if let acceptingMutations {
                value["accepting_mutations"] = acceptingMutations
            }
            if let storeAvailable { value["store_available"] = storeAvailable }
            if let reason { value["reason"] = reason }
            if let telemetry = writeTelemetry,
               let data = try? JSONEncoder().encode(telemetry),
               let decoded = try? JSONSerialization.jsonObject(with: data),
               let object = decoded as? [String: Any] {
                value.merge(object) { _, typed in typed }
                if let maintained = telemetry.writeConservationMaintained {
                    value["write_conservation_maintained"] = maintained
                }
                if let failed = telemetry.hasStickyWriteFailure {
                    value["sticky_write_failure"] = failed
                }
                if let backlog = telemetry.hasOutstandingBacklog {
                    value["outstanding_backlog"] = backlog
                }
                if let conserving =
                    telemetry.recoveryMutationWaitConservationMaintained {
                    value["recovery_mutation_wait_conservation_maintained"] =
                        conserving
                }
                if telemetry.recoveryMutationTelemetryPresent {
                    value["recovery_mutation_barrier_degraded"] = telemetry
                        .recoveryMutationBarrierDegraded
                }
            }
            return value
        }

        private static func int64(_ value: Any?) -> Int64? {
            if let value = value as? Int64 { return value }
            if let value = value as? Int { return Int64(value) }
            if let value = value as? NSNumber { return value.int64Value }
            return nil
        }

        private static func int(_ value: Any?) -> Int? {
            if let value = value as? Int { return value }
            if let value = value as? NSNumber { return value.intValue }
            return nil
        }

        private static func decodeWriteTelemetry(
            _ raw: [String: Any]
        ) -> MacCrabCore.HeartbeatSnapshot.TraceGraphStorageAdmission? {
            guard JSONSerialization.isValidJSONObject(raw),
                  let data = try? JSONSerialization.data(withJSONObject: raw)
            else { return nil }
            return try? JSONDecoder().decode(
                MacCrabCore.HeartbeatSnapshot.TraceGraphStorageAdmission.self,
                from: data
            )
        }
    }

    public struct EventPipeline: Sendable, Equatable {
        public let offeredBySource: [String: UInt64]
        public let offeredBySourceAndLane: [String: [String: UInt64]]
        public let droppedBySourceAndLane: [String: [String: UInt64]]
        public let terminatedBySourceAndLane: [String: [String: UInt64]]
        public let collectorOfferedBySourceAndLane: [String: [String: UInt64]]
        public let upstreamDroppedBySourceAndLane: [String: [String: UInt64]]
        public let upstreamTerminatedBySourceAndLane: [String: [String: UInt64]]
        public let mergedDroppedBySourceAndLane: [String: [String: UInt64]]
        public let mergedTerminatedBySourceAndLane: [String: [String: UInt64]]
        public let offeredByLane: [String: UInt64]
        public let dequeuedByLane: [String: UInt64]
        public let ruleEvaluationReachedByLaneAndCategory: [String: [String: UInt64]]
        public let ruleEvaluationCompletedByLaneAndCategory: [String: [String: UInt64]]
        public let completedByLane: [String: UInt64]
        public let backlogEstimateByLane: [String: UInt64]
        public let inFlightByLane: [String: UInt64]
        public let processingP99MicrosByLane: [String: UInt64]
        public let latencySampleCountByLane: [String: UInt64]
        public let upstreamDroppedByLane: [String: UInt64]
        public let upstreamTerminatedByLane: [String: UInt64]
        public let mergedDroppedByLane: [String: UInt64]
        public let mergedTerminatedByLane: [String: UInt64]
        public let collectorCapacityBySource: [String: UInt64]
        public let preBufferDroppedBySource: [String: UInt64]
        public let detectionInputDroppedTotal: UInt64
        public let capacityByLane: [String: UInt64]
        public let collectorBuffer: [String: UInt64]

        init?(from raw: [String: Any]?) {
            guard let raw else { return nil }
            offeredBySource = Self.counterMap(raw["offered_by_source"])
            offeredBySourceAndLane = Self.nestedCounterMap(
                raw["offered_by_source_and_lane"]
            )
            droppedBySourceAndLane = Self.nestedCounterMap(
                raw["dropped_by_source_and_lane"]
            )
            terminatedBySourceAndLane = Self.nestedCounterMap(
                raw["terminated_by_source_and_lane"]
            )
            collectorOfferedBySourceAndLane = Self.nestedCounterMap(
                raw["collector_offered_by_source_and_lane"]
            )
            upstreamDroppedBySourceAndLane = Self.nestedCounterMap(
                raw["upstream_dropped_by_source_and_lane"]
            )
            upstreamTerminatedBySourceAndLane = Self.nestedCounterMap(
                raw["upstream_terminated_by_source_and_lane"]
            )
            mergedDroppedBySourceAndLane = Self.nestedCounterMap(
                raw["merged_dropped_by_source_and_lane"]
            )
            mergedTerminatedBySourceAndLane = Self.nestedCounterMap(
                raw["merged_terminated_by_source_and_lane"]
            )
            offeredByLane = Self.counterMap(raw["offered_by_lane"])
            dequeuedByLane = Self.counterMap(raw["dequeued_by_lane"])
            ruleEvaluationReachedByLaneAndCategory = Self.nestedCounterMap(
                raw["rule_evaluation_reached_by_lane_and_category"]
            )
            ruleEvaluationCompletedByLaneAndCategory = Self.nestedCounterMap(
                raw["rule_evaluation_completed_by_lane_and_category"]
            )
            completedByLane = Self.counterMap(raw["completed_by_lane"])
            backlogEstimateByLane = Self.counterMap(raw["backlog_estimate_by_lane"])
            inFlightByLane = Self.counterMap(raw["in_flight_by_lane"])
            processingP99MicrosByLane = Self.counterMap(raw["processing_p99_us_by_lane"])
            latencySampleCountByLane = Self.counterMap(raw["latency_sample_count_by_lane"])
            upstreamDroppedByLane = Self.counterMap(raw["upstream_dropped_by_lane"])
            upstreamTerminatedByLane = Self.counterMap(raw["upstream_terminated_by_lane"])
            mergedDroppedByLane = Self.counterMap(raw["merged_dropped_by_lane"])
            mergedTerminatedByLane = Self.counterMap(raw["merged_terminated_by_lane"])
            collectorCapacityBySource = Self.counterMap(raw["collector_capacity_by_source"])
            preBufferDroppedBySource = Self.counterMap(raw["pre_buffer_dropped_by_source"])
            detectionInputDroppedTotal = Self.counter(raw["detection_input_dropped_total"])
            capacityByLane = Self.counterMap(raw["capacity_by_lane"])
            collectorBuffer = Self.counterMap(raw["collector_buffer"])
        }

        private static func counterMap(_ value: Any?) -> [String: UInt64] {
            guard let raw = value as? [String: Any] else { return [:] }
            return raw.compactMapValues { value in
                if let value = value as? UInt64 { return value }
                if let value = value as? Int, value >= 0 { return UInt64(value) }
                if let value = value as? NSNumber {
                    return UInt64(value.stringValue)
                }
                return nil
            }
        }

        private static func nestedCounterMap(
            _ value: Any?
        ) -> [String: [String: UInt64]] {
            guard let raw = value as? [String: Any] else { return [:] }
            return raw.mapValues(counterMap)
        }

        private static func counter(_ value: Any?) -> UInt64 {
            if let value = value as? UInt64 { return value }
            if let value = value as? Int, value >= 0 { return UInt64(value) }
            if let value = value as? NSNumber {
                return UInt64(value.stringValue) ?? 0
            }
            return 0
        }

        /// Complete operator-facing wire representation used by diagnostics
        /// export. Keeping this beside decoding prevents new fields from being
        /// silently parsed and then discarded by the System workspace.
        var diagnosticDictionary: [String: Any] {
            [
                "offered_by_source": offeredBySource,
                "offered_by_source_and_lane": offeredBySourceAndLane,
                "dropped_by_source_and_lane": droppedBySourceAndLane,
                "terminated_by_source_and_lane": terminatedBySourceAndLane,
                "collector_offered_by_source_and_lane": collectorOfferedBySourceAndLane,
                "upstream_dropped_by_source_and_lane": upstreamDroppedBySourceAndLane,
                "upstream_terminated_by_source_and_lane": upstreamTerminatedBySourceAndLane,
                "merged_dropped_by_source_and_lane": mergedDroppedBySourceAndLane,
                "merged_terminated_by_source_and_lane": mergedTerminatedBySourceAndLane,
                "offered_by_lane": offeredByLane,
                "dequeued_by_lane": dequeuedByLane,
                "rule_evaluation_reached_by_lane_and_category": ruleEvaluationReachedByLaneAndCategory,
                "rule_evaluation_completed_by_lane_and_category": ruleEvaluationCompletedByLaneAndCategory,
                "completed_by_lane": completedByLane,
                "backlog_estimate_by_lane": backlogEstimateByLane,
                "in_flight_by_lane": inFlightByLane,
                "processing_p99_us_by_lane": processingP99MicrosByLane,
                "latency_sample_count_by_lane": latencySampleCountByLane,
                "upstream_dropped_by_lane": upstreamDroppedByLane,
                "upstream_terminated_by_lane": upstreamTerminatedByLane,
                "merged_dropped_by_lane": mergedDroppedByLane,
                "merged_terminated_by_lane": mergedTerminatedByLane,
                "collector_capacity_by_source": collectorCapacityBySource,
                "pre_buffer_dropped_by_source": preBufferDroppedBySource,
                "detection_input_dropped_total": detectionInputDroppedTotal,
                "capacity_by_lane": capacityByLane,
                "collector_buffer": collectorBuffer,
            ]
        }
    }

    public struct BrowserInventory: Sendable, Equatable {
        public let coverageKnown: Bool
        public let complete: Bool
        public let degraded: Bool
        public let reason: String?
        public let lastScanWasTruncated: Bool
        public let scansTotal: UInt64
        public let truncatedScansTotal: UInt64
        public let inspectedDirectoryEntriesTotal: UInt64
        public let truncatedDirectoriesTotal: UInt64
        public let truncatedHomesTotal: UInt64
        public let lastScanCompletedAtUnix: Double?
        public let lastScanHomes: Int
        public let lastScanInspectedDirectoryEntries: UInt64
        public let lastScanTruncatedDirectoryCount: UInt64
        public let lastScanTruncatedHomeCount: UInt64
        public let perHomeDirectoryEntryBudget: Int

        init?(from raw: [String: Any]?) {
            guard let raw else { return nil }
            coverageKnown = raw["coverage_known"] as? Bool ?? false
            complete = raw["complete"] as? Bool ?? false
            reason = (raw["reason"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            lastScanWasTruncated = raw["last_scan_was_truncated"] as? Bool ?? false
            degraded = (raw["degraded"] as? Bool ?? false)
                || !coverageKnown
                || !complete
                || lastScanWasTruncated
            scansTotal = Self.counter(raw["scans_total"])
            truncatedScansTotal = Self.counter(raw["truncated_scans_total"])
            inspectedDirectoryEntriesTotal = Self.counter(raw["inspected_directory_entries_total"])
            truncatedDirectoriesTotal = Self.counter(raw["truncated_directories_total"])
            truncatedHomesTotal = Self.counter(raw["truncated_homes_total"])
            lastScanCompletedAtUnix = raw["last_scan_completed_at_unix"] as? Double
            lastScanHomes = Self.integer(raw["last_scan_homes"])
            lastScanInspectedDirectoryEntries = Self.counter(
                raw["last_scan_inspected_directory_entries"]
            )
            lastScanTruncatedDirectoryCount = Self.counter(
                raw["last_scan_truncated_directory_count"]
            )
            lastScanTruncatedHomeCount = Self.counter(
                raw["last_scan_truncated_home_count"]
            )
            perHomeDirectoryEntryBudget = Self.integer(
                raw["per_home_directory_entry_budget"]
            )
        }

        public var operatorDetail: String {
            if !coverageKnown {
                return "The browser-extension inventory has not completed its first bounded scan. Extension counts are not yet complete."
            }
            if lastScanWasTruncated || degraded || !complete {
                return "The latest browser-extension inventory exhausted its bounded directory budget. Displayed rows are partial and absence of an extension is not evidence that it is not installed."
            }
            return "The latest bounded browser-extension inventory completed."
        }

        var diagnosticDictionary: [String: Any] {
            var value: [String: Any] = [
                "coverage_known": coverageKnown,
                "complete": complete,
                "degraded": degraded,
                "reason": reason ?? "",
                "last_scan_was_truncated": lastScanWasTruncated,
                "scans_total": scansTotal,
                "truncated_scans_total": truncatedScansTotal,
                "inspected_directory_entries_total": inspectedDirectoryEntriesTotal,
                "truncated_directories_total": truncatedDirectoriesTotal,
                "truncated_homes_total": truncatedHomesTotal,
                "last_scan_homes": lastScanHomes,
                "last_scan_inspected_directory_entries": lastScanInspectedDirectoryEntries,
                "last_scan_truncated_directory_count": lastScanTruncatedDirectoryCount,
                "last_scan_truncated_home_count": lastScanTruncatedHomeCount,
                "per_home_directory_entry_budget": perHomeDirectoryEntryBudget,
            ]
            if let lastScanCompletedAtUnix {
                value["last_scan_completed_at_unix"] = lastScanCompletedAtUnix
            }
            return value
        }

        private static func counter(_ value: Any?) -> UInt64 {
            if let value = value as? UInt64 { return value }
            if let value = value as? Int, value >= 0 { return UInt64(value) }
            if let value = value as? NSNumber {
                return UInt64(value.stringValue) ?? 0
            }
            return 0
        }

        private static func integer(_ value: Any?) -> Int {
            if let value = value as? Int { return max(0, value) }
            if let value = value as? NSNumber { return max(0, value.intValue) }
            return 0
        }
    }

    public struct SequenceCheckpoint: Sendable, Equatable {
        public let restoreStatus: String?
        public let restoreDetail: String?
        public let dirty: Bool?
        public let configuredCrashRPOSeconds: Double?
        public let crashRPOBoundCurrentlyMaintained: Bool?
        public let lastFailure: String?
        public let durableCarrierValid: Bool?
        public let orphanCleanupScanTruncated: Bool?
        public let carrierInvalidationsTotal: UInt64?
        public let lastCarrierInvalidationReason: String?
        public let stateContinuityMaintained: Bool?
        public let stateContinuityDetail: String?
        public let partialsEvictedTotal: Int?
        public let partialsInFlight: Int?
        public let pendingStepsCurrent: Int?
        public let pendingStepsEvictedTotal: Int?
        public let checkpointStateWeightBytes: Int?
        public let checkpointStateWeightRecomputedBytes: Int?
        public let checkpointStateWeightLimitBytes: Int?

        init?(from raw: [String: Any]?, runtimeRaw: [String: Any]? = nil) {
            guard let raw else { return nil }
            restoreStatus = (raw["restore_status"] as? String)
                .flatMap { $0.isEmpty ? nil : $0 }
            restoreDetail = (raw["restore_detail"] as? String)
                .flatMap { $0.isEmpty ? nil : $0 }
            dirty = raw["dirty"] as? Bool
            configuredCrashRPOSeconds = Self.double(
                raw["configured_crash_rpo_seconds"]
            )
            crashRPOBoundCurrentlyMaintained =
                raw["crash_rpo_bound_currently_maintained"] as? Bool
            lastFailure = (raw["last_failure"] as? String)
                .flatMap { $0.isEmpty ? nil : $0 }
            durableCarrierValid = raw["durable_carrier_valid"] as? Bool
            orphanCleanupScanTruncated = raw["orphan_cleanup_scan_truncated"] as? Bool
            carrierInvalidationsTotal = Self.unsigned(raw["carrier_invalidations_total"])
            lastCarrierInvalidationReason =
                (raw["last_carrier_invalidation_reason"] as? String)
                    .flatMap { $0.isEmpty ? nil : $0 }
            stateContinuityMaintained =
                runtimeRaw?["sequence_state_continuity_maintained"] as? Bool
            stateContinuityDetail =
                (runtimeRaw?["sequence_state_continuity_detail"] as? String)
                    .flatMap { $0.isEmpty ? nil : $0 }
            partialsEvictedTotal = Self.integer(
                runtimeRaw?["sequence_partials_evicted_total"]
            )
            partialsInFlight = Self.integer(
                runtimeRaw?["sequence_partials_in_flight"]
            )
            pendingStepsCurrent = Self.integer(
                runtimeRaw?["sequence_pending_steps_current"]
            )
            pendingStepsEvictedTotal = Self.integer(
                runtimeRaw?["sequence_pending_steps_evicted_total"]
            )
            checkpointStateWeightBytes = Self.integer(
                runtimeRaw?["sequence_checkpoint_state_weight_bytes"]
            )
            checkpointStateWeightRecomputedBytes = Self.integer(
                runtimeRaw?["sequence_checkpoint_state_weight_recomputed_bytes"]
            )
            checkpointStateWeightLimitBytes = Self.integer(
                runtimeRaw?["sequence_checkpoint_state_weight_limit_bytes"]
            )
        }

        public var degraded: Bool {
            restoreStatus == "rejected"
                || crashRPOBoundCurrentlyMaintained == false
                || durableCarrierValid == false
                || orphanCleanupScanTruncated == true
                || stateContinuityMaintained == false
        }

        public var operatorDetail: String {
            if stateContinuityMaintained == false {
                let reason = stateContinuityDetail ?? "runtime state loss or accounting drift"
                return "MacCrab's live multi-event detection state is degraded (\(reason)). Some in-flight sequences may have been evicted or cannot be accounted for exactly."
            }
            if durableCarrierValid == false {
                return "MacCrab does not currently have a verified durable sequence checkpoint carrier. Detection continues, but restart recovery is unavailable."
            }
            if orphanCleanupScanTruncated == true {
                return "MacCrab could not completely inspect its bounded checkpoint-temporary-file set. Restart continuity may still be current, but its checkpoint disk budget is not fully verified."
            }
            if restoreStatus == "rejected" {
                return "MacCrab rejected the previous sequence checkpoint instead of trusting incompatible or damaged state. In-flight multi-event detections from before this engine start could not be recovered."
            }
            if crashRPOBoundCurrentlyMaintained == false {
                return "MacCrab cannot currently guarantee its configured restart-recovery window for in-flight multi-event detections. Detection continues, but a crash could lose partial sequence state."
            }
            if let seconds = configuredCrashRPOSeconds {
                let recovered = (carrierInvalidationsTotal ?? 0) > 0
                    ? " A prior carrier invalidation was repaired and remains recorded."
                    : ""
                return "In-flight multi-event sequence state is durably recoverable within the configured \(Int(seconds.rounded()))-second crash window.\(recovered)"
            }
            return "In-flight multi-event sequence state is durably recoverable."
        }

        var diagnosticDictionary: [String: Any] {
            var value: [String: Any] = [:]
            if let restoreStatus { value["restore_status"] = restoreStatus }
            if let restoreDetail { value["restore_detail"] = restoreDetail }
            if let dirty { value["dirty"] = dirty }
            if let configuredCrashRPOSeconds {
                value["configured_crash_rpo_seconds"] = configuredCrashRPOSeconds
            }
            if let crashRPOBoundCurrentlyMaintained {
                value["crash_rpo_bound_currently_maintained"] = crashRPOBoundCurrentlyMaintained
            }
            if let lastFailure { value["last_failure"] = lastFailure }
            if let durableCarrierValid { value["durable_carrier_valid"] = durableCarrierValid }
            if let orphanCleanupScanTruncated {
                value["orphan_cleanup_scan_truncated"] = orphanCleanupScanTruncated
            }
            if let carrierInvalidationsTotal {
                value["carrier_invalidations_total"] = carrierInvalidationsTotal
            }
            if let lastCarrierInvalidationReason {
                value["last_carrier_invalidation_reason"] = lastCarrierInvalidationReason
            }
            if let stateContinuityMaintained {
                value["state_continuity_maintained"] = stateContinuityMaintained
            }
            if let stateContinuityDetail {
                value["state_continuity_detail"] = stateContinuityDetail
            }
            if let partialsEvictedTotal { value["partials_evicted_total"] = partialsEvictedTotal }
            if let partialsInFlight { value["partials_in_flight"] = partialsInFlight }
            if let pendingStepsCurrent { value["pending_steps_current"] = pendingStepsCurrent }
            if let pendingStepsEvictedTotal {
                value["pending_steps_evicted_total"] = pendingStepsEvictedTotal
            }
            if let checkpointStateWeightBytes {
                value["checkpoint_state_weight_bytes"] = checkpointStateWeightBytes
            }
            if let checkpointStateWeightRecomputedBytes {
                value["checkpoint_state_weight_recomputed_bytes"] = checkpointStateWeightRecomputedBytes
            }
            if let checkpointStateWeightLimitBytes {
                value["checkpoint_state_weight_limit_bytes"] = checkpointStateWeightLimitBytes
            }
            return value
        }

        private static func double(_ value: Any?) -> Double? {
            if let value = value as? Double { return value }
            if let value = value as? Int { return Double(value) }
            if let value = value as? NSNumber { return value.doubleValue }
            return nil
        }

        private static func integer(_ value: Any?) -> Int? {
            if let value = value as? Int { return value }
            if let value = value as? NSNumber { return value.intValue }
            return nil
        }

        private static func unsigned(_ value: Any?) -> UInt64? {
            if let value = value as? UInt64 { return value }
            if let value = value as? Int, value >= 0 { return UInt64(value) }
            if let value = value as? NSNumber {
                return UInt64(value.stringValue)
            }
            return nil
        }
    }

    /// Engine LLM health parsed from the heartbeat `llm` block.
    public struct LLMHealth: Sendable, Equatable {
        public let configured: Bool
        public let provider: String
        public let model: String
        public let lastSuccessUnix: Double?
        public let consecutiveFailures: Int
        public let circuitOpen: Bool
        public let healthy: Bool
        public let runtimeTelemetry: LLMRuntimeTelemetrySnapshot?
        public let runtimeTelemetryEncodingFailed: Bool
        private let sharedRuntimeHealth: MacCrabCore.HeartbeatSnapshot.LLMHealth?

        init(from raw: [String: Any]) {
            configured = raw["configured"] as? Bool ?? false
            provider = raw["provider"] as? String ?? ""
            model = raw["model"] as? String ?? ""
            let ls = raw["last_success_unix"] as? Double ?? 0
            lastSuccessUnix = ls > 0 ? ls : nil
            consecutiveFailures = raw["consecutive_failures"] as? Int ?? 0
            circuitOpen = raw["circuit_open"] as? Bool ?? false
            healthy = raw["healthy"] as? Bool ?? false
            sharedRuntimeHealth = Self.decodeSharedRuntimeHealth(raw)
            runtimeTelemetry = sharedRuntimeHealth?.runtimeTelemetry
                ?? Self.decodeRuntimeTelemetry(raw["runtime_telemetry"])
            runtimeTelemetryEncodingFailed =
                raw["runtime_telemetry_encoding_failed"] as? Bool ?? false
        }

        public var runtimeConservationMaintained: Bool? {
            if let verdict = sharedRuntimeHealth?.runtimeConservationMaintained {
                return verdict
            }
            guard let telemetry = runtimeTelemetry else {
                return runtimeTelemetryEncodingFailed ? false : nil
            }
            let counters = [telemetry.totals] + telemetry.perFeature.map(\.counters)
            return counters.allSatisfy {
                $0.conservationMaintained
                    && $0.backendAdmissionConservationMaintained
                    && $0.circuitRecoveryConservationMaintained
                    && $0.downstreamValidation.conservationMaintained
            }
        }

        public var unspecifiedRequestsTotal: UInt64? {
            sharedRuntimeHealth?.unspecifiedRequestsTotal
                ?? runtimeTelemetry?.counters(for: .unspecified)?.requestedTotal
        }

        public var semanticRetriesTotal: UInt64? {
            runtimeTelemetry?.totals.downstreamValidation.retryRequested
        }

        public var semanticFinalRejectionsTotal: UInt64? {
            runtimeTelemetry?.totals.downstreamValidation.finalRejection
        }

        public var runtimeRequiresAttention: Bool {
            guard configured else { return false }
            if runtimeTelemetryEncodingFailed
                || sharedRuntimeHealth?.runtimeTelemetryDegraded == true {
                return true
            }
            // Outcome counters are process-lifetime diagnostics. A failure,
            // shed, oversize reply, or semantic rejection from hours ago must
            // not permanently pin current health red after a real success has
            // reset the failure streak. Current operational failure is already
            // represented by the service-owned streak/circuit state; ledger
            // conservation and unattributed calls remain structural defects.
            return runtimeConservationMaintained == false
                || (unspecifiedRequestsTotal ?? 0) > 0
                || circuitOpen
                || consecutiveFailures > 0
        }

        public var runtimeOperatorDetail: String {
            guard let totals = runtimeTelemetry?.totals else {
                return runtimeTelemetryEncodingFailed
                    ? "MacCrab could not encode its content-free AI runtime ledger. Request health and feature attribution are unknown."
                    : "AI runtime accounting is unavailable from this engine."
            }
            let outcomes = totals.outcomes
            let semantic = totals.downstreamValidation
            let features = runtimeTelemetry?.perFeature.map {
                "\($0.feature.rawValue) \($0.counters.requestedTotal)"
            }.joined(separator: ", ") ?? "unavailable"
            return "Process-lifetime ledger: \(totals.requestedTotal) request(s), \(totals.currentInFlight) in flight; outcomes: success \(outcomes.success), cache \(outcomes.cacheHit), backend failure \(outcomes.backendFailure), circuit rejection \(outcomes.circuitRejection), privacy rejection \(outcomes.privacyRejection), admission shed \(outcomes.admissionShed), cancellation \(outcomes.cancellation), oversize \(outcomes.responseOversize). Accounting: \(runtimeConservationMaintained == true ? "conserving" : "degraded"); unspecified feature: \(unspecifiedRequestsTotal ?? 0); semantic validation: operations \(semantic.operationsStartedTotal), current \(semantic.currentOperations), accepted \(semantic.accepted), retries \(semantic.retryRequested), final rejection \(semantic.finalRejection). Requests by fixed feature: \(features). Historical outcome counts do not describe current health. No prompt or response content is retained in these metrics."
        }

        /// One-line operator-facing summary of engine LLM state.
        public var summary: String {
            if !configured { return "Not configured for the engine" }
            let who = "\(provider)/\(model)"
            if runtimeRequiresAttention {
                return "\(who) — runtime quality needs attention"
            }
            if healthy { return "\(who) — healthy" }
            if circuitOpen { return "\(who) — circuit open (repeated failures)" }
            if lastSuccessUnix == nil { return "\(who) — enabled, but no successful call yet" }
            // AI-08: the reachable-but-failing state — the branch a backend
            // that died after one good call now lands in. "degraded" alone gave
            // the operator nothing to act on; name the failure streak, since
            // this is the only place the LLM's real state is shown in the UI.
            if consecutiveFailures > 0 {
                return "\(who) — last \(consecutiveFailures) call(s) failed; AI analysis is paused until one succeeds"
            }
            return "\(who) — degraded"
        }

        public var diagnosticDictionary: [String: Any] {
            var value: [String: Any] = [
                "configured": configured,
                "provider": provider,
                "model": model,
                "consecutive_failures": consecutiveFailures,
                "circuit_open": circuitOpen,
                "healthy": healthy,
                "runtime_telemetry_encoding_failed": runtimeTelemetryEncodingFailed,
            ]
            if let lastSuccessUnix { value["last_success_unix"] = lastSuccessUnix }
            if let runtimeTelemetry,
               let data = try? JSONEncoder().encode(runtimeTelemetry),
               let object = try? JSONSerialization.jsonObject(with: data) {
                value["runtime_telemetry"] = object
            }
            return value
        }

        private static func decodeRuntimeTelemetry(_ value: Any?) -> LLMRuntimeTelemetrySnapshot? {
            guard let value, JSONSerialization.isValidJSONObject(value),
                  let data = try? JSONSerialization.data(withJSONObject: value)
            else { return nil }
            return try? JSONDecoder().decode(LLMRuntimeTelemetrySnapshot.self, from: data)
        }

        private static func decodeSharedRuntimeHealth(
            _ raw: [String: Any]
        ) -> MacCrabCore.HeartbeatSnapshot.LLMHealth? {
            guard JSONSerialization.isValidJSONObject(raw),
                  let data = try? JSONSerialization.data(withJSONObject: raw)
            else { return nil }
            return try? JSONDecoder().decode(
                MacCrabCore.HeartbeatSnapshot.LLMHealth.self,
                from: data
            )
        }
    }

    /// Compatibility entry point; source selection is fixed for this session.
    public static func readFreshest() -> V2HeartbeatSnapshot? {
        V2EngineSource.session.heartbeat()
    }

    /// Read readiness even before the first rich heartbeat. Merge only telemetry
    /// from this process epoch; an old store must not make a restarting engine
    /// appear to have healthy, running collectors.
    static func read(directory: String, now: Date = Date()) -> V2HeartbeatSnapshot? {
        func payload(_ name: String) -> [String: Any]? {
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: directory + "/" + name))
            else { return nil }
            return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
        let minimal = payload("heartbeat.json")
        let rich = payload("heartbeat_rich.json")
        var combined: [String: Any]
        if let minimal {
            combined = rich.flatMap {
                V2HeartbeatPayload.currentRich($0, minimal: minimal, now: now) ? $0 : nil
            } ?? [:]
            // Minimal heartbeat fields are written independently and describe
            // the current process. Keep richer schema/count-window metadata.
            for (key, value) in minimal where key != "schema_version" || combined[key] == nil {
                combined[key] = value
            }
        } else if let rich {
            combined = rich
        } else {
            return nil
        }
        guard let written = combined["written_at_unix"] as? TimeInterval,
              written.isFinite, now.timeIntervalSince1970 - written >= 0,
              now.timeIntervalSince1970 - written <= 300 else { return nil }
        return decode(raw: combined)
    }

    /// Internal fixture seam; production callers use `readFreshest()`.
    static func decode(at path: String) -> V2HeartbeatSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return decode(raw: raw)
    }

    static func decode(raw: [String: Any]) -> V2HeartbeatSnapshot {
        let writtenAt = Date(timeIntervalSince1970: TimeInterval(
            raw["written_at_unix"] as? Double ?? 0
        ))
        let collectorRaw = raw["collector_health"] as? [[String: Any]] ?? []
        let collectors: [Collector] = collectorRaw.compactMap { c in
            guard let name = c["name"] as? String else { return nil }
            return Collector(
                name: name,
                eventCount: c["event_count"] as? Int ?? 0,
                healthy: c["healthy"] as? Bool ?? false,
                lastTickUnix: c["last_tick_unix"] as? Double,
                reason: c["reason"] as? String,
                state: c["state"] as? String,
                enabled: c["enabled"] as? Bool,
                lastError: c["last_error"] as? String
            )
        }
        let legacyCounts: [String: Int] = (raw["event_type_counts_1h"] as? [String: Any])?
            .compactMapValues { $0 as? Int } ?? [:]
        let eventTypeCounts: [String: Int] =
            (raw["event_type_counts"] as? [String: Any])?
                .compactMapValues { $0 as? Int } ?? legacyCounts
        let eventTypeCountWindow = EventTypeCountWindow(
            from: raw["event_type_count_window"] as? [String: Any]
        )
        let llm = (raw["llm"] as? [String: Any]).map(LLMHealth.init(from:))
        let prevention = Prevention(from: raw["prevention"] as? [String: Any])
        let traceGraphStorageAdmission = TraceGraphStorageAdmission(
            from: raw["tracegraph_storage_admission"] as? [String: Any]
        )
        let traceStoreStorageAdmission = TraceGraphStorageAdmission(
            from: raw["traces_storage_admission"] as? [String: Any]
        )
        let alertEvidenceBudget: MacCrabCore.HeartbeatSnapshot.AlertEvidenceBudget? =
            decodeCoreBlock(raw["alert_evidence_budget"])
        let timerLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["timer_lifecycle"])
        let livenessTimerLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["liveness_timer_lifecycle"])
        let startupWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["startup_work_lifecycle"])
        let detectionWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["detection_work_lifecycle"])
        let advisoryWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["advisory_work_lifecycle"])
        let outputWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["output_work_lifecycle"])
        let legacyDerivedWorkLifecycle: MacCrabCore.HeartbeatSnapshot.TimerLifecycle? =
            decodeCoreBlock(raw["derived_work_lifecycle"])
        let otlpReceiverLifecycle: MacCrabCore.HeartbeatSnapshot.OTLPReceiverLifecycle? =
            decodeCoreBlock(raw["otlp_receiver_lifecycle"])
        let eventPipeline = EventPipeline(
            from: raw["event_pipeline"] as? [String: Any]
        )
        let browserInventory = BrowserInventory(
            from: raw["browser_inventory"] as? [String: Any]
        )
        let sequenceCheckpoint = SequenceCheckpoint(
            from: raw["sequence_checkpoint"] as? [String: Any],
            runtimeRaw: raw
        )
        return V2HeartbeatSnapshot(
            writtenAt: writtenAt,
            bootPhase: raw["boot_phase"] as? String,
            liveness: raw["liveness"] as? Bool,
            rulesLoaded: raw["rules_loaded"] as? Int,
            engineIdentity: EngineTelemetryIdentity(heartbeat: raw),
            dnsCapture: (raw["dns_capture"] as? [String: Any]).map(V2DNSCaptureStatus.init),
            uptimeSeconds: raw["uptime_seconds"] as? Int ?? 0,
            eventsProcessed: raw["events_processed"] as? Int ?? 0,
            alertsEmitted: raw["alerts_emitted"] as? Int ?? 0,
            residentMemoryMB: raw["resident_memory_mb"] as? Int,
            sysextHasFDA: raw["sysext_has_fda"] as? Bool ?? false,
            schemaVersion: raw["schema_version"] as? Int ?? 0,
            eventTypeCounts: eventTypeCounts,
            eventTypeCountWindow: eventTypeCountWindow,
            eventTypeCounts1h: legacyCounts,
            collectors: collectors,
            // Wave 9O: pre-9O these keys were emitted by DaemonTimers
            // (Wave 9K) but silently dropped here. Default to 0 when
            // missing so legacy heartbeats from older daemons that
            // pre-date Wave 9K render as "no truncation, no drops"
            // rather than crash.
            payloadTruncatedTotal: raw["payload_truncated_total"] as? Int ?? 0,
            esloggerDroppedTotal: raw["eslogger_dropped_total"] as? Int ?? 0,
            // Phase-1 D2 — defaults to "not degraded" on legacy heartbeats.
            esSensorDegraded: raw["es_sensor_degraded"] as? Bool ?? false,
            esSensorDegradedDetail: (raw["es_sensor_degraded_detail"] as? String).flatMap { $0.isEmpty ? nil : $0 },
            esSensorDegradedSeverity: (raw["es_sensor_degraded_severity"] as? String).flatMap { $0.isEmpty ? nil : $0 },
            llm: llm,
            prevention: prevention,
            traceGraphStorageAdmission: traceGraphStorageAdmission,
            traceStoreStorageAdmission: traceStoreStorageAdmission,
            alertEvidenceBudget: alertEvidenceBudget,
            alertInsertErrorsTotal: alertWriteFailureCount(from: raw),
            timerLifecycle: timerLifecycle,
            livenessTimerLifecycle: livenessTimerLifecycle,
            startupWorkLifecycle: startupWorkLifecycle,
            detectionWorkLifecycle: detectionWorkLifecycle,
            advisoryWorkLifecycle: advisoryWorkLifecycle,
            outputWorkLifecycle: outputWorkLifecycle,
            legacyDerivedWorkLifecycle: legacyDerivedWorkLifecycle,
            otlpReceiverLifecycle: otlpReceiverLifecycle,
            eventPipeline: eventPipeline,
            browserInventory: browserInventory,
            sequenceCheckpoint: sequenceCheckpoint
        )
    }

    private static func decodeCoreBlock<T: Decodable>(_ value: Any?) -> T? {
        guard let value, JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value)
        else { return nil }
        return try? JSONDecoder().decode(T.self, from: data)
    }

    /// Keep the app's two heartbeat consumers consistent. Decoding as Int
    /// rejects booleans, strings, fractional counts and overflow; a present
    /// null/negative/malformed value must not silently clear the warning.
    static func alertWriteFailureCount(from raw: [String: Any]) -> Int? {
        guard let value = raw["alert_insert_errors_total"] else { return 0 }
        struct Counter: Decodable { let count: Int }
        guard let data = try? JSONSerialization.data(withJSONObject: ["count": value]),
              let decoded = try? JSONDecoder().decode(Counter.self, from: data),
              decoded.count >= 0 else { return nil }
        return decoded.count
    }
}

extension V2HeartbeatSnapshot {
    /// Human-friendly uptime, e.g. "2h 14m" or "12d".
    public var uptimeDisplay: String {
        let s = uptimeSeconds
        if s < 60        { return "\(s)s" }
        if s < 3600      { return "\(s / 60)m" }
        if s < 86_400    {
            let h = s / 3600, m = (s % 3600) / 60
            return m > 0 ? "\(h)h \(m)m" : "\(h)h"
        }
        let d = s / 86_400, h = (s % 86_400) / 3600
        return h > 0 ? "\(d)d \(h)h" : "\(d)d"
    }

    /// Rolling event rate in events/sec only when the daemon proves the full
    /// requested interval. `nil` means unknown, never an observed zero.
    public var eventsPerSecond1h: Double? {
        if let window = eventTypeCountWindow {
            guard window.queryAvailable,
                  window.complete,
                  window.requestedWindowComplete,
                  window.requestedDurationSeconds > 0 else { return nil }
            let total = eventTypeCounts.values.reduce(0, +)
            return Double(total) / Double(window.requestedDurationSeconds)
        }
        // A pre-window-contract heartbeat's `_1h` field is its compatibility
        // proof. Empty counts still represent an observed zero for that old
        // schema, not a failed new query.
        let total = eventTypeCounts1h.values.reduce(0, +)
        return Double(total) / 3600.0
    }
}
