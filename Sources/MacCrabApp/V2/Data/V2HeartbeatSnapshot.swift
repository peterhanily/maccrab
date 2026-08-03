// V2HeartbeatSnapshot.swift
// View model derived from the daemon's `heartbeat_rich.json` file
// (written every 30s by `Sources/MacCrabAgentKit/DaemonTimers.swift`).
// Used by the System workspace to replace hardcoded health metrics
// with real ones.

import Foundation

public struct V2HeartbeatSnapshot: Sendable, Equatable {
    public let writtenAt: Date

    /// v1.21.4: canonical staleness threshold — MUST match
    /// AppState.HeartbeatSnapshot.staleThreshold (120s) so every workspace
    /// agrees on "live vs degraded". `readFreshest()` only nils heartbeats
    /// older than 300s, so a 120–300s-old heartbeat is returned NON-nil and
    /// callers that treated non-nil as "live" (System "Daemon: Running",
    /// Prevention "on" chips) falsely reassured during a 2–5 min outage. Gate
    /// live/green state on `!isStale`, not merely on the snapshot existing.
    public static let staleThreshold: TimeInterval = 120
    public var isStale: Bool { Date().timeIntervalSince(writtenAt) > Self.staleThreshold }
    /// Whole seconds since the daemon last wrote a heartbeat (for "N m ago").
    public var ageSeconds: Int { max(0, Int(Date().timeIntervalSince(writtenAt))) }
    public let uptimeSeconds: Int
    public let eventsProcessed: Int
    public let alertsEmitted: Int
    public let residentMemoryMB: Int?
    public let sysextHasFDA: Bool
    public let schemaVersion: Int
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
    /// Fixed-cardinality event-flow diagnostics. Nil means the running engine
    /// predates the causality block; absence must not be read as zero drops.
    public let eventPipeline: EventPipeline?
    /// Bounded browser inventory coverage. A degraded value means rows shown in
    /// Detection > Browser are partial, not a clean inventory.
    public let browserInventory: BrowserInventory?

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

        public var lastTick: Date? {
            lastTickUnix.map(Date.init(timeIntervalSince1970:))
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
        public let blocked: Bool
        public let storeAvailable: Bool?
        public let startupBlocked: Bool
        public let reason: String?
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

        init?(from raw: [String: Any]?) {
            guard let raw else { return nil }
            enabled = raw["enabled"] as? Bool ?? false
            blocked = raw["blocked"] as? Bool ?? false
            storeAvailable = raw["store_available"] as? Bool
            startupBlocked = raw["startup_blocked"] as? Bool ?? false
            reason = (raw["reason"] as? String).flatMap { $0.isEmpty ? nil : $0 }
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
        }

        public var evidenceUnavailable: Bool {
            blocked || storeAvailable == false
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
            return "TraceGraph persistence is paused (\(readableReason)). Detection continues, but new causal evidence is currently being shed while bounded recovery runs."
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

    /// Engine LLM health parsed from the heartbeat `llm` block.
    public struct LLMHealth: Sendable, Equatable {
        public let configured: Bool
        public let provider: String
        public let model: String
        public let lastSuccessUnix: Double?
        public let consecutiveFailures: Int
        public let circuitOpen: Bool
        public let healthy: Bool

        init(from raw: [String: Any]) {
            configured = raw["configured"] as? Bool ?? false
            provider = raw["provider"] as? String ?? ""
            model = raw["model"] as? String ?? ""
            let ls = raw["last_success_unix"] as? Double ?? 0
            lastSuccessUnix = ls > 0 ? ls : nil
            consecutiveFailures = raw["consecutive_failures"] as? Int ?? 0
            circuitOpen = raw["circuit_open"] as? Bool ?? false
            healthy = raw["healthy"] as? Bool ?? false
        }

        /// One-line operator-facing summary of engine LLM state.
        public var summary: String {
            if !configured { return "Not configured for the engine" }
            let who = "\(provider)/\(model)"
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
    }

    /// Returns the freshest heartbeat from any candidate dir, or nil.
    public static func readFreshest() -> V2HeartbeatSnapshot? {
        let userDir = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        let systemDir = "/Library/Application Support/MacCrab"
        let candidates = Array(Set([userDir, systemDir]))
        let withMtime: [(String, Date)] = candidates.compactMap { dir in
            let path = dir + "/heartbeat_rich.json"
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let mtime = attrs[.modificationDate] as? Date else { return nil }
            return (path, mtime)
        }
        guard let chosen = withMtime.max(by: { $0.1 < $1.1 }) else { return nil }
        // Discard stale heartbeats (>5 minutes old).
        if chosen.1.timeIntervalSinceNow < -300 { return nil }
        return decode(at: chosen.0)
    }

    private static func decode(at path: String) -> V2HeartbeatSnapshot? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
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
                lastTickUnix: c["last_tick_unix"] as? Double
            )
        }
        let counts: [String: Int] = (raw["event_type_counts_1h"] as? [String: Any])?
            .compactMapValues { $0 as? Int } ?? [:]
        let llm = (raw["llm"] as? [String: Any]).map(LLMHealth.init(from:))
        let prevention = Prevention(from: raw["prevention"] as? [String: Any])
        let traceGraphStorageAdmission = TraceGraphStorageAdmission(
            from: raw["tracegraph_storage_admission"] as? [String: Any]
        )
        let traceStoreStorageAdmission = TraceGraphStorageAdmission(
            from: raw["traces_storage_admission"] as? [String: Any]
        )
        let eventPipeline = EventPipeline(
            from: raw["event_pipeline"] as? [String: Any]
        )
        let browserInventory = BrowserInventory(
            from: raw["browser_inventory"] as? [String: Any]
        )
        return V2HeartbeatSnapshot(
            writtenAt: writtenAt,
            uptimeSeconds: raw["uptime_seconds"] as? Int ?? 0,
            eventsProcessed: raw["events_processed"] as? Int ?? 0,
            alertsEmitted: raw["alerts_emitted"] as? Int ?? 0,
            residentMemoryMB: raw["resident_memory_mb"] as? Int,
            sysextHasFDA: raw["sysext_has_fda"] as? Bool ?? false,
            schemaVersion: raw["schema_version"] as? Int ?? 0,
            eventTypeCounts1h: counts,
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
            eventPipeline: eventPipeline,
            browserInventory: browserInventory
        )
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

    /// Rolling event rate in events/sec, derived from the 1h counts.
    public var eventsPerSecond1h: Double {
        let total = eventTypeCounts1h.values.reduce(0, +)
        return Double(total) / 3600.0
    }
}
