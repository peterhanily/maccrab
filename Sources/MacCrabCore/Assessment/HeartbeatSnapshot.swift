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
    /// Total userspace-eviction drops folded by the collector registry
    /// (a SUPERSET of the merged-stream detection-input drops below).
    public let eventsDropped: Int?

    // MARK: Rule coverage
    public let rulesLoaded: Int?
    public let rulesActive: Int?

    // MARK: Nested health blocks
    public let collectorHealth: [CollectorHealth]?
    public let llm: LLMHealth?
    public let prevention: Prevention?
    public let traceRegistry: TraceRegistry?

    // MARK: Drop attribution (the gauges the app decoder omitted)
    /// Native ES per-client kernel ingest-drops. Distinct from `eventsDropped`
    /// (userspace AsyncStream eviction) — the kernel/userspace split is the
    /// whole point of the drop-attribution methodology.
    public let esKernelDroppedTotal: Int?
    public let esKernelDroppedByType: [String: Int]?
    public let esProcessedByType: [String: Int]?
    public let esCopyBackpressureDroppedTotal: Int?
    public let esStreamYieldDroppedTotal: Int?
    public let esloggerDroppedTotal: Int?
    /// Merged priority-stream detection-input drops (lost exec/process events).
    public let mergedPriorityDroppedTotal: Int?
    /// Merged file-stream detection-input drops (file-noise flood).
    public let mergedFileDroppedTotal: Int?
    /// Aggregate detection-input loss (priority + file). A SUBSET of
    /// `eventsDropped`; the single "did the engine lose detection input" gauge.
    public let detectionInputDroppedTotal: Int?
    /// Batched-writer storage-layer drop — a storage loss, NOT a detection gap.
    public let eventsStorageWriteDroppedTotal: Int?
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
    /// AES-GCM authenticated-decrypt failures — non-zero means DB tamper.
    public let dbTamperDecryptFailures: Int?

    // MARK: Full Disk Access probe
    public let fdaCheckedAtUnix: Double?
    public let sysextHasFDA: Bool?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case writtenAtUnix = "written_at_unix"
        case uptimeSeconds = "uptime_seconds"
        case buildChannel = "build_channel"
        case alertsEmitted = "alerts_emitted"
        case eventsProcessed = "events_processed"
        case eventsDropped = "events_dropped"
        case rulesLoaded = "rules_loaded"
        case rulesActive = "rules_active"
        case collectorHealth = "collector_health"
        case llm
        case prevention
        case traceRegistry = "trace_registry"
        case esKernelDroppedTotal = "es_kernel_dropped_total"
        case esKernelDroppedByType = "es_kernel_dropped_by_type"
        case esProcessedByType = "es_processed_by_type"
        case esCopyBackpressureDroppedTotal = "es_copy_backpressure_dropped_total"
        case esStreamYieldDroppedTotal = "es_stream_yield_dropped_total"
        case esloggerDroppedTotal = "eslogger_dropped_total"
        case mergedPriorityDroppedTotal = "merged_priority_dropped_total"
        case mergedFileDroppedTotal = "merged_file_dropped_total"
        case detectionInputDroppedTotal = "detection_input_dropped_total"
        case eventsStorageWriteDroppedTotal = "events_storage_write_dropped_total"
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

        private enum CodingKeys: String, CodingKey {
            case name
            case healthy
            case lastTick = "last_tick_unix"
            case eventCount = "event_count"
            case errorCount = "error_count"
            case lastError = "last_error"
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

        private enum CodingKeys: String, CodingKey {
            case configured
            case provider
            case model
            case lastSuccessUnix = "last_success_unix"
            case consecutiveFailures = "consecutive_failures"
            case circuitOpen = "circuit_open"
            case healthy
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
        guard let age = ageSeconds(now: now) else { return true }
        return age > maxAge
    }
}
