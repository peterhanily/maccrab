import Foundation
import MacCrabCore
import os.log

/// Thread-safe runtime ownership for the bounded schema-v8 upgrade reserve.
///
/// Candidate ownership and the actually-applied hard ceiling are deliberately
/// separate. A candidate can shrink only after a generation-matched,
/// post-checkpoint measurement proves that the complete events.db family plus
/// the 32 MiB event transaction reserve fits below the proposed ceiling.
struct LegacyEvidenceTransitionBudgetSnapshot: Sendable, Equatable {
    var rowCount: Int?
    var chargedBytes: Int64?
    var appliedReserveMiB: Int
    var pendingReserveMiB: Int?
    var pendingReserveFitsHardBoundary: Bool?
    var maximumReserveMiB: Int
    var measurementFailed: Bool
    var familyFootprintBytes: Int64?
    var proposedHardAdmissionBoundaryBytes: Int64?
    var transactionReserveBytes: Int64
    var walCheckpointDrained: Bool?
    var freelistBytes: Int64?
    var configurationGeneration: UInt64
    var staleMeasurementsDiscarded: UInt64
    var measuredAt: Date

    /// Compatibility name used by existing readers. This is the applied, not
    /// merely measured, reserve.
    var reserveMiB: Int { appliedReserveMiB }

    var transitionPending: Bool { pendingReserveMiB != nil }
}

struct LegacyEvidenceTransitionMeasurementTicket: Sendable, Equatable {
    let configurationGeneration: UInt64
    let storage: DaemonConfig.StorageConfig
}

final class LegacyEvidenceTransitionBudget: @unchecked Sendable {
    private struct RuntimeState: Sendable {
        var storage: DaemonConfig.StorageConfig
        var snapshot: LegacyEvidenceTransitionBudgetSnapshot
    }

    private let lock: OSAllocatedUnfairLock<RuntimeState>

    init(maximumReserveMiB: Int) {
        var storage = DaemonConfig.StorageConfig().clampedToSafeFloors()
        storage.evidenceMaxSizeMB = max(0, maximumReserveMiB)
        self.lock = Self.makeLock(storage: storage)
    }

    init(storageConfig: DaemonConfig.StorageConfig) {
        self.lock = Self.makeLock(
            storage: storageConfig.clampedToSafeFloors()
        )
    }

    private static func makeLock(
        storage: DaemonConfig.StorageConfig
    ) -> OSAllocatedUnfairLock<RuntimeState> {
        let maximum = max(0, storage.evidenceMaxSizeMB)
        let liveCap = storage.effectiveEventsFamilyMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB: maximum
        )
        return OSAllocatedUnfairLock(initialState:
            RuntimeState(
                storage: storage,
                snapshot: LegacyEvidenceTransitionBudgetSnapshot(
                rowCount: nil,
                chargedBytes: nil,
                appliedReserveMiB: maximum,
                pendingReserveMiB: nil,
                pendingReserveFitsHardBoundary: nil,
                maximumReserveMiB: maximum,
                measurementFailed: true,
                familyFootprintBytes: nil,
                proposedHardAdmissionBoundaryBytes:
                    SQLitePersistentStorePolicy.capBytes(maxSizeMiB: liveCap),
                transactionReserveBytes: SQLitePersistentStorePolicy
                    .eventTransactionReserveBytes,
                walCheckpointDrained: nil,
                freelistBytes: nil,
                configurationGeneration: 0,
                staleMeasurementsDiscarded: 0,
                measuredAt: Date()
                )
            )
        )
    }

    func storageConfig() -> DaemonConfig.StorageConfig {
        lock.withLock { $0.storage }
    }

    /// Publish one clamped config generation and return the ticket its
    /// asynchronous footprint measurement must present. An older timer probe
    /// can no longer overwrite a newer SIGHUP result.
    @discardableResult
    func installStorageConfig(
        _ requested: DaemonConfig.StorageConfig
    ) -> LegacyEvidenceTransitionMeasurementTicket {
        let storage = requested.clampedToSafeFloors()
        return lock.withLock { state in
            guard state.storage != storage else {
                return LegacyEvidenceTransitionMeasurementTicket(
                    configurationGeneration:
                        state.snapshot.configurationGeneration,
                    storage: state.storage
                )
            }
            state.storage = storage
            state.snapshot.configurationGeneration &+= 1
            let maximum = max(0, storage.evidenceMaxSizeMB)
            if maximum != state.snapshot.appliedReserveMiB {
                state.snapshot.pendingReserveMiB = maximum
                // Growth is footprint-safe, but remains pending until the
                // EventStore policy update succeeds. Shrink needs a new proof.
                state.snapshot.pendingReserveFitsHardBoundary =
                    maximum > state.snapshot.appliedReserveMiB
            } else {
                state.snapshot.pendingReserveMiB = nil
                state.snapshot.pendingReserveFitsHardBoundary = nil
            }
            state.snapshot.maximumReserveMiB = maximum
            state.snapshot.measurementFailed = true
            state.snapshot.rowCount = nil
            state.snapshot.chargedBytes = nil
            state.snapshot.familyFootprintBytes = nil
            state.snapshot.walCheckpointDrained = nil
            state.snapshot.freelistBytes = nil
            let candidate = state.snapshot.pendingReserveMiB
                ?? state.snapshot.appliedReserveMiB
            state.snapshot.proposedHardAdmissionBoundaryBytes =
                SQLitePersistentStorePolicy.capBytes(
                    maxSizeMiB: storage.effectiveEventsFamilyMaxSizeMB(
                        appliedLegacyEvidenceTransitionReserveMiB: candidate
                    )
                )
            state.snapshot.measuredAt = Date()
            return LegacyEvidenceTransitionMeasurementTicket(
                configurationGeneration:
                    state.snapshot.configurationGeneration,
                storage: state.storage
            )
        }
    }

    func measurementTicket() -> LegacyEvidenceTransitionMeasurementTicket {
        lock.withLock { state in
            LegacyEvidenceTransitionMeasurementTicket(
                configurationGeneration: state.snapshot.configurationGeneration,
                storage: state.storage
            )
        }
    }

    @discardableResult
    func update(
        measurement: LegacyAlertEvidenceTransitionMeasurement?,
        ticket: LegacyEvidenceTransitionMeasurementTicket
    ) -> LegacyEvidenceTransitionBudgetSnapshot {
        lock.withLock { state in
            guard ticket.configurationGeneration
                    == state.snapshot.configurationGeneration,
                  ticket.storage == state.storage else {
                state.snapshot.staleMeasurementsDiscarded &+= 1
                return state.snapshot
            }

            let maximum = max(0, state.storage.evidenceMaxSizeMB)
            state.snapshot.maximumReserveMiB = maximum
            state.snapshot.measuredAt = Date()
            state.snapshot.transactionReserveBytes =
                SQLitePersistentStorePolicy.eventTransactionReserveBytes

            guard let measurement else {
                // Measurement failure may grow to the complete configured
                // allowance, but can never shrink an already-applied reserve.
                if maximum != state.snapshot.appliedReserveMiB {
                    state.snapshot.pendingReserveMiB = maximum
                    state.snapshot.pendingReserveFitsHardBoundary =
                        maximum > state.snapshot.appliedReserveMiB
                } else {
                    state.snapshot.pendingReserveMiB = nil
                    state.snapshot.pendingReserveFitsHardBoundary = nil
                }
                state.snapshot.measurementFailed = true
                state.snapshot.rowCount = nil
                state.snapshot.chargedBytes = nil
                state.snapshot.familyFootprintBytes = nil
                state.snapshot.walCheckpointDrained = nil
                state.snapshot.freelistBytes = nil
                let candidate = state.snapshot.pendingReserveMiB
                    ?? state.snapshot.appliedReserveMiB
                state.snapshot.proposedHardAdmissionBoundaryBytes =
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage
                            .effectiveEventsFamilyMaxSizeMB(
                                appliedLegacyEvidenceTransitionReserveMiB:
                                    candidate
                            )
                    )
                return state.snapshot
            }

            let evidence = measurement.evidence
            let maximumBytes = SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: maximum
            )
            let charged = min(maximumBytes, max(0, evidence.chargedBytes))
            let candidate = evidence.rowCount == 0 || charged == 0
                ? 0
                : Int(
                    (charged - 1) / SQLitePersistentStorePolicy.bytesPerMiB + 1
                )
            let boundedCandidate = min(maximum, max(0, candidate))
            let proposedCapMiB = state.storage
                .effectiveEventsFamilyMaxSizeMB(
                    appliedLegacyEvidenceTransitionReserveMiB:
                        boundedCandidate
                )
            let proposedBoundary = SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: proposedCapMiB
            )
            let required = SQLitePersistentStoreAdmission.saturatingAdd(
                measurement.familyFootprintBytes,
                SQLitePersistentStorePolicy.eventTransactionReserveBytes
            )
            let physicalMeasurementValid = measurement.familyFootprintBytes >= 0
                && measurement.pageSizeBytes > 0
                && measurement.pageCount >= 0
                && measurement.freelistCount >= 0
                && measurement.freelistCount <= measurement.pageCount
            let shrinkIsSafe = physicalMeasurementValid
                && measurement.walCheckpointDrained
                && required <= proposedBoundary

            if boundedCandidate == state.snapshot.appliedReserveMiB {
                state.snapshot.pendingReserveMiB = nil
                state.snapshot.pendingReserveFitsHardBoundary = nil
            } else {
                state.snapshot.pendingReserveMiB = boundedCandidate
                state.snapshot.pendingReserveFitsHardBoundary =
                    boundedCandidate > state.snapshot.appliedReserveMiB
                        || shrinkIsSafe
            }

            state.snapshot.rowCount = evidence.rowCount
            state.snapshot.chargedBytes = evidence.chargedBytes
            state.snapshot.measurementFailed = !physicalMeasurementValid
            state.snapshot.familyFootprintBytes =
                measurement.familyFootprintBytes
            state.snapshot.proposedHardAdmissionBoundaryBytes =
                proposedBoundary
            state.snapshot.walCheckpointDrained =
                measurement.walCheckpointDrained
            state.snapshot.freelistBytes = measurement.freelistBytes
            return state.snapshot
        }
    }

    /// Commit a measured candidate only after EventStore has adopted the
    /// matching hard-admission policy. This makes `appliedReserveMiB` honest:
    /// a failed policy update leaves the old ceiling active and the candidate
    /// visible as pending for retry.
    @discardableResult
    func commitPendingReserve(
        _ expectedReserveMiB: Int,
        ticket: LegacyEvidenceTransitionMeasurementTicket
    ) -> LegacyEvidenceTransitionBudgetSnapshot {
        lock.withLock { state in
            guard ticket.configurationGeneration
                    == state.snapshot.configurationGeneration,
                  ticket.storage == state.storage,
                  state.snapshot.pendingReserveMiB == expectedReserveMiB,
                  state.snapshot.pendingReserveFitsHardBoundary == true else {
                return state.snapshot
            }
            state.snapshot.appliedReserveMiB = max(0, expectedReserveMiB)
            state.snapshot.pendingReserveMiB = nil
            state.snapshot.pendingReserveFitsHardBoundary = nil
            state.snapshot.measuredAt = Date()
            return state.snapshot
        }
    }

    /// Compatibility path for older integration sites. Evidence-only DBSTAT
    /// cannot authorize a physical cap reduction, so it deliberately retains
    /// the current applied reserve and exposes the measured candidate as
    /// pending until the caller adopts `legacyAlertEvidenceTransitionMeasurement`.
    @discardableResult
    func update(
        measurement: AlertEvidenceBudgetSnapshot?,
        maximumReserveMiB: Int
    ) -> LegacyEvidenceTransitionBudgetSnapshot {
        var updated = storageConfig()
        updated.evidenceMaxSizeMB = max(0, maximumReserveMiB)
        let ticket = installStorageConfig(updated)
        return lock.withLock { state in
            guard ticket.configurationGeneration
                    == state.snapshot.configurationGeneration else {
                state.snapshot.staleMeasurementsDiscarded &+= 1
                return state.snapshot
            }
            state.snapshot.measurementFailed = true
            state.snapshot.rowCount = measurement?.rowCount
            state.snapshot.chargedBytes = measurement?.chargedBytes
            state.snapshot.familyFootprintBytes = nil
            state.snapshot.walCheckpointDrained = nil
            state.snapshot.freelistBytes = nil
            if let measurement {
                let maximum = max(0, maximumReserveMiB)
                let charged = min(
                    SQLitePersistentStorePolicy.capBytes(maxSizeMiB: maximum),
                    max(0, measurement.chargedBytes)
                )
                let candidate = measurement.rowCount == 0 || charged == 0
                    ? 0
                    : Int(
                        (charged - 1)
                            / SQLitePersistentStorePolicy.bytesPerMiB + 1
                    )
                let bounded = min(maximum, max(0, candidate))
                state.snapshot.pendingReserveMiB = bounded
                state.snapshot.pendingReserveFitsHardBoundary = false
                state.snapshot.proposedHardAdmissionBoundaryBytes =
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage
                            .effectiveEventsFamilyMaxSizeMB(
                                appliedLegacyEvidenceTransitionReserveMiB:
                                    bounded
                            )
                    )
            }
            state.snapshot.measuredAt = Date()
            return state.snapshot
        }
    }

    func snapshot() -> LegacyEvidenceTransitionBudgetSnapshot {
        lock.withLock { $0.snapshot }
    }
}

/// Fail-visible snapshot of a TraceGraph store that could not open because the
/// storage-admission gate fired during initialization.  The store actor does
/// not exist in this state, so its live `storageAdmissionStatus()` cannot be
/// queried by the heartbeat writer; retain the typed error's non-sensitive
/// fields here instead of collapsing the evidence gap into `enabled: false`.
struct TraceGraphStartupAdmissionStatus: Sendable, Equatable {
    let reason: CausalGraphStorageBlockReason
    let maxFootprintBytes: Int64?
    let admissionThresholdBytes: Int64?
    let transactionReserveBytes: Int64?
    let footprintBytes: Int64?
    let freeSpaceBytes: Int64?
    let freeSpaceFloorBytes: Int64?

    init(
        error: CausalGraphStorageAdmissionError,
        configuredMaxFootprintBytes: Int64?,
        configuredFreeSpaceFloorBytes: Int64?
    ) {
        maxFootprintBytes = configuredMaxFootprintBytes
        freeSpaceFloorBytes = configuredFreeSpaceFloorBytes

        switch error {
        case .footprintLimit(let footprint, let threshold, let cap):
            reason = .footprintLimit
            admissionThresholdBytes = threshold
            transactionReserveBytes = max(0, cap - threshold)
            footprintBytes = footprint
            freeSpaceBytes = nil

        case .lowFreeSpace(let free, let floor, let required):
            reason = .lowFreeSpace
            admissionThresholdBytes = nil
            transactionReserveBytes = max(0, required - floor)
            footprintBytes = nil
            freeSpaceBytes = free

        case .probeFailed:
            reason = .probeFailure
            admissionThresholdBytes = nil
            transactionReserveBytes = nil
            footprintBytes = nil
            freeSpaceBytes = nil

        case .mutationTooLarge(_, let reserve):
            reason = .mutationTooLarge
            admissionThresholdBytes = nil
            transactionReserveBytes = reserve
            footprintBytes = nil
            freeSpaceBytes = nil

        case .recoveryInProgress:
            reason = .recoveryInProgress
            admissionThresholdBytes = nil
            transactionReserveBytes = nil
            footprintBytes = nil
            freeSpaceBytes = nil
        }
    }

    /// Schema-5 heartbeat representation. `store_available` distinguishes a
    /// boot-time refusal (no actor exists) from a live actor temporarily
    /// shedding writes; `startup_blocked` makes that distinction explicit for
    /// older consumers that only understand `blocked`.
    var heartbeatDictionary: [String: Any] {
        var result: [String: Any] = [
            "enabled": true,
            "blocked": true,
            "store_available": false,
            "startup_blocked": true,
            "reason": reason.rawValue,
            "shed_mutations_total": Int64(0),
            "pinned_reader": false,
            "recovering": false,
        ]
        if let maxFootprintBytes { result["max_footprint_bytes"] = maxFootprintBytes }
        if let admissionThresholdBytes { result["admission_threshold_bytes"] = admissionThresholdBytes }
        if let transactionReserveBytes { result["transaction_reserve_bytes"] = transactionReserveBytes }
        if let footprintBytes { result["footprint_bytes"] = footprintBytes }
        if let freeSpaceBytes { result["free_space_bytes"] = freeSpaceBytes }
        if let freeSpaceFloorBytes { result["free_space_floor_bytes"] = freeSpaceFloorBytes }
        return result
    }
}

/// Typed traces.db pressure captured when the actor cannot be constructed.
/// The receiver is disabled in this state, but the heartbeat must still say
/// why advisory OTLP evidence is unavailable.
struct TraceStoreStartupAdmissionStatus: Sendable, Equatable {
    let reason: TraceStoreStorageBlockReason
    let maxFootprintBytes: Int64?
    let freeSpaceFloorBytes: Int64?

    init(
        error: TraceStoreStorageAdmissionError,
        configuredMaxFootprintBytes: Int64?,
        configuredFreeSpaceFloorBytes: Int64?
    ) {
        maxFootprintBytes = configuredMaxFootprintBytes
        freeSpaceFloorBytes = configuredFreeSpaceFloorBytes
        switch error {
        case .footprintLimit: reason = .footprintLimit
        case .lowFreeSpace: reason = .lowFreeSpace
        case .probeFailed: reason = .probeFailure
        case .mutationTooLarge: reason = .mutationTooLarge
        case .sqliteFull: reason = .sqliteFull
        case .filesystemFull: reason = .filesystemFull
        }
    }

    var heartbeatDictionary: [String: Any] {
        var value: [String: Any] = [
            "enabled": true,
            "blocked": true,
            "store_available": false,
            "startup_blocked": true,
            "reason": reason.rawValue,
            "shed_mutations_total": Int64(0),
            "pinned_reader": false,
            "recovering": false,
        ]
        if let maxFootprintBytes { value["max_footprint_bytes"] = maxFootprintBytes }
        if let freeSpaceFloorBytes { value["free_space_floor_bytes"] = freeSpaceFloorBytes }
        return value
    }
}

/// Holds all engine and component references shared across the daemon.
/// Created once during initialization and passed to all subsystems.
final class DaemonState {
    // MARK: - Paths
    let isRoot: Bool
    let supportDir: String
    let compiledRulesDir: String
    let rulesDir: String
    let rulesURL: URL
    let sequenceRulesDir: String
    let effectiveRulesDir: String

    // MARK: - Storage
    let eventStore: EventStore
    /// Temporary, measured allowance for preserved legacy
    /// events.db.alert_evidence. Fresh installs hold zero; measurement failure
    /// retains the full configured evidence tier so an upgrade cannot latch
    /// event persistence merely because DBSTAT is unavailable.
    let legacyEvidenceTransitionBudget: LegacyEvidenceTransitionBudget
    /// v1.21.4 (F2/A1): async batched writer sitting in FRONT of `eventStore`
    /// for the hot detection path. The event loop hands events here (O(1))
    /// instead of blocking on a per-event SQLite transaction; the writer flushes
    /// them in batches off the consumer's critical path. See BatchedEventWriter.
    let eventWriter: BatchedEventWriter
    /// Sticky post-sweep truth: a configured budget miss remains degraded until
    /// a later sweep proves convergence or a config change invalidates it.
    let eventRetentionBudgetHealth = EventRetentionBudgetHealth()
    let alertStore: AlertStore
    /// Single chokepoint for all alert insertion. Routes everything through
    /// AlertDeduplicator before reaching AlertStore, closing the v1.6.9
    /// NoiseFilter-layering bug class architecturally. All call sites that
    /// previously called `state.alertStore.insert(...)` directly should now
    /// call `state.alertSink.submit(...)` instead.
    let alertSink: AlertSink

    /// v1.11.0 (audit stability HIGH): reentrancy guard for the v1.10.1
    /// inbox file-IPC poller. Pre-fix the 5s DispatchSourceTimer fired
    /// a fresh Task every tick — if the previous tick's Task was still
    /// draining a campaign suppress fan-out (worst case 30+ seconds at
    /// 5K alerts × 6ms per write), the next tick spawned a parallel
    /// Task that re-listed the same dir + raced for the same files.
    /// `withLock` provides correct mutual exclusion across the
    /// DispatchSource thread and any spawned Task.
    let inboxPollerLock = OSAllocatedUnfairLock<Bool>(initialState: false)

    /// Serializes rule reload with terminal shutdown and owns the joinable main
    /// ingestion plane. These are separate from MonitorSupervisor because the
    /// six source drivers and two EventLoop consumers are the primary detector,
    /// not optional background monitors.
    let daemonLifecycle = DaemonLifecycleCoordinator()
    let eventIngestionLifecycle = EventIngestionLifecycle()
    /// One-shot hydration/scans plus the rule-watch and trace-binding workers
    /// launched while DaemonSetup is assembling state. The instance is created
    /// before those tasks and then transferred here for shutdown ownership.
    let startupWorkLifecycle: DaemonTimerLifecycle
    /// Bounded, joinable lanes for work spawned by EventLoop/monitor producers.
    /// Security detection never competes with slow model or external-output
    /// calls for capacity; each plane has independent conservation and overload
    /// telemetry and is sealed before final persistence.
    let detectionWorkLifecycle = DaemonTimerLifecycle(
        maximumInFlightHandlers: 256
    )
    let advisoryWorkLifecycle = DaemonTimerLifecycle(
        maximumInFlightHandlers: 64
    )
    let outputWorkLifecycle = DaemonTimerLifecycle(
        maximumInFlightHandlers: 128
    )

    // MARK: - Core Engines
    let enricher: EventEnricher
    /// Bounded external ownership for events awaiting deferred heavyweight
    /// evidence. Its capacity matches HeavyEnrichmentPlane's 512-result cap;
    /// the two ingestion lanes reserve before enrichment so pressure is
    /// back-pressured rather than converted into an unreported evidence drop.
    let deferredEnrichmentBuffer = DeferredEnrichmentBuffer()
    let ruleEngine: RuleEngine
    let sequenceEngine: SequenceEngine
    /// Owns the bounded, integrity-checked recovery point for in-flight
    /// multi-event detections. It is constructed/restored only after the full
    /// active sequence corpus loads and before event-loop ingestion starts.
    let sequenceCheckpointCoordinator: SequenceCheckpointCoordinator
    let baselineEngine: BaselineEngine
    let behaviorScoring: BehaviorScoring
    let deduplicator: AlertDeduplicator
    let suppressionManager: SuppressionManager
    let statisticalDetector: StatisticalAnomalyDetector
    let crossProcessCorrelator: CrossProcessCorrelator
    let processTreeAnalyzer: ProcessTreeAnalyzer
    let topologyAnomalyDetector: TopologyAnomalyDetector

    // MARK: - Outputs
    let notifier: NotificationOutput
    let responseEngine: ResponseEngine
    let webhookOutput: WebhookOutput?
    let syslogOutput: SyslogOutput?
    /// Phase 7 outputs built from daemon_config.json.outputs[]. Each alert
    /// is fanned out to every entry here via the Output protocol.
    let additionalOutputs: [any Output]
    let notificationIntegrations: NotificationIntegrations

    // MARK: - Self-Defense
    let selfDefense: SelfDefense
    let esHealthMonitor: ESClientMonitor

    // MARK: - Threat Intelligence
    let threatIntel: ThreatIntelFeed
    let ctMonitor: CertTransparency
    let mispClient: MISPClient

    // MARK: - AI Guard
    let aiRegistry: AIToolRegistry
    let aiTracker: AIProcessTracker
    /// Serializes root registration, EXIT, missed-EXIT reconciliation, and the
    /// final synchronous ES callback snapshot across all derivative AI stores.
    let aiSessionLifecycleCoordinator = AISessionLifecycleCoordinator()
    let credentialFence: CredentialFence
    let projectBoundary: ProjectBoundary
    let aiNetworkSandbox: AINetworkSandbox
    let fileInjectionScanner: FileInjectionScanner

    // MARK: - MCP attribution + baseline (v1.7.0)
    let mcpAttributor: MCPAttributor
    let mcpBaseline: MCPBaselineService

    // MARK: - Agent trace registry (v1.9 PR-2)
    //
    // Optional so a daemon binary running with `MACCRAB_AGENT_TRACES`
    // unset (default) doesn't allocate or schedule the consumer Task.
    // Set by DaemonSetup post-construction via `installTraceRegistry`,
    // mirroring how `var collector: ESCollector?` is wired (see line ~91).
    var traceRegistry: TraceRegistry?

    // MARK: - OTLP receiver + trace store (v1.9 PR-4)
    //
    // Both optional and post-construction-set. Allocated when
    // `MACCRAB_OTLP_RECEIVER=1` is in the daemon env. The receiver
    // listens on 127.0.0.1:4318, the trace store persists ingested
    // spans into `<supportDir>/traces.db`. PR-5 will wire a Settings
    // toggle that SIGHUPs the daemon to start/stop the receiver
    // dynamically; PR-4 ships env-var-only auto-start.
    var traceStore: TraceStore?
    var traceStoreStartupAdmission: TraceStoreStartupAdmissionStatus?
    var otlpReceiver: OTLPReceiver?

    // MARK: - Collector registry (v1.7.2)
    let collectorRegistry: CollectorRegistry

    // MARK: - Monitors
    let mcpMonitor: MCPMonitor
    let usbMonitor: USBMonitor
    let clipboardMonitor: ClipboardMonitor
    /// Shared with `clipboardMonitor` (which records delivery-shaped clipboard
    /// payloads) so the event loop can correlate a subsequent shell/Terminal
    /// exec against them — the ClickFix paste-and-run detection. Optional: nil
    /// disables the correlation (e.g. in tests / non-clipboard daemons).
    let clickFix: ClickFixDetector?
    /// Per-user entity behaviour analytics (v1.21.4). Optional: nil disables
    /// UEBA (the default — see `DaemonConfig.uebaEnabled`). When set, the event
    /// loop feeds process-exec events in and routes any returned `UEBAAnomaly`
    /// to `alertSink`. In-memory only: profiles rebuild from the cold-start
    /// window on each daemon start (no persistence timer is wired).
    let uebaEngine: UEBAEngine?
    let clipboardInjectionDetector: ClipboardInjectionDetector
    let browserExtMonitor: BrowserExtensionMonitor
    let ultrasonicMonitor: UltrasonicMonitor
    let eventTapMonitor: EventTapMonitor
    let systemPolicyMonitor: SystemPolicyMonitor
    let rootkitDetector: RootkitDetector
    let tccMonitor: TCCMonitor
    let edrMonitor: EDRMonitor
    let sdrDeviceMonitor: SDRDeviceMonitor
    let btmSnapshotMonitor: BTMSnapshotMonitor
    let fsEventsCollector: FSEventsCollector

    // MARK: - Collectors
    var collector: ESCollector?
    var esloggerCollector: EsloggerCollector?
    var kdebugCollector: KdebugCollector?
    var ulCollector: UnifiedLogCollector?
    let networkCollector: NetworkCollector
    let dnsCollector: DNSCollector
    let esMode: String

    // MARK: - Network Analysis
    let dohDetector: DoHDetector
    let tlsFingerprinter: TLSFingerprinter

    // MARK: - Forensics
    let crashReportMiner: CrashReportMiner
    let powerAnomalyDetector: PowerAnomalyDetector
    let libraryInventory: LibraryInventory
    let cdhashExtractor: CDHashExtractor
    let quarantineEnricher: QuarantineEnricher
    /// Phase-5 delivery-provenance weld: attaches download-origin context to
    /// firing cred/exfil alerts. Enrichment-only — emits no alerts of its own.
    let deliveryProvenanceWeld: DeliveryProvenanceWeld
    /// Phase-5 injection-evidence weld: on a firing agent-attributed cred-read /
    /// read->egress trigger, retro-scans the session's prior agent-content reads
    /// for injection markers and, on a hit, attaches the poisoned file + bumps
    /// severity. Session-scoped, additive — emits no alerts of its own.
    let injectionEvidenceWeld: InjectionEvidenceWeld

    // MARK: - Enrichment
    let yaraEnricher: YARAEnricher
    let dbEncryption: DatabaseEncryption

    // MARK: - Prevention
    let preventionEnabled: Bool
    let dnsSinkhole: DNSSinkhole
    let networkBlocker: NetworkBlocker
    let persistenceGuard: PersistenceGuard
    let sandboxAnalyzer: SandboxAnalyzer
    let aiContainment: AIContainment
    let supplyChainGate: SupplyChainGate
    let tccRevocation: TCCRevocation

    // MARK: - User Security Features
    let securityScorer: SecurityScorer
    let appPrivacyAuditor: AppPrivacyAuditor
    let vulnScanner: VulnerabilityScanner
    // PanicButton was removed from DaemonState in v1.6.19. The actor was
    // instantiated and stored but `activate()` had zero callers in
    // production code — the dashboard never exposed a Panic button surface.
    // PanicButton.swift remains in MacCrabCore for reintroduction once
    // the UI surface ships.
    let travelMode: TravelMode
    let securityDigest: SecurityDigest
    let alertExporter: AlertExporter
    let scheduledReports: ScheduledReports

    // MARK: - Grouping & Campaigns
    let incidentGrouper: IncidentGrouper
    let campaignDetector: CampaignDetector
    /// Persistent campaign store — nil when storage init failed.
    /// Detected campaigns are written here so the dashboard can query
    /// across restarts and analysts can attach notes/suppression.
    let campaignStore: CampaignStore?
    let ruleGenerator: RuleGenerator

    // MARK: - TraceGraph
    /// Per-event causal-graph bridge. nil when SQLiteCausalGraphStore
    /// init failed (rare — only on disk-full or perms issues). When
    /// set, the EventLoop feeds every event through this bridge so
    /// AnchorDetector can materialize traces of interest.
    let causalGraphBridge: EventToRollingCausalGraphBridge?

    /// Causal-graph store used by TraceMaterializer. Held on
    /// DaemonState so the daily retention timer in DaemonTimers can
    /// drive prune + size-cap. Pre-fix the store was scope-locked
    /// inside DaemonSetup's `do { }` block — only the bridge
    /// survived, so timers had no way to call pruneTraces /
    /// pruneOldestTraces / databaseSizeBytes. nil whenever
    /// SQLiteCausalGraphStore init failed.
    let causalStore: SQLiteCausalGraphStore?

    /// Typed storage pressure that prevented `causalStore` from opening. nil
    /// for a live store and for non-admission initialization failures. Without
    /// this retained snapshot, heartbeat/status consumers saw only a generic
    /// disabled flag and could not tell that causal evidence was being shed.
    let causalStoreStartupAdmission: TraceGraphStartupAdmissionStatus?

    /// Graph rule evaluator for v1.10.0 §23 multi-entity rules. Loaded
    /// once at daemon startup from `Rules/graph/*.json`. EventLoop runs
    /// every materialized Trace through `evaluate(entities:edges:)`
    /// and routes matches into the standard alert sink. nil when the
    /// causal store failed to initialize or no graph rules were found.
    /// v1.12.0 RC3 (Int-HSig1): `var` so SIGHUP can swap in a fresh
    /// evaluator with reloaded `Rules/graph/*.json` content. The
    /// evaluator itself holds rules as `let`, so we rebuild rather
    /// than mutate.
    ///
    /// Sec-R5-N4 fix: SIGHUP writes this from the `.main` queue
    /// (SignalHandlers.swift) while EventLoop reads it from a detached
    /// Task — a data race on the bare `var` (benign on Darwin where the
    /// reference swap is atomic, but a real race Swift 6 strict-concurrency
    /// flags, and a use-after-free risk if the old evaluator is released
    /// mid-read). Guarded by an unfair lock, mirroring `inboxPollerLock`.
    /// Access via `withGraphEvaluator` / `setGraphEvaluator`.
    private let graphEvaluatorLock = OSAllocatedUnfairLock<GraphRuleEvaluator?>(initialState: nil)

    /// Thread-safe read of the current graph evaluator (returns a retained
    /// reference, so a concurrent SIGHUP swap can't release it mid-use).
    func currentGraphEvaluator() -> GraphRuleEvaluator? {
        graphEvaluatorLock.withLock { $0 }
    }

    /// Thread-safe replace of the graph evaluator (SIGHUP rule reload).
    func setGraphEvaluator(_ evaluator: GraphRuleEvaluator?) {
        graphEvaluatorLock.withLock { $0 = evaluator }
    }

    // MARK: - Intent posterior (v1.12.0)
    /// Bayesian belief network maintaining a posterior over attacker
    /// goals per process tree. EventLoop translates each event into
    /// zero or more `Evidence` values and feeds them in. When the top
    /// non-benign goal probability crosses `intentAlertThreshold`
    /// (default 0.85) with sufficient evidence, an alert is emitted.
    let bayesianIntent: BayesianIntentEngine

    /// LLM-backed classifier for package-install intent. Held on
    /// DaemonState so MCP handlers + PackageScanner share a single
    /// instance with the daemon's `LLMService`. Not invoked on every
    /// event — only on explicit package-install signals.
    let intentClassifier: IntentClassifier

    /// v1.12.6 — budget cap + result cache for `intentClassifier` when
    /// EventLoop fires it as a tie-breaker on AI-attributed installs
    /// with low heuristic confidence. Bounds LLM dispatches at one per
    /// process tree per 10 minutes and stores the verdict so subsequent
    /// events in the same tree see the refined label without paying
    /// another LLM call. LRU-bounded at 256 entries.
    let intentRefinementCache: IntentRefinementCache = IntentRefinementCache()

    /// v1.12.0 post-audit (M-Int1): correlates an AI agent's recent
    /// context reads with package installs to label the install as
    /// user-initiated / autonomous / slopsquat / injectionContext /
    /// vagueDestructive. EventLoop fires it in a detached Task when a
    /// package-install exec carries an AgentTool enrichment.
    let promptIntentBridge: PromptIntentBridge

    // MARK: - Package Security
    let packageChecker: PackageFreshnessChecker
    let notarizationChecker: NotarizationChecker

    // MARK: - Git Security
    let gitSecurityMonitor: GitSecurityMonitor

    // MARK: - Misc
    let reportGenerator: ReportGenerator
    let threatHunter: ThreatHunter
    let toolIntegrations: SecurityToolIntegrations
    let fleetClient: FleetClient?

    // MARK: - LLM
    let llmService: LLMService?

    // MARK: - Lifecycle
    /// Wall-clock timestamp captured when this state object is constructed —
    /// i.e., at daemon startup. Used by the event loop to gate alerting
    /// during the initial warm-up window, when one-shot inventory scans
    /// (browser extensions, quarantine stripping, process tree baseline)
    /// generate a burst of events that aren't live threat signals.
    let daemonStartTime: Date = Date()

    /// `true` during the first 60 seconds after daemon start. Inventory
    /// scans complete within this window; gating non-critical alerts here
    /// prevents startup noise from landing in the alert list as if it were
    /// real-time activity.
    var isWarmingUp: Bool {
        Date().timeIntervalSince(daemonStartTime) < 60
    }

    /// v1.8.0 per-tier retention budgets for events / alerts / campaigns.
    /// Populated by DaemonSetup from `DaemonConfig.storage`. DaemonTimers
    /// reads each knob live so a SIGHUP-driven config reload is honored on
    /// the next sweep without a daemon restart.
    ///
    /// Pre-v1.8 used a single `retentionDays` + `maxDatabaseSizeMB` pair
    /// shared across all three tiers. The split here lets event-firehose
    /// churn coexist with multi-year alert/campaign history.
    var storage: DaemonConfig.StorageConfig {
        get { legacyEvidenceTransitionBudget.storageConfig() }
        set { legacyEvidenceTransitionBudget.installStorageConfig(newValue) }
    }

    /// v1.19.1: opt-in network-enrichment switches, OFF by default. Set by
    /// DaemonSetup from config and re-applied live by the SIGHUP handler.
    /// DaemonTimers (vuln scan) and EventLoop (package freshness) read these
    /// live so toggling in the dashboard takes effect on the next sweep/event
    /// without a restart; the threat-intel feed's network loop is started /
    /// stopped directly via `threatIntel.setNetworkRefresh(_:)`.
    var vulnScanEnabled: Bool = false
    var packageFreshnessEnabled: Bool = false
    var threatIntelEnabled: Bool = false
    var certTransparencyEnabled: Bool = false

    /// v1.21.5: the `rule_profile` the daemon booted with. On SIGHUP,
    /// RuleEngine.reloadRules re-applies its BOOT-stored statuses internally,
    /// while the sequence/graph reload re-derives from a fresh config load —
    /// so the SIGHUP handler compares the fresh profile against this to warn
    /// honestly when the two rule families diverge until restart. Set by
    /// DaemonSetup post-construction (mirroring `traceRegistry`).
    var bootRuleProfile: String = "stable"

    // v1.12.0 post-audit (M-Cfg1): intent posterior thresholds from
    // daemon_config.json. EventLoop reads these instead of hardcoded
    // 0.85 / 3 so an operator can tune false-positive aggressiveness.
    var intentPosteriorThreshold: Double = 0.85
    var intentPosteriorMinDistinctEvidence: Int = 3

    // MARK: - v1.6.6 AI Suite
    //
    // These six services ship as the AI Suite. Stateless-or-internally-
    // stateful ones are constructed with defaults here; the ones that
    // depend on `llmService` are optional and populated by DaemonSetup
    // after the LLM service is wired. Exposed via the DaemonState bag
    // so EventLoop, dashboard pollers, and the MCP server can reach
    // them without touching the designated initialiser.

    // Sysext-side AI Suite services. Only `AgentLineageService` is
    // genuinely sysext-bound — it weaves live ES events into per-AI-
    // tool session timelines and is consumed by `EventLoop`.
    //
    // The four orphans that previously lived here were removed in
    // v1.6.15 after the audit found them declared but unconsumed:
    //
    //   `triageService`, `llmConsensusService`, `agenticInvestigator`
    //     → moved to `AppState`. Outbound HTTPS with vendor API keys
    //       does not belong at ES-entitlement root privilege when the
    //       dashboard already owns the LLM config and is the natural
    //       consumer of triage results.
    //
    //   `alertClusterService`
    //     → ClusterSheet instantiates its own copy. Fingerprint state
    //       is per-render, not durable; nothing benefits from a single
    //       sysext-side instance.
    //
    //   `mcpBaselineService`
    //     → service is implemented but the producer half (per-event
    //       MCP-server-name attribution from process ancestry) is not
    //       yet built. Reintroduce when the producer lands; today the
    //       observation API has no caller.
    var agentLineageService: AgentLineageService = AgentLineageService()

    /// Wave-3 Phase 1: durable agent-session ids. Mints a UUID per
    /// AI-tool root and resolves it for the root's own events + all
    /// descendants, so EventLoop can stamp events.ai_tool_session_id
    /// (today provably always NULL — no producer).
    var agentSessionRegistry: AgentSessionRegistry = AgentSessionRegistry()

    init(
        isRoot: Bool,
        supportDir: String,
        compiledRulesDir: String,
        rulesDir: String,
        rulesURL: URL,
        sequenceRulesDir: String,
        effectiveRulesDir: String,
        eventStore: EventStore,
        legacyEvidenceTransitionBudget: LegacyEvidenceTransitionBudget,
        alertStore: AlertStore,
        evidenceBudgetBytes: Int64,
        startupWorkLifecycle: DaemonTimerLifecycle,
        enricher: EventEnricher,
        ruleEngine: RuleEngine,
        sequenceEngine: SequenceEngine,
        sequenceCheckpointCoordinator: SequenceCheckpointCoordinator,
        baselineEngine: BaselineEngine,
        behaviorScoring: BehaviorScoring,
        deduplicator: AlertDeduplicator,
        suppressionManager: SuppressionManager,
        statisticalDetector: StatisticalAnomalyDetector,
        crossProcessCorrelator: CrossProcessCorrelator,
        processTreeAnalyzer: ProcessTreeAnalyzer,
        topologyAnomalyDetector: TopologyAnomalyDetector,
        notifier: NotificationOutput,
        responseEngine: ResponseEngine,
        webhookOutput: WebhookOutput?,
        syslogOutput: SyslogOutput?,
        additionalOutputs: [any Output] = [],
        notificationIntegrations: NotificationIntegrations,
        selfDefense: SelfDefense,
        esHealthMonitor: ESClientMonitor,
        threatIntel: ThreatIntelFeed,
        ctMonitor: CertTransparency,
        mispClient: MISPClient,
        aiRegistry: AIToolRegistry,
        aiTracker: AIProcessTracker,
        credentialFence: CredentialFence,
        projectBoundary: ProjectBoundary,
        aiNetworkSandbox: AINetworkSandbox,
        fileInjectionScanner: FileInjectionScanner,
        mcpAttributor: MCPAttributor,
        mcpBaseline: MCPBaselineService,
        collectorRegistry: CollectorRegistry,
        mcpMonitor: MCPMonitor,
        usbMonitor: USBMonitor,
        clipboardMonitor: ClipboardMonitor,
        clipboardInjectionDetector: ClipboardInjectionDetector,
        browserExtMonitor: BrowserExtensionMonitor,
        ultrasonicMonitor: UltrasonicMonitor,
        eventTapMonitor: EventTapMonitor,
        systemPolicyMonitor: SystemPolicyMonitor,
        rootkitDetector: RootkitDetector,
        tccMonitor: TCCMonitor,
        edrMonitor: EDRMonitor,
        sdrDeviceMonitor: SDRDeviceMonitor,
        btmSnapshotMonitor: BTMSnapshotMonitor,
        fsEventsCollector: FSEventsCollector,
        collector: ESCollector?,
        esloggerCollector: EsloggerCollector?,
        kdebugCollector: KdebugCollector?,
        ulCollector: UnifiedLogCollector?,
        networkCollector: NetworkCollector,
        dnsCollector: DNSCollector,
        esMode: String,
        dohDetector: DoHDetector,
        tlsFingerprinter: TLSFingerprinter,
        crashReportMiner: CrashReportMiner,
        powerAnomalyDetector: PowerAnomalyDetector,
        libraryInventory: LibraryInventory,
        cdhashExtractor: CDHashExtractor,
        quarantineEnricher: QuarantineEnricher,
        deliveryProvenanceWeld: DeliveryProvenanceWeld,
        injectionEvidenceWeld: InjectionEvidenceWeld,
        yaraEnricher: YARAEnricher,
        dbEncryption: DatabaseEncryption,
        preventionEnabled: Bool,
        dnsSinkhole: DNSSinkhole,
        networkBlocker: NetworkBlocker,
        persistenceGuard: PersistenceGuard,
        sandboxAnalyzer: SandboxAnalyzer,
        aiContainment: AIContainment,
        supplyChainGate: SupplyChainGate,
        tccRevocation: TCCRevocation,
        securityScorer: SecurityScorer,
        appPrivacyAuditor: AppPrivacyAuditor,
        vulnScanner: VulnerabilityScanner,
        travelMode: TravelMode,
        securityDigest: SecurityDigest,
        alertExporter: AlertExporter,
        scheduledReports: ScheduledReports,
        incidentGrouper: IncidentGrouper,
        campaignDetector: CampaignDetector,
        campaignStore: CampaignStore?,
        ruleGenerator: RuleGenerator,
        causalGraphBridge: EventToRollingCausalGraphBridge? = nil,
        causalStore: SQLiteCausalGraphStore? = nil,
        causalStoreStartupAdmission: TraceGraphStartupAdmissionStatus? = nil,
        graphEvaluator: GraphRuleEvaluator? = nil,
        bayesianIntent: BayesianIntentEngine,
        intentClassifier: IntentClassifier,
        promptIntentBridge: PromptIntentBridge,
        packageChecker: PackageFreshnessChecker,
        notarizationChecker: NotarizationChecker,
        gitSecurityMonitor: GitSecurityMonitor,
        reportGenerator: ReportGenerator,
        threatHunter: ThreatHunter,
        toolIntegrations: SecurityToolIntegrations,
        fleetClient: FleetClient?,
        llmService: LLMService?,
        clickFix: ClickFixDetector? = nil,
        uebaEngine: UEBAEngine? = nil
    ) {
        self.isRoot = isRoot
        self.supportDir = supportDir
        self.compiledRulesDir = compiledRulesDir
        self.rulesDir = rulesDir
        self.rulesURL = rulesURL
        self.sequenceRulesDir = sequenceRulesDir
        self.effectiveRulesDir = effectiveRulesDir
        self.eventStore = eventStore
        self.legacyEvidenceTransitionBudget = legacyEvidenceTransitionBudget
        // Constructed with default flushThreshold/hardCap/flush-interval — these
        // are intentionally NOT config-surfaced (no daemon_config.json key),
        // unlike the priority/file stream caps below (DaemonSetup wires those
        // from DaemonConfig.storage). See BatchedEventWriter.init's note.
        // volumePath wires the disk admission check to the store volume: below the
        // free-space floor the writer pauses persistence and says so, instead of
        // writing until the boot volume is 100% full.
        let eventWriter = BatchedEventWriter(
            store: eventStore,
            volumePath: supportDir
        )
        self.eventWriter = eventWriter
        self.alertStore = alertStore
        self.startupWorkLifecycle = startupWorkLifecycle
        // Build AlertSink from the already-stored alertStore + deduplicator so
        // we don't need a new initializer parameter. Construction is cheap
        // (the actor is empty); first use is what triggers any work.
        // EventStore selects the fixed preceding candidate window; AlertStore
        // owns the slim snapshot in alerts.db after the alert commits. The
        // evidence sub-budget is independent from alert rows even though the
        // two share one combined-family hard admission policy.
        // Inject the SAME shared "alerts emitted" counter the heartbeat reads
        // (`_sharedAlertCount`, file-scope in DaemonBootstrap). The sink
        // increments it once per emitted alert across every path, so
        // heartbeat `alerts_emitted` / Prometheus `alerts_total` count all
        // ~60 alert paths — not just the single-event rule-match site, which
        // was the pre-fix ~16x undercount.
        self.alertSink = AlertSink(
            alertStore: alertStore,
            deduplicator: deduplicator,
            eventStore: eventStore,
            builtinSettingsDir: supportDir,
            alertCounter: _sharedAlertCount,
            evidenceBudgetBytes: evidenceBudgetBytes,
            evidencePrefixGeneration: {
                await eventWriter.evidencePrefixGeneration()
            },
            evidencePrefixBarrier: { generation in
                await eventWriter.awaitEvidencePrefix(through: generation)
            }
        )
        self.enricher = enricher
        self.ruleEngine = ruleEngine
        self.sequenceEngine = sequenceEngine
        self.sequenceCheckpointCoordinator = sequenceCheckpointCoordinator
        self.baselineEngine = baselineEngine
        self.behaviorScoring = behaviorScoring
        self.deduplicator = deduplicator
        self.suppressionManager = suppressionManager
        self.statisticalDetector = statisticalDetector
        self.crossProcessCorrelator = crossProcessCorrelator
        self.processTreeAnalyzer = processTreeAnalyzer
        self.topologyAnomalyDetector = topologyAnomalyDetector
        self.notifier = notifier
        self.responseEngine = responseEngine
        self.webhookOutput = webhookOutput
        self.syslogOutput = syslogOutput
        self.additionalOutputs = additionalOutputs
        self.notificationIntegrations = notificationIntegrations
        self.selfDefense = selfDefense
        self.esHealthMonitor = esHealthMonitor
        self.threatIntel = threatIntel
        self.ctMonitor = ctMonitor
        self.mispClient = mispClient
        self.aiRegistry = aiRegistry
        self.aiTracker = aiTracker
        self.credentialFence = credentialFence
        self.projectBoundary = projectBoundary
        self.aiNetworkSandbox = aiNetworkSandbox
        self.fileInjectionScanner = fileInjectionScanner
        self.mcpAttributor = mcpAttributor
        self.mcpBaseline = mcpBaseline
        self.collectorRegistry = collectorRegistry
        self.mcpMonitor = mcpMonitor
        self.usbMonitor = usbMonitor
        self.clipboardMonitor = clipboardMonitor
        self.clipboardInjectionDetector = clipboardInjectionDetector
        self.browserExtMonitor = browserExtMonitor
        self.ultrasonicMonitor = ultrasonicMonitor
        self.eventTapMonitor = eventTapMonitor
        self.systemPolicyMonitor = systemPolicyMonitor
        self.rootkitDetector = rootkitDetector
        self.tccMonitor = tccMonitor
        self.edrMonitor = edrMonitor
        self.sdrDeviceMonitor = sdrDeviceMonitor
        self.btmSnapshotMonitor = btmSnapshotMonitor
        self.fsEventsCollector = fsEventsCollector
        self.collector = collector
        self.esloggerCollector = esloggerCollector
        self.kdebugCollector = kdebugCollector
        self.ulCollector = ulCollector
        self.networkCollector = networkCollector
        self.dnsCollector = dnsCollector
        self.esMode = esMode
        self.dohDetector = dohDetector
        self.tlsFingerprinter = tlsFingerprinter
        self.crashReportMiner = crashReportMiner
        self.powerAnomalyDetector = powerAnomalyDetector
        self.libraryInventory = libraryInventory
        self.cdhashExtractor = cdhashExtractor
        self.quarantineEnricher = quarantineEnricher
        self.deliveryProvenanceWeld = deliveryProvenanceWeld
        self.injectionEvidenceWeld = injectionEvidenceWeld
        self.yaraEnricher = yaraEnricher
        self.dbEncryption = dbEncryption
        self.preventionEnabled = preventionEnabled
        self.dnsSinkhole = dnsSinkhole
        self.networkBlocker = networkBlocker
        self.persistenceGuard = persistenceGuard
        self.sandboxAnalyzer = sandboxAnalyzer
        self.aiContainment = aiContainment
        self.supplyChainGate = supplyChainGate
        self.tccRevocation = tccRevocation
        self.securityScorer = securityScorer
        self.appPrivacyAuditor = appPrivacyAuditor
        self.vulnScanner = vulnScanner
        self.travelMode = travelMode
        self.securityDigest = securityDigest
        self.alertExporter = alertExporter
        self.scheduledReports = scheduledReports
        self.incidentGrouper = incidentGrouper
        self.campaignDetector = campaignDetector
        self.campaignStore = campaignStore
        self.ruleGenerator = ruleGenerator
        self.causalGraphBridge = causalGraphBridge
        self.causalStore = causalStore
        self.causalStoreStartupAdmission = causalStoreStartupAdmission
        graphEvaluatorLock.withLock { $0 = graphEvaluator }
        self.bayesianIntent = bayesianIntent
        self.intentClassifier = intentClassifier
        self.promptIntentBridge = promptIntentBridge
        self.packageChecker = packageChecker
        self.notarizationChecker = notarizationChecker
        self.gitSecurityMonitor = gitSecurityMonitor
        self.reportGenerator = reportGenerator
        self.threatHunter = threatHunter
        self.toolIntegrations = toolIntegrations
        self.fleetClient = fleetClient
        self.llmService = llmService
        self.clickFix = clickFix
        self.uebaEngine = uebaEngine
    }

    private let mergedStreamLogger = Logger(subsystem: "com.maccrab.agent", category: "EventStream")

    /// v1.21.4 (F2/A2): file-category events ride a SEPARATE bounded stream so a
    /// file-write flood can't evict high-value exec/network/tcc events from the
    /// priority stream. This is its own drop counter — folded into the
    /// heartbeat's detection-input `events_dropped` alongside the priority drops,
    /// but reported distinctly so operators can see that shed volume was
    /// low-value file noise, not a missed exec.
    /// Fixed-cardinality causality counters around the two merged detection
    /// lanes. Source identity is attached at each `driveSource` call, so this
    /// distinguishes collector production from merged-buffer/consumer loss.
    let eventPipelineTelemetry = EventPipelineTelemetry()

    /// Upper bound on in-flight events queued to the detection pipeline.
    /// Past this depth, AsyncStream's `.bufferingNewest` policy drops the
    /// *oldest* event to make room. At 10k events/sec this cap represents
    /// ~10 seconds of buffered backlog, which is an order of magnitude more
    /// than any healthy enrichment + rule-match cycle, so normal workloads
    /// never reach the cap. Bursts above it lose the oldest events rather
    /// than growing the resident set unboundedly — an explicit choice because
    /// an OOM'd daemon detects nothing. Sequence rules tolerate a sparse
    /// drop via the partial-match timeout; a memory blow-up wouldn't.
    /// v1.21.4 (F2/A2): the merged stream is split in two so a file-write flood
    /// can't evict high-value events. Each has its own bounded buffer. Defaults
    /// preserve the prior 100k depth per stream; tunable via DaemonConfig (A3).
    static var priorityStreamCap = 100_000
    static var fileStreamCap = 100_000

    /// v1.21.4 (F2/A2): which split stream an event rides. The file-write family
    /// is the flood source, so it goes to the dedicated `file` stream where a
    /// storm can only evict OTHER file events; everything else (exec/network/
    /// tcc/auth/registry) rides the `priority` stream and is protected from that
    /// eviction. Explicit + testable so a future high-volume category isn't
    /// silently routed onto the priority stream (which would reopen the gap).
    static func ridesFileStream(_ category: EventCategory, action: String) -> Bool {
        EventPipelineLane.routesToFile(category, action: action)
    }

    /// One read of every collector-local delivery boundary. Every snapshot is
    /// internally atomic and keyed by a compile-time source inventory; the
    /// downstream telemetry merges these stage counters without counting an
    /// upstream eviction again when its replacement reaches the merger.
    func eventCollectorBufferSnapshots() -> [
        EventPipelineSource: EventCollectorBufferSnapshot
    ] {
        var snapshots: [EventPipelineSource: EventCollectorBufferSnapshot] = [
            .tcc: tccMonitor.deliveryCounters,
            .network: networkCollector.deliveryCounters,
        ]
        if let collector {
            snapshots[.endpointSecurity] = collector.deliveryCounters
        }
        if let kdebugCollector {
            snapshots[.kdebug] = kdebugCollector.deliveryCounters
        }
        if let esloggerCollector {
            snapshots[.eslogger] = esloggerCollector.deliveryCounters
        }
        if let ulCollector {
            snapshots[.unifiedLog] = ulCollector.deliveryCounters
        }
        return snapshots
    }

    /// Merges all event sources into TWO async streams, split by category so a
    /// file-write flood is contained to the `file` stream and cannot evict
    /// high-value exec/network/tcc/auth events from the `priority` stream.
    /// Each source runs in a restart loop — if the underlying AsyncStream ends
    /// (subprocess exit, actor error, buffer overflow), the Task re-attaches
    /// after a back-off so the source recovers without a daemon restart. A
    /// single source (e.g. ESCollector) emits BOTH families; the yield closure
    /// routes each event by `eventCategory` into the correct stream.
    func mergedEventStreams() async -> (
        priority: AsyncStream<EventPipelineEnvelope>,
        file: AsyncStream<EventPipelineEnvelope>
    ) {
        var priorityCont: AsyncStream<EventPipelineEnvelope>.Continuation!
        var fileCont: AsyncStream<EventPipelineEnvelope>.Continuation!
        let priorityStream = AsyncStream<EventPipelineEnvelope>(
            bufferingPolicy: .bufferingNewest(Self.priorityStreamCap)) { priorityCont = $0 }
        let fileStream = AsyncStream<EventPipelineEnvelope>(
            bufferingPolicy: .bufferingNewest(Self.fileStreamCap)) { fileCont = $0 }

        // Capture the continuations as `let` (Sendable) so the @Sendable yield
        // closure stays isolation-free. The telemetry operation owns each
        // actual yield result and attributes `.dropped` to the OLD envelope.
        let pCont = priorityCont!
        let fCont = fileCont!
        await eventIngestionLifecycle.configure(
            priority: pCont,
            file: fCont
        )
        let pipelineTelemetry = eventPipelineTelemetry
        let yield: @Sendable (EventPipelineSource, Event) -> Void = { source, event in
            let lane: EventPipelineLane = DaemonState.ridesFileStream(
                event.eventCategory,
                action: event.eventAction
            ) ? .file : .priority
            let envelope = EventPipelineEnvelope(source: source, event: event)
            if lane == .file {
                pipelineTelemetry.yield(envelope, to: fCont, lane: lane)
            } else {
                pipelineTelemetry.yield(envelope, to: pCont, lane: lane)
            }
        }
        let continuationPair = (priorityStream, fileStream)
        let logger = mergedStreamLogger
            // v1.18: each source runs an independent backoff + escalation loop.
            // A source whose AsyncStream ends PERMANENTLY (ES client invalidated,
            // eslogger subprocess gone) no longer hot-spins at a fixed 2s logging
            // a warning forever while the heartbeat stays green — it backs off
            // exponentially and escalates ONCE to a CRITICAL fault, so the host
            // can't go silently blind on its highest-fidelity sensor.
            // (Re-establishing the underlying client — es_new_client — remains a
            // deeper follow-up; this stops the silent-spin + raises the alarm.)
            // v1.18: the primary process/file sensors (ES + its eslogger
            // fallback) are ESSENTIAL — when one dies permanently (the post-
            // Sparkle-update case: the kext is replaced out from under the old
            // process and its es_client_t is invalidated, so the stream ends
            // and never recovers), driveSource asks for a guarded daemon
            // relaunch instead of sitting silently at 0 ev/s until the user
            // reboots. The OS keeps an ES system extension alive, so exiting
            // yields a fresh process that re-runs es_new_client.
            let sd = supportDir
            if let es = collector {
                await eventIngestionLifecycle.spawnDriver {
                    await driveSource(.endpointSecurity, logger: logger, essential: true, supportDir: sd, events: { es.events }, yield: yield)
                }
            }
            if let kdebug = kdebugCollector {
                await eventIngestionLifecycle.spawnDriver {
                    await driveSource(.kdebug, logger: logger, events: { kdebug.events }, yield: yield)
                }
            }
            if let eslogger = esloggerCollector {
                await eventIngestionLifecycle.spawnDriver {
                    await driveSource(.eslogger, logger: logger, essential: true, supportDir: sd, events: { eslogger.events }, yield: yield)
                }
            }
            if let ul = ulCollector {
                await eventIngestionLifecycle.spawnDriver {
                    await driveSource(.unifiedLog, logger: logger, events: { ul.events }, yield: yield)
                }
            }
            let tcc = tccMonitor
            await eventIngestionLifecycle.spawnDriver {
                await driveSource(.tcc, logger: logger, events: { tcc.events }, yield: yield)
            }
            let net = networkCollector
            await eventIngestionLifecycle.spawnDriver {
                await driveSource(.network, logger: logger, events: { net.events }, yield: yield)
            }
        return continuationPair
    }
}

/// Drive one collector stream with exponential backoff + one-shot down
/// escalation (SourceRestartState), replacing the fixed-2s re-iterate-forever
/// spin. A re-attach that yields ≥1 event resets the backoff; repeated empty
/// re-attaches back off (capped) and, past the threshold, escalate once to a
/// CRITICAL fault so a permanently-dead source can't go unnoticed.
private func driveSource(
    _ source: EventPipelineSource,
    logger: Logger,
    policy: SourceRestartPolicy = SourceRestartPolicy(),
    essential: Bool = false,
    supportDir: String? = nil,
    events: @escaping @Sendable () -> AsyncStream<Event>,
    yield: @escaping @Sendable (EventPipelineSource, Event) -> Void
) async {
    let name = source.key
    var state = SourceRestartState(policy: policy)
    while !Task.isCancelled {
        var produced = false
        for await event in events() {
            produced = true
            yield(source, event)
        }
        let delay: TimeInterval
        switch state.record(produced: produced) {
        case .retry(let d):
            delay = d
        case .recovered(let d):
            delay = d
            logger.notice("\(name) RECOVERED — event source producing again")
        case .escalate(let d):
            delay = d
            logger.fault("\(name) is DOWN — \(state.consecutiveEmpty) consecutive empty re-attaches; host detection degraded on this source")
            // v1.18: an essential sensor that's confirmed dead can't recover
            // in-process (the ES client is invalidated). Request a guarded
            // daemon relaunch so a fresh process re-establishes es_new_client.
            if essential, let supportDir {
                if recoverEssentialSourceOrStayDegraded(
                    name: name,
                    supportDir: supportDir,
                    logger: logger
                ) {
                    return
                }
            }
        }
        try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
    }
}

/// Process start time, captured at first reference, for the min-uptime guard.
private let daemonProcessStart = Date()

/// When an essential event source (ES / eslogger) is confirmed dead, exit so
/// the OS relaunches a fresh daemon that re-runs the full collector init
/// (es_new_client). Two guards prevent a crash loop:
///   • min uptime — never exit within the first 180 s, so a boot-time ES
///     failure (e.g. entitlement not yet granted) doesn't loop;
///   • cross-restart rate limit — a marker file records recent relaunches; if
///     we've already relaunched ≥3 times in the last 10 min, give up and stay
///     degraded (the CRITICAL fault is already logged) rather than thrash.
/// NEEDS ON-DEVICE VERIFICATION: relies on the system relaunching the ES
/// extension after exit (standard for kept-alive security extensions).
private func recoverEssentialSourceOrStayDegraded(
    name: String,
    supportDir: String,
    logger: Logger
) -> Bool {
    // Only a supervised, non-interactive process is relaunched on exit (the
    // sysext / LaunchDaemon). A developer running `swift run maccrabd` from a
    // terminal would just have it quit — so never exit when stdin is a TTY;
    // stay degraded instead.
    guard isatty(STDIN_FILENO) == 0 else {
        logger.fault("\(name) DOWN in an interactive session — not relaunching (no supervisor); staying degraded")
        return false
    }
    let uptime = Date().timeIntervalSince(daemonProcessStart)
    guard uptime > 180 else {
        logger.fault("\(name) DOWN \(Int(uptime))s after start — within startup guard window; staying up, not relaunching")
        return false
    }
    let markerPath = supportDir + "/.collector_restart"
    let now = Date().timeIntervalSince1970
    let recent: [Double] = {
        guard let text = try? String(contentsOfFile: markerPath, encoding: .utf8) else { return [] }
        return text.split(whereSeparator: { $0 == "\n" }).compactMap { Double($0) }
            .filter { now - $0 < 600 }
    }()
    guard recent.count < 3 else {
        logger.fault("\(name) DOWN but already relaunched \(recent.count)× in 10 min — giving up auto-recovery to avoid a restart loop; host stays degraded until manual restart")
        return false
    }
    let updated = (recent + [now]).map { String($0) }.joined(separator: "\n") + "\n"
    // Atomic write (temp + rename): if ES + eslogger escalate concurrently and
    // both reach here in the same process, the marker can't be left corrupt by
    // interleaved writes. (Semantically one entry per process death is correct —
    // exit() below ends the process before a second writer matters.)
    try? updated.data(using: .utf8)?.write(to: URL(fileURLWithPath: markerPath), options: .atomic)
    logger.fault("\(name) confirmed dead — exiting for a clean relaunch so a fresh ES client can be established (relaunch \(recent.count + 1) in the last 10 min)")
    // Preserve EX_TEMPFAIL(75), but route through the central SIGTERM
    // finalizer so writer/evidence/graph/checkpoint state is closed first.
    DaemonExitRequest.requestRelaunch()
    return true
}
