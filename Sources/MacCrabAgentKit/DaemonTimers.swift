import Foundation
import MacCrabCore
import CSQLCipher
import os.log
import SystemConfiguration

// v1.7.3 added a HeartbeatInFlight class that wrapped the heartbeat
// body in an outer overlap guard. Combined with serial `await` of
// the snapshot writers it created a deadlock: any single guard-less
// snapshot writer (MCPBaseline / RuleEngine / TCCMonitor in v1.7.3)
// could block the heartbeat indefinitely, holding the lock,
// preventing any further heartbeat ticks. Dashboard would then show
// "Detection engine appears silent" after 120 s.
//
// v1.7.4 reverts the outer guard. Each snapshot writer now has its
// own per-writer `snapshotWriteInFlight` guard (matching
// AgentLineageService.swift), so fire-and-forget Tasks at the
// heartbeat level are safe — concurrent writeSnapshot calls no-op
// instead of queueing on the actor. The heartbeat write itself
// stays on the critical fast path.

// MARK: - v1.21.4 Phase-1 D2 — sensor-degraded / possible-evasion evaluator
//
// A file-write flood that spikes above baseline WHILE the kernel is dropping
// ES messages (or the process/exec channel collapses) is the "cross-channel
// blind-spot" signature: a benign-looking storm starving MacCrab's exec
// attribution. This evaluator is PURE + deterministic (baseline in → decision
// + baseline out) so it can be unit-tested with synthetic heartbeat inputs
// without a live daemon. The rolling EWMA baseline is held LOCALLY by the
// heartbeat closure in `DaemonTimers.start` (a locked box), NOT on DaemonState.
//
// Evasion advisory ONLY — nothing here auto-throttles or auto-mutes in
// response (owner decision). It emits a HIGH meta-alert (LOW when the dominant
// high-I/O writer is a known-benign signer, so coverage loss is never fully
// silent).
enum SensorDegradationEvaluator {

    // Tunables — NEEDS-ON-DEVICE calibration against real host baselines.
    /// EWMA smoothing factor over 30 s ticks (~3-4 tick memory).
    static let ewmaAlpha = 0.3
    /// A tick's file-event rate must exceed baseline × this to count as a spike.
    static let fileSpikeMultiplier = 3.0
    /// Absolute floor: below this many file events in a tick, no spike (guards
    /// the divide-by-tiny-baseline FP on an idle box / at daemon start).
    static let minFileEventsForSpike = 2000.0
    /// Process/exec events collapse when they fall below baseline × this.
    static let processCollapseRatio = 0.5
    /// The process/exec baseline must have been at least this busy for a
    /// "collapse" to mean anything — stops a near-idle box (trivial exec rate)
    /// from tripping the collapse branch on ordinary noise. The kernel-drop
    /// branch is unaffected.
    static let minProcessBaselineForCollapse = 50.0
    /// #12 (mother-of-all-audits): the spike gate above only fires when the file
    /// rate exceeds baseline × 3, so an attacker who ramps activity GRADUALLY —
    /// or simply operates on an already-busy host — can bleed millions of dropped
    /// events while the rate never spikes, and the meta-alert (the T1562.001
    /// telemetry-drop-evasion detector) never trips. This spike-INDEPENDENT branch
    /// fires when the per-tick drop FRACTION (dropped / offered) stays at or above
    /// this bound: a sensor losing this share of events is degraded regardless of
    /// whether the absolute rate spiked.
    static let sustainedDropFraction = 0.15
    /// Volume floor for the sustained-loss branch — need meaningful traffic for a
    /// fraction to be trustworthy (guards the idle-box / startup FP).
    static let minOfferedForLossFraction = 2000.0
    /// At least this many of the last `sustainedLossWindow` ticks must have an
    /// elevated drop fraction before the sustained-loss branch fires. Since
    /// `offered` includes the drops themselves, a single big transient burst can
    /// clear the volume floor on its own; requiring several elevated ticks WITHIN
    /// A WINDOW (not strictly consecutive) separates a benign momentary burst from
    /// an attacker holding — or duty-cycling — telemetry suppression.
    static let sustainedLossMinTicks = 2
    /// Sliding-window size (ticks) for the elevated-loss shift register. 4 × 30 s
    /// ≈ 2 min. Must be ≤ 8 (UInt8 mask).
    static let sustainedLossWindow: UInt8 = 4

    /// Rolling baseline carried tick-to-tick. `degradedActive` is the latch
    /// that makes a sustained flood fire exactly once (rising-edge only).
    struct Baseline: Equatable {
        var fileEventEwma: Double = 0
        var processEventEwma: Double = 0
        var seeded: Bool = false
        var degradedActive: Bool = false
        /// #12: separate rising-edge latch for the sustained drop-fraction branch,
        /// so a chronic-loss episode also fires exactly once and re-arms only when
        /// the drop fraction subsides (independent of the spike latch).
        var sustainedLossActive: Bool = false
        /// #12: shift-register of the last `sustainedLossWindow` ticks — bit 0 is
        /// the most recent tick, set when the drop fraction was elevated. The
        /// branch fires only when at least `sustainedLossMinTicks` of the recent
        /// window were elevated, so (a) a SINGLE transient burst (Spotlight, a
        /// build, wake-from-sleep) doesn't fire (rc.3-verify FP fix) AND (b) an
        /// attacker duty-cycling suppression (one loud tick / one quiet tick) can't
        /// evade by keeping a *consecutive* counter from ever advancing — the
        /// windowed count still accumulates (rc.4-verify evasion fix).
        var recentElevatedMask: UInt8 = 0
    }

    /// Per-tick inputs, all derived from the D1/D4 monotonic counters' deltas.
    struct Input {
        /// File write-family events processed this tick (CREATE/WRITE/CLOSE/
        /// RENAME/UNLINK delta).
        var fileEventsThisTick: Double
        /// Process/exec events reached-at-callback this tick (EXEC/FORK/EXIT
        /// delta). Collapses precisely when the kernel drops exec messages.
        var processEventsThisTick: Double
        /// `es_kernel_dropped_total` delta over this tick.
        var kernelDropDelta: UInt64
        /// ES-collector-stage userspace drops over this tick:
        /// `es_copy_backpressure_dropped_total` + `es_stream_yield_dropped_total`.
        /// After Phase-3 (async retain-worker) and Phase-4 (file/exec client
        /// split), a flood no longer produces KERNEL drops — the message is
        /// retained off the kernel queue and then lost when the bounded worker
        /// queue or the collector's AsyncStream buffer overflows. Those are the
        /// dominant coverage-loss signal now, so D2 must gate on them too, not
        /// just `kernelDropDelta` (else a real flood degrades the sensor
        /// silently). NOT the merged-stream `events_dropped` — that is a
        /// downstream consumer stage, deliberately kept out of the ES-sensor
        /// verdict.
        var collectorDropDelta: UInt64
        /// The dominant high-I/O writer this window is a known-benign signer.
        var benignHighIOSigner: Bool
    }

    enum Outcome: Equatable {
        case noAlert
        /// Fire. `severity` is HIGH normally, LOW when attributed to a
        /// benign signer; `benignAttribution` echoes the input for the
        /// "(benign attribution)" wording.
        case degraded(severity: Severity, benignAttribution: Bool)
    }

    /// Which branch fired. The alert description used to assert BOTH a file-rate
    /// spike AND an exec-channel collapse unconditionally, so a `sustainedLoss`
    /// fire reported a "fall" in exec throughput that had in fact RISEN — 90 HIGH
    /// alerts on one host claiming an attacker was suppressing telemetry when the
    /// real condition was MacCrab's own worker shedding load.
    enum Reason: Equatable {
        /// File-rate spike concurrent with kernel/collector drops or an exec collapse.
        case spikeWithLoss
        /// Chronic drop fraction over a meaningful volume, with no spike.
        case sustainedLoss
    }

    struct Result: Equatable {
        var outcome: Outcome
        var reason: Reason?
        var newBaseline: Baseline
        // Diagnostics for the alert description.
        var fileRate: Double
        var fileBaseline: Double
        var processRate: Double
        var processBaseline: Double
        var kernelDropDelta: UInt64
        var collectorDropDelta: UInt64
    }

    /// Pure evaluation: given this tick's inputs and the prior baseline,
    /// decide whether the sensor is degraded and return the advanced baseline.
    static func evaluate(input: Input, baseline: Baseline) -> Result {
        var b = baseline

        // First observation: seed the baseline; a spike needs history.
        guard b.seeded else {
            b.fileEventEwma = input.fileEventsThisTick
            b.processEventEwma = input.processEventsThisTick
            b.seeded = true
            return Result(
                outcome: .noAlert, newBaseline: b,
                fileRate: input.fileEventsThisTick, fileBaseline: input.fileEventsThisTick,
                processRate: input.processEventsThisTick, processBaseline: input.processEventsThisTick,
                kernelDropDelta: input.kernelDropDelta,
                collectorDropDelta: input.collectorDropDelta
            )
        }

        let spike = input.fileEventsThisTick >= minFileEventsForSpike
            && input.fileEventsThisTick > b.fileEventEwma * fileSpikeMultiplier
        let processCollapse = b.processEventEwma >= minProcessBaselineForCollapse
            && input.processEventsThisTick < b.processEventEwma * processCollapseRatio
        // Any coverage-loss signal — kernel drops OR the ES-collector-stage
        // userspace drops (backpressure / stream-yield) OR an exec-channel
        // collapse — while the file rate is spiking is a degraded sensor.
        // collectorDropDelta is the signal that survives Phase-3/4 (which drove
        // kernelDropDelta to ~0); without it the meta-alert never fires on a
        // real flood.
        let conjunction = spike
            && (input.kernelDropDelta > 0 || input.collectorDropDelta > 0 || processCollapse)

        // #12: spike-independent sustained-loss signal. `offered` = events the
        // sensor SHOULD have processed this tick = processed (file + exec) + lost
        // (kernel + collector drops). A high loss fraction over a meaningful
        // volume means the sensor is degraded even if the absolute rate never
        // crossed the spike multiplier (the gradual-ramp / already-busy-host
        // evasion). Requires the volume floor so an idle box can't trip it.
        let dropped = Double(input.kernelDropDelta) + Double(input.collectorDropDelta)
        let offered = input.fileEventsThisTick + input.processEventsThisTick + dropped
        let dropFraction = offered > 0 ? dropped / offered : 0
        let lossElevated = offered >= minOfferedForLossFraction
            && dropFraction >= sustainedDropFraction
        // Slide the elevated-loss window: shift in this tick's bit, keep the low
        // `sustainedLossWindow` bits. Fire when at least `sustainedLossMinTicks`
        // of the window were elevated — persistent OR duty-cycled loss both
        // accumulate, a lone transient burst does not.
        let windowMask: UInt8 = (1 << sustainedLossWindow) &- 1
        b.recentElevatedMask = ((b.recentElevatedMask << 1) | (lossElevated ? 1 : 0)) & windowMask
        let windowedElevated = Int(b.recentElevatedMask.nonzeroBitCount)
        let sustainedLoss = windowedElevated >= sustainedLossMinTicks

        var outcome: Outcome = .noAlert
        var reason: Reason?
        if conjunction && !b.degradedActive {
            // Rising edge — fire once. Benign signer downgrades HIGH → LOW.
            let severity: Severity = input.benignHighIOSigner ? .low : .high
            outcome = .degraded(severity: severity, benignAttribution: input.benignHighIOSigner)
            reason = .spikeWithLoss
            b.degradedActive = true
        } else if sustainedLoss && !b.sustainedLossActive {
            // #12: chronic loss without a spike — the evasion the spike gate misses.
            let severity: Severity = input.benignHighIOSigner ? .low : .high
            outcome = .degraded(severity: severity, benignAttribution: input.benignHighIOSigner)
            reason = .sustainedLoss
            b.sustainedLossActive = true
        }
        // Re-arm the spike latch when the file-rate spike subsides (not merely
        // when drops pause), and the loss latch when the windowed loss drops back
        // below the threshold, so each episode stays latched at exactly one fire.
        if !spike { b.degradedActive = false }
        if !sustainedLoss { b.sustainedLossActive = false }

        // Don't learn from anomalies: freeze the baseline while spiking so a
        // flood can't poison it (which would blind the next episode).
        if !spike {
            b.fileEventEwma = ewmaAlpha * input.fileEventsThisTick + (1 - ewmaAlpha) * b.fileEventEwma
            b.processEventEwma = ewmaAlpha * input.processEventsThisTick + (1 - ewmaAlpha) * b.processEventEwma
        }

        return Result(
            outcome: outcome, reason: reason, newBaseline: b,
            fileRate: input.fileEventsThisTick, fileBaseline: baseline.fileEventEwma,
            processRate: input.processEventsThisTick, processBaseline: baseline.processEventEwma,
            kernelDropDelta: input.kernelDropDelta,
            collectorDropDelta: input.collectorDropDelta
        )
    }
}

/// Exact events.db maintenance boundaries derived from the same binary-MiB cap
/// and transaction reserve as the EventStore hard-admission policy.
///
/// Admission permits a write only while `footprint + reserve <= cap`. Waiting
/// until the nominal cap to start maintenance therefore deadlocks recovery: the
/// writer is already paused one reserve earlier. Maintenance starts one further
/// reserve below that line, leaving room for the cleanup transaction itself.
/// The sweep target retains the historical 80% target where it is lower, but
/// never lands above the proactive boundary on smaller configured caps.
struct EventsSizeCapBoundary: Sendable, Equatable {
    let nominalCapBytes: Int64
    let hardAdmissionBoundaryBytes: Int64
    let fileLaneAdmissionBoundaryBytes: Int64
    let proactiveSweepBoundaryBytes: Int64
    let targetBytes: Int64

    init(maxSizeMiB: Int) {
        let safeCapMiB = min(
            DaemonConfig.StorageConfig.maximumSizeMiB,
            max(DaemonConfig.StorageConfig.minimumEventsSizeMiB, maxSizeMiB)
        )
        let cap = SQLitePersistentStorePolicy.capBytes(
            maxSizeMiB: safeCapMiB
        )
        let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
        let hardBoundary = max(0, cap - reserve)
        let fileLaneBoundary = max(
            0,
            hardBoundary - EventStore.priorityLaneReserveBytes(
                maxFootprintBytes: cap
            )
        )
        // Maintenance must arm before either full-reserve production lane can
        // shed. Up to 320 MiB the transaction reserve is the tighter second
        // margin; above it, the proportional priority-only reserve makes the
        // file lane the tighter boundary.
        let proactiveBoundary = min(
            max(0, hardBoundary - reserve),
            fileLaneBoundary
        )
        // Overflow-safe exact 4/5 calculation (the historical 80% target).
        let eightyPercent = (cap / 5) * 4 + ((cap % 5) * 4) / 5

        nominalCapBytes = cap
        hardAdmissionBoundaryBytes = hardBoundary
        fileLaneAdmissionBoundaryBytes = fileLaneBoundary
        proactiveSweepBoundaryBytes = proactiveBoundary
        targetBytes = min(eightyPercent, proactiveBoundary)
    }

    /// Strict comparison lets a sweep that lands exactly on the proactive
    /// watermark converge instead of immediately re-arming the watchdog.
    func requiresMaintenance(footprintBytes: Int64) -> Bool {
        footprintBytes > proactiveSweepBoundaryBytes
    }

    /// Startup must publish a converged retention-health snapshot, not merely
    /// a currently writable store. The interval `(target, proactive]` is safe
    /// for an ordinary write but would otherwise start the first epoch with a
    /// sticky `degraded_budget_unmet` heartbeat that periodic maintenance will
    /// not revisit until later growth crosses the proactive boundary.
    func requiresStartupConvergence(footprintBytes: Int64) -> Bool {
        footprintBytes > targetBytes
    }
}

/// Exact alerts.db family boundaries derived from the same absolute cap and
/// transaction reserve as `AlertStore` admission.
///
/// Alert/evidence DBSTAT ownership budgets remain independent maxima, but they
/// cannot stand in for physical-family recovery: SQLite refuses an ordinary
/// write once `footprint + reserve > cap`, even when each owner is below its
/// sub-cap. Maintenance therefore starts at that hard admission boundary and
/// aims one more reserve below it so the first recovered write does not
/// immediately re-latch the store.
struct AlertsSizeCapBoundary: Sendable, Equatable {
    let nominalCapBytes: Int64
    let transactionReserveBytes: Int64
    let hardAdmissionBoundaryBytes: Int64
    let recoveryTargetBytes: Int64

    init(
        nominalCapBytes: Int64,
        transactionReserveBytes: Int64 = 8 * SQLitePersistentStorePolicy.bytesPerMiB
    ) {
        let cap = max(0, nominalCapBytes)
        let reserve = max(0, transactionReserveBytes)
        let hardBoundary = max(0, cap - reserve)

        self.nominalCapBytes = cap
        self.transactionReserveBytes = reserve
        hardAdmissionBoundaryBytes = hardBoundary
        recoveryTargetBytes = max(0, hardBoundary - reserve)
    }

    /// Admission permits equality (`footprint + reserve == cap`).
    func requiresMaintenance(footprintBytes: Int64) -> Bool {
        footprintBytes > hardAdmissionBoundaryBytes
    }

    /// Setup requires one complete transaction of durable headroom beyond the
    /// ordinary write boundary. Periodic maintenance retains its historical
    /// hard-boundary trigger; only the pre-ingestion path forces this target.
    func requiresStartupConvergence(footprintBytes: Int64) -> Bool {
        footprintBytes > recoveryTargetBytes
    }
}

let preIngestionStorageRecoveryMaximumPasses = 120
let preIngestionStoragePinnedRetryPasses = 120
let preIngestionStoragePinnedRetryDelayNanoseconds: UInt64 = 500_000_000

/// v1.22.0 (item 2, boot <3s): a hard wall-clock ceiling across each of the two
/// pre-producer storage-retry loops. Attempt counts alone let a persistently
/// WAL-pinned boot (e.g. a stuck dashboard read that never releases its read
/// snapshot) hang for up to ~60s per loop before the outer abort fires. That
/// converts a slow success into a fast, loud failure so boot cannot silently
/// blow the readiness budget; a genuinely transient pin still clears well inside
/// it. This bounds the WORST case — it does not itself make a contended boot
/// reach readiness in <3s (that remains a fail-fast, not a fail-slow).
let preIngestionStorageRetryWallClockBudgetSeconds: TimeInterval = 5

/// Retry only EventStore's typed lock-contention signal during the
/// pre-producer transaction. The operation must be crash-resumable or
/// read/checkpoint-only; permanent storage/corruption errors escape
/// immediately. The callback keeps the independent boot heartbeat fresh while
/// an installed dashboard holds a legitimate read snapshot.
func retryTransientEventStoreStartupOperation<T>(
    maximumAttempts: Int = preIngestionStoragePinnedRetryPasses,
    retryDelayNanoseconds: UInt64 =
        preIngestionStoragePinnedRetryDelayNanoseconds,
    onRetry: @Sendable (Int) -> Void = { _ in },
    operation: () async throws -> T
) async throws -> T {
    let attemptLimit = max(1, maximumAttempts)
    // v1.22.0 (item 2): also bound the loop by wall-clock time, not just by
    // attempt count, so a persistently pinned reader fails boot fast instead of
    // burning the full attempt budget of 500ms sleeps.
    let retryStart = Date()
    for attempt in 1...attemptLimit {
        do {
            return try await operation()
        } catch let error as EventStoreError {
            // Already attempt-bounded, so retrying in-process credit exhaustion
            // here is safe and preserves the pre-rc.32 startup behaviour that
            // `.busy` used to cover before the two conditions were split.
            let retryable: Bool
            switch error {
            case .busy, .memoryLeaseUnavailable: retryable = true
            default: retryable = false
            }
            guard retryable, attempt < attemptLimit,
                  Date().timeIntervalSince(retryStart)
                    < preIngestionStorageRetryWallClockBudgetSeconds else {
                throw error
            }
            onRetry(attempt)
            if retryDelayNanoseconds > 0 {
                try await Task.sleep(nanoseconds: retryDelayNanoseconds)
            }
        }
    }
    preconditionFailure("startup retry loop exhausted without returning")
}

/// Setup distinguishes a real maintenance pass from a checkpoint preflight
/// that found a transient reader pin. Only the latter may retry without a
/// smaller footprint: no row deletion has started, so the grace cannot repeat
/// destructive work against an unreachable protected-history floor.
enum PreIngestionStorageMaintenanceResult: Sendable, Equatable {
    case ran
    case transientlyPinned
    case ranThenTransientlyPinned
    case didNotRun
}

/// Auditable result from the bounded maintenance -> ordinary-admission loop
/// used before collector construction. A `.ran` maintenance outcome means
/// only that the helper ran; it is never treated as proof of convergence.
struct PreIngestionStorageRecoveryResult: Sendable, Equatable {
    let component: String
    let writableBeforeProducers: Bool
    let passes: Int
    let lastFootprintBytes: Int64?
    let lastProbeError: String?
    let reason: String
}

struct EventStoreActivationProof: Sendable, Equatable {
    let footprintBytes: Int64
    let priorityAdmission: SQLitePersistentStoreAdmissionSnapshot
    let fileAdmission: SQLitePersistentStoreAdmissionSnapshot
}

struct AlertStoreActivationProof: Sendable, Equatable {
    let footprintBytes: Int64
    let admission: SQLitePersistentStoreAdmissionSnapshot
}

private enum PreIngestionStorageRecoveryError: LocalizedError {
    case admissionPolicyMismatch(
        component: String,
        expectedCapBytes: Int64,
        actualCapBytes: Int64?,
        expectedReserveBytes: Int64,
        actualReserveBytes: Int64?
    )
    case startupTargetNotReached(
        component: String,
        footprintBytes: Int64,
        targetBytes: Int64
    )
    case activationBoundaryExceeded(
        component: String,
        footprintBytes: Int64,
        boundaryBytes: Int64
    )

    var errorDescription: String? {
        switch self {
        case let .admissionPolicyMismatch(
            component,
            expectedCap,
            actualCap,
            expectedReserve,
            actualReserve
        ):
            return "\(component) ordinary admission used cap=\(actualCap ?? -1), reserve=\(actualReserve ?? -1); expected cap=\(expectedCap), reserve=\(expectedReserve)"
        case let .startupTargetNotReached(component, footprint, target):
            return "\(component) ordinary admission passed at \(footprint) bytes, but startup retention target is \(target) bytes"
        case let .activationBoundaryExceeded(
            component,
            footprint,
            boundary
        ):
            return "\(component) activation footprint \(footprint) bytes exceeded ordinary admission boundary \(boundary) bytes"
        }
    }
}

/// Run a finite number of maintenance passes, stopping immediately when the
/// helper cannot run, an exact family measurement fails, or a failed normal
/// reprobe follows a real maintenance pass with no physical progress. A
/// reader-pin outcome gets a short grace. A preflight pin guarantees no delete;
/// a post-maintenance pin records that one bounded mutation pass already ran,
/// and the next pass repeats the preflight before any further deletion. All
/// other no-progress outcomes stop before another full-file rewrite.
func runBoundedPreIngestionStorageRecovery(
    component: String,
    maximumPasses: Int = preIngestionStorageRecoveryMaximumPasses,
    maximumPinnedRetries: Int = preIngestionStoragePinnedRetryPasses,
    pinnedRetryDelayNanoseconds: UInt64 =
        preIngestionStoragePinnedRetryDelayNanoseconds,
    onTransientPinRetry: @Sendable (Int) -> Void = { _ in },
    measureFootprint: @Sendable () async throws -> Int64,
    maintenance: @Sendable () async
        -> PreIngestionStorageMaintenanceResult,
    reprobeOrdinaryAdmission: @Sendable () async throws -> Void
) async -> PreIngestionStorageRecoveryResult {
    let passLimit = max(1, maximumPasses)
    let pinnedRetryLimit = max(1, min(passLimit, maximumPinnedRetries))
    var lastFootprint: Int64?
    var lastProbeError: String?
    var pinnedRetries = 0
    // v1.22.0 (item 2): wall-clock ceiling on the pin-WAIT grace. Initialized
    // lazily at the FIRST observed reader pin — not at function entry — so that
    // time spent on legitimate, successful maintenance in earlier passes (a WAL
    // checkpoint fsync, retention prune, or a multi-second VACUUM inside
    // enforce*SizeCap) is never deducted from the grace a genuinely transient
    // pin is meant to get. A reader that never releases its pin still fails boot
    // fast instead of exhausting the full pinnedRetryLimit of 500ms sleeps.
    var pinnedRetryStart: Date?

    for pass in 1...passLimit {
        let before: Int64
        do {
            before = try await measureFootprint()
            lastFootprint = before
        } catch {
            return PreIngestionStorageRecoveryResult(
                component: component,
                writableBeforeProducers: false,
                passes: pass - 1,
                lastFootprintBytes: lastFootprint,
                lastProbeError: lastProbeError,
                reason: "exact family measurement before pass \(pass) failed: \(error.localizedDescription)"
            )
        }

        let maintenanceResult = await maintenance()

        let after: Int64
        do {
            after = try await measureFootprint()
            lastFootprint = after
        } catch {
            return PreIngestionStorageRecoveryResult(
                component: component,
                writableBeforeProducers: false,
                passes: pass,
                lastFootprintBytes: before,
                lastProbeError: lastProbeError,
                reason: "exact family measurement after pass \(pass) failed: \(error.localizedDescription)"
            )
        }

        do {
            try await reprobeOrdinaryAdmission()
            return PreIngestionStorageRecoveryResult(
                component: component,
                writableBeforeProducers: true,
                passes: pass,
                lastFootprintBytes: after,
                lastProbeError: nil,
                reason: "ordinary write admission reprobe succeeded"
            )
        } catch {
            lastProbeError = error.localizedDescription
        }

        switch maintenanceResult {
        case .didNotRun:
            return PreIngestionStorageRecoveryResult(
                component: component,
                writableBeforeProducers: false,
                passes: pass,
                lastFootprintBytes: after,
                lastProbeError: lastProbeError,
                reason: "maintenance helper did not run on pass \(pass); ordinary admission remained blocked: \(lastProbeError ?? "unknown probe failure")"
            )
        case .ran:
            guard after < before else {
                return PreIngestionStorageRecoveryResult(
                    component: component,
                    writableBeforeProducers: false,
                    passes: pass,
                    lastFootprintBytes: after,
                    lastProbeError: lastProbeError,
                    reason: "no physical family progress on pass \(pass) (before=\(before), after=\(after)); ordinary admission remained blocked: \(lastProbeError ?? "unknown probe failure")"
                )
            }
        case .transientlyPinned, .ranThenTransientlyPinned:
            pinnedRetries += 1
            let pinStart = pinnedRetryStart ?? Date()
            pinnedRetryStart = pinStart
            let withinWallClock = Date().timeIntervalSince(pinStart)
                < preIngestionStorageRetryWallClockBudgetSeconds
            guard pinnedRetries < pinnedRetryLimit, withinWallClock else {
                let phase = maintenanceResult == .transientlyPinned
                    ? "pre-maintenance" : "post-maintenance"
                let bound = withinWallClock
                    ? "after \(pinnedRetries) bounded retries"
                    : "within the \(Int(preIngestionStorageRetryWallClockBudgetSeconds))s wall-clock budget"
                return PreIngestionStorageRecoveryResult(
                    component: component,
                    writableBeforeProducers: false,
                    passes: pass,
                    lastFootprintBytes: after,
                    lastProbeError: lastProbeError,
                    reason: "reader-pinned \(phase) checkpoint did not clear \(bound) (before=\(before), after=\(after)); ordinary admission remained blocked: \(lastProbeError ?? "unknown probe failure")"
                )
            }
            onTransientPinRetry(pinnedRetries)
            if pinnedRetryDelayNanoseconds > 0 {
                try? await Task.sleep(
                    nanoseconds: pinnedRetryDelayNanoseconds
                )
            }
        }
    }

    return PreIngestionStorageRecoveryResult(
        component: component,
        writableBeforeProducers: false,
        passes: passLimit,
        lastFootprintBytes: lastFootprint,
        lastProbeError: lastProbeError,
        reason: "exhausted \(passLimit) bounded maintenance passes; ordinary admission remained blocked: \(lastProbeError ?? "unknown probe failure")"
    )
}

/// Raw-event history that byte-cap maintenance may not delete. Fifteen minutes
/// is a forensic/correlation service floor: graph/cross-process reconstruction,
/// alert context and hunt all need a meaningful recent window. It is NOT a
/// claim that SequenceEngine currently rehydrates from events.db (it does not;
/// durable sequence checkpoint/chronological rehydrate remains separate work).
struct EventRetentionFloor {
    static let minutes = 15

    /// Progressively tighten only until the hard floor. At the floor there is
    /// deliberately one rung: inventing 14/13-minute rungs makes the configured
    /// guarantee false and hands churn to the row-count fallback.
    static func adaptiveCutoffs(hotTierMinutes: Int) -> [Int] {
        let hot = max(minutes, hotTierMinutes)
        let candidates = [hot, max(minutes, hot / 2), max(minutes, hot / 4)]
        var result: [Int] = []
        for candidate in candidates where result.last != candidate {
            result.append(candidate)
        }
        return result
    }
}

/// Sticky truth surface for the configured events.db budget. A post-sweep
/// target miss stays degraded even if subsequent ingest/prune oscillation
/// briefly dips below the watchdog boundary. It clears only after an actual
/// sweep demonstrates convergence or a configuration change invalidates the
/// old conclusion and returns the state to honest-unknown.
final class EventRetentionBudgetHealth: @unchecked Sendable {
    struct Snapshot: Sendable, Equatable {
        let state: String
        let reason: String
        let sticky: Bool
        let observedFootprintBytes: Int64?
        let targetBytes: Int64?
        let proactiveBoundaryBytes: Int64?
        let nominalCapBytes: Int64?
        let evaluatedAtUnix: Double?

        var dictionary: [String: Any] {
            var result: [String: Any] = [
                "state": state,
                "reason": reason,
                "sticky": sticky,
                "forensic_floor_minutes": EventRetentionFloor.minutes,
            ]
            if let observedFootprintBytes {
                result["observed_footprint_bytes"] = observedFootprintBytes
            }
            if let targetBytes { result["target_bytes"] = targetBytes }
            if let proactiveBoundaryBytes {
                result["proactive_boundary_bytes"] = proactiveBoundaryBytes
            }
            if let nominalCapBytes {
                result["nominal_cap_bytes"] = nominalCapBytes
            }
            if let evaluatedAtUnix {
                result["evaluated_at_unix"] = evaluatedAtUnix
            }
            return result
        }
    }

    private struct State {
        var snapshot = Snapshot(
            state: "unknown",
            reason: "awaiting_post_sweep_measurement",
            sticky: false,
            observedFootprintBytes: nil,
            targetBytes: nil,
            proactiveBoundaryBytes: nil,
            nominalCapBytes: nil,
            evaluatedAtUnix: nil
        )
    }

    private let lock = NSLock()
    private var state = State()

    func recordSweep(
        observedFootprintBytes: Int64?,
        boundary: EventsSizeCapBoundary,
        at date: Date = Date()
    ) {
        lock.lock(); defer { lock.unlock() }
        let converged = observedFootprintBytes.map { $0 <= boundary.targetBytes }
        let stateName: String
        let reason: String
        let sticky: Bool
        switch converged {
        case .some(true):
            stateName = "converged"
            reason = "post_sweep_at_or_below_target"
            sticky = false
        case .some(false):
            stateName = "degraded_budget_unmet"
            reason = "post_sweep_above_target"
            sticky = true
        case .none:
            stateName = "degraded_budget_unknown"
            reason = "post_sweep_measurement_failed"
            sticky = true
        }
        state.snapshot = Snapshot(
            state: stateName,
            reason: reason,
            sticky: sticky,
            observedFootprintBytes: observedFootprintBytes,
            targetBytes: boundary.targetBytes,
            proactiveBoundaryBytes: boundary.proactiveSweepBoundaryBytes,
            nominalCapBytes: boundary.nominalCapBytes,
            evaluatedAtUnix: date.timeIntervalSince1970
        )
    }

    func recordConfigurationChange() {
        lock.lock(); defer { lock.unlock() }
        state.snapshot = Snapshot(
            state: "unknown",
            reason: "configuration_changed_awaiting_sweep",
            sticky: false,
            observedFootprintBytes: nil,
            targetBytes: nil,
            proactiveBoundaryBytes: nil,
            nominalCapBytes: nil,
            evaluatedAtUnix: Date().timeIntervalSince1970
        )
    }

    func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return state.snapshot
    }
}

/// v1.21.6 (audit DL-03): back-off state for the early-fire size-cap watchdog.
///
/// The watchdog is a BURST catcher, not a second scheduler: it exists to react
/// when events.db crosses its proactive reserve boundary BETWEEN the (hourly
/// by default) scheduled sweeps. On a host whose irreducible content (alert_evidence + the
/// events_fts index + schema) already exceeds the 0.8x-cap sweep target it can
/// never clear the threshold, and the unconditional 60 s cadence turned it into
/// a permanent full-FTS-optimize + incremental_vacuum loop — field-observed 59
/// fires/hour for 7 consecutive hours, 1.9M page rewrites (7.3 GiB) in 12 h,
/// sysext pinned at 151-241% CPU, footprint parked at ~2x cap the whole time.
/// Doubling the minimum interval after each INEFFECTIVE fire caps that at
/// ~32 min while leaving the burst response at the original 60 s on a healthy
/// host (any fire that clears the threshold resets the streak).
///
/// LOCAL to `DaemonTimers.start` (captured by the watchdog closure), lock-
/// guarded because DispatchSourceTimer handlers can overlap. NOT a DaemonState
/// field — same shape as `SensorDegradationState` below.
final class SizeCapWatchdogBackoff: @unchecked Sendable {
    private let lock = NSLock()
    private var ineffectiveStreak = 0
    private var nextEligible = Date.distantPast
    private var configurationToken: String?

    /// Base cadence — matches the timer's `repeating:` interval.
    private static let baseInterval: TimeInterval = 60
    /// Ceiling: 60 s x 2^5 ~= 32 min, deliberately under the default hourly
    /// scheduled sweep so the watchdog never becomes the only enforcement.
    private static let maxDoublings = 5

    /// True when enough back-off has elapsed for another early fire.
    func mayFire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return Date() >= nextEligible
    }

    /// A materially changed budget invalidates the prior convergence result.
    /// This is the only reset other than an actual fired sweep that lands at or
    /// below target; an ordinary under-boundary sampling tick is not evidence.
    func observeConfiguration(_ token: String) {
        lock.lock(); defer { lock.unlock() }
        guard configurationToken != token else { return }
        configurationToken = token
        ineffectiveStreak = 0
        nextEligible = .distantPast
    }

    /// Record a fired sweep's outcome. Returns the seconds until the next
    /// eligible fire (for logging). `stillOver == false` resets the streak.
    @discardableResult
    func recordSweep(stillOver: Bool) -> Int {
        lock.lock(); defer { lock.unlock() }
        guard stillOver else {
            ineffectiveStreak = 0
            nextEligible = .distantPast
            return Int(Self.baseInterval)
        }
        ineffectiveStreak = min(ineffectiveStreak + 1, Self.maxDoublings)
        let delay = Self.baseInterval * pow(2.0, Double(ineffectiveStreak))
        nextEligible = Date().addingTimeInterval(delay)
        return Int(delay)
    }
}

/// Thread-safe holder for the D2 EWMA baseline + the previous cumulative
/// counters (for the per-tick delta) — LOCAL to `DaemonTimers.start` (captured
/// by the heartbeat closure), so overlapping heartbeat ticks (the design
/// permits parallel ticks when one runs > 30 s) can't race the
/// read-modify-write. NOT a DaemonState field.
final class SensorDegradationState: @unchecked Sendable {
    private let lock = NSLock()
    private var baseline = SensorDegradationEvaluator.Baseline()
    private var lastFileCumulative: UInt64 = 0
    private var lastProcessCumulative: UInt64 = 0
    private var lastKernelDropCumulative: UInt64 = 0
    private var lastCollectorDropCumulative: UInt64 = 0
    private var haveLastCumulative = false

    /// Fold this tick's CUMULATIVE counters (monotonic since the last ES
    /// client (re)create) into per-tick deltas, then evaluate. A client
    /// reconnect resets the kernel counters to a lower value; a negative delta
    /// is clamped to 0 so a restart isn't miscounted as a giant burst.
    func step(
        fileCumulative: UInt64,
        processCumulative: UInt64,
        kernelDropCumulative: UInt64,
        collectorDropCumulative: UInt64,
        benignHighIOSigner: Bool
    ) -> SensorDegradationEvaluator.Result {
        lock.lock(); defer { lock.unlock() }

        // First call: no prior cumulative, so no real delta exists yet. Record
        // and skip the evaluator so its baseline is seeded from the first REAL
        // delta (next tick) rather than a fake zero — which would otherwise let
        // any first delta ≥ minFileEventsForSpike spike against a zero baseline.
        guard haveLastCumulative else {
            lastFileCumulative = fileCumulative
            lastProcessCumulative = processCumulative
            lastKernelDropCumulative = kernelDropCumulative
            lastCollectorDropCumulative = collectorDropCumulative
            haveLastCumulative = true
            return SensorDegradationEvaluator.Result(
                outcome: .noAlert, newBaseline: baseline,
                fileRate: 0, fileBaseline: 0, processRate: 0, processBaseline: 0,
                kernelDropDelta: 0, collectorDropDelta: 0
            )
        }

        func delta(_ cur: UInt64, _ last: UInt64) -> UInt64 { cur >= last ? cur &- last : 0 }
        let fileDelta = delta(fileCumulative, lastFileCumulative)
        let processDelta = delta(processCumulative, lastProcessCumulative)
        let dropDelta = delta(kernelDropCumulative, lastKernelDropCumulative)
        let collectorDropDelta = delta(collectorDropCumulative, lastCollectorDropCumulative)

        lastFileCumulative = fileCumulative
        lastProcessCumulative = processCumulative
        lastKernelDropCumulative = kernelDropCumulative
        lastCollectorDropCumulative = collectorDropCumulative

        let input = SensorDegradationEvaluator.Input(
            fileEventsThisTick: Double(fileDelta),
            processEventsThisTick: Double(processDelta),
            kernelDropDelta: dropDelta,
            collectorDropDelta: collectorDropDelta,
            benignHighIOSigner: benignHighIOSigner
        )
        let result = SensorDegradationEvaluator.evaluate(input: input, baseline: baseline)
        baseline = result.newBaseline
        return result
    }
}

/// Rising-edge latch for the DB-tamper meta-alert — LOCAL to `DaemonTimers.start`
/// (captured by the heartbeat closure) so overlapping ticks can't race the
/// read-modify-write. `DatabaseEncryption.authenticatedDecryptFailures` is a
/// monotonic count of malformed authenticated-encryption envelopes or AES-GCM
/// authentication failures (a corrupted/tampered encrypted DB column/row).
/// `shouldAlert(current:)` returns true only when the count grew
/// since the last observation, so a new alert is raised per fresh tamper burst
/// rather than every 30 s tick; the AlertSink's dedup/suppression backstops the
/// rate limit if failures keep climbing tick-over-tick.
final class TamperAlertState: @unchecked Sendable {
    private let lock = NSLock()
    private var lastSeen = 0

    /// True when `current` exceeds the last observed value (a fresh tamper
    /// failure occurred since the last tick). Updates the watermark. `current`
    /// is monotonic, but a defensive `current < lastSeen` (e.g. a fresh
    /// DatabaseEncryption instance after a reload) never fires and re-seeds.
    func shouldAlert(current: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard current > lastSeen else {
            if current < lastSeen { lastSeen = current }
            return false
        }
        lastSeen = current
        return true
    }
}

// MARK: - v1.21.4 Phase-2 D3 — coverage-canary two-point verdict
//
// The watchdog spawns `/usr/bin/true` with a per-run nonce, then checks two
// independent points: (1) did the ES callback SEE the exec, and (2) did it
// land in `events.db`. This PURE evaluator turns those two booleans into a
// verdict that NAMES the failing stage — so a coverage gap is attributed to
// the kernel/ingest path vs the store/eviction path, not reported as an
// undifferentiated "we lost it". Deterministic → unit-tested without a spawn.
enum CoverageCanaryEvaluator {
    enum StorePresence: Equatable {
        case present
        case absent
        /// Sparse projection or retained-window coverage cannot prove absence.
        case coverageUnknown
    }

    enum Verdict: Equatable {
        /// Seen at the callback AND present in the DB — full coverage.
        case healthy
        /// Missing at the ES callback ⇒ the kernel/ingest stage dropped it
        /// (per-client-queue backpressure — the D1 blind-spot made visible).
        case kernelGap
        /// Seen at the callback but absent from the DB ⇒ the store/eviction
        /// stage lost it (retention sweep evicted the row, or an insert gap).
        case evictionGap
        /// Seen at the callback, but the retained message was refused at the
        /// callback→worker hand-off (the per-client `ESMessageWorker` was at its
        /// in-flight cap). The message existed and we threw it away BEFORE the
        /// pipeline — a third, distinct stage. Without this case every hand-off
        /// drop was reported as `.evictionGap`, pointing the operator at the
        /// storage/retention subsystem for a loss that happened in ingest.
        case ingestHandoffGap
        /// The canary was seen at ingest, but the exact retained/search coverage
        /// ledger cannot prove whether an empty projection means absence.
        case storeQueryUnknown

        /// Human-readable stage name for the alert (nil when healthy).
        var stageLabel: String? {
            switch self {
            case .healthy:           return nil
            case .kernelGap:         return "kernel/ingest"
            case .evictionGap:       return "store/eviction"
            case .ingestHandoffGap:  return "ingest hand-off (worker backpressure)"
            case .storeQueryUnknown: return "store/query coverage unknown"
            }
        }
    }

    /// Two-point verdict. A miss at the callback dominates: if the exec never
    /// reached us, the DB result is moot (and a lone DB hit without a callback
    /// sighting would be a timing artifact of the recognizer window, not real
    /// coverage), so `seenAtCallback == false` is always a kernel gap.
    /// `droppedAtHandoff` is the third point: the probe's retained message was
    /// freed at the callback→worker hand-off, so it provably could not reach
    /// events.db and the absence is NOT eviction. Defaulted to `false` so the
    /// existing two-point call sites and unit tests are source-compatible.
    static func verdict(seenAtCallback: Bool, foundInDB: Bool,
                        droppedAtHandoff: Bool = false) -> Verdict {
        verdict(
            seenAtCallback: seenAtCallback,
            storePresence: foundInDB ? .present : .absent,
            droppedAtHandoff: droppedAtHandoff
        )
    }

    static func verdict(
        seenAtCallback: Bool,
        storePresence: StorePresence,
        droppedAtHandoff: Bool = false
    ) -> Verdict {
        guard seenAtCallback else { return .kernelGap }
        if storePresence == .present { return .healthy }
        if droppedAtHandoff { return .ingestHandoffGap }
        return storePresence == .coverageUnknown
            ? .storeQueryUnknown : .evictionGap
    }
}

/// Non-convergence latch for the events.db size-cap sweep.
///
/// The sweep's target is `0.8 × events_max_size_mb`, but the measured footprint
/// (`db + -wal + -shm`) has a FLOOR the sweep cannot go below: the schema, the
/// `alert_evidence` sub-cap, the `events_fts` index, and the WAL sidecar the
/// footprint measurement itself includes. When the configured cap puts the
/// target under that floor, the file is over target on every tick forever, so
/// the full VACUUM (a whole-file rewrite) ran on every sweep indefinitely —
/// field-measured at ~34 GB dirtied in 2.8 h with 13 consecutive macOS
/// resource-limit diagnostics. v1.21.4 raised the DEFAULT 350 → 420 for exactly
/// this reason, but that fixed no existing install: any config written before
/// that (every upgrader who ever touched `storage{}`) still carries the low cap.
///
/// Rather than guess the floor at config-load time (it depends on the live FTS
/// index and evidence sizes, which the sweep itself changes), detect it
/// empirically: if N consecutive full VACUUMs leave the footprint above target,
/// the rebuild is not converging — stop rebuilding, say so loudly, and re-arm
/// after a back-off so a genuinely transient case still recovers. Prune and
/// incremental_vacuum keep running either way, so the working set stays bounded.
enum SizeCapConvergence {
    private static let lock = NSLock()
    private static var consecutiveFailures = 0
    private static var suppressedUntil: Date?

    /// Consecutive non-converging full VACUUMs before the latch trips.
    static let failureLimit = 3
    /// How long the full VACUUM stays suppressed once latched.
    static let backoffSeconds: TimeInterval = 6 * 3600

    /// Whether the sweep may run a full VACUUM this tick.
    static func shouldFullVacuum(now: Date = Date()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if let until = suppressedUntil {
            guard now >= until else { return false }
            suppressedUntil = nil
            consecutiveFailures = 0
        }
        return true
    }

    /// Record the outcome of a full VACUUM. Returns `true` exactly on the tick
    /// the latch trips, so the caller logs the cap-unreachable error ONCE per
    /// back-off window rather than every sweep.
    static func record(converged: Bool, now: Date = Date()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if converged {
            consecutiveFailures = 0
            suppressedUntil = nil
            return false
        }
        consecutiveFailures += 1
        guard consecutiveFailures >= failureLimit, suppressedUntil == nil else { return false }
        suppressedUntil = now.addingTimeInterval(backoffSeconds)
        return true
    }
}

/// Trace retention is daily while healthy, but a storage-shed TraceStore needs
/// repeated bounded passes to consume more than one 256-row recovery batch.
/// The Dispatch timer supplies the five-minute tick; this small locked gate
/// suppresses healthy ticks until the daily deadline. `DaemonTimerLifecycle`'s
/// label coalescing independently guarantees that slow passes never overlap.
final class TraceStoreRecoveryCadenceGate: @unchecked Sendable {
    static let initialDelaySeconds: TimeInterval = 180
    static let pressureIntervalSeconds: TimeInterval = 300
    static let healthyIntervalSeconds: TimeInterval = 86_400

    private let lock = NSLock()
    private var lastRunAt: Date?
    /// A healthy retention pass is intentionally bounded. If it leaves expired
    /// rows behind, keep the pressure cadence until the producer reports that
    /// the backlog is empty; otherwise a machine producing more than 256 spans
    /// per day can never enforce its configured retention horizon.
    private var retentionDrainPending = false

    func shouldRun(blocked: Bool, now: Date = Date()) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if blocked || retentionDrainPending {
            lastRunAt = now
            return true
        }
        if let lastRunAt {
            let elapsed = now.timeIntervalSince(lastRunAt)
            guard elapsed < 0 || elapsed >= Self.healthyIntervalSeconds else {
                return false
            }
        }
        lastRunAt = now
        return true
    }

    func recordRecoveryOutcome(retentionBacklogRemaining: Bool) {
        lock.lock()
        retentionDrainPending = retentionBacklogRemaining
        lock.unlock()
    }
}

/// TraceGraph recovery is one bounded store pass per admitted timer tick. The
/// gate keeps pressure/proactive drains at a short cadence, holds the current
/// evidence cutoff while eligible backlog remains, and advances only after the
/// store proves that rung is exhausted. Row progress alone is never convergence.
final class TraceGraphRecoveryCadenceGate: @unchecked Sendable {
    static let initialDelaySeconds: TimeInterval = 30
    static let pressureIntervalSeconds: TimeInterval = 30
    static let healthyIntervalSeconds: TimeInterval = 300

    enum Outcome: Equatable {
        case converged
        case draining
        case advanced(toHours: Int)
        case evidenceFloorExhausted
        case waitingAtEvidenceFloor
    }

    private let lock = NSLock()
    private var lastRunAt: Date?
    private var activeCutoffHours: Int?
    private var drainPending = false
    private var evidenceFloorExhausted = false

    func cutoffHoursIfShouldRun(
        blocked: Bool,
        footprintBytes: Int64?,
        proactiveThresholdBytes: Int64?,
        configuredRetentionHours: Int,
        now: Date = Date()
    ) -> Int? {
        lock.lock()
        defer { lock.unlock() }
        let proactive = {
            guard let footprintBytes, let proactiveThresholdBytes else { return false }
            return footprintBytes >= proactiveThresholdBytes
        }()
        let pressure = (blocked || proactive || drainPending)
            && !evidenceFloorExhausted
        let interval = pressure
            ? Self.pressureIntervalSeconds
            : Self.healthyIntervalSeconds
        if let lastRunAt {
            let elapsed = now.timeIntervalSince(lastRunAt)
            guard elapsed < 0 || elapsed >= interval else { return nil }
        }
        lastRunAt = now
        return activeCutoffHours ?? max(1, configuredRetentionHours)
    }

    func recordRecoveryOutcome(
        _ result: CausalGraphStorageRecoveryResult,
        configuredRetentionHours: Int,
        cutoffRungs: [Int]
    ) -> Outcome {
        lock.lock()
        defer { lock.unlock() }

        if result.recoveryDeficitBytes == 0 {
            activeCutoffHours = nil
            drainPending = result.eligibleBacklogRemaining == true
            evidenceFloorExhausted = false
            return drainPending ? .draining : .converged
        }

        // Without a configured cap there is no byte target, but bounded
        // retention still drains every pressure tick while old rows remain.
        if result.recoveryDeficitBytes == nil {
            drainPending = result.eligibleBacklogRemaining != false
            if !drainPending {
                activeCutoffHours = nil
                evidenceFloorExhausted = false
                return .converged
            }
            return .draining
        }

        // Unknown or present backlog is proof that this exact cutoff must run
        // again. This deliberately ignores how many rows/pages the pass moved.
        if result.pinnedReader || result.eligibleBacklogRemaining != false {
            drainPending = true
            evidenceFloorExhausted = false
            return .draining
        }

        let current = activeCutoffHours ?? max(1, configuredRetentionHours)
        if let next = cutoffRungs.first(where: { $0 < current }) {
            activeCutoffHours = next
            drainPending = true
            evidenceFloorExhausted = false
            return .advanced(toHours: next)
        }

        let newlyExhausted = !evidenceFloorExhausted
        drainPending = false
        evidenceFloorExhausted = true
        return newlyExhausted ? .evidenceFloorExhausted : .waitingAtEvidenceFloor
    }
}

/// Creates and starts all periodic timers (forensic scans, hourly tasks,
/// stats logging, retention pruning, maintenance sweeps).
/// Returns the timer sources so they stay alive.
enum DaemonTimers {
    /// Journal retention is a separate contract from the configurable legacy
    /// size-cap sweep. Honor a tighter operator cadence, but never permit more
    /// than the fixed five-minute canonical overhang.
    static func journalExpiryCadenceMinutes(
        configuredMinutes: Int
    ) -> Int {
        min(5, max(1, configuredMinutes > 0 ? configuredMinutes : 5))
    }

    /// One actor turn remains finite even when large canonical records force
    /// small blocks. The timer immediately yields and continues bounded turns
    /// until the store itself proves no eligible block remains.
    static let journalExpiryMaximumBlocksPerQuantum = 64
    /// How long a pass may wait out committed record ownership with no quantum
    /// making progress before it gives the cadence back.
    static let journalExpiryConsecutiveBackpressureBudgetSeconds: TimeInterval = 30
    /// Total waiting one pass may accumulate across all of its quanta. Well
    /// inside the sweep's documented five-minute overhang, so a pass that keeps
    /// alternating between progress and backpressure still cannot carry its
    /// cutoff outside the window it was taken for.
    static let journalExpiryCumulativeBackpressureBudgetSeconds: TimeInterval = 120
    static let journalExpiryBackpressureRetryMilliseconds = 250

    /// Progressively tighter retention windows for TraceGraph recovery, used
    /// only after the store proves the current cutoff has no eligible backlog
    /// while a byte deficit remains. Ordered coarse→fine and floored at one hour, which is well clear of
    /// the 5-minute trace materialization window, so a tightened sweep can never
    /// delete the causal context of a trace still being assembled.
    ///
    /// There is deliberately no rung below the floor: inventing 30- and
    /// 15-minute steps would trade a bounded, reported degradation for silent
    /// destruction of the recent graph, which is the evidence most likely to
    /// matter. If the floor is not enough, the condition is reported instead.
    static let tracegraphRecoveryCutoffHours: [Int] = [72, 24, 6, 1]
    /// Boot may spend several ordinary timer-sized quanta recovering an
    /// inherited blocked graph, but it remains strictly bounded. At the
    /// current per-pass limits this can retire at most 16,384 traces and 128k
    /// orphan rows per table before producers are allowed to start.
    static let tracegraphStartupRecoveryMaximumPasses = 64

    /// How recently sequence eviction must have occurred for continuity to count
    /// as currently degraded. Long enough that a genuinely sustained flush stays
    /// flagged across heartbeat ticks; short enough that a single spike clears
    /// on its own instead of latching for the life of the process.
    static let sequenceEvictionHealthWindow: TimeInterval = 300

    /// Stateful, non-recursive POSIX directory stream for the privileged inbox.
    ///
    /// Keeping the stream open across ticks is intentional. A fresh `readdir`
    /// from offset zero on every tick lets a flood of dot-prefixed atomic-temp
    /// names permanently hide a legitimate request behind the fixed per-tick
    /// cap. Resuming the same stream guarantees that every entry in the current
    /// directory generation is eventually visited while still doing at most
    /// `limit` entry reads (and allocations) per tick.
    final class InboxDirectoryScanner: @unchecked Sendable {
        private let path: String
        private let lock = NSLock()
        private var stream: UnsafeMutablePointer<DIR>?

        init(path: String) {
            self.path = path
        }

        deinit {
            if let stream { closedir(stream) }
        }

        /// Return at most `limit` immediate child names. This never recursively
        /// walks attacker-created directories and never materializes the whole
        /// inbox. Reaching EOF closes the generation; the next tick opens a new
        /// stream so requests created during/after the prior scan are observed.
        func nextBatch(limit: Int) -> [String] {
            guard limit > 0 else { return [] }
            lock.lock()
            defer { lock.unlock() }

            if stream == nil { stream = opendir(path) }
            guard let stream else { return [] }

            var names: [String] = []
            names.reserveCapacity(limit)
            while names.count < limit {
                guard let entry = readdir(stream) else {
                    closedir(stream)
                    self.stream = nil
                    break
                }
                let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                    pointer.withMemoryRebound(
                        to: CChar.self,
                        capacity: MemoryLayout.size(ofValue: entry.pointee.d_name)
                    ) { String(cString: $0) }
                }
                if name == "." || name == ".." { continue }
                names.append(name)
            }
            return names
        }
    }

    struct InboxScanBatch: Equatable {
        let requestNames: [String]
        let examinedEntryCount: Int
    }

    /// One source of truth for the names the poller will claim. The read-cap
    /// policy below and the partitioning in the timer both derive from this
    /// list, preventing a newly added request shape from silently bypassing the
    /// hardened reader.
    static let knownInboxRequestPrefixes = [
        "suppress-alert-", "unsuppress-alert-", "delete-alert-",
        "suppress-campaign-", "refresh-intel-", "reload-rules-",
        "llm-config-", "flush-request-", "record-clipboard-",
        "builtin-rule-setting-", "set-daemon-config-", "install-rule-",
        "remove-rule-", "set-agent-capabilities-", "prune-alerts-",
        "apply-agent-traces-", "prevention-config-", "trace-dashboard-key-",
    ]

    static func isClaimedInboxRequestName(_ name: String) -> Bool {
        name.hasSuffix(".json")
            && knownInboxRequestPrefixes.contains(where: { name.hasPrefix($0) })
    }

    /// Safely remove one immediate inbox entry without recursively traversing
    /// an attacker-created directory. `unlink` handles files, FIFOs, sockets and
    /// symlinks; `rmdir` is attempted only for an empty directory.
    static func removeInboxEntry(at path: String) {
        if unlink(path) != 0, errno == EISDIR || errno == EPERM {
            _ = rmdir(path)
        }
    }

    /// Stream one bounded poller batch and discard entries no handler can ever
    /// claim. Recent dotfiles receive a grace window because legitimate writers
    /// use `.<verb>-<uuid>.tmp` followed by atomic rename. The retained scanner
    /// advances past them, so even more than one tick's worth cannot starve a
    /// valid request; stale temp files are eventually unlinked.
    static func inboxScanBatch(
        scanner: InboxDirectoryScanner,
        inboxDir: String,
        maxEntries: Int = 512,
        temporaryFileGrace: TimeInterval = 60,
        now: Date = Date()
    ) -> InboxScanBatch {
        let names = scanner.nextBatch(limit: maxEntries)
        var requests: [String] = []
        requests.reserveCapacity(names.count)

        for name in names {
            if isClaimedInboxRequestName(name) {
                requests.append(name)
                continue
            }

            let path = inboxDir + "/" + name
            guard name.hasPrefix(".") else {
                removeInboxEntry(at: path)
                continue
            }

            // lstat never follows a planted symlink and never opens a FIFO.
            // Only a recent REGULAR dotfile can be a legitimate atomic writer.
            var st = stat()
            guard lstat(path, &st) == 0 else { continue }
            let type = st.st_mode & S_IFMT
            guard type == S_IFREG else {
                removeInboxEntry(at: path)
                continue
            }
            let modified = Date(
                timeIntervalSince1970: TimeInterval(st.st_mtimespec.tv_sec)
                    + TimeInterval(st.st_mtimespec.tv_nsec) / 1_000_000_000
            )
            let age = now.timeIntervalSince(modified)
            // A far-future mtime is attacker-controlled, not an indefinite
            // lease. Allow one grace interval for ordinary clock adjustment.
            if age >= temporaryFileGrace || age < -temporaryFileGrace {
                removeInboxEntry(at: path)
            }
        }

        return InboxScanBatch(
            requestNames: requests,
            examinedEntryCount: names.count
        )
    }

    struct Handles {
        let lifecycle: DaemonTimerLifecycle
        /// Reserved capacity for the minimal no-actor liveness write. Slow
        /// maintenance/rich-heartbeat/model work can never consume this slot.
        let livenessLifecycle: DaemonTimerLifecycle
        let forensicTimer: DispatchSourceTimer
        let hourlyTimer: DispatchSourceTimer
        let statsTimer: DispatchSourceTimer
        /// Short owned drain for heavyweight results that finish after the last
        /// input event. Without it, a quiet host can retain completed evidence
        /// indefinitely and never run dependency-filtered detection replay.
        let deferredEnrichmentTimer: DispatchSourceTimer
        /// v1.8.0: split from one shared `pruneTimer` so events / alerts /
        /// campaigns each have their own retention cadence + size cap.
        let alertsPruneTimer: DispatchSourceTimer
        let alertsSizeCapTimer: DispatchSourceTimer
        let campaignsPruneTimer: DispatchSourceTimer?
        let campaignsSizeCapTimer: DispatchSourceTimer?
        let sizeCapTimer: DispatchSourceTimer
        /// Canonical event-journal expiry is independent of the legacy
        /// projection/cap sweep and must never lag by more than five minutes.
        let eventJournalExpiryTimer: DispatchSourceTimer
        /// v1.12.6: early-fire watchdog (60 s cadence) for the events.db
        /// size cap. Defense-in-depth for the configurable scheduled
        /// `sizeCapTimer` — catches growth before hard admission pauses writes
        /// between scheduled sweeps. Retained here so the DispatchSourceTimer
        /// isn't ARC-deallocated on return from `start()` (mirrors the
        /// v1.10.0 fix for the trace/tracegraph prune timers).
        let sizeCapWatchdogTimer: DispatchSourceTimer
        let maintenanceTimer: DispatchSourceTimer
        let heartbeatTimer: DispatchSourceTimer
        /// v1.7.5: minimal liveness heartbeat decoupled from the rich
        /// payload. Synchronous dispatch-thread file write of
        /// `heartbeat.json`. Cannot deadlock on actor work.
        let livenessTimer: DispatchSourceTimer
        /// v1.10.0: daily retention sweeps for the v1.10 stores. Pre-fix
        /// these were declared as local lets inside start() and went
        /// out of scope on return — DispatchSourceTimer ARC-deallocates
        /// without retention, silently breaking pruning. Now retained.
        let tracegraphPruneTimer: DispatchSourceTimer?
        let tracesPruneTimer: DispatchSourceTimer?
        /// v1.18.0: daily sweep for generated-artifact directories that
        /// previously had no retention — `reports/` (age-based) and
        /// `compiled_rules/auto_generated/` (count cap, oldest-first).
        let artifactsPruneTimer: DispatchSourceTimer?
        /// v1.10.0: file-based IPC poller. Polls
        /// /Library/Application Support/MacCrab/inbox/*.json every 5 s
        /// so the dashboard (running as the user) can request mutations
        /// on a root-owned DB without needing signal-delivery permission.
        /// Handles: flush-request-*, suppress-alert-*, unsuppress-alert-*,
        /// delete-alert-*, suppress-campaign-* (v1.10.1).
        let inboxPoller: DispatchSourceTimer
        /// v1.21.4 Phase-2 (D3): jittered coverage-canary watchdog. Self-
        /// reschedules ~5-15 min out on each fire (see start()). Retained here
        /// so the DispatchSourceTimer isn't ARC-deallocated on return from
        /// start() (same reason as the prune timers above).
        let coverageCanaryTimer: DispatchSourceTimer
    }

    static func start(state: DaemonState, eventCount: @escaping () -> UInt64, alertCount: @escaping () -> UInt64, startTime: Date) -> Handles {
        let engineIdentity = DaemonProcessIdentity.current
        let timerLifecycle = DaemonTimerLifecycle(coalesceByLabel: true)
        let livenessLifecycle = DaemonTimerLifecycle(
            maximumInFlightHandlers: 1,
            coalesceByLabel: true
        )
        let deferredEnrichmentTimer = DispatchSource.makeTimerSource(
            queue: .global()
        )
        deferredEnrichmentTimer.schedule(
            deadline: .now() + .milliseconds(100),
            repeating: .milliseconds(100),
            leeway: .milliseconds(25)
        )
        deferredEnrichmentTimer.setEventHandler {
            timerLifecycle.submit(label: "deferred-enrichment-drain") {
                await DeferredEnrichmentDispatcher.drainAvailable(state: state)
            }
        }
        deferredEnrichmentTimer.resume()
        @Sendable func liveEventsFamilyCapMiB() -> Int {
            let transition = state.legacyEvidenceTransitionBudget.snapshot()
            return state.storage.effectiveEventsFamilyMaxSizeMB(
                appliedLegacyEvidenceTransitionReserveMiB:
                    transition.appliedReserveMiB
            )
        }

        /// Re-measure only after a maintenance boundary. Alert capture never
        /// grows the legacy table, so DBSTAT stays entirely off the hot path.
        @discardableResult
        @Sendable func refreshLegacyEvidenceTransitionBudget(
            context: String
        ) async -> LegacyEvidenceTransitionBudgetSnapshot {
            let ticket = state.legacyEvidenceTransitionBudget
                .measurementTicket()
            let before = state.legacyEvidenceTransitionBudget.snapshot()
            guard before.configurationGeneration
                    == ticket.configurationGeneration else {
                return before
            }
            let maximum = ticket.storage.evidenceMaxSizeMB
            let measurement: LegacyAlertEvidenceTransitionMeasurement?
            do {
                measurement = try await state.eventStore
                    .legacyAlertEvidenceTransitionMeasurement(
                        maxBytes: SQLitePersistentStorePolicy.capBytes(
                            maxSizeMiB: maximum
                        )
                    )
            } catch {
                measurement = nil
                logger.warning("\(context, privacy: .public): legacy alert-evidence ownership probe failed; retaining the full \(maximum) MiB transition reserve: \(error.localizedDescription, privacy: .public)")
            }
            let after = state.legacyEvidenceTransitionBudget.update(
                measurement: measurement,
                ticket: ticket
            )
            guard after.configurationGeneration
                    == ticket.configurationGeneration else {
                logger.info("\(context, privacy: .public): discarded stale legacy-evidence measurement for storage generation \(ticket.configurationGeneration); current generation is \(after.configurationGeneration)")
                return after
            }
            guard let pending = after.pendingReserveMiB else { return after }
            guard after.pendingReserveFitsHardBoundary == true else {
                logger.warning("\(context, privacy: .public): legacy-evidence reserve candidate \(pending) MiB remains pending; WAL/family footprint does not yet prove the lower hard boundary")
                return after
            }
            let oldCap = ticket.storage.effectiveEventsFamilyMaxSizeMB(
                appliedLegacyEvidenceTransitionReserveMiB:
                    before.appliedReserveMiB
            )
            let newCap = ticket.storage.effectiveEventsFamilyMaxSizeMB(
                appliedLegacyEvidenceTransitionReserveMiB:
                    pending
            )
            do {
                let admission = try await state.eventStore.updateStorageAdmission(
                    SQLitePersistentStorePolicy(
                        maxFootprintBytes: SQLitePersistentStorePolicy.capBytes(
                            maxSizeMiB: newCap
                        ),
                        freeSpaceFloorBytes: SQLitePersistentStorePolicy
                            .freeSpaceFloorBytes,
                        transactionReserveBytes: SQLitePersistentStorePolicy
                            .eventTransactionReserveBytes,
                        storageVolumePath: state.supportDir
                    )
                )
                let committed = state.legacyEvidenceTransitionBudget
                    .commitPendingReserve(pending, ticket: ticket)
                guard committed.appliedReserveMiB == pending,
                      committed.pendingReserveMiB == nil else {
                    logger.error("\(context, privacy: .public): events-family policy reached \(newCap) MiB, but storage generation changed before the reserve commit; the current configuration will re-apply its authoritative policy")
                    return committed
                }
                state.eventRetentionBudgetHealth.recordConfigurationChange()
                logger.notice("\(context, privacy: .public): applied legacy evidence reserve \(before.appliedReserveMiB)->\(committed.appliedReserveMiB) MiB; events-family cap \(oldCap)->\(newCap) MiB; admission=\(admission?.latchedFailure ?? "active", privacy: .public)")
                return committed
            } catch {
                logger.fault("\(context, privacy: .public): failed to apply measured events-family transition cap \(newCap) MiB: \(error.localizedDescription, privacy: .public)")
            }
            return after
        }
        // Periodic forensic scans (crash reports, power anomalies, library inventory)
        let forensicTimer = DispatchSource.makeTimerSource(queue: .global())
        forensicTimer.schedule(deadline: .now() + 120, repeating: 300) // First at 2min, then every 5min
        // v1.6.22: counter so the library-inventory scan runs only every
        // other forensic tick (10 min cadence) instead of every tick (5 min).
        // The pre-v1.6.22 inline comment claimed "every other cycle" but no
        // skip logic existed, so it ran on every fire. Tally is bumped on
        // every fire and the scan only runs on odd values.
        let libraryInventoryTickCounter = LockedCounter()
        forensicTimer.setEventHandler {
            timerLifecycle.submit(label: "forensic") {
                // Crash report mining.
                // Route every synthetic alert here through the shared
                // AlertDeduplicator. Without it, a single long-lived process
                // (lldb-rpc-server, WindowServer, etc.) emitting the same
                // finding on successive scans produces a fresh alert every
                // tick — observed in production as 19 identical alerts per
                // 48 h for a single Xcode debug session.
                let exploits = await state.crashReportMiner.scan()
                for exploit in exploits {
                    let ruleId = "maccrab.forensic.crash-exploit-\(exploit.indicator)"
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Exploitation Indicator in Crash Report: \(exploit.processName)",
                        severity: exploit.severity,
                        eventId: UUID().uuidString,
                        processPath: exploit.reportPath, processName: exploit.processName,
                        description: "\(exploit.indicator): \(exploit.excerpt)",
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1203",
                        suppressed: false
                    )
                    let inserted: Bool
                    do { inserted = try await state.alertSink.submit(alert: alert) }
                    catch { await StorageErrorTracker.shared.recordAlertError(error); continue }
                    guard inserted else { continue }
                    if exploit.severity >= .high { await state.notifier.notify(alert: alert) }
                    print("[CRASH] \(exploit.indicator) in \(exploit.processName)")
                }

                // Power anomaly detection.
                let anomalies = await state.powerAnomalyDetector.scan()
                for anomaly in anomalies {
                    let ruleId = "maccrab.forensic.power-\(anomaly.type.rawValue)"
                    // processPath is nil for power events; use processName as
                    // the dedup-fallback key so AlertSink partitions by app.
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Power Anomaly: \(anomaly.processName) \(anomaly.type.rawValue)",
                        severity: anomaly.severity,
                        eventId: UUID().uuidString,
                        processPath: anomaly.processName,
                        processName: anomaly.processName,
                        description: anomaly.detail,
                        mitreTactics: "attack.execution", mitreTechniques: "attack.t1496",
                        suppressed: false
                    )
                    do { _ = try await state.alertSink.submit(alert: alert) }
                    catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // Library inventory scan (every other cycle — resource intensive).
                // v1.6.22 made the every-other-cycle skip real (it had been a
                // promise without an implementation). LibraryInventory also
                // does its own (pid, libraryPath) dedup internally so the same
                // loaded dylib doesn't re-alert across scans even if the
                // surrounding AlertDeduplicator window expires.
                let tick = libraryInventoryTickCounter.increment()
                guard tick.isMultiple(of: 2) else { return }
                let injected = await state.libraryInventory.scanAllProcesses()
                for lib in injected {
                    let ruleId = "maccrab.forensic.injected-library"
                    let alert = Alert(
                        ruleId: ruleId,
                        ruleTitle: "Injected Library: \(lib.processName) loaded \((lib.libraryPath as NSString).lastPathComponent)",
                        severity: lib.severity,
                        eventId: UUID().uuidString,
                        processPath: lib.processPath, processName: lib.processName,
                        description: "\(lib.reason). Library: \(lib.libraryPath)",
                        mitreTactics: "attack.defense_evasion", mitreTechniques: "attack.t1574.006",
                        suppressed: false
                    )
                    let inserted: Bool
                    do { inserted = try await state.alertSink.submit(alert: alert) }
                    catch { await StorageErrorTracker.shared.recordAlertError(error); continue }
                    guard inserted else { continue }
                    if lib.severity >= .high { await state.notifier.notify(alert: alert) }
                    print("[INJECT] \(lib.processName) <- \(lib.libraryPath)")
                }
            }
        }
        forensicTimer.resume()

        // Hourly: security score refresh, vuln scan, privacy audit purge, digest
        let hourlyTimer = DispatchSource.makeTimerSource(queue: .global())
        hourlyTimer.schedule(deadline: .now() + 3600, repeating: 3600)
        hourlyTimer.setEventHandler {
            timerLifecycle.submit(label: "hourly") {
                // Refresh security score
                let score = await state.securityScorer.calculate()
                logger.info("Security score: \(score.totalScore)/100 (\(score.grade))")

                // LLM security posture analysis (non-blocking, hourly, only if score < 90)
                if let llm = state.llmService, score.totalScore < 90 {
                    let totalScore = score.totalScore
                    let grade = score.grade
                    let factors = score.factors.map { ($0.name, $0.category, $0.score, $0.maxScore, $0.status, $0.detail) }
                    let recs = score.recommendations
                    state.advisoryWorkLifecycle.submit(
                        label: "hourly.llm-posture"
                    ) {
                        if let analysis = await llm.commentary(
                            systemPrompt: LLMPrompts.securityScoreSystem,
                            userPrompt: LLMPrompts.securityScoreUser(
                                totalScore: totalScore, grade: grade,
                                factors: factors, recommendations: recs
                            ),
                            maxTokens: 512, temperature: 0.3,
                            feature: .securityPosture
                        ) {
                            // AI-14: this alert had no explicit id, so every
                            // hourly emission minted a fresh UUID and appended a
                            // row — 369 rows on this host with 369 DISTINCT
                            // descriptions for an essentially unchanged posture
                            // (same grade, same failing factor for months).
                            // AlertDeduplicator cannot help: its suppression
                            // window is 3600s, EXACTLY this timer's period, so
                            // every emission arrives just as the window lapses.
                            // A posture-derived id lets alerts.db's INSERT OR
                            // REPLACE (id is the PRIMARY KEY) collapse an
                            // unchanged posture onto ONE row that updates in
                            // place — the same mechanism the vuln scan below
                            // already uses with id: "vuln-<cveId>". A genuine
                            // score change still mints a new row, which is the
                            // signal worth keeping.
                            let scoreAlert = Alert(
                                id: "llm-security-score-\(grade)-\(totalScore)",
                                ruleId: "maccrab.llm.security-score",
                                ruleTitle: "AI Security Recommendations (\(grade) — \(totalScore)/100)",
                                severity: .informational,
                                eventId: UUID().uuidString,
                                processPath: nil, processName: "maccrabd",
                                description: analysis.response,
                                mitreTactics: nil, mitreTechniques: nil,
                                suppressed: false
                            )
                            do { _ = try await state.alertSink.submit(alert: scoreAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                            print("[LLM] Security score analysis: \(grade) (\(totalScore)/100)")
                        }
                    }
                }

                // Vulnerability scan — emit alerts for critical/high CVEs.
                // Alert ID = "vuln-<cveId>" so INSERT OR REPLACE deduplicates
                // at the DB level: same CVE updates the existing alert rather
                // than creating duplicates on every hourly scan.
                //
                // v1.19.1: the osv.dev lookup POSTs the installed-software
                // inventory, so it is opt-in (off by default). Read the flag
                // live from state so a SIGHUP toggle takes effect next sweep.
                let vulns = state.vulnScanEnabled ? await state.vulnScanner.scanInstalledApps() : []
                for vuln in vulns {
                    for v in vuln.vulnerabilities where v.severity == "critical" || v.severity == "high" {
                        logger.warning("Vulnerable app: \(vuln.appName) v\(vuln.installedVersion) -- \(v.cveId)")
                        let sev: Severity = v.severity == "critical" ? .critical : .high
                        let fixNote = v.fixedInVersion.map { " Fixed in \($0)." } ?? ""
                        let desc = "\(vuln.appName) \(vuln.installedVersion) contains \(v.cveId) (\(v.severity.uppercased())).\(fixNote) Update immediately."
                        let vulnAlert = Alert(
                            id: "vuln-\(v.cveId)",
                            ruleId: "maccrab.vuln.\(v.cveId)",
                            ruleTitle: "\(v.cveId) in \(vuln.appName) \(vuln.installedVersion)",
                            severity: sev,
                            eventId: "vuln-\(v.cveId)",
                            processPath: vuln.appPath,
                            processName: vuln.appName,
                            description: desc,
                            mitreTactics: nil,
                            mitreTechniques: nil,
                            suppressed: false
                        )
                        do { _ = try await state.alertSink.submit(alert: vulnAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                    }
                }

                // Privacy egress anomaly alerts. Alert ID keyed on process +
                // anomaly kind so each unique (app, kind) pair produces one
                // alert regardless of scan frequency.
                let privacyAnomalies = await state.appPrivacyAuditor.checkForAnomalies()
                for anomaly in privacyAnomalies {
                    logger.warning("Privacy anomaly [\(anomaly.kind.rawValue)]: \(anomaly.detail)")
                    let alertId = "privacy-\(anomaly.processName)-\(anomaly.kind.rawValue)"
                    let privAlert = Alert(
                        id: alertId,
                        ruleId: "maccrab.privacy.\(anomaly.kind.rawValue)",
                        ruleTitle: "Privacy: \(anomaly.kind.rawValue.replacingOccurrences(of: "_", with: " ").capitalized) — \(anomaly.processName)",
                        severity: .medium,
                        eventId: alertId,
                        processPath: anomaly.processPath,
                        processName: anomaly.processName,
                        description: anomaly.detail,
                        mitreTactics: nil,
                        mitreTechniques: nil,
                        suppressed: false
                    )
                    do { _ = try await state.alertSink.submit(alert: privAlert) } catch { await StorageErrorTracker.shared.recordAlertError(error) }
                }

                // Purge old privacy audit data
                await state.appPrivacyAuditor.purge(olderThan: 86400)

                // MISP sync (if configured)
                if await state.mispClient.isConfigured {
                    let iocs = await state.mispClient.fetchCategorized(lastDays: 1)
                    if !iocs.ips.isEmpty || !iocs.domains.isEmpty {
                        await state.threatIntel.addCustomIOCs(hashes: iocs.hashes, ips: iocs.ips, domains: iocs.domains)
                    }
                }

                // v1.6.15: refresh the on-disk integrations snapshot so
                // the dashboard's IntegrationsView shows the daemon's
                // enriched results (running-state checks done at root
                // privilege) instead of re-scanning from user context.
                let integrationsSnapshotPath = state.supportDir + "/integrations_snapshot.json"
                await state.toolIntegrations.writeSnapshot(to: integrationsSnapshotPath)

                // Scheduled reports -- daily digest + weekly HTML report
                let recentAlerts = (try? await state.alertStore.alerts(
                    since: Date().addingTimeInterval(-7 * 86400),
                    limit: 10000
                )) ?? []
                let alertTuples = recentAlerts.map { a in
                    (ruleTitle: a.ruleTitle, severity: a.severity.rawValue,
                     processName: a.processName ?? "unknown", timestamp: a.timestamp)
                }
                let alertTotal = (try? await state.alertStore.count()) ?? 0
                await state.scheduledReports.checkAndGenerate(
                    alerts: alertTuples,
                    eventCount: alertTotal,
                    securityScore: score.totalScore,
                    reportGenerator: state.reportGenerator,
                    digestGenerator: state.securityDigest,
                    notificationIntegrations: state.notificationIntegrations
                )
            }
        }
        hourlyTimer.resume()

        // Keep references alive for on-demand use
        _ = state.cdhashExtractor
        _ = state.travelMode
        _ = state.securityDigest
        _ = state.vulnScanner
        _ = state.toolIntegrations
        _ = state.alertExporter
        _ = state.scheduledReports

        // Periodic stats logging
        let statsTimer = DispatchSource.makeTimerSource(queue: .global())
        statsTimer.schedule(deadline: .now() + 60, repeating: 60)
        statsTimer.setEventHandler {
            // Reconcile missed AI-root EXITs on the existing owned/joined timer
            // plane. This is deliberately a separate coalescing label from
            // stats: slow event-store health work cannot queue reconciliation,
            // and shutdown cancels/joins the exact accepted task prefix.
            timerLifecycle.submit(label: "ai-session-reconcile") {
                let result = await state.aiSessionLifecycleCoordinator.reconcile(
                    tracker: state.aiTracker,
                    projectBoundary: state.projectBoundary,
                    lineageService: state.agentLineageService,
                    sessionRegistry: state.agentSessionRegistry
                )
                if result.removedDead > 0 || result.removedReplaced > 0 {
                    logger.notice("AI session reconciliation: examined=\(result.examined), dead=\(result.removedDead), replaced=\(result.removedReplaced), cas_misses=\(result.generationCASMisses), callback_snapshot_accepted=\(result.callbackSnapshotAccepted)")
                }
            }
            timerLifecycle.submit(label: "stats") {
                let ec = eventCount()
                let ac = alertCount()
                let uptime = Int(Date().timeIntervalSince(startTime))
                let hours = uptime / 3600
                let minutes = (uptime % 3600) / 60
                logger.info("Stats: \(ec) events processed, \(ac) alerts, uptime \(hours)h\(minutes)m")

                // Learned intent state is explicitly bounded and decaying;
                // prune it on an owned timer rather than relying only on future
                // observations to discover idle scopes. Conservation failures
                // or capacity eviction are health signals, not debug trivia.
                let intentPrune = await state.bayesianIntent.prune(asOf: Date())
                let intentStats = await state.bayesianIntent.statistics()
                if !intentStats.observationsConserved
                    || !intentStats.treeLifecycleConserved
                    || !intentStats.treeCapacityRespected {
                    logger.error("Intent advisory invariant failed: observations=\(intentStats.observations), accepted=\(intentStats.acceptedObservations), suppressed=\(intentStats.suppressedObservations), active_trees=\(intentStats.activeTrees), max_trees=\(intentStats.maximumTrees)")
                } else if intentPrune.treesRemoved > 0
                    || intentPrune.evidenceRecordsExpired > 0 {
                    logger.info("Intent advisory prune: trees=\(intentPrune.treesRemoved), evidence=\(intentPrune.evidenceRecordsExpired), active=\(intentStats.activeTrees)")
                }

                // Report eslogger sequence-gap drops (buffer overflow indicator)
                if let eslogger = state.esloggerCollector {
                    let dropped = await eslogger.getDroppedEventCount()
                    if dropped > 0 {
                        logger.warning("eslogger: \(dropped) events dropped (sequence gaps)")
                    }
                }

                // Event flow health check: warn if no new events stored in the last 5 minutes.
                // Skips the first 2 minutes of uptime to allow collectors to start up.
                guard uptime > 120 else { return }
                if let snapshot = try? await state.eventStore
                    .exactEventsSnapshot(
                        since: Date.distantPast,
                        limit: 1
                    ), snapshot.isComplete,
                   let latestEvent = snapshot.events.first {
                    let staleness = Date().timeIntervalSince(latestEvent.timestamp)
                    if staleness > 300 {
                        let staleMinutes = Int(staleness / 60)
                        logger.warning("Event flow stalled: no new events stored for \(staleMinutes)m — collectors may need restart")
                        logger.warning("Check: log stream --predicate 'subsystem==\"com.maccrab.agent\" AND category==\"EventStream\"'")
                    }
                    withExtendedLifetime(snapshot) {}
                }
            }
        }
        statsTimer.resume()

        // v1.8.0 storage redesign: per-tier retention, decoupled timers.
        // Pre-v1.8 used one daily timer to prune both events and alerts
        // with the same cutoff, so a heavy event firehose evicted alerts
        // as collateral damage. The redesign:
        //
        //   - Events are governed by the adaptive rollup below (1h hot
        //     tier by default). No separate daily timer for events.
        //   - Alerts and campaigns each get their own daily prune timer
        //     reading their own retentionDays — typically 365d, fully
        //     independent of event churn.
        //   - Each store also has an hourly size-cap timer for defense
        //     in depth: alertsMaxSizeMB / campaignsMaxSizeMB.
        //
        // All knobs read live from state.storage so a SIGHUP-driven
        // config reload is honored on the next tick.

        let alertsPruneTimer = DispatchSource.makeTimerSource(queue: .global())
        alertsPruneTimer.schedule(deadline: .now() + 3600, repeating: 86400)
        alertsPruneTimer.setEventHandler {
            timerLifecycle.submit(label: "alerts-retention") {
                let days = max(1, min(state.storage.alertsRetentionDays, 3650))
                let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                let pruned = (try? await state.alertStore.prune(olderThan: cutoff)) ?? 0
                if pruned > 0 {
                    logger.info("Alerts retention sweep: \(pruned) alerts older than \(days)d pruned")
                }
            }
        }
        alertsPruneTimer.resume()

        let campaignsPruneTimer: DispatchSourceTimer?
        if let campaignStore = state.campaignStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 3600, repeating: 86400)
            t.setEventHandler {
                timerLifecycle.submit(label: "campaigns-retention") {
                    let days = max(1, min(state.storage.campaignsRetentionDays, 3650))
                    let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                    let pruned = (try? await campaignStore.prune(olderThan: cutoff)) ?? 0
                    if pruned > 0 {
                        logger.info("Campaigns retention sweep: \(pruned) campaigns older than \(days)d pruned")
                    }
                }
            }
            t.resume()
            campaignsPruneTimer = t
        } else {
            campaignsPruneTimer = nil
        }

        // v1.10.0 audit fix: tracegraph.db + traces.db both shipped
        // in v1.9/v1.10 with no retention. On a dev machine running
        // Claude Code daily this grew several GB / month indefinitely.
        // Default 90d retention + size cap (250 MB tracegraph, 100 MB
        // traces). Size-cap fallback applies pruneOldest if a 90d cut alone
        // can't fit the budget.
        let tracegraphPruneTimer: DispatchSourceTimer?
        if let causalStore = state.causalStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            let recoveryCadence = TraceGraphRecoveryCadenceGate()
            // Inspect every 30 seconds so a blocked/proactive drain can consume
            // many bounded quanta before ingest refills the recovered pages.
            // The cadence gate retains the five-minute healthy sweep and timer
            // lifecycle label coalescing prevents overlapping actor passes.
            t.schedule(
                deadline: .now() + TraceGraphRecoveryCadenceGate.initialDelaySeconds,
                repeating: TraceGraphRecoveryCadenceGate.pressureIntervalSeconds
            )
            t.setEventHandler {
                timerLifecycle.submit(label: "tracegraph-recovery") {
                    let days = max(1, min(state.storage.tracegraphRetentionDays, 3650))
                    let configuredHours = days * 24
                    let now = Date()
                    let before = await causalStore.storageAdmissionStatus()
                    guard let cutoffHours = recoveryCadence.cutoffHoursIfShouldRun(
                        blocked: before.blocked,
                        footprintBytes: before.footprintBytes,
                        proactiveThresholdBytes: before.proactiveRecoveryThresholdBytes,
                        configuredRetentionHours: configuredHours,
                        now: now
                    ) else { return }
                    let cutoff = now.addingTimeInterval(-Double(cutoffHours) * 3600)
                    // Never delete graph substrate or traces newer than this
                    // one-hour floor; it is well clear of materialization's 5m window.
                    let orphanCutoff = now.addingTimeInterval(-3600)
                    do {
                        let result = try await causalStore.recoverStorageBudget(
                            retentionCutoff: cutoff,
                            orphanCutoff: orphanCutoff
                        )
                        let admission = await causalStore.storageAdmissionStatus()
                        let outcome = recoveryCadence.recordRecoveryOutcome(
                            result,
                            configuredRetentionHours: configuredHours,
                            cutoffRungs: Self.tracegraphRecoveryCutoffHours
                        )
                        let madeProgress = result.tracesDeleted > 0
                            || result.traceChildRowsDeleted > 0
                            || result.edgesDeleted > 0
                            || result.entitiesDeleted > 0
                            || result.vacuumPagesReclaimed > 0
                        if result.pinnedReader {
                            logger.warning("TraceGraph bounded recovery paused by a reader-pinned WAL; no further delete/vacuum work issued this tick")
                        } else if madeProgress {
                            logger.info("TraceGraph bounded recovery at \(cutoffHours)h: \(result.tracesDeleted) traces + \(result.traceChildRowsDeleted) trace-child rows + \(result.edgesDeleted) edges + \(result.entitiesDeleted) entities deleted; \(result.vacuumPagesReclaimed) pages reclaimed; footprint \(result.footprintBeforeBytes ?? -1) -> \(result.footprintBytes ?? -1) bytes; target \(result.recoveryTargetBytes ?? -1), deficit \(result.recoveryDeficitBytes ?? -1), eligible backlog=\(String(describing: result.eligibleBacklogRemaining))")
                        }
                        switch outcome {
                        case .advanced(let nextHours):
                            logger.notice("TraceGraph recovery still has a \(result.recoveryDeficitBytes ?? -1)-byte deficit after exhausting the \(cutoffHours)h cutoff; the next bounded pass will tighten traces to \(nextHours)h")
                        case .evidenceFloorExhausted:
                            logger.fault("TraceGraph remains \(result.recoveryDeficitBytes ?? -1) bytes above its recovery target after exhausting the one-hour evidence floor. Recent causal evidence was NOT deleted. Recovery can resume only as physical-write suppression slows growth and protected rows age past the floor, or when capacity is raised; graph rules and trace queries remain degraded meanwhile.")
                        case .converged, .draining, .waitingAtEvidenceFloor:
                            break
                        }

                        if admission.blocked, result.autoVacuumMode == 0 {
                            logger.warning("TraceGraph remains storage-shed and auto_vacuum mode is 0/NONE. Stop the engine before performing an offline full-VACUUM conversion; online full VACUUM recovery is intentionally disabled. Mode 1/FULL reclaims on DELETE commit and does not require conversion.")
                        }
                    } catch {
                        logger.warning("TraceGraph bounded recovery failed: \(error.localizedDescription, privacy: .public)")
                    }
                }
            }
            t.resume()
            tracegraphPruneTimer = t
        } else {
            tracegraphPruneTimer = nil
        }

        let tracesPruneTimer: DispatchSourceTimer?
        let t = DispatchSource.makeTimerSource(queue: .global())
        let tracesRecoveryCadence = TraceStoreRecoveryCadenceGate()
        // First bounded recovery shortly after boot, then inspect every five
        // minutes. A blocked store runs one bounded pass per tick until it
        // converges; a healthy store is admitted by the cadence gate only once
        // per day. The timer is retained even when the receiver is disabled at
        // boot and resolves the current actor only when it fires, so SIGHUP
        // enable/disable and port changes cannot pin a stale TraceStore handle.
        // Label coalescing prevents overlap if one pass exceeds five minutes.
        t.schedule(
            deadline: .now() + TraceStoreRecoveryCadenceGate.initialDelaySeconds,
            repeating: TraceStoreRecoveryCadenceGate.pressureIntervalSeconds
        )
        t.setEventHandler {
            timerLifecycle.submit(label: "traces-recovery") {
                guard let traceStore = state.traceStore else { return }
                let admissionBefore = await traceStore.storageAdmissionStatus()
                guard tracesRecoveryCadence.shouldRun(
                    blocked: admissionBefore.blocked
                ) else { return }
                let days = max(1, min(state.storage.tracesRetentionDays, 3650))
                let cutoff = Date().addingTimeInterval(-Double(days) * 86400)
                do {
                    let result = try await traceStore.recoverStorageBudget(
                        retentionCutoff: cutoff
                    )
                    tracesRecoveryCadence.recordRecoveryOutcome(
                        retentionBacklogRemaining:
                            result.retentionBacklogRemaining
                    )
                    if result.pinnedReader {
                        logger.warning("OTLP traces bounded recovery aborted: a reader pins traces.db-wal; no DELETE or vacuum was issued")
                    } else if result.spansDeleted > 0
                                || result.vacuumPagesReclaimed > 0 {
                        logger.notice("OTLP traces bounded recovery: \(result.spansDeleted) spans deleted, \(result.vacuumPagesReclaimed) pages reclaimed; footprint=\(result.footprintBytes ?? -1) bytes, free=\(result.freeSpaceBytes ?? -1) bytes")
                    }
                    let admission = await traceStore.storageAdmissionStatus()
                    if admission.blocked, result.autoVacuumMode != 2,
                       !result.pinnedReader {
                        logger.warning("OTLP traces remain storage-shed and auto_vacuum mode is \(result.autoVacuumMode), not 2/INCREMENTAL. The actor-owned one-shot conversion was deferred; recovery will retry on the next bounded cadence.")
                    }
                } catch {
                    // A failed healthy pass has not proven the retention backlog
                    // empty. Retry at the bounded cadence instead of postponing
                    // the same failed maintenance boundary for a full day.
                    tracesRecoveryCadence.recordRecoveryOutcome(
                        retentionBacklogRemaining: true
                    )
                    logger.warning("OTLP traces bounded recovery failed: \(error.localizedDescription, privacy: .public)")
                }
            }
        }
        t.resume()
        tracesPruneTimer = t

        // v1.18.0: generated-artifact retention. Daily, cheap, independent
        // of the DB stores. reports/ pruned by age (storage.reportsRetentionDays);
        // compiled_rules/auto_generated/ capped to the newest N files
        // (storage.autoGeneratedRulesMax, oldest pruned first). 0 disables
        // either sweep.
        let artifactsPruneTimer: DispatchSourceTimer
        let artifactsTimer = DispatchSource.makeTimerSource(queue: .global())
        artifactsTimer.schedule(deadline: .now() + 3600, repeating: 86400)
        let artifactsSupportDir = state.supportDir
        let reportsRetentionDays = state.storage.reportsRetentionDays
        let autoGeneratedRulesMax = state.storage.autoGeneratedRulesMax
        artifactsTimer.setEventHandler {
            timerLifecycle.submit(label: "artifact-retention") {
            let fm = FileManager.default
            if reportsRetentionDays > 0 {
                let dir = artifactsSupportDir + "/reports"
                let cutoff = Date().addingTimeInterval(-Double(reportsRetentionDays) * 86400)
                var removed = 0
                if let names = try? fm.contentsOfDirectory(atPath: dir) {
                    for name in names {
                        let p = dir + "/" + name
                        let mtime = (try? fm.attributesOfItem(atPath: p))?[.modificationDate] as? Date
                        if let m = mtime, m < cutoff, (try? fm.removeItem(atPath: p)) != nil { removed += 1 }
                    }
                }
                if removed > 0 {
                    logger.info("Reports retention sweep: \(removed) report(s) older than \(reportsRetentionDays)d pruned")
                }
            }
            if autoGeneratedRulesMax > 0 {
                let dir = artifactsSupportDir + "/compiled_rules/auto_generated"
                if let names = try? fm.contentsOfDirectory(atPath: dir), names.count > autoGeneratedRulesMax {
                    let byAge = names.compactMap { name -> (String, Date)? in
                        let p = dir + "/" + name
                        let m = (try? fm.attributesOfItem(atPath: p))?[.modificationDate] as? Date
                        return m.map { (p, $0) }
                    }.sorted { $0.1 < $1.1 }   // oldest first
                    let dropCount = byAge.count - autoGeneratedRulesMax
                    var removed = 0
                    for (p, _) in byAge.prefix(dropCount) where (try? fm.removeItem(atPath: p)) != nil { removed += 1 }
                    if removed > 0 {
                        logger.info("Auto-generated rules cap: pruned \(removed) oldest rule file(s) (kept newest \(autoGeneratedRulesMax))")
                    }
                }
            }
            }
        }
        artifactsTimer.resume()
        artifactsPruneTimer = artifactsTimer

        // v1.8.0 tiered storage with adaptive retention + size-cap fallback.
        //
        // First-cut design assumed ~5-10k events/hour. Field measurement on
        // production data showed ~950k events/hour on a busy dev/AI machine
        // — 13× higher. The 24h hot tier alone produces 4.4 GB at that
        // rate, which a 200 MB cap couldn't hold. v1.8.0-final defaults the
        // hot tier to 1h instead of 24h.
        //
        // Layered fix:
        //   - Layer 1 (EventInsertFilter): drop self-monitoring + dev-tool
        //     scratch at insert time. Closes ~17%+ of volume.
        //   - Layer 2 (this code): adaptive retention. Default cutoff =
        //     state.storage.eventsHotTierHours (1h); if DB > targetSizeBytes,
        //     tighten progressively (h, h/2, h/4, h/8) until it fits.
        //   - Layer 3 (this code): hard cap fallback. If even the tightest
        //     cutoff can't bring the DB under cap, force pruneOldest() so
        //     we never exceed the user's disk-budget intent.
        //
        // Fresh installs use the steady-state event allocation after moving
        // evidence to alerts.db. Upgrades add only the measured, bounded
        // legacy-evidence transition reserve so preserved rows cannot strand
        // event admission.
        let dbFilePath = state.supportDir + "/events.db"
        let startupSizeMB = measureDatabaseFootprintMB(dbPath: dbFilePath)
        let startupTransition = state.legacyEvidenceTransitionBudget.snapshot()
        let startupBoundary = EventsSizeCapBoundary(
            maxSizeMiB: liveEventsFamilyCapMiB()
        )
        let startupCapMiB = startupBoundary.nominalCapBytes
            / SQLitePersistentStorePolicy.bytesPerMiB
        let startupHotMinutes = max(
            EventRetentionFloor.minutes,
            state.storage.eventsHotTierMinutes
        )
        // v1.12.6: cadence is now user-configurable via
        // storage.eventsSizeCapIntervalMinutes. The default (60 min)
        // replaces the v1.10.0 hardcoded 6h interval that left field
        // hosts wedged with up to ~17 GB of unswept growth on busy
        // workloads. Operators on heavier workloads can drop the
        // interval (e.g. 5 min); idle hosts can lift it to save CPU.
        let configuredSweepMinutes = state.storage.eventsSizeCapIntervalMinutes
        let sweepIntervalMinutes: Int
        if configuredSweepMinutes > 0 {
            sweepIntervalMinutes = configuredSweepMinutes
        } else {
            sweepIntervalMinutes = 60
            logger.warning("eventsSizeCapIntervalMinutes=\(configuredSweepMinutes) is non-positive — falling back to default 60 min cadence.")
        }
        let journalExpiryIntervalMinutes = journalExpiryCadenceMinutes(
            configuredMinutes: configuredSweepMinutes
        )
        logger.notice("Tier-rollup timer armed: hot-tier=\(startupHotMinutes)m adaptive, live events-family cap=\(startupCapMiB) MiB (steady=\(state.storage.effectiveEventsFamilyMaxSizeMB) MiB, applied legacy evidence reserve=\(startupTransition.appliedReserveMiB) MiB, pending reserve=\(startupTransition.pendingReserveMiB ?? -1) MiB, evidence allocation=\(state.storage.evidenceMaxSizeMB) MiB), proactive boundary=\(startupBoundary.proactiveSweepBoundaryBytes / SQLitePersistentStorePolicy.bytesPerMiB) MiB, sweep cadence=\(sweepIntervalMinutes)m, currently \(startupSizeMB) MB (db+wal+shm). First sweep in 60 s.")

        // v1.10.0 audit fix: first sweep at .now() + 60 s instead of
        // + 900 s. If the user is booting into a sysext that
        // inherited a 1+ GB events.db from a previous run, waiting
        // 15 min before the first prune is far too long — most
        // users assume the daemon isn't working. 60 s gives the rest
        // of startup time to settle while still firing fast enough
        // for the user to see "DB shrunk from X to Y" within 1-2
        // minutes of launching the dashboard.
        //
        // v1.12.6: repeat interval pulled from
        // `state.storage.eventsSizeCapIntervalMinutes` (default 60 min,
        // configurable via daemon_config.json or user_overrides.json).
        // The hardcoded 6h interval that this replaces let a busy host's
        // events.db overrun a 300 MB cap by ~17 GB between sweeps.
        // Shared by scheduled and watchdog sweeps. A changed token is explicit
        // operator intent and invalidates the previous convergence conclusion.
        let watchdogBackoff = SizeCapWatchdogBackoff()
        @Sendable func retentionConfigurationToken() -> String {
            let transition = state.legacyEvidenceTransitionBudget.snapshot()
            return [
                state.storage.eventsMaxSizeMB,
                state.storage.evidenceMaxSizeMB,
                transition.appliedReserveMiB,
                transition.pendingReserveMiB ?? -1,
                state.storage.eventsHotTierMinutes,
                state.storage.processEventsFloorMinutes,
            ].map(String.init).joined(separator: ":")
        }

        let sizeCapTimer = DispatchSource.makeTimerSource(queue: .global())
        sizeCapTimer.schedule(
            deadline: .now() + 60,
            repeating: .seconds(sweepIntervalMinutes * 60)
        )
        sizeCapTimer.setEventHandler {
            timerLifecycle.submit(label: "events-size-cap") {
                let boundary = EventsSizeCapBoundary(
                    maxSizeMiB: liveEventsFamilyCapMiB()
                )
                watchdogBackoff.observeConfiguration(
                    retentionConfigurationToken()
                )
                let hotMinutes = max(
                    EventRetentionFloor.minutes,
                    state.storage.eventsHotTierMinutes
                )
                let aggregateDays = max(1, state.storage.aggregateDays)
                let alertsRetention = max(1, state.storage.alertsRetentionDays)
                // v1.12.6: serialize scheduled sweeps with the early-fire
                // watchdog (and any inbox flush-request) via the shared
                // beginSizeCapPrune guard on EventStore. Without this,
                // a watchdog burst on a wedged host could stack on top
                // of an in-flight scheduled sweep, doubling the I/O
                // load just when the disk is most pressured.
                guard await state.eventStore.beginSizeCapPrune() else {
                    logger.info("Tier-rollup scheduled sweep: another sweep already in flight, skipping.")
                    return
                }
                await { () async -> Void in
                await runAdaptiveRollupSweep(
                    eventStore: state.eventStore,
                    dbPath: dbFilePath,
                    targetSizeBytes: boundary.targetBytes,
                    capSizeBytes: boundary.proactiveSweepBoundaryBytes,
                    hotTierMinutes: hotMinutes,
                    aggregateDays: aggregateDays,
                    alertsRetentionDays: alertsRetention,
                    evidenceMaxSizeMB: max(10, state.storage.evidenceMaxSizeMB),
                    processFloorMinutes: max(0, state.storage.processEventsFloorMinutes)
                )
                let refreshedTransition = await refreshLegacyEvidenceTransitionBudget(
                    context: "Tier-rollup scheduled sweep"
                )
                let postSweepBoundary = EventsSizeCapBoundary(
                    maxSizeMiB: state.storage.effectiveEventsFamilyMaxSizeMB(
                        appliedLegacyEvidenceTransitionReserveMiB:
                            refreshedTransition.appliedReserveMiB
                    )
                )
                let afterBytes = try? measureDatabaseFootprintBytes(
                    dbPath: dbFilePath
                )
                state.eventRetentionBudgetHealth.recordSweep(
                    observedFootprintBytes: afterBytes,
                    boundary: postSweepBoundary
                )
                // Only an actual sweep at/below TARGET proves enough headroom
                // to re-arm the one-minute burst catcher. A transient ordinary
                // tick below the wider proactive boundary proves nothing.
                watchdogBackoff.recordSweep(
                    stillOver: afterBytes.map {
                        $0 > postSweepBoundary.targetBytes
                    } ?? true
                )
                }()
                await state.eventStore.endSizeCapPrune()
            }
        }
        sizeCapTimer.resume()

        // The canonical tier owns a fixed 15-minute admission-time floor and a
        // maximum five-minute sweep overhang. Serialize with every legacy cap /
        // on-demand recovery path through the same EventStore guard so aggregate
        // rollup, FTS cleanup and cap convergence can never overlap each other.
        let eventJournalExpiryTimer = DispatchSource.makeTimerSource(
            queue: .global()
        )
        eventJournalExpiryTimer.schedule(
            deadline: .now() + .seconds(journalExpiryIntervalMinutes * 60),
            repeating: .seconds(journalExpiryIntervalMinutes * 60)
        )
        eventJournalExpiryTimer.setEventHandler {
            timerLifecycle.submit(label: "event-journal-expiry") {
                // One admitted timer task owns one immutable cutoff. Advancing
                // Date() between quanta can chase an old backlog indefinitely
                // and makes the five-minute overhang proof ill-defined.
                let retainedThrough = Date()
                var reportedCoalescing = false
                var reportedLeaseBackpressure = false
                var totalExpired = 0
                var leaseDeferrals = 0
                // Consecutive waiting resets whenever a quantum makes progress;
                // cumulative waiting never does. Anchoring either to the pass's
                // start would spend the budget on the minutes the pass spends
                // draining, leaving nothing for the refusal it exists to absorb.
                var consecutiveWaitSeconds: TimeInterval = 0
                var cumulativeWaitSeconds: TimeInterval = 0
                while !Task.isCancelled {
                    var acquired = false
                    while !Task.isCancelled {
                        if await state.eventStore.beginJournalExpiryPrune() {
                            acquired = true
                            break
                        }
                        if !reportedCoalescing {
                            await state.eventStore
                                .recordJournalExpiryPendingTick()
                            logger.info("Event journal expiry: storage recovery is in flight; retaining this tick for prompt retry.")
                            reportedCoalescing = true
                        }
                        do {
                            try await Task.sleep(for: .milliseconds(250))
                        } catch {
                            return
                        }
                    }
                    guard acquired else { return }
                    if Task.isCancelled {
                        await state.eventStore.endSizeCapPrune()
                        return
                    }
                    let expired: Int
                    do {
                        expired = try await state.eventStore
                            .expireJournalBlocks(
                                retainedThrough: retainedThrough,
                                maximumBlocks:
                                    journalExpiryMaximumBlocksPerQuantum
                            )
                    } catch let error as EventStoreError {
                        await state.eventStore.endSizeCapPrune()
                        // A memory lease is bounded backpressure, not a fault:
                        // the pipeline's record ownership is fully committed at
                        // this instant and will not be a moment later. Treat it
                        // exactly as lock contention is already treated a few
                        // lines above -- conserve the tick and retry promptly --
                        // rather than discarding the rest of the backlog until
                        // the next cadence, which meets the same contention.
                        //
                        // Discarding it compounds: expiry is the only thing that
                        // removes journal blocks, and every exact read pays for
                        // each surviving block. Measured on the reference host
                        // after ~3h, 36,774 of 43,133 blocks (86% of retained
                        // events) sat past `retained_until` while this fired
                        // every few minutes, and a 5-minute dashboard query had
                        // to consider 1,091 blocks to return 200 rows.
                        if JournalExpiryBackpressurePolicy.decide(
                            error: error,
                            consecutiveWaitSeconds: consecutiveWaitSeconds,
                            cumulativeWaitSeconds: cumulativeWaitSeconds,
                            maximumConsecutiveWaitSeconds:
                                journalExpiryConsecutiveBackpressureBudgetSeconds,
                            maximumCumulativeWaitSeconds:
                                journalExpiryCumulativeBackpressureBudgetSeconds
                        ) == .conserveAndRetry {
                            leaseDeferrals += 1
                            if !reportedLeaseBackpressure {
                                reportedLeaseBackpressure = true
                                await state.eventStore
                                    .recordJournalExpiryLeaseDeferral()
                                // notice, not info: macOS does not persist
                                // info-level to disk, so an info here is as
                                // unobtainable as the print() it replaced.
                                logger.notice("Event journal expiry: bounded record ownership is committed; conserving this pass for prompt retry.")
                            }
                            do {
                                try await Task.sleep(
                                    for: .milliseconds(
                                        journalExpiryBackpressureRetryMilliseconds
                                    )
                                )
                            } catch {
                                return
                            }
                            let waited = Double(
                                journalExpiryBackpressureRetryMilliseconds
                            ) / 1000.0
                            consecutiveWaitSeconds += waited
                            cumulativeWaitSeconds += waited
                            continue
                        }
                        await state.eventStore.recordJournalExpiryFailure()
                        logger.fault("Event journal expiry failed: \(error.localizedDescription, privacy: .public)")
                        return
                    } catch {
                        await state.eventStore.recordJournalExpiryFailure()
                        await state.eventStore.endSizeCapPrune()
                        logger.fault("Event journal expiry failed: \(error.localizedDescription, privacy: .public)")
                        return
                    }
                    await state.eventStore.endSizeCapPrune()
                    // Progress earns a fresh consecutive budget. Cumulative is
                    // deliberately not reset, so the pass stays bounded overall.
                    consecutiveWaitSeconds = 0
                    totalExpired += expired
                    guard expired > 0 else { break }
                    // Release the shared maintenance exclusion after every
                    // finite quantum. A legacy cap/watchdog pass can win the
                    // next acquisition instead of being starved by a large
                    // canonical backlog.
                    await Task.yield()
                }
                if totalExpired > 0, !Task.isCancelled {
                    logger.notice("Event journal expiry: aggregate-rolled and expired \(totalExpired, privacy: .public) authenticated event records across bounded quanta (lease deferrals \(leaseDeferrals, privacy: .public)).")
                }
            }
        }
        eventJournalExpiryTimer.resume()

        // v1.12.6: early-fire size-cap watchdog. Defense-in-depth for the
        // configurable scheduled cadence above — if the DB crosses the
        // proactive reserve boundary between scheduled sweeps (sustained
        // event-firehose burst, runaway rule write-amplification, etc.), fire a
        // sweep before hard admission has to pause writes.
        //
        // Cadence: 60 s. Cheap — three stat() calls (db + wal + shm)
        // and a numeric compare; only schedules a sweep on the cold
        // path (over-threshold).
        //
        // Reentrancy: shares the EventStore `beginSizeCapPrune` guard
        // with the scheduled sweep + inbox flush-request handler, so
        // the watchdog cannot stack on top of an in-flight sweep.
        let sizeCapWatchdogTimer = DispatchSource.makeTimerSource(queue: .global())
        sizeCapWatchdogTimer.schedule(deadline: .now() + 120, repeating: 60)
        // v1.21.6 (audit DL-03): back-off box captured by the handler below, so
        // a structurally-over-cap host degrades to a periodic reminder instead
        // of re-arming a full FTS optimize + vacuum every single minute.
        sizeCapWatchdogTimer.setEventHandler {
            timerLifecycle.submit(label: "events-size-watchdog") {
                let boundary = EventsSizeCapBoundary(
                    maxSizeMiB: liveEventsFamilyCapMiB()
                )
                watchdogBackoff.observeConfiguration(
                    retentionConfigurationToken()
                )
                let nowBytes: Int64
                do {
                    nowBytes = try measureDatabaseFootprintBytes(dbPath: dbFilePath)
                } catch {
                    logger.fault("Tier-rollup early-fire watchdog: authoritative events.db family probe failed; refusing maintenance: \(error.localizedDescription, privacy: .public)")
                    return
                }
                guard boundary.requiresMaintenance(footprintBytes: nowBytes) else {
                    // A sampling tick can catch the sawtooth just after prune /
                    // checkpoint and before the firehose refills it. Do NOT reset
                    // sticky backoff here; only a fired sweep at/below TARGET or
                    // a material configuration change can prove recovery.
                    return
                }
                // v1.21.6 (audit DL-03): over threshold is NOT sufficient to
                // fire. When the last fire failed to clear the threshold this
                // gate holds us off for 2/4/8/16/32 min, because re-running the
                // sweep every 60 s on a host whose budget is unreachable buys
                // nothing and costs a full FTS `optimize` + incremental_vacuum
                // each time (measured: 1.9M page rewrites / 7.3 GiB in 12 h).
                guard watchdogBackoff.mayFire() else { return }
                guard await state.eventStore.beginSizeCapPrune() else {
                    // A scheduled sweep is already running. The
                    // scheduled sweep will bring us back under the cap
                    // — no need to queue another.
                    return
                }
                await { () async -> Void in
                let hotMinutes = max(
                    EventRetentionFloor.minutes,
                    state.storage.eventsHotTierMinutes
                )
                let aggregateDays = max(1, state.storage.aggregateDays)
                let alertsRetention = max(1, state.storage.alertsRetentionDays)
                logger.warning("Tier-rollup early-fire watchdog: events.db family \(nowBytes) bytes exceeds proactive boundary \(boundary.proactiveSweepBoundaryBytes) bytes (hard admission at \(boundary.hardAdmissionBoundaryBytes), nominal cap \(boundary.nominalCapBytes)) — running sweep now.")
                await runAdaptiveRollupSweep(
                    eventStore: state.eventStore,
                    dbPath: dbFilePath,
                    targetSizeBytes: boundary.targetBytes,
                    capSizeBytes: boundary.proactiveSweepBoundaryBytes,
                    hotTierMinutes: hotMinutes,
                    aggregateDays: aggregateDays,
                    alertsRetentionDays: alertsRetention,
                    evidenceMaxSizeMB: max(10, state.storage.evidenceMaxSizeMB),
                    processFloorMinutes: max(0, state.storage.processEventsFloorMinutes)
                )
                let refreshedTransition = await refreshLegacyEvidenceTransitionBudget(
                    context: "Tier-rollup watchdog sweep"
                )
                let postSweepBoundary = EventsSizeCapBoundary(
                    maxSizeMiB: state.storage.effectiveEventsFamilyMaxSizeMB(
                        appliedLegacyEvidenceTransitionReserveMiB:
                            refreshedTransition.appliedReserveMiB
                    )
                )
                // v1.21.6 (audit DL-03): did the sweep actually achieve
                // anything? Feed the answer back into the back-off, and when it
                // did not, say so ONCE per back-off window at fault level with
                // the knobs named. Before this the operator got a `warning` that
                // said 'running sweep now' every minute for hours and never a
                // single line explaining that the configured budget is not
                // reachable on this host.
                let afterBytes: Int64
                do {
                    afterBytes = try measureDatabaseFootprintBytes(dbPath: dbFilePath)
                } catch {
                    let backoffSeconds = watchdogBackoff.recordSweep(stillOver: true)
                    state.eventRetentionBudgetHealth.recordSweep(
                        observedFootprintBytes: nil,
                        boundary: postSweepBoundary
                    )
                    logger.fault("Tier-rollup early-fire watchdog: post-sweep events.db family probe failed; treating the sweep as ineffective and backing off to \(backoffSeconds)s: \(error.localizedDescription, privacy: .public)")
                    return
                }
                let stillOver = postSweepBoundary.requiresMaintenance(
                    footprintBytes: afterBytes
                )
                state.eventRetentionBudgetHealth.recordSweep(
                    observedFootprintBytes: afterBytes,
                    boundary: postSweepBoundary
                )
                let backoffSeconds = watchdogBackoff.recordSweep(
                    stillOver: afterBytes > postSweepBoundary.targetBytes
                )
                if stillOver {
                    logger.fault("Tier-rollup early-fire watchdog: sweep left events.db at \(afterBytes) bytes — still over the live proactive \(postSweepBoundary.proactiveSweepBoundaryBytes)-byte boundary. The event-family budget is NOT reachable on this host. New alert evidence no longer grows events.db; the applied legacy transition reserve is \(refreshedTransition.appliedReserveMiB) MiB (pending \(refreshedTransition.pendingReserveMiB ?? -1) MiB). Backing the watchdog off to \(backoffSeconds)s to stop the prune+VACUUM rewrite loop.")
                }
                }()
                await state.eventStore.endSizeCapPrune()
            }
        }
        sizeCapWatchdogTimer.resume()

        // Hourly ownership + family defense for alerts.db after the awaited
        // pre-ingestion bootstrap pass. Alert rows and slim evidence have independent budgets,
        // while SQLite hard admission counts their exact combined DB+WAL+SHM
        // family ceiling minus its transaction reserve. The former 30-minute
        // first-fire delay stranded a shed-only store for twice the forensic
        // qualification window.
        //
        // Wave 9B (v1.12.6): on a low-disk host the post-prune VACUUM
        // would skip silently. We now run incremental_vacuum first
        // (free, in-place truncate) and only fall through to full
        // VACUUM if the shared floor + 2x-main-file headroom gate passes.
        let alertsSizeCapTimer = DispatchSource.makeTimerSource(queue: .global())
        // Bootstrap awaits the first pass before starting any producer. The
        // timer therefore begins one period later instead of racing a duplicate
        // asynchronous pass against startup.
        alertsSizeCapTimer.schedule(deadline: .now() + 3600, repeating: 3600)
        alertsSizeCapTimer.setEventHandler {
            timerLifecycle.submit(label: "alerts-size-cap") {
                await enforceAlertsSizeCapNow(state: state)
            }
        }
        alertsSizeCapTimer.resume()

        // v1.22.0: early-fire watchdog for the alerts family. The hourly pass
        // above stays the scheduled enforcement; this only reacts to the state
        // that pauses alert-evidence writes, so a host does not sit with
        // evidence capture stopped for up to an hour after a restart. Mirrors
        // the events size-cap watchdog: 2-minute first fire, 60s cadence, and
        // it does no work at all unless writes are actually blocked.
        let alertsSizeCapWatchdogTimer = DispatchSource.makeTimerSource(
            queue: .global()
        )
        alertsSizeCapWatchdogTimer.schedule(deadline: .now() + 120, repeating: 60)
        alertsSizeCapWatchdogTimer.setEventHandler {
            timerLifecycle.submit(label: "alerts-size-watchdog") {
                guard await alertsFamilyBlocksWrites(state: state) else { return }
                logger.warning("Alerts family admission watchdog: evidence writes are blocked by family footprint; running the family pass now instead of waiting for the hourly sweep.")
                _ = await enforceAlertsSizeCapNow(state: state)
            }
        }
        alertsSizeCapWatchdogTimer.resume()

        // Same hourly defense for campaigns.db when present.
        //
        // Wave 9B (v1.12.6): incremental_vacuum + low-disk-safe full
        // VACUUM mirror the alerts.db enforcer above. Campaigns table
        // is tiny in practice, but the consistent shape keeps the
        // structured-log output uniform across stores so operators
        // grep one predicate to see all four.
        let campaignsSizeCapTimer: DispatchSourceTimer?
        if let campaignStore = state.campaignStore {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 1800, repeating: 3600)
            t.setEventHandler {
                timerLifecycle.submit(label: "campaigns-size-cap") {
                    let capMB = max(50, state.storage.campaignsMaxSizeMB)
                    let cPath = state.supportDir + "/campaigns.db"
                    let nowMB = measureDatabaseFootprintMB(dbPath: cPath)
                    guard nowMB > capMB else { return }
                    let total = (try? await campaignStore.count()) ?? 0
                    let overFraction = Double(nowMB - capMB) / Double(max(1, nowMB))
                    let dropTarget = max(100, Int(Double(total) * (overFraction + 0.1)))
                    let dropped = (try? await campaignStore.pruneOldest(count: dropTarget)) ?? 0
                    logger.warning("Campaigns size cap: pruned \(dropped) oldest campaigns (\(nowMB) MB > \(capMB) MB cap, target drop \(dropTarget))")

                    let postPruneMB = measureDatabaseFootprintMB(dbPath: cPath)
                    let reclaimed = (try? await campaignStore.incrementalVacuum(maxPages: 200_000)) ?? 0
                    let postIncrementalMB = measureDatabaseFootprintMB(dbPath: cPath)
                    if reclaimed > 0 {
                        logger.notice("Campaigns size cap: incremental_vacuum reclaimed \(reclaimed) pages, \(postPruneMB) MB → \(postIncrementalMB) MB")
                    }

                    let headroom = fullVacuumHeadroom(dbPath: cPath)
                    let freeMB = Int((headroom?.freeSpaceBytes ?? 0) / 1_000_000)
                    let needMB = Int((headroom?.requiredFreeBytes ?? Int64.max) / 1_000_000)
                    if headroom?.admitted == true {
                        do {
                            try await campaignStore.vacuum()
                            let finalMB = measureDatabaseFootprintMB(dbPath: cPath)
                            logger.notice("Campaigns size cap: full VACUUM complete — \(postIncrementalMB) MB → \(finalMB) MB")
                        } catch {
                            logger.warning("Campaigns size cap: full VACUUM failed (\(error.localizedDescription)). incremental_vacuum reclaimed \(reclaimed) pages.")
                        }
                    } else if reclaimed == 0 {
                        logger.warning("Campaigns size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB) AND incremental_vacuum was no-op.")
                    } else {
                        logger.warning("Campaigns size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB). incremental_vacuum still reclaimed \(reclaimed) pages.")
                    }
                }
            }
            t.resume()
            campaignsSizeCapTimer = t
        } else {
            campaignsSizeCapTimer = nil
        }

        // Periodic learned-state save + bounded-state sweeps (every 5 minutes)
        let maintenanceTimer = DispatchSource.makeTimerSource(queue: .global())
        maintenanceTimer.schedule(deadline: .now() + 300, repeating: 300)
        maintenanceTimer.setEventHandler {
            timerLifecycle.submit(label: "maintenance") {
                try? await state.baselineEngine.save()
                try? await state.processTreeAnalyzer.save()
                if let ueba = state.uebaEngine, !(await ueba.save()) {
                    logger.error("UEBA periodic persistence failed; the in-memory model remains active but restart continuity is degraded")
                }
                await state.deduplicator.sweep()
                await state.crossProcessCorrelator.purgeStale()
                await state.topologyAnomalyDetector.purgeStale()
                await state.campaignDetector.sweep()
                await state.tlsFingerprinter.sweep()
                // Allowlist v2: prune expired suppressions. The sweep
                // appends an audit entry per expired row, so operators
                // can reconstruct when each allow lapsed.
                let expired = await state.suppressionManager.sweepExpired()
                if !expired.isEmpty {
                    logger.info("Allowlist sweep expired \(expired.count) suppression(s)")
                }
                // v1.11.1 (audit scalability HIGH): drain ProcessLineage's
                // pendingPromotions buffer so under PID-recycle storms
                // skeleton records aren't silently truncated by the
                // 1024-cap removeFirst at evictLRUProcess(). v1.11.1
                // surfaces them as a count + log; v1.11.2+ will forward
                // to CompactPersistentLineage / SQLiteCausalGraphStore
                // per the §6.3.1 invariant ("silent ancestry loss is not
                // allowed"). Currently the surfaced count is enough to
                // observe whether the cap is actively saturated.
                let drained = await state.enricher.lineage.drainPendingPromotions()
                if !drained.isEmpty {
                    logger.info("ProcessLineage maintenance drain: \(drained.count) skeleton(s) released from pendingPromotions cap")
                }
            }
        }
        maintenanceTimer.resume()

        // v1.7.5 design split: TWO heartbeat-related timers.
        //
        // 1. **Liveness heartbeat** — synchronous dispatch-thread
        //    write of a minimal `heartbeat.json`. NO actor hops, NO
        //    EventStore queries, NO snapshot writes. Just a fast
        //    file write of {written_at_unix, uptime_seconds,
        //    sysext_has_fda, schema_version}. The dashboard's
        //    "Detection engine appears silent" banner is gated on
        //    THIS file. Cannot deadlock because there's nothing
        //    async to deadlock on.
        // 2. **Rich heartbeat** — the v1.7.0–v1.7.4 payload, now
        //    written to `heartbeat_rich.json` and consumed by the
        //    ES Health panel for the per-event-category breakdown,
        //    collector liveness array, drop count. Can stall
        //    indefinitely without affecting liveness detection.
        //
        // This separation cures the v1.7.3 silent-heartbeat class
        // architecturally — liveness is decoupled from any heavyweight
        // work. Future regressions in the rich payload (slow query,
        // stuck actor, full disk for snapshot writes) can NEVER cause
        // the dashboard to think the daemon is dead when it isn't.
        // v1.12.0 fix: first heartbeat fires at +0.5 s, not +5 s, so the
        // dashboard's 10-second poll cadence has a fresh heartbeat to
        // read on its first tick. Pre-fix, the +5 s timer delay stacked
        // with the dashboard poll lag to produce a 15-25 s "Daemon:
        // starting…" window before "Daemon: Running ✓" appeared, even
        // though the daemon process was up and serving events in ~3 s.
        let livenessTimer = DispatchSource.makeTimerSource(queue: .global())
        livenessTimer.schedule(deadline: .now() + 0.5, repeating: 30)
        livenessTimer.setEventHandler {
            // Joinable even though the body itself has no actor hops. A
            // shutdown must not race its temp-file publication with the final
            // heartbeat/store boundary.
            livenessLifecycle.submit(label: "liveness-heartbeat") {
            //
            // v1.8.0 audit: wrap JSONSerialization in autoreleasepool.
            // DispatchSource timer event handlers run on a long-lived
            // global queue with no Swift Task scope, so autoreleased
            // NSDictionary / NSString temporaries created by
            // JSONSerialization survive until the queue thread exits
            // (effectively forever). Same shape as the v1.7.7-v1.7.9
            // EsloggerCollector / FileHasher leak chain that put
            // ~1 GB of NSConcreteData into long-running daemons.
            autoreleasepool {
                let sysextHasFDA = probeSysextFDA()
                let nowUnix = Date().timeIntervalSince1970
                let uptime = Int(Date().timeIntervalSince(startTime))
                let payload: [String: Any] = [
                    "written_at_unix": nowUnix,
                    "engine_pid": engineIdentity.pid,
                    "engine_started_at_unix": engineIdentity.startedAtUnix,
                    "engine_version": engineIdentity.version,
                    "engine_build": engineIdentity.build,
                    "uptime_seconds": uptime,
                    "sysext_has_fda": sysextHasFDA,
                    "fda_checked_at_unix": nowUnix,
                    "events_processed": eventCount(),
                    "alerts_emitted": alertCount(),
                    "schema_version": 4,
                    "liveness": true,
                    // v1.12.0 RC15: keep boot_phase populated even after
                    // boot completes so the dashboard's interpretation
                    // logic ({phase == "ready"} → "Running") doesn't have
                    // to fall back to inferring from liveness alone.
                    "boot_phase": "ready",
                ]
                guard let data = try? JSONSerialization.data(
                    withJSONObject: payload,
                    options: [.sortedKeys]
                ) else { return }
                let path = state.supportDir + "/heartbeat.json"
                let tmp = path + ".tmp"
                do {
                    try data.write(to: URL(fileURLWithPath: tmp))
                    try FileManager.default.moveItem(atPath: tmp, toPath: path)
                } catch {
                    try? FileManager.default.removeItem(atPath: path)
                    try? FileManager.default.moveItem(atPath: tmp, toPath: path)
                }
            }
            }
        }
        livenessTimer.resume()

        // v1.4.3 fail-loud: write a heartbeat snapshot every 30s so
        // the dashboard can detect a silently-replaced or hung sysext.
        // If an attacker drops in a no-op sysext binary, the dashboard
        // still sees the old heartbeat file aging past the threshold
        // and raises a DetectionHealthBanner. The snapshot includes
        // event/alert counters + uptime so the dashboard can also
        // show rich debugging info on the ES Health page.
        //
        // v1.7.4 design: heartbeat write is the critical fast path.
        // Snapshot writers live behind their own per-writer
        // snapshotWriteInFlight guards, so fire-and-forget Tasks at
        // this level are safe — concurrent calls no-op instead of
        // queueing on the actor (which is what caused the v1.7.0–
        // v1.7.3 leak class). No outer overlap guard: if a tick takes
        // longer than 30 s the next tick simply runs in parallel, and
        // since each writeSnapshot guards itself, no actor backlog
        // forms.
        // v1.21.4 Phase-1 D2: rolling baseline for the sensor-degraded
        // meta-alert. Captured by the heartbeat closure below; lives here (not
        // on DaemonState) and is lock-guarded so overlapping ticks are safe.
        let sensorDegradation = SensorDegradationState()
        // v1.21.4 (audit): rising-edge latch so a fresh AES-GCM decrypt failure
        // (DB tamper) raises a rate-limited alert, not just a heartbeat counter.
        let tamperAlertState = TamperAlertState()

        let heartbeatTimer = DispatchSource.makeTimerSource(queue: .global())
        heartbeatTimer.schedule(deadline: .now() + 5, repeating: 30)
        heartbeatTimer.setEventHandler {
            // v1.7.1: heartbeat body wrapped in Task to allow the
            // EventStore query for per-category counts to await across
            // actor isolation. The dispatch-timer event handler itself
            // is synchronous; spawning a Task lets the body run async
            // without blocking the timer queue.
            timerLifecycle.submit(label: "rich-heartbeat") {
            // Probe sysext Full Disk Access authoritatively. The sysext
            // runs as root but TCC still gates its access to the user and
            // system TCC databases. If we can open + query the system
            // TCC.db, FDA is granted (TCC bypasses the service). If TCC
            // denies us, sqlite3_open / sqlite3_prepare will fail.
            // The dashboard reads this field and uses it as the primary
            // sysext-FDA signal — way more reliable than inferring from
            // WAL mtime or trying to read TCC.db from the non-root app
            // (where Unix perms + TCC both apply).
            let sysextHasFDA = probeSysextFDA()

            let nowUnix = Date().timeIntervalSince1970
            let uptime = Int(Date().timeIntervalSince(startTime))
            let events = eventCount()
            let alerts = alertCount()

            // Exact admission-time category counts. The retained journal can be
            // shorter than the requested hour, so publish the effective interval
            // and gap ledger with the values. The legacy `_1h` alias is emitted
            // only when storage proves the complete requested hour.
            let categoryCountUntil = Date()
            let oneHourAgo = categoryCountUntil.addingTimeInterval(-3600)
            var eventTypeCounts: [String: Int] = [:]
            var eventTypeCountSnapshot: EventCategoryCountSnapshot?
            do {
                let snapshot = try await state.eventStore
                    .eventCategoryCountSnapshot(
                        since: oneHourAgo,
                        until: categoryCountUntil
                    )
                eventTypeCounts = snapshot.counts
                eventTypeCountSnapshot = snapshot
            } catch {
                // Heartbeat write must succeed even when the EventStore
                // query fails (db locked under contention, etc.).
            }
            let eventTypeCountWindow: [String: Any]
            if let snapshot = eventTypeCountSnapshot {
                eventTypeCountWindow = [
                    "query_available": true,
                    "mutation_generation": Int64(clamping:
                        snapshot.mutationGeneration),
                    "requested_duration_seconds": max(0, Int(
                        snapshot.requestedUntil.timeIntervalSince(
                            snapshot.requestedSince
                        )
                    )),
                    "effective_duration_seconds": max(0, Int(
                        snapshot.effectiveUntil.timeIntervalSince(
                            snapshot.effectiveSince
                        )
                    )),
                    "requested_window_complete":
                        snapshot.requestedWindowComplete,
                    "complete": snapshot.isComplete,
                    "canonical_poison_records":
                        snapshot.gaps.canonicalPoisonRecords,
                    "corrupt_legacy_records":
                        snapshot.gaps.corruptLegacyRecords,
                    "inherited_legacy_loss_records":
                        snapshot.gaps.inheritedLegacyLossRecords,
                    "resource_limited_records":
                        snapshot.gaps.resourceLimitedRecords,
                    "gap_records": snapshot.gaps.total,
                ]
            } else {
                eventTypeCountWindow = [
                    "query_available": false,
                    "requested_duration_seconds": 3600,
                    "effective_duration_seconds": 0,
                    "requested_window_complete": false,
                    "complete": false,
                ]
            }
            let eventSearchProjection: [String: Any]
            do {
                let snapshot = try await state.eventStore.searchSnapshot(
                    text: "",
                    since: oneHourAgo,
                    until: categoryCountUntil,
                    limit: 1
                )
                eventSearchProjection = [
                    "query_available": true,
                    "mutation_generation": Int64(clamping:
                        snapshot.mutationGeneration),
                    "requested_duration_seconds": max(0, Int(
                        snapshot.requestedUntil.timeIntervalSince(
                            snapshot.requestedSince
                        )
                    )),
                    "effective_duration_seconds": max(0, Int(
                        snapshot.effectiveUntil.timeIntervalSince(
                            snapshot.effectiveSince
                        )
                    )),
                    "requested_window_complete":
                        snapshot.requestedWindowComplete,
                    "projection_considered": snapshot.projectionConsidered,
                    "projection_materialized":
                        snapshot.projectionMaterialized,
                    "projection_omitted_quota":
                        snapshot.projectionOmittedQuota,
                    "projection_omitted_replaced":
                        snapshot.projectionOmittedReplaced,
                    "projection_omitted_physical":
                        snapshot.projectionOmittedPhysical,
                    "projection_omitted_external":
                        snapshot.projectionOmittedExternal,
                    "projection_omitted_migration":
                        snapshot.projectionOmittedMigration,
                    "projection_pending": snapshot.projectionPending,
                    "projection_omitted_total": snapshot.projectionOmitted,
                    "canonical_poison_records":
                        snapshot.gaps.canonicalPoisonRecords,
                    "corrupt_legacy_records":
                        snapshot.gaps.corruptLegacyRecords,
                    "inherited_legacy_loss_records":
                        snapshot.gaps.inheritedLegacyLossRecords,
                    "resource_limited_records":
                        snapshot.gaps.resourceLimitedRecords,
                    "gap_records_total": snapshot.gaps.total,
                    "complete": snapshot.isComplete,
                ]
            } catch {
                eventSearchProjection = [
                    "query_available": false,
                    "requested_duration_seconds": 3600,
                    "effective_duration_seconds": 0,
                    "requested_window_complete": false,
                    "complete": false,
                ]
            }

            // v1.21.6 (PERF-04): honest retention. The configured hot tier is 30
            // minutes; on the field host `file` was delivering 30 SECONDS because
            // the Layer-3 row-count fallback evicts the fodder categories to hold
            // the footprint under cap. Nothing surfaced that, so a whole tactic's
            // worth of write-time correlation was blind with a green heartbeat.
            // Publish the actual span, and warn when a category with real volume
            // has fallen under the 15-minute raw-event forensic/correlation floor.
            var retainedSpanByCategory: [String: Int] = [:]
            var retainedLookbackByCategory: [String: Int] = [:]
            do {
                let retainedWindows = try await state.eventStore
                    .retainedWindowSecondsByCategory(asOf: categoryCountUntil)
                retainedSpanByCategory = retainedWindows.mapValues(
                    \.spanSeconds
                )
                retainedLookbackByCategory = retainedWindows.mapValues(
                    \.lookbackSeconds
                )
            } catch {
                // Same rule as above: never block the heartbeat write.
            }
            // Volume floor before calling a short span "starved": a category
            // holding a handful of rows legitimately spans ~0 seconds, and
            // flagging that would ship a false red (the mistake this batch is
            // explicitly avoiding). 1000 retained rows inside 15 minutes is the
            // signature of a pruned firehose, not of a quiet channel.
            let forensicFloorSeconds = EventRetentionFloor.minutes * 60
            let starvedCategories = retainedLookbackByCategory
                .filter { $0.value < forensicFloorSeconds && (eventTypeCounts[$0.key] ?? 0) >= 1000 }
                .keys.sorted()
            if !starvedCategories.isEmpty {
                let detail = starvedCategories
                    .map { "\($0)=\(retainedLookbackByCategory[$0] ?? 0)s" }
                    .joined(separator: ", ")
                logger.warning("Event retention BELOW the 15-minute raw-event forensic/correlation floor: \(detail, privacy: .public). Graph reconstruction, cross-process correlation and `hunt` are blind past that window for those categories — the size-cap sweep or storage admission has created an evidence gap. SequenceEngine does not currently rehydrate from events.db; its restart continuity is tracked separately. Do not read this as a quiet host.")
            }

            // v1.7.2: collector liveness + drop counter.
            let collectorStatuses = await state.collectorRegistry.snapshot()
            // Snapshot each collector-local bounded stream, then merge those
            // stage counters with the downstream pair under the pipeline's one
            // atomic lock. Terminal yields are rejected input and are included
            // without being left behind as phantom backlog.
            let upstreamCollectorBuffers = state.eventCollectorBufferSnapshots()
            let eventPipeline = state.eventPipelineTelemetry.snapshot(
                upstreamBuffers: upstreamCollectorBuffers
            )
            let priorityDropped = eventPipeline.mergedDroppedByLane["priority"] ?? 0
            let fileDropped = eventPipeline.mergedDroppedByLane["file"] ?? 0
            let priorityTerminated = eventPipeline.mergedTerminatedByLane["priority"] ?? 0
            let fileTerminated = eventPipeline.mergedTerminatedByLane["file"] ?? 0
            let eventWriterTelemetry = await state.eventWriter.telemetrySnapshot()
            let eventRetentionBudget = state.eventRetentionBudgetHealth
                .snapshot().dictionary
            let evidenceBudgetBytes = SQLitePersistentStorePolicy.capBytes(
                maxSizeMiB: state.storage.evidenceMaxSizeMB
            )
            let evidenceSnapshot = try? await state.alertStore
                .evidenceBudgetSnapshot(maxBytes: evidenceBudgetBytes)
            let alertsAdmission = await state.alertStore
                .storageAdmissionSnapshot()
            let evidenceCaptureStats = await state.alertSink.evidenceStats()
            // Unlike the actor-local queue, this count survives a crash between
            // alert commit and post-commit evidence capture. `-1` is explicit
            // unknown/fail-closed rather than a fabricated healthy zero.
            let durableEvidenceContextCounts = try? await state.alertStore
                .evidenceContextCounts()
            let durablePendingEvidenceContexts =
                durableEvidenceContextCounts?.pending ?? -1
            let legacyTransition = state.legacyEvidenceTransitionBudget.snapshot()
            let liveEventsFamilyCapMiB = state.storage
                .effectiveEventsFamilyMaxSizeMB(
                    appliedLegacyEvidenceTransitionReserveMiB:
                        legacyTransition.appliedReserveMiB
                )
            var alertEvidenceBudget: [String: Any] = [
                "events_family_effective_cap_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: liveEventsFamilyCapMiB
                    ),
                "events_family_steady_state_cap_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage
                            .effectiveEventsFamilyMaxSizeMB
                    ),
                "events_legacy_envelope_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage.eventsMaxSizeMB
                    ),
                "alert_rows_max_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage.alertsMaxSizeMB
                    ),
                "evidence_max_bytes": evidenceBudgetBytes,
                "alerts_family_combined_cap_bytes":
                    AlertStore.combinedFamilyCapBytes(
                        alertsMaxSizeMiB: state.storage.alertsMaxSizeMB,
                        evidenceMaxSizeMiB: state.storage.evidenceMaxSizeMB
                    ),
                "events_and_alerts_total_cap_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage
                            .configuredEventsAndAlertsTotalMaxSizeMB(
                                appliedLegacyEvidenceTransitionReserveMiB:
                                    legacyTransition.appliedReserveMiB
                            )
                    ),
                "events_and_alerts_steady_state_total_cap_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: state.storage
                            .configuredEventsAndAlertsTotalMaxSizeMB
                    ),
                "legacy_transition_reserve_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: legacyTransition.appliedReserveMiB
                    ),
                "legacy_transition_applied_reserve_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: legacyTransition.appliedReserveMiB
                    ),
                "legacy_transition_max_bytes":
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: legacyTransition.maximumReserveMiB
                    ),
                "legacy_transition_measurement_failed":
                    legacyTransition.measurementFailed,
                "legacy_transition_generation":
                    legacyTransition.configurationGeneration,
                "legacy_transition_stale_measurements_discarded":
                    legacyTransition.staleMeasurementsDiscarded,
                "legacy_transition_transaction_reserve_bytes":
                    legacyTransition.transactionReserveBytes,
                "capture_rows_total": evidenceCaptureStats.capturedRows,
                "capture_pruned_rows_total": evidenceCaptureStats.prunedRows,
                "capture_offered_total": evidenceCaptureStats.offered,
                "capture_completed_total": evidenceCaptureStats.completed,
                "capture_failures_total": evidenceCaptureStats.failures,
                "capture_shed_total": evidenceCaptureStats.shed,
                "capture_pending": evidenceCaptureStats.pending,
                "capture_in_flight": evidenceCaptureStats.inFlight,
                "capture_queue_capacity": evidenceCaptureStats.queueCapacity,
                "capture_accepting": evidenceCaptureStats.accepting,
                "capture_conserved": evidenceCaptureStats.conserved,
                "capture_exact_context_incomplete_total":
                    evidenceCaptureStats.exactContextIncomplete,
                "capture_exact_context_query_failures_total":
                    evidenceCaptureStats.exactContextQueryFailures,
                "capture_durable_pending_contexts":
                    durablePendingEvidenceContexts,
                "capture_durable_complete_contexts":
                    durableEvidenceContextCounts?.complete ?? -1,
                "capture_durable_incomplete_contexts":
                    durableEvidenceContextCounts?.incomplete ?? -1,
                "capture_durable_failed_contexts":
                    durableEvidenceContextCounts?.captureFailed ?? -1,
                "capture_durable_unhealthy_contexts":
                    durableEvidenceContextCounts?.unhealthy ?? -1,
                "capture_durable_context_rows":
                    durableEvidenceContextCounts?.contextRows ?? -1,
                "capture_durable_alert_rows":
                    durableEvidenceContextCounts?.alertRows ?? -1,
                "capture_durable_legacy_unverified_contexts":
                    durableEvidenceContextCounts?.legacyUnverified ?? -1,
                "capture_durable_poison_records":
                    durableEvidenceContextCounts?.poisonRecords ?? -1,
                "capture_durable_corrupt_records":
                    durableEvidenceContextCounts?.corruptRecords ?? -1,
                "capture_durable_inherited_loss_records":
                    durableEvidenceContextCounts?.inheritedLossRecords ?? -1,
                "capture_durable_resource_limited_records":
                    durableEvidenceContextCounts?.resourceLimitedRecords ?? -1,
                "capture_durable_journal_admission_gap_records":
                    durableEvidenceContextCounts?.journalAdmissionGapRecords
                        ?? -1,
                "capture_durable_contexts_reconcile":
                    durableEvidenceContextCounts?.reconciles ?? false,
            ]
            if let rowCount = legacyTransition.rowCount {
                alertEvidenceBudget["legacy_row_count"] = rowCount
            }
            if let chargedBytes = legacyTransition.chargedBytes {
                alertEvidenceBudget["legacy_charged_bytes"] = chargedBytes
            }
            if let pendingReserveMiB = legacyTransition.pendingReserveMiB {
                alertEvidenceBudget["legacy_transition_pending_reserve_bytes"] =
                    SQLitePersistentStorePolicy.capBytes(
                        maxSizeMiB: pendingReserveMiB
                    )
            }
            if let pendingFits = legacyTransition
                .pendingReserveFitsHardBoundary {
                alertEvidenceBudget["legacy_transition_pending_fits_boundary"] =
                    pendingFits
            }
            if let footprint = legacyTransition.familyFootprintBytes {
                alertEvidenceBudget["legacy_transition_family_footprint_bytes"] =
                    footprint
            }
            if let boundary = legacyTransition
                .proposedHardAdmissionBoundaryBytes {
                alertEvidenceBudget["legacy_transition_proposed_boundary_bytes"] =
                    boundary
            }
            if let drained = legacyTransition.walCheckpointDrained {
                alertEvidenceBudget["legacy_transition_wal_checkpoint_drained"] =
                    drained
            }
            if let freelist = legacyTransition.freelistBytes {
                alertEvidenceBudget["legacy_transition_freelist_bytes"] =
                    freelist
            }
            if let evidenceSnapshot {
                alertEvidenceBudget["row_count"] = evidenceSnapshot.rowCount
                alertEvidenceBudget["logical_bytes"] = evidenceSnapshot.logicalBytes
                alertEvidenceBudget["allocated_bytes"] = evidenceSnapshot.allocatedBytes
                alertEvidenceBudget["charged_bytes"] = evidenceSnapshot.chargedBytes
                alertEvidenceBudget["over_budget"] = evidenceSnapshot.overBudget
                alertEvidenceBudget["allocated_bytes_exact"] =
                    evidenceSnapshot.allocatedBytesExact
                alertEvidenceBudget["mutation_generation"] =
                    evidenceSnapshot.mutationGeneration
                alertEvidenceBudget["full_refreshes_total"] =
                    evidenceSnapshot.fullRefreshesTotal
            }
            if let alertsAdmission {
                if let value = alertsAdmission.footprintBytes {
                    alertEvidenceBudget["alerts_family_footprint_bytes"] = value
                }
                if let value = alertsAdmission.maxFootprintBytes {
                    alertEvidenceBudget["alerts_family_admission_cap_bytes"] = value
                }
                if let cap = alertsAdmission.maxFootprintBytes,
                   let reserve = alertsAdmission.transactionReserveBytes {
                    let boundary = AlertsSizeCapBoundary(
                        nominalCapBytes: cap,
                        transactionReserveBytes: reserve
                    )
                    alertEvidenceBudget["alerts_family_transaction_reserve_bytes"] =
                        boundary.transactionReserveBytes
                    alertEvidenceBudget["alerts_family_admission_boundary_bytes"] =
                        boundary.hardAdmissionBoundaryBytes
                    alertEvidenceBudget["alerts_family_recovery_target_bytes"] =
                        boundary.recoveryTargetBytes
                }
                alertEvidenceBudget["alerts_family_blocked"] =
                    alertsAdmission.latchedFailure != nil
                alertEvidenceBudget["alerts_family_reason"] =
                    alertsAdmission.latchedFailure ?? ""
            }
            let unifiedLogDelivery = upstreamCollectorBuffers[.unifiedLog]
            let registryDroppedTotal = await state.collectorRegistry.droppedEventsTotal()
            let addSaturating: (UInt64, UInt64) -> UInt64 = { lhs, rhs in
                let (sum, overflow) = lhs.addingReportingOverflow(rhs)
                return overflow ? UInt64.max : sum
            }
            let unifiedLogNormalizedTotal = unifiedLogDelivery.map {
                $0.offeredByLane.values.reduce(UInt64(0), addSaturating)
            } ?? 0
            // Encode collectors as plain dicts for JSONSerialization
            // compatibility (it can't take a [Codable] directly).
            let collectorDicts: [[String: Any]] = collectorStatuses.map { s in
                var d: [String: Any] = [
                    "name": s.name,
                    "event_count": s.eventCount,
                    "error_count": s.errorCount,
                    "expected_interval_seconds": s.expectedIntervalSeconds,
                    "healthy": s.healthy,
                    // v1.21.6-rc.45: a boolean cannot say "never started".
                    "reason": s.reason,
                ]
                if let lt = s.lastTick { d["last_tick_unix"] = lt.timeIntervalSince1970 }
                if let le = s.lastError { d["last_error"] = le }
                return d
            }

            // v1.12.6 Wave 9D: surface event-insert error counts + rate +
            // last-kind into the rich heartbeat so the dashboard can
            // render a "storage degraded" banner without having to
            // poll storage_errors.json as a second source. Reads
            // through the StorageErrorTracker actor — strictly off the
            // hot insert path (30 s cadence).
            let insertErrorSnapshot = await StorageErrorTracker.shared.eventInsertErrorSnapshot()
            // v1.22.0 (item 1): alert-side twin. 34f1ef1/4c8d563 fixed the
            // alerts-family write pause; this surfaces any residual alert-insert
            // failure instead of leaving it silent. Total-count-only.
            let alertInsertErrorSnapshot = await StorageErrorTracker.shared
                .alertInsertErrorSnapshot()

            // v1.12.6 Wave 9K: previously-orphaned operator counters
            // wired into the rich heartbeat:
            //  - `payload_truncated_total`: the durable distinct-UUID count of
            //    canonical journal poison. Projection-only truncation is not
            //    evidence loss. Qualification must distinguish a proven zero
            //    from an unavailable/corrupt ledger, so this key is omitted on
            //    error rather than manufacturing zero.
            //  - `eslogger_dropped_total`: `global_seq_num` gaps observed by
            //    the dev-fallback `EsloggerCollector` subprocess (nil in the
            //    release sysext, so 0 there). This is the *eslogger fallback's*
            //    own drop counter — NOT the native ES client's kernel drops,
            //    which are surfaced separately below as `es_kernel_dropped_total`
            //    / `es_kernel_dropped_by_type` (v1.21.4 Phase-0 D1). Pre-9K it
            //    was only logged as a warning every 30 s.
            let payloadPoisonTotal: Int?
            do {
                payloadPoisonTotal = try await state.eventStore
                    .payloadPoisonTotalSnapshot()
            } catch {
                payloadPoisonTotal = nil
            }
            let eventInsertFilterCounters = await state.eventStore.insertFilterCounters()
            let journalExpiryScheduling = await state.eventStore
                .journalExpirySchedulingCounters()
            let esloggerDroppedTotal = await state.esloggerCollector?.getDroppedEventCount() ?? 0

            // v1.21.4 Phase-0 (D1 + D4): native ES kernel-drop accounting +
            // hot-path gauges, read straight off the ESCollector (synchronous,
            // lock-guarded — no actor hop). nil collector (dev eslogger/kdebug
            // fallback path, no ES entitlement) → zeros, so the keys are always
            // present. The aggregate now includes these as a distinct pre-buffer
            // stage while the named counters preserve stage diagnosis. By-type
            // maps are re-keyed to readable event-type names for the heartbeat.
            let esGlobalDropped = state.collector?.esGlobalDropped() ?? 0
            let esKernelDroppedByType: [String: UInt64] =
                (state.collector?.esKernelDroppedByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esProcessedByType: [String: UInt64] =
                (state.collector?.esProcessedByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esIntentionallyFilteredBeforeWorkerByType: [String: UInt64] =
                (state.collector?.esIntentionallyFilteredBeforeWorkerByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esNormalizedYieldedByType: [String: UInt64] =
                (state.collector?.esNormalizedYieldedByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esHandlerP99Micros = state.collector?.esHandlerP99Micros() ?? 0
            let esStreamYieldDropped = state.collector?.esStreamYieldDropped() ?? 0
            let esCopyBackpressureDropped = state.collector?.esCopyBackpressureDropped() ?? 0
            // v1.21.6 (audit DET-05): per-type attribution for the copy-stage
            // drops, name-keyed like `es_kernel_dropped_by_type`. On the field
            // host this stage discards ~22.6% of every delivered ES message, and
            // the single aggregate counter cannot say which detections pay for it.
            let esCopyBackpressureDroppedByType: [String: UInt64] =
                (state.collector?.esCopyBackpressureDroppedByType() ?? [:])
                    .reduce(into: [:]) { $0[ESCollector.eventTypeName($1.key)] = $1.value }
            let esClientSplitDegraded = state.collector?.esClientSplitDegraded() ?? false

            // Loss before a collector's AsyncStream has no normalized Event and
            // therefore no honest final-lane attribution. Keep it source-only,
            // but include it exactly once in the detection-input aggregate.
            let esPreBufferDropped = addSaturating(
                esGlobalDropped,
                esCopyBackpressureDropped
            )
            let preBufferDroppedBySource: [String: UInt64] = [
                EventPipelineSource.endpointSecurity.key: state.collector == nil
                    ? 0 : esPreBufferDropped,
                EventPipelineSource.eslogger.key: state.collector == nil
                    ? esloggerDroppedTotal : 0,
            ]
            let preBufferDroppedTotal = preBufferDroppedBySource.values.reduce(UInt64(0)) {
                addSaturating($0, $1)
            }
            let detectionInputDroppedTotal = addSaturating(
                preBufferDroppedTotal,
                eventPipeline.detectionInputDroppedTotal
            )
            // CollectorRegistry is reserved for losses outside the six fixed
            // merged sources. It currently has no overlapping production caller;
            // keep it a separate summand so a future caller cannot silently hide.
            let droppedTotal = addSaturating(
                registryDroppedTotal,
                detectionInputDroppedTotal
            )

            // Sequence-engine partial-match state. The 10K cap evicts
            // oldest-first from ONE global queue shared by all 41 sequence
            // rules, so flooding any enabled rule's cheap first step flushes
            // every other rule's in-flight kill-chain state. Publishing both the
            // cumulative evictions and the current depth makes that visible:
            // in-flight parked near the cap with evictions climbing is the
            // signature of the flush, whether accidental or deliberate.
            let sequencePartialsEvicted = await state.sequenceEngine.partialsEvictedTotal
            let sequencePendingStepsEvicted = await state.sequenceEngine.pendingStepsEvictedTotal
            let sequenceJournalConservation = await state.sequenceEngine.pendingStepConservation()
            let sequenceJournalByRule = await state.sequenceEngine
                .pendingStepConservationByRule()
            let sequenceJournalByRuleDict: [String: [String: UInt64]] =
                sequenceJournalByRule.mapValues { ledger in
                    [
                        "offered": ledger.offered,
                        "completed": ledger.completed,
                        "queued": ledger.queued,
                        "in_flight": ledger.inFlight,
                        "explicitly_shed": ledger.explicitlyShed,
                    ]
                }
            let sequenceWeight = await state.sequenceEngine.checkpointWeightDiagnostics()
            let sequencePartialsInFlight = sequenceWeight.partialCount
            let sequencePendingStepsCurrent = sequenceWeight.pendingCount
            let sequenceStateContinuityMaintained: Bool
            let sequenceStateContinuityDetail: String
            if sequencePartialsInFlight < 0 || sequencePendingStepsCurrent < 0 {
                sequenceStateContinuityMaintained = false
                sequenceStateContinuityDetail = "negative_runtime_count"
            } else if sequenceWeight.cachedWeight != sequenceWeight.recomputedWeight {
                sequenceStateContinuityMaintained = false
                sequenceStateContinuityDetail = "checkpoint_weight_accounting_drift"
            } else if sequenceWeight.cachedWeight > sequenceWeight.maximumWeight {
                sequenceStateContinuityMaintained = false
                sequenceStateContinuityDetail = "checkpoint_weight_limit_exceeded"
            } else if await state.sequenceEngine.evictionIsOngoing(
                within: Self.sequenceEvictionHealthWindow
            ) {
                // v1.21.7: this used to read `sequencePartialsEvicted > 0` /
                // `sequencePendingStepsEvicted > 0` — CUMULATIVE-since-boot
                // counters. A lifetime total never decreases, so the flag
                // latched on at the first eviction and could never clear for the
                // life of the process. Measured on an installed rc.8 host: one
                // load spike left `sequence_state_continuity_maintained = false`
                // permanently, which is the single input driving the menu bar's
                // "protection degraded" label — so the product reported degraded
                // protection indefinitely while every other health signal was
                // clean. An indicator that cannot clear teaches the operator to
                // ignore it, which costs more than the eviction did.
                //
                // A health flag must answer "is state being lost NOW". The
                // cumulative totals remain in the heartbeat below as
                // diagnostics, where a monotonic counter is the right shape.
                sequenceStateContinuityMaintained = false
                sequenceStateContinuityDetail = sequencePendingStepsEvicted > 0
                    ? "pending_step_eviction"
                    : "partial_match_eviction"
            } else {
                sequenceStateContinuityMaintained = true
                sequenceStateContinuityDetail = "nominal"
            }
            let sequenceCheckpoint = await state.sequenceCheckpointCoordinator.telemetry(
                engine: state.sequenceEngine,
                now: Date(timeIntervalSince1970: nowUnix)
            )
            var sequenceCheckpointDict: [String: Any] = [
                "restore_status": sequenceCheckpoint.restoreStatus.rawValue,
                "checkpoint_bytes": sequenceCheckpoint.checkpointBytes,
                "durable_carrier_valid": sequenceCheckpoint.durableCarrierValid,
                "dirty": sequenceCheckpoint.dirty,
                "current_generation": sequenceCheckpoint.currentGeneration,
                "configured_crash_rpo_seconds": sequenceCheckpoint.configuredCrashRPOSeconds,
                "crash_rpo_bound_currently_maintained": sequenceCheckpoint.crashRPOBoundCurrentlyMaintained,
                "periodic_writes_last_hour": sequenceCheckpoint.periodicWritesLastHour,
                "periodic_bytes_last_hour": sequenceCheckpoint.periodicBytesLastHour,
                "writes_total": sequenceCheckpoint.writesTotal,
                "bytes_written_total": sequenceCheckpoint.bytesWrittenTotal,
                "unchanged_skips_total": sequenceCheckpoint.unchangedSkipsTotal,
                "budget_deferrals_total": sequenceCheckpoint.budgetDeferralsTotal,
                "conservation": [
                    "offered": sequenceCheckpoint.conservation.offered,
                    "completed": sequenceCheckpoint.conservation.completed,
                    "queued": sequenceCheckpoint.conservation.queued,
                    "in_flight": sequenceCheckpoint.conservation.inFlight,
                    "explicitly_shed": sequenceCheckpoint.conservation.explicitlyShed,
                ],
                "orphan_files_current": sequenceCheckpoint.orphanFilesCurrent,
                "orphan_bytes_current": sequenceCheckpoint.orphanBytesCurrent,
                "orphan_files_removed_total": sequenceCheckpoint.orphanFilesRemovedTotal,
                "orphan_bytes_removed_total": sequenceCheckpoint.orphanBytesRemovedTotal,
                "orphan_cleanup_scan_truncated": sequenceCheckpoint.orphanCleanupScanTruncated,
                "carrier_invalidations_total": sequenceCheckpoint.carrierInvalidationsTotal,
            ]
            if let value = sequenceCheckpoint.restoreDetail {
                sequenceCheckpointDict["restore_detail"] = value
            }
            if let value = sequenceCheckpoint.lastRestoreAt {
                sequenceCheckpointDict["last_restore_at_unix"] = value.timeIntervalSince1970
            }
            if let value = sequenceCheckpoint.lastAttemptAt {
                sequenceCheckpointDict["last_attempt_at_unix"] = value.timeIntervalSince1970
            }
            if let value = sequenceCheckpoint.lastSuccessAt {
                sequenceCheckpointDict["last_success_at_unix"] = value.timeIntervalSince1970
            }
            if let value = sequenceCheckpoint.lastFailureAt {
                sequenceCheckpointDict["last_failure_at_unix"] = value.timeIntervalSince1970
            }
            if let value = sequenceCheckpoint.lastFailure {
                sequenceCheckpointDict["last_failure"] = value
            }
            if let value = sequenceCheckpoint.checkpointCapturedAt {
                sequenceCheckpointDict["checkpoint_captured_at_unix"] = value.timeIntervalSince1970
            }
            if let value = sequenceCheckpoint.checkpointAgeSeconds {
                sequenceCheckpointDict["checkpoint_age_seconds"] = value
            }
            if let value = sequenceCheckpoint.currentSemanticDigest {
                sequenceCheckpointDict["current_semantic_digest"] = value
            }
            if let value = sequenceCheckpoint.durableSemanticDigest {
                sequenceCheckpointDict["durable_semantic_digest"] = value
            }
            if let value = sequenceCheckpoint.durableGeneration {
                sequenceCheckpointDict["durable_generation"] = value
            }
            if let value = sequenceCheckpoint.lastOrphanCleanupAt {
                sequenceCheckpointDict["last_orphan_cleanup_at_unix"] = value.timeIntervalSince1970
            }
            if let value = sequenceCheckpoint.lastCarrierInvalidationReason {
                sequenceCheckpointDict["last_carrier_invalidation_reason"] = value.rawValue
            }
            if let value = sequenceCheckpoint.lastCarrierInvalidationAt {
                sequenceCheckpointDict["last_carrier_invalidation_at_unix"] = value.timeIntervalSince1970
            }

            // v1.21.4 Phase-1 D2: sensor-degraded / possible-evasion meta-alert.
            // Fold the D1/D4 cumulative counters into per-tick deltas and gate on
            // the conjunction (file-event spike above rolling baseline AND
            // (kernel drops > 0 OR process/exec channel collapse)). Advisory
            // ONLY — never auto-throttles/auto-mutes (owner decision).
            let fileEventsCumulative = Self.esFileEventTypeNames
                .reduce(UInt64(0)) { $0 &+ (esProcessedByType[$1] ?? 0) }
            let processEventsCumulative = Self.esProcessEventTypeNames
                .reduce(UInt64(0)) { $0 &+ (esProcessedByType[$1] ?? 0) }
            // Best-effort FP control: is the dominant recent file writer a
            // known-benign high-I/O signer (Time Machine / Spotlight / Xcode /
            // MacCrab)? Bounded query (off the hot path, 30 s cadence). Only
            // downgrades severity — never silences the alert.
            let benignHighIOSigner = await Self.dominantFileWriterIsBenign(state: state)
            let sensorResult = sensorDegradation.step(
                fileCumulative: fileEventsCumulative,
                processCumulative: processEventsCumulative,
                kernelDropCumulative: esGlobalDropped,
                // ES-collector-stage userspace drops (Phase-3 worker queue +
                // Phase-4/collector AsyncStream). These, not kernel drops, are
                // what a real flood produces after the retain-worker + client
                // split — so D2 gates on them too (see Input.collectorDropDelta).
                // v1.21.4 (audit): include the DOWNSTREAM merged-stream evictions
                // (priority + file AsyncStream, drained by the two consumers) in
                // D2's coverage-loss signal — that is the exact stage of the
                // original 400k-drop incident, and it was previously invisible to
                // the sensor-degraded conjunction (only the ES copy/kernel stage
                // was folded in). These are already in `events_dropped`; D2 now
                // sees them too so it fires when enrichment/detection is the
                // bottleneck, not just the ES stage.
                collectorDropCumulative: {
                    let source = EventPipelineSource.endpointSecurity.key
                    let upstreamTerminated = eventPipeline
                        .upstreamTerminatedBySourceAndLane[source]?
                        .values.reduce(UInt64(0), addSaturating) ?? 0
                    let mergedDropped = eventPipeline
                        .mergedDroppedBySourceAndLane[source]?
                        .values.reduce(UInt64(0), addSaturating) ?? 0
                    let mergedTerminated = eventPipeline
                        .mergedTerminatedBySourceAndLane[source]?
                        .values.reduce(UInt64(0), addSaturating) ?? 0
                    return [
                        esCopyBackpressureDropped,
                        esStreamYieldDropped,
                        upstreamTerminated,
                        mergedDropped,
                        mergedTerminated,
                    ].reduce(UInt64(0), addSaturating)
                }(),
                benignHighIOSigner: benignHighIOSigner
            )
            var esSensorDegraded = false
            var esSensorDegradedSeverity = ""
            var esSensorDegradedDetail = ""
            if case let .degraded(severity, benignAttribution) = sensorResult.outcome {
                esSensorDegraded = true
                esSensorDegradedSeverity = severity.rawValue
                let attribution = benignAttribution ? " (benign attribution)" : ""
                // Plain interpolation (no String(format:) — avoids the CVarArg
                // %@/%llu pitfalls this codebase has been bitten by).
                // Describe the branch that ACTUALLY fired. The previous single
                // template asserted a file spike AND an exec-channel collapse
                // unconditionally, so a sustained-loss fire reported exec
                // throughput as having "fallen" when it had risen — and told the
                // operator an attacker was suppressing telemetry when the real
                // condition was the userspace worker shedding load.
                let dropped = "\(sensorResult.kernelDropDelta) kernel-dropped, "
                    + "\(sensorResult.collectorDropDelta) dropped at the collector stage "
                    + "(backpressure/stream-yield)"
                switch sensorResult.reason {
                case .sustainedLoss:
                    esSensorDegradedDetail =
                        "ES sensor degraded\(attribution) — sustained event loss without a rate spike: \(dropped) this tick. File rate \(Int(sensorResult.fileRate))/tick (baseline \(Int(sensorResult.fileBaseline))), process/exec \(Int(sensorResult.processRate))/tick (baseline \(Int(sensorResult.processBaseline))). A chronic loss fraction can indicate telemetry-drop evasion, but it is equally consistent with the sensor being unable to keep up — check load before concluding evasion."
                case .spikeWithLoss, .none:
                    let execVerb = sensorResult.processRate < sensorResult.processBaseline ? "fell" : "rose"
                    esSensorDegradedDetail =
                        "ES sensor degraded\(attribution) — file-event rate \(Int(sensorResult.fileRate))/tick spiked above baseline \(Int(sensorResult.fileBaseline)) while \(dropped), and process/exec throughput \(execVerb) to \(Int(sensorResult.processRate))/tick (baseline \(Int(sensorResult.processBaseline))). Possible telemetry-drop evasion; verify what is generating the file storm."
                }
                let alert = Alert(
                    ruleId: "maccrab.self-defense.\(ESClientMonitor.ESHealthEvent.EventType.sensorDegraded.rawValue)",
                    ruleTitle: "Sensor Degraded: possible telemetry-drop evasion",
                    severity: severity,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "maccrabd",
                    description: esSensorDegradedDetail,
                    mitreTactics: "attack.defense_evasion",
                    mitreTechniques: "attack.t1562.001",
                    suppressed: false
                )
                // Route through AlertSink (not the raw alertStore.insert) so the
                // meta-alert inherits dedup/suppression — the sink dedups on the
                // shared ruleId, backstopping the evaluator's rising-edge latch.
                _ = try? await state.alertSink.submit(alert: alert)
            }

            // v1.18: engine LLM health — surfaces "enabled but unreachable /
            // misconfigured model" instead of failing silently. nil service
            // → not configured for the engine.
            let llmHealthDict: [String: Any]
            if let llm = state.llmService {
                let h = await llm.healthSnapshot()
                let runtime = await llm.runtimeTelemetrySnapshot()
                // AI-08: `healthy` is now LLMService.isUsable() — the SAME
                // predicate that gates `maccrab.llm.*` emission, so the gauge
                // cannot claim healthy while commentary is being withheld. The
                // old expression (`lastSuccess != nil && !circuitOpen`) reported
                // healthy for a backend that succeeded once at boot and then
                // died: the 5-min circuit cooldown expires on the clock with no
                // success required, leaving `circuit_open: false` sitting next
                // to `consecutive_failures: 3`.
                var llmDict: [String: Any] = [
                    "configured": true,
                    "provider": h.provider,
                    "model": h.model,
                    "consecutive_failures": h.consecutiveFailures,
                    "circuit_open": h.circuitOpen,
                    "healthy": h.usable,
                ]
                // Fixed-cardinality/content-free accounting only. Encode the
                // typed snapshot and immediately convert it to a JSON object;
                // prompt/response text and dynamic feature labels never enter
                // the heartbeat.
                if let runtimeData = try? JSONEncoder().encode(runtime),
                   let object = try? JSONSerialization.jsonObject(with: runtimeData),
                   let runtimeObject = object as? [String: Any] {
                    llmDict["runtime_telemetry"] = runtimeObject
                } else {
                    llmDict["runtime_telemetry_encoding_failed"] = true
                }
                // Omit rather than write epoch-0 when the backend has never
                // answered — the same honesty rule the collector block follows
                // for `last_tick_unix`. A fabricated 0 reads as "last succeeded
                // in 1970" to anything that doesn't special-case it.
                if let last = h.lastSuccessAtUnix { llmDict["last_success_unix"] = last }
                llmHealthDict = llmDict
            } else {
                llmHealthDict = ["configured": false]
            }

            // UX-3: live prevention-module state so the dashboard's Prevention
            // tab can show real sinkhole / network-blocker / persistence-guard
            // status instead of "unavailable". Each .stats() is a cheap actor read.
            let sinkholeStats = await state.dnsSinkhole.stats()
            let blockerStats = await state.networkBlocker.stats()
            let guardStats = await state.persistenceGuard.stats()
            let preventionDict: [String: Any] = [
                "sinkhole": ["enabled": sinkholeStats.enabled, "count": sinkholeStats.domainCount],
                // `enabled` is operator intent; `enforcing` is whether packets
                // are actually being dropped. Publishing only the former made
                // the dashboard claim protection that PF was not providing.
                "network_blocker": [
                    "enabled": blockerStats.enabled,
                    "count": blockerStats.blockedCount,
                    "enforcing": blockerStats.enforcing,
                    "enforcement_reason": blockerStats.reason,
                ],
                "persistence_guard": ["enabled": guardStats.enabled, "count": guardStats.protectedCount],
            ]

            // RA-041: a same-UID adversary can pad browser profile/version
            // directories. Enumeration remains bounded, but a bounded partial
            // result is an evidence gap, never a clean inventory. Publish both
            // the latest outcome and saturating lifetime counters so every
            // operator surface can distinguish "none found" from "not all
            // entries were inspected".
            let browserCoverage = await state.browserExtMonitor.coverageDiagnostics()
            var browserInventoryDict: [String: Any] = [
                "coverage_known": browserCoverage.coverageKnown,
                "complete": browserCoverage.lastScanComplete,
                "degraded": browserCoverage.degraded,
                "reason": browserCoverage.reason,
                "last_scan_was_truncated": browserCoverage.lastScanWasTruncated,
                "scans_total": Int64(clamping: browserCoverage.scansTotal),
                "truncated_scans_total": Int64(clamping: browserCoverage.truncatedScansTotal),
                "inspected_directory_entries_total": Int64(clamping: browserCoverage.inspectedDirectoryEntriesTotal),
                "truncated_directories_total": Int64(clamping: browserCoverage.truncatedDirectoriesTotal),
                "truncated_homes_total": Int64(clamping: browserCoverage.truncatedHomesTotal),
                "last_scan_homes": browserCoverage.lastScanHomes,
                "last_scan_inspected_directory_entries": Int64(clamping: browserCoverage.lastScanInspectedDirectoryEntries),
                "last_scan_truncated_directory_count": Int64(clamping: browserCoverage.lastScanTruncatedDirectoryCount),
                "last_scan_truncated_home_count": Int64(clamping: browserCoverage.lastScanTruncatedHomeCount),
                "per_home_directory_entry_budget": browserCoverage.perHomeDirectoryEntryBudget,
            ]
            if let completedAt = browserCoverage.lastScanCompletedAtUnix {
                browserInventoryDict["last_scan_completed_at_unix"] = completedAt
            }

            // v1.21.4 (#260): TraceRegistry telemetry — surfaced only when the
            // agent-trace binding is active (MACCRAB_AGENT_TRACES; the registry
            // is nil otherwise). `ttlEvictions` (bindings aged out) and
            // `pidRecycleRejected` (a stale pid→binding hit refused because the
            // pid was recycled to a different process) were counted on the hot
            // path but never surfaced; now visible so a Pass-11 audit can verify
            // the recycle-rejection + TTL-eviction accounting from the heartbeat.
            let traceRegistryDict: [String: Any]
            if let reg = state.traceRegistry {
                let m = await reg.metricsSnapshot()
                traceRegistryDict = [
                    "enabled": true,
                    "live_bindings": m.liveBindings,
                    "cap": m.cap,
                    "pid_recycle_rejected": m.pidRecycleRejected,
                    "cap_evictions": m.capEvictions,
                    "ttl_evictions": m.ttlEvictions,
                ]
            } else {
                traceRegistryDict = ["enabled": false]
            }

            // TraceGraph storage shedding is a deliberate evidence gap, not a
            // healthy empty graph. Surface the hot-path admission latch and its
            // cumulative shed count so CLI/dashboard/audit probes can tell the
            // difference and verify the DB+WAL+SHM cap on the running host.
            let traceGraphStorageDict: [String: Any]
            if let causalStore = state.causalStore {
                let s = await causalStore.storageAdmissionStatus()
                var d: [String: Any] = [
                    "enabled": s.enabled,
                    "accepting_mutations": s.acceptingMutations,
                    "blocked": s.blocked,
                    "store_available": true,
                    "startup_blocked": false,
                    "reason": s.reason?.rawValue ?? "",
                    "shed_mutations_total": Int64(clamping: s.shedMutationsTotal),
                    "pinned_reader": s.pinnedReader,
                    "recovering": s.recovering,
                    "recovery_mutation_waiters": s.recoveryMutationWaiters,
                    "recovery_mutation_waiter_limit": s.recoveryMutationWaiterLimit,
                    "recovery_mutation_queue_saturated": s.recoveryMutationQueueSaturated,
                    "recovery_mutation_waiter_high_watermark": s.recoveryMutationWaiterHighWatermark,
                    "recovery_mutation_waits_total": Int64(clamping: s.recoveryMutationWaitsTotal),
                    "recovery_mutation_wait_releases_total": Int64(clamping: s.recoveryMutationWaitReleasesTotal),
                    "recovery_mutation_wait_cancellations_total": Int64(clamping: s.recoveryMutationWaitCancellationsTotal),
                    "recovery_mutation_wait_closed_total": Int64(clamping: s.recoveryMutationWaitClosedTotal),
                    "recovery_mutation_wait_saturations_total": Int64(clamping: s.recoveryMutationWaitSaturationsTotal),
                    "recovery_mutation_wait_nanoseconds_total": Int64(clamping: s.recoveryMutationWaitNanosecondsTotal),
                    "recovery_mutation_max_wait_nanoseconds": Int64(clamping: s.recoveryMutationMaxWaitNanoseconds),
                    "recovery_mutation_oldest_wait_nanoseconds": Int64(clamping: s.recoveryMutationOldestWaitNanoseconds),
                    "recovery_writer_preemptions_total": Int64(clamping: s.recoveryWriterPreemptionsTotal),
                    "auto_vacuum_mode": s.autoVacuumMode,
                    "footprint_latch_trips_total": Int64(clamping: s.footprintLatchTripsTotal),
                    "footprint_latch_clears_total": Int64(clamping: s.footprintLatchClearsTotal),
                    "recovery_runs_total": Int64(clamping: s.recoveryRunsTotal),
                    "recovery_traces_deleted_total": Int64(clamping: s.recoveryTracesDeletedTotal),
                    "recovery_trace_child_rows_deleted_total": Int64(clamping: s.recoveryTraceChildRowsDeletedTotal),
                    "recovery_edges_deleted_total": Int64(clamping: s.recoveryEdgesDeletedTotal),
                    "recovery_entities_deleted_total": Int64(clamping: s.recoveryEntitiesDeletedTotal),
                    "recovery_vacuum_pages_reclaimed_total": Int64(clamping: s.recoveryVacuumPagesReclaimedTotal),
                    "recovery_no_physical_progress_total": Int64(clamping: s.recoveryNoPhysicalProgressTotal),
                ]
                if let value = s.maxFootprintBytes { d["max_footprint_bytes"] = value }
                if let value = s.admissionThresholdBytes { d["admission_threshold_bytes"] = value }
                if let value = s.resumeBelowBytes { d["resume_below_bytes"] = value }
                if let value = s.transactionReserveBytes { d["transaction_reserve_bytes"] = value }
                if let value = s.footprintBytes { d["footprint_bytes"] = value }
                if let value = s.freeSpaceBytes { d["free_space_bytes"] = value }
                if let value = s.freeSpaceFloorBytes { d["free_space_floor_bytes"] = value }
                if let value = s.lastRecoveryFootprintBeforeBytes { d["last_recovery_footprint_before_bytes"] = value }
                if let value = s.lastRecoveryFootprintAfterBytes { d["last_recovery_footprint_after_bytes"] = value }
                if let value = s.proactiveRecoveryThresholdBytes { d["proactive_recovery_threshold_bytes"] = value }
                if let value = s.recoveryDeficitBytes { d["recovery_deficit_bytes"] = value }
                if let value = s.lastRecoveryEligibleBacklogRemaining { d["last_recovery_eligible_backlog_remaining"] = value }
                if let bridge = state.causalGraphBridge {
                    let w = await bridge.writeTelemetry()
                    d["ingest_events_total"] = Int64(clamping: w.inputEventsTotal)
                    d["ingest_events_committed_total"] = Int64(clamping: w.eventsCommittedTotal)
                    d["ingest_events_failed_total"] = Int64(clamping: w.eventsFailedTotal)
                    d["ingest_events_in_flight"] = w.eventsInFlight
                    d["ingest_events_pending"] = w.eventsPending
                    d["entity_observations_total"] = Int64(clamping: w.entityObservationsTotal)
                    d["edge_observations_total"] = Int64(clamping: w.edgeObservationsTotal)
                    d["relevance_suppressed_file_events_total"] = Int64(clamping: w.relevanceSuppressedFileEventsTotal)
                    d["relevance_suppressed_rows_total"] = Int64(clamping: w.relevanceSuppressedRowsTotal)
                    d["physical_write_suppressed_events_total"] = Int64(clamping: w.physicalWriteSuppressedEventsTotal)
                    d["physical_write_suppressed_rows_total"] = Int64(clamping: w.physicalWriteSuppressedRowsTotal)
                    d["write_attempts_total"] = Int64(clamping: w.writeAttemptsTotal)
                    d["write_batches_committed_total"] = Int64(clamping: w.writeBatchesCommittedTotal)
                    d["write_batches_failed_total"] = Int64(clamping: w.writeBatchesFailedTotal)
                    d["write_batches_in_flight"] = w.writeBatchesInFlight
                    d["write_rows_attempted_total"] = Int64(clamping: w.writeRowsAttemptedTotal)
                    d["write_rows_committed_total"] = Int64(clamping: w.writeRowsCommittedTotal)
                    d["write_rows_failed_total"] = Int64(clamping: w.writeRowsFailedTotal)
                    d["write_rows_in_flight"] = w.writeRowsInFlight
                    d["coalesced_noop_rows_total"] = Int64(clamping: w.coalescedNoopRowsTotal)
                    d["pending_entity_rows"] = w.pendingEntityRows
                    d["pending_edge_rows"] = w.pendingEdgeRows
                }
                traceGraphStorageDict = d
            } else if let startupAdmission = state.causalStoreStartupAdmission {
                traceGraphStorageDict = startupAdmission.heartbeatDictionary
            } else {
                // A nil store is never a healthy/intentional configuration in
                // the daemon. Keep generic initialization failures visible even
                // when they were not one of the typed admission errors above.
                traceGraphStorageDict = [
                    "enabled": false,
                    "accepting_mutations": false,
                    "blocked": true,
                    "store_available": false,
                    "startup_blocked": false,
                    "reason": "initialization_failed",
                    "shed_mutations_total": Int64(0),
                    "pinned_reader": false,
                    "recovering": false,
                ]
            }

            // traces.db holds loopback OTLP input supplied by local tools. It
            // is explicitly unauthenticated/self-reported, but silently losing
            // even advisory evidence would still make an empty trace view
            // misleading. Publish its independent admission state so every
            // operator surface can distinguish "no spans" from "spans shed".
            let traceStoreStorageDict: [String: Any]
            if let traceStore = state.traceStore {
                let s = await traceStore.storageAdmissionStatus()
                var d: [String: Any] = [
                    "enabled": s.enabled,
                    "blocked": s.blocked,
                    "store_available": true,
                    "startup_blocked": false,
                    "reason": s.reason?.rawValue ?? "",
                    "shed_mutations_total": Int64(clamping: s.shedMutationsTotal),
                    "pinned_reader": s.pinnedReader,
                    "recovering": s.recovering,
                ]
                let ingest = s.ingestConservation
                d["ingest_conservation"] = [
                    "offered": Int64(clamping: ingest.offered),
                    "completed": Int64(clamping: ingest.completed),
                    "queued": Int64(clamping: ingest.queued),
                    "in_flight": Int64(clamping: ingest.inFlight),
                    "explicitly_shed": Int64(clamping: ingest.explicitlyShed),
                ]
                if let value = s.maxFootprintBytes { d["max_footprint_bytes"] = value }
                if let value = s.admissionThresholdBytes { d["admission_threshold_bytes"] = value }
                if let value = s.transactionReserveBytes { d["transaction_reserve_bytes"] = value }
                if let value = s.footprintBytes { d["footprint_bytes"] = value }
                if let value = s.freeSpaceBytes { d["free_space_bytes"] = value }
                if let value = s.freeSpaceFloorBytes { d["free_space_floor_bytes"] = value }
                traceStoreStorageDict = d
            } else if let startupAdmission = state.traceStoreStartupAdmission {
                traceStoreStorageDict = startupAdmission.heartbeatDictionary
            } else {
                // A disabled receiver is intentional and is not itself a
                // storage failure. Keep it distinguishable from an enabled
                // receiver whose TraceStore failed to initialize.
                traceStoreStorageDict = [
                    "enabled": false,
                    "blocked": false,
                    "store_available": false,
                    "startup_blocked": false,
                    "reason": "receiver_disabled",
                    "shed_mutations_total": Int64(0),
                    "pinned_reader": false,
                    "recovering": false,
                ]
            }

            // v1.21.4 (F3): honest single-event rule coverage. `rules_loaded` =
            // every rule the engine loaded from disk; `rules_active` = the subset
            // that will actually EVALUATE (enabled). Under the F-04 stable rule
            // profile these diverge sharply (e.g. ~438 loaded / ~87 active), so
            // the dashboard + `maccrabctl status` can report effective coverage
            // rather than the on-disk file count that overstates protection.
            // Cheap actor reads, off the hot path (30 s cadence).
            let rulesLoaded = await state.ruleEngine.ruleCount
            // v1.21.4 (audit): surface DB tamper-evidence — a malformed ENC2
            // envelope or AES-GCM authentication failure means an encrypted DB
            // column/row was corrupted or modified. Previously only fault-logged; now visible so the operator
            // (and the dashboard) can see + act on it. Monotonic since boot.
            let dbTamperFailures = state.dbEncryption.authenticatedDecryptFailures
            // v1.21.4 (audit): the counter above is surfaced in the heartbeat,
            // but a non-zero value is a security event that must actively page —
            // an encrypted DB column had an invalid envelope or failed AES-GCM
            // authentication. On a fresh failure since the
            // last tick, raise a structured tamper Alert. Routed through
            // AlertSink so it inherits dedup/suppression (the rate limiter if
            // failures keep climbing tick-over-tick) — the same pattern the D2
            // sensor-degraded meta-alert above uses.
            if tamperAlertState.shouldAlert(current: dbTamperFailures) {
                let tamperAlert = Alert(
                    ruleId: "maccrab.self-defense.db-tamper",
                    ruleTitle: "Database Tamper Detected: authenticated envelope failure",
                    severity: .critical,
                    eventId: UUID().uuidString,
                    processPath: nil,
                    processName: "maccrabd",
                    description: "An encrypted database column had a malformed ENC2 envelope or failed AES-GCM authentication (tamper_count=\(dbTamperFailures)) — the stored authenticated-encryption value of an event/trace field was corrupted or modified at rest. Values emitted by MacCrab always have a valid base64 AES-GCM envelope, so this is not a benign decode miss. (A plaintext value in an encryption-enabled column — a possible substitution but also a legacy pre-encryption row — is tracked separately as a lower-confidence advisory, not here.) This is best-effort at-rest integrity, not a full MAC over the database — investigate for unauthorized access to the MacCrab databases.",
                    mitreTactics: "attack.defense_evasion",
                    mitreTechniques: "attack.t1565.001",
                    suppressed: false
                )
                _ = try? await state.alertSink.submit(alert: tamperAlert)
            }
            let rulesActive = await state.ruleEngine.enabledRuleCount
            let timerPlane = timerLifecycle.snapshot()
            let livenessPlane = livenessLifecycle.snapshot()
            let startupWorkPlane = state.startupWorkLifecycle.snapshot()
            let detectionWorkPlane = state.detectionWorkLifecycle.snapshot()
            let advisoryWorkPlane = state.advisoryWorkLifecycle.snapshot()
            let outputWorkPlane = state.outputWorkLifecycle.snapshot()
            let heavyEnrichmentPlane = await state.enricher
                .heavyEnrichmentSnapshot()
            let deferredEnrichmentBuffer = await state.deferredEnrichmentBuffer
                .snapshot()
            let eventPipelineLiveMemory = EventPipelineLiveMemoryBudget
                .processShared.snapshot()
            // v1.22.0 (item 6, measurement): per-owner budget pressure so a
            // qualification burst can show whether .eventSource / .journalPrepared
            // are the owners that saturate the shared 96 MiB envelope. Read-only.
            let eventPipelineOwnerStats = EventPipelineLiveMemoryBudget
                .processShared.perOwnerSnapshot()
            // v1.22.0 (item 6, measurement): real pre/post-enrichment source-size
            // distribution + sanitized-JSON expansion ratio, so the lease-sizing
            // constants are chosen from measured tails, not guessed.
            let eventSourceSizeTelemetry = EventJournalSourceSizeTelemetry
                .snapshot()
            // v1.22.0 (item 7): journal-index refresh accounting so a recurrence
            // of the dashboard-starves-expiry defect (full rebuilds climbing while
            // append refreshes also climb) is visible and gated in qualification.
            let journalIndexDiagnostics = await state.eventStore
                .journalIndexRefreshDiagnostics()
            // v1.22.0 (item 3, Phase 0): per-trigger drain attribution, to measure
            // whether memory-pressure retries drive the small-block write bursts
            // before choosing the sustained-write-rate fix.
            let drainDiagnostics = await state.eventWriter
                .diagnosticDrainSnapshot()

            func workLifecycleDictionary(
                _ plane: DaemonTimerLifecycleSnapshot
            ) -> [String: Any] {
                [
                    "accepting": plane.accepting,
                    "offered_handlers_total": plane.offeredHandlers,
                    "accepted_handlers_total": plane.acceptedHandlers,
                    "completed_handlers_total": plane.completedHandlers,
                    "rejected_handlers_total": plane.rejectedHandlers,
                    "closed_rejected_handlers_total":
                        plane.closedRejectedHandlers,
                    "overload_shed_handlers_total":
                        plane.overloadShedHandlers,
                    "coalesced_handlers_total": plane.coalescedHandlers,
                    "coalesced_by_label": plane.coalescedByLabel,
                    "rejected_by_label": plane.rejectedByLabel,
                    "inline_fallback_handlers_total":
                        plane.inlineFallbackHandlers,
                    "inline_fallbacks_by_label":
                        plane.inlineFallbacksByLabel,
                    "in_flight_handlers": plane.inFlightHandlers,
                    "maximum_in_flight_handlers":
                        plane.maximumInFlightHandlers,
                    "conserves_accepted_handlers":
                        plane.conservesAcceptedHandlers,
                    "conserves_offered_handlers":
                        plane.conservesOfferedHandlers,
                ]
            }

            let heavyEnrichmentPlaneDict: [String: Any] = [
                "accepting": heavyEnrichmentPlane.accepting,
                "offered_requests_total":
                    heavyEnrichmentPlane.offeredRequestsTotal,
                "completed_requests_total":
                    heavyEnrichmentPlane.completedRequestsTotal,
                "timed_out_requests_total":
                    heavyEnrichmentPlane.timedOutRequestsTotal,
                "cancelled_requests_total":
                    heavyEnrichmentPlane.cancelledRequestsTotal,
                "rejected_requests_total":
                    heavyEnrichmentPlane.rejectedRequestsTotal,
                "cache_hits_total": heavyEnrichmentPlane.cacheHitsTotal,
                "coalesced_requests_total":
                    heavyEnrichmentPlane.coalescedRequestsTotal,
                "late_worker_exits_total":
                    heavyEnrichmentPlane.lateWorkerExitsTotal,
                "queued_requests": heavyEnrichmentPlane.queuedRequests,
                "running_requests": heavyEnrichmentPlane.runningRequests,
                "physical_workers": heavyEnrichmentPlane.physicalWorkers,
                "lingering_timed_out_or_cancelled_workers":
                    heavyEnrichmentPlane
                        .lingeringTimedOutOrCancelledWorkers,
                "deferred_results": heavyEnrichmentPlane.deferredResults,
                "active_reserved_result_bytes":
                    heavyEnrichmentPlane.activeReservedResultBytes,
                "deferred_result_bytes":
                    heavyEnrichmentPlane.deferredResultBytes,
                "cache_result_bytes": heavyEnrichmentPlane.cacheResultBytes,
                "retained_result_bytes_high_watermark":
                    heavyEnrichmentPlane.retainedResultBytesHighWatermark,
                "maximum_retained_result_bytes":
                    heavyEnrichmentPlane.maximumRetainedResultBytes,
                "oversized_result_values_total":
                    heavyEnrichmentPlane.oversizedResultValuesTotal,
                "lingering_reservation_split_refusals_total":
                    heavyEnrichmentPlane
                        .lingeringReservationSplitRefusalsTotal,
                "cached_results": heavyEnrichmentPlane.cachedResults,
                "maximum_concurrent_workers":
                    heavyEnrichmentPlane.maximumConcurrentWorkers,
                "requests_conserved": heavyEnrichmentPlane.requestsConserved,
                "physical_capacity_conserved":
                    heavyEnrichmentPlane.physicalCapacityConserved,
                "result_byte_capacity_conserved":
                    heavyEnrichmentPlane.resultByteCapacityConserved,
                "cleanly_drained": heavyEnrichmentPlane.cleanlyDrained,
            ]
            let deferredEnrichmentBufferDict: [String: Any] = [
                "accepting_reservations":
                    deferredEnrichmentBuffer.acceptingReservations,
                "event_capacity": deferredEnrichmentBuffer.eventCapacity,
                "patch_capacity": deferredEnrichmentBuffer.patchCapacity,
                "raw_event_byte_capacity":
                    deferredEnrichmentBuffer.rawEventByteCapacity,
                "reservation_raw_event_byte_charge":
                    deferredEnrichmentBuffer.reservationRawEventByteCharge,
                "patch_byte_capacity":
                    deferredEnrichmentBuffer.patchByteCapacity,
                "reserved_slots": deferredEnrichmentBuffer.reservedSlots,
                "retained_events": deferredEnrichmentBuffer.retainedEvents,
                "rejected_pending_events":
                    deferredEnrichmentBuffer.rejectedPendingEvents,
                "reserved_raw_event_bytes":
                    deferredEnrichmentBuffer.reservedRawEventBytes,
                "retained_raw_event_bytes":
                    deferredEnrichmentBuffer.retainedRawEventBytes,
                "retained_raw_event_bytes_high_watermark":
                    deferredEnrichmentBuffer
                        .retainedRawEventBytesHighWatermark,
                "buffered_patch_bytes":
                    deferredEnrichmentBuffer.bufferedPatchBytes,
                "buffered_patch_bytes_high_watermark":
                    deferredEnrichmentBuffer
                        .bufferedPatchBytesHighWatermark,
                "applied_patch_bytes":
                    deferredEnrichmentBuffer.appliedPatchBytes,
                "applied_patch_bytes_high_watermark":
                    deferredEnrichmentBuffer
                        .appliedPatchBytesHighWatermark,
                "buffered_patches": deferredEnrichmentBuffer.bufferedPatches,
                "orphan_patches": deferredEnrichmentBuffer.orphanPatches,
                "waiting_reservations":
                    deferredEnrichmentBuffer.waitingReservations,
                "drain_capacity_claimed":
                    deferredEnrichmentBuffer.drainCapacityClaimed,
                "drain_byte_capacity_claimed":
                    deferredEnrichmentBuffer.drainByteCapacityClaimed,
                "reservation_requests_total":
                    deferredEnrichmentBuffer.reservationRequestsTotal,
                "reservations_granted_total":
                    deferredEnrichmentBuffer.reservationsGrantedTotal,
                "reservations_rejected_after_seal_total":
                    deferredEnrichmentBuffer
                        .reservationsRejectedAfterSealTotal,
                "slots_released_total":
                    deferredEnrichmentBuffer.slotsReleasedTotal,
                "retained_events_total":
                    deferredEnrichmentBuffer.retainedEventsTotal,
                "closed_events_total":
                    deferredEnrichmentBuffer.closedEventsTotal,
                "retained_raw_event_bytes_total":
                    deferredEnrichmentBuffer.retainedRawEventBytesTotal,
                "released_raw_event_bytes_total":
                    deferredEnrichmentBuffer.releasedRawEventBytesTotal,
                "raw_event_byte_rejections_total":
                    deferredEnrichmentBuffer.rawEventByteRejectionsTotal,
                "rejected_pending_events_total":
                    deferredEnrichmentBuffer.rejectedPendingEventsTotal,
                "rejected_pending_events_closed_total":
                    deferredEnrichmentBuffer
                        .rejectedPendingEventsClosedTotal,
                "patches_received_total":
                    deferredEnrichmentBuffer.patchesReceivedTotal,
                "patches_consumed_total":
                    deferredEnrichmentBuffer.patchesConsumedTotal,
                "patch_bytes_received_total":
                    deferredEnrichmentBuffer.patchBytesReceivedTotal,
                "patch_bytes_consumed_total":
                    deferredEnrichmentBuffer.patchBytesConsumedTotal,
                "identity_rejected_patches_total":
                    deferredEnrichmentBuffer.identityRejectedPatchesTotal,
                "reservation_conserved":
                    deferredEnrichmentBuffer.reservationConserved,
                "slots_conserved": deferredEnrichmentBuffer.slotsConserved,
                "events_conserved": deferredEnrichmentBuffer.eventsConserved,
                "raw_event_bytes_conserved":
                    deferredEnrichmentBuffer.rawEventBytesConserved,
                "patches_conserved": deferredEnrichmentBuffer.patchesConserved,
                "patch_bytes_conserved":
                    deferredEnrichmentBuffer.patchBytesConserved,
                "within_capacity": deferredEnrichmentBuffer.withinCapacity,
                "cleanly_drained": deferredEnrichmentBuffer.cleanlyDrained,
            ]
            let eventPipelineLiveMemoryDict: [String: Any] = [
                "current_bytes": eventPipelineLiveMemory.currentBytes,
                "high_watermark_bytes":
                    eventPipelineLiveMemory.highWatermarkBytes,
                "maximum_bytes": eventPipelineLiveMemory.maximumBytes,
                "forward_progress_reserve_bytes":
                    eventPipelineLiveMemory.forwardProgressReserveBytes,
                "event_store_workspace_reserve_bytes":
                    eventPipelineLiveMemory.eventStoreWorkspaceReserveBytes,
                "compact_receipt_reserve_bytes":
                    eventPipelineLiveMemory.compactReceiptReserveBytes,
                "active_leases": eventPipelineLiveMemory.activeLeases,
                "waiting_acquisitions":
                    eventPipelineLiveMemory.waitingAcquisitions,
                "waiter_high_watermark":
                    eventPipelineLiveMemory.waiterHighWatermark,
                "acquisition_total":
                    Int64(clamping: eventPipelineLiveMemory.acquisitionTotal),
                "release_total":
                    Int64(clamping: eventPipelineLiveMemory.releaseTotal),
                "waits_total":
                    Int64(clamping: eventPipelineLiveMemory.waitsTotal),
                "nonblocking_rejections_total": Int64(clamping:
                    eventPipelineLiveMemory.nonblockingRejectionsTotal),
                "waiter_limit_saturations_total": Int64(clamping:
                    eventPipelineLiveMemory.waiterLimitSaturationsTotal),
                "oversized_requests_total": Int64(clamping:
                    eventPipelineLiveMemory.oversizedRequestsTotal),
                "cancelled_waiter_total": Int64(clamping:
                    eventPipelineLiveMemory.cancelledWaiterTotal),
                "bytes_by_owner": eventPipelineLiveMemory.bytesByOwner,
                "within_capacity": eventPipelineLiveMemory.withinCapacity,
                "leases_conserved": eventPipelineLiveMemory.leasesConserved,
            ]

            let ruleSyncObservation = state.bundledRuleSyncObservation
            var ruleSync: [String: Any]
            switch ruleSyncObservation.outcome {
            case .skipped(let reason):
                ruleSync = [
                    "status": "skipped",
                    "reason": reason,
                    "bundled_tampered": false,
                    "installed_tampered": false,
                    "installed_corpus_verified": false,
                ]
            case .unchanged(let version):
                ruleSync = [
                    "status": "unchanged",
                    "version": version,
                    "bundled_tampered": false,
                    "installed_tampered": false,
                    "installed_corpus_verified":
                        ruleSyncObservation.installedCorpus != nil,
                ]
            case .installed(let version):
                ruleSync = [
                    "status": "installed",
                    "version": version,
                    "bundled_tampered": false,
                    "installed_tampered": false,
                    "installed_corpus_verified":
                        ruleSyncObservation.installedCorpus != nil,
                ]
            case .failed(
                let reason,
                let bundledTampered,
                let installedTampered,
                let installedCorpusVerified
            ):
                ruleSync = [
                    "status": "failed",
                    "reason": reason,
                    "bundled_tampered": bundledTampered,
                    "installed_tampered": installedTampered,
                    "installed_corpus_verified":
                        installedCorpusVerified
                            && ruleSyncObservation.installedCorpus != nil,
                ]
            }
            if let corpus = ruleSyncObservation.installedCorpus {
                ruleSync["version"] = corpus.version
                ruleSync["installed_manifest_sha256"] = corpus.manifestSHA256
                ruleSync["installed_manifest_hash_entry_count"] =
                    corpus.manifestHashEntryCount
            }

            let journalRecovery = state.eventJournalRecovery
            var journalAccountedEvents = 0
            var journalConservationOverflow = false
            for count in [
                journalRecovery.migratedEvents,
                journalRecovery.rolledExpiredEvents,
                journalRecovery.corruptPreservedEvents,
                journalRecovery.remainingEvents,
            ] {
                let addition = journalAccountedEvents
                    .addingReportingOverflow(count)
                journalAccountedEvents = addition.partialValue
                journalConservationOverflow =
                    journalConservationOverflow || addition.overflow
            }
            let journalRecoveryConserved = !journalConservationOverflow
                && journalRecovery.sourceEvents >= 0
                && journalRecovery.migratedEvents >= 0
                && journalRecovery.rolledExpiredEvents >= 0
                && journalRecovery.corruptPreservedEvents >= 0
                && journalRecovery.remainingEvents >= 0
                && journalRecovery.sourceEvents == journalAccountedEvents
            let eventJournalRecovery: [String: Any] = [
                "source_events": journalRecovery.sourceEvents,
                "migrated_events": journalRecovery.migratedEvents,
                "rolled_expired_events": journalRecovery.rolledExpiredEvents,
                "corrupt_preserved_events":
                    journalRecovery.corruptPreservedEvents,
                "remaining_events": journalRecovery.remainingEvents,
                "complete": journalRecovery.complete,
                "conserved": journalRecoveryConserved,
            ]

            // v1.22.0 (item 7): journal-index refresh counters for the
            // recurrence gate. full_rebuilds_total should stay flat while
            // append_refreshes_total climbs under healthy operation.
            let eventJournalIndexDict: [String: Any] = [
                "refreshes_total":
                    Int64(clamping: journalIndexDiagnostics.refreshes),
                "slow_refreshes_total":
                    Int64(clamping: journalIndexDiagnostics.slowRefreshes),
                "last_refresh_ms":
                    Int64(journalIndexDiagnostics.lastNanoseconds / 1_000_000),
                "full_rebuilds_total":
                    Int64(clamping: journalIndexDiagnostics.fullRebuilds),
                "append_refreshes_total":
                    Int64(clamping: journalIndexDiagnostics.appendRefreshes),
            ]

            // v1.22.0 (item 6, measurement): per-owner live-memory pressure.
            var eventPipelineLiveMemoryByOwnerDict: [String: Any] = [:]
            for (owner, stats) in eventPipelineOwnerStats {
                eventPipelineLiveMemoryByOwnerDict[owner.rawValue] = [
                    "waits_total": Int64(clamping: stats.waitsTotal),
                    "waiter_high_watermark": stats.waiterHighWatermark,
                    "nonblocking_rejections_total":
                        Int64(clamping: stats.nonblockingRejectionsTotal),
                    "waiter_limit_saturations_total":
                        Int64(clamping: stats.waiterLimitSaturationsTotal),
                    "oversized_requests_total":
                        Int64(clamping: stats.oversizedRequestsTotal),
                ] as [String: Any]
            }

            // v1.22.0 (item 6, measurement): event-source size distribution.
            let eventJournalSourceSizeDict: [String: Any] = [
                "sample_count":
                    Int64(clamping: eventSourceSizeTelemetry.sampleCount),
                "bucket_upper_bounds":
                    eventSourceSizeTelemetry.bucketUpperBounds,
                "bucket_counts": eventSourceSizeTelemetry.bucketCounts
                    .map { Int64(clamping: $0) },
                "maximum_source_bytes":
                    eventSourceSizeTelemetry.maximumSourceBytes,
                "sampled_expansion_ratios":
                    eventSourceSizeTelemetry.sampledExpansionRatios,
            ]

            // v1.22.0 (item 3, Phase 0): drain-trigger attribution.
            var drainTriggersDict: [String: Any] = [:]
            for (reason, stat) in drainDiagnostics {
                drainTriggersDict[reason] = [
                    "count": stat.count,
                    "avg_depth": stat.avgDepth,
                ] as [String: Any]
            }

            var payload: [String: Any] = [
                "written_at_unix": nowUnix,
                "engine_pid": engineIdentity.pid,
                "engine_started_at_unix": engineIdentity.startedAtUnix,
                "engine_version": engineIdentity.version,
                "engine_build": engineIdentity.build,
                "llm": llmHealthDict,
                "timer_lifecycle": workLifecycleDictionary(timerPlane),
                "liveness_timer_lifecycle":
                    workLifecycleDictionary(livenessPlane),
                "startup_work_lifecycle":
                    workLifecycleDictionary(startupWorkPlane),
                "detection_work_lifecycle":
                    workLifecycleDictionary(detectionWorkPlane),
                "advisory_work_lifecycle":
                    workLifecycleDictionary(advisoryWorkPlane),
                "output_work_lifecycle":
                    workLifecycleDictionary(outputWorkPlane),
                "heavy_enrichment_plane": heavyEnrichmentPlaneDict,
                "deferred_enrichment_buffer":
                    deferredEnrichmentBufferDict,
                "event_pipeline_live_memory":
                    eventPipelineLiveMemoryDict,
                "prevention": preventionDict,
                "browser_inventory": browserInventoryDict,
                "uptime_seconds": uptime,
                "events_processed": events,
                "alerts_emitted": alerts,
                "sysext_has_fda": sysextHasFDA,
                "fda_checked_at_unix": nowUnix,
                "event_type_counts": eventTypeCounts,
                "event_type_count_window": eventTypeCountWindow,
                "event_search_projection": eventSearchProjection,
                "rule_sync": ruleSync,
                "event_journal_recovery": eventJournalRecovery,
                "event_journal_index": eventJournalIndexDict,
                "event_pipeline_live_memory_by_owner":
                    eventPipelineLiveMemoryByOwnerDict,
                "event_journal_source_size": eventJournalSourceSizeDict,
                "drain_triggers": drainTriggersDict,
                // v1.21.6 (PERF-04): the DELIVERED retention window per category,
                // which is not the configured one. The companion list is the
                // categories under the 15-minute raw-event forensic/correlation
                // floor despite holding real volume.
                "events_retained_span_seconds_by_category": retainedSpanByCategory,
                "events_retained_lookback_seconds_by_category":
                    retainedLookbackByCategory,
                "events_retention_below_forensic_floor": starvedCategories,
                "collector_health": collectorDicts,
                "events_dropped": droppedTotal,
                // v1.21.6 (DET event-loss re-audit): cumulative causality
                // counters at each bounded stage. The source×lane upstream maps
                // cover all six collector-local AsyncStreams; `collector_buffer`
                // retains the legacy Unified Log scalar view. The merged maps
                // describe the later pair of 100K detection inputs.
                // `dropped_by_source_and_lane` uses the actual OLD value returned
                // by bufferingNewest, not an inference from offered proportions.
                // Source labels are a fixed compile-time enum, never
                // event-controlled. Histogram sample counts must equal the
                // corresponding completed counts.
                "event_pipeline": [
                    "offered_by_source": eventPipeline.offeredBySource,
                    "offered_by_source_and_lane": eventPipeline.offeredBySourceAndLane,
                    "dropped_by_source_and_lane": eventPipeline.droppedBySourceAndLane,
                    "terminated_by_source_and_lane": eventPipeline.terminatedBySourceAndLane,
                    "collector_offered_by_source_and_lane": eventPipeline.collectorOfferedBySourceAndLane,
                    "upstream_dropped_by_source_and_lane": eventPipeline.upstreamDroppedBySourceAndLane,
                    "upstream_terminated_by_source_and_lane": eventPipeline.upstreamTerminatedBySourceAndLane,
                    "merged_dropped_by_source_and_lane": eventPipeline.mergedDroppedBySourceAndLane,
                    "merged_terminated_by_source_and_lane": eventPipeline.mergedTerminatedBySourceAndLane,
                    "offered_by_lane": eventPipeline.offeredByLane,
                    "dequeued_by_lane": eventPipeline.dequeuedByLane,
                    "rule_evaluation_reached_by_lane_and_category": eventPipeline.ruleEvaluationReachedByLaneAndCategory,
                    "rule_evaluation_completed_by_lane_and_category": eventPipeline.ruleEvaluationCompletedByLaneAndCategory,
                    "completed_by_lane": eventPipeline.completedByLane,
                    "backlog_estimate_by_lane": eventPipeline.backlogEstimateByLane,
                    "in_flight_by_lane": eventPipeline.inFlightByLane,
                    "processing_p99_us_by_lane": eventPipeline.processingP99MicrosByLane,
                    "latency_sample_count_by_lane": eventPipeline.latencySampleCountByLane,
                    "upstream_dropped_by_lane": eventPipeline.upstreamDroppedByLane,
                    "upstream_terminated_by_lane": eventPipeline.upstreamTerminatedByLane,
                    "merged_dropped_by_lane": eventPipeline.mergedDroppedByLane,
                    "merged_terminated_by_lane": eventPipeline.mergedTerminatedByLane,
                    "collector_capacity_by_source": eventPipeline.collectorCapacityBySource,
                    "pre_buffer_dropped_by_source": preBufferDroppedBySource,
                    "detection_input_dropped_total": detectionInputDroppedTotal,
                    "capacity_by_lane": [
                        "priority": UInt64(DaemonState.priorityStreamCap),
                        "file": UInt64(DaemonState.fileStreamCap),
                    ],
                    "collector_buffer": [
                        "unified_log_normalized_total": unifiedLogNormalizedTotal,
                        "unified_log_stream_yield_dropped_total": unifiedLogDelivery?.droppedTotal ?? 0,
                        "unified_log_stream_yield_terminated_total": unifiedLogDelivery?.terminatedTotal ?? 0,
                        "unified_log_capacity": UInt64(UnifiedLogCollector.streamCapacity),
                    ],
                ],
                // v1.21.4 Phase-0 D1: honest kernel-drop counters (per-client
                // global + per-event-type), separate from `events_dropped`
                // (userspace AsyncStream eviction). Names via ESCollector.eventTypeName.
                "es_kernel_dropped_total": esGlobalDropped,
                "es_kernel_dropped_by_type": esKernelDroppedByType,
                // v1.21.4 Phase-0 D4: leading-indicator gauges.
                "es_msg_e2e_latency_p99_us": esHandlerP99Micros, // v1.21.4: end-to-end (callback→worker-done incl. queue wait), NOT inline callback wall-time

                "es_processed_by_type": esProcessedByType,
                // Callback-stage ledger: intentional admission filtering is
                // policy, while normalized-yielded means an Event was offered
                // to the collector-local bounded stream. Neither map folds in
                // copy-backpressure or stream eviction loss.
                "es_intentionally_filtered_before_worker_by_type": esIntentionallyFilteredBeforeWorkerByType,
                "es_normalized_yielded_by_type": esNormalizedYieldedByType,
                "es_stream_yield_dropped_total": esStreamYieldDropped,
                "es_copy_backpressure_dropped_total": esCopyBackpressureDropped,
                // v1.21.6 (audit DET-05): rich-heartbeat only, like the other
                // by-type maps. For one uninterrupted process epoch,
                // drop/(drop+processed) is the callback→worker refusal fraction.
                // It is NOT detection recall: processed includes intentional
                // pre-worker filtering and normalizer rejects, now split above.
                "es_copy_backpressure_dropped_by_type": esCopyBackpressureDroppedByType,
                "es_client_split_degraded": esClientSplitDegraded,
                // Which kernel event source actually won the boot-time fallback
                // chain (native ES client → eslogger proxy → kdebug → nothing).
                // Previously `esMode` was ONLY `print`ed at startup and rendered
                // in the startup banner — both stdout, which is discarded for a
                // sysextd-launched System Extension — so the most realistic
                // total-blindness cases (entitlement revoked by an OS update,
                // ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS after the user
                // installs another EDR, FDA withdrawn) all ended with the sysext
                // alive, liveness true, "Daemon: Running" and zero kernel
                // telemetry, unreportable from any surface. Anything other than
                // "native client" is degraded coverage.
                "es_mode": state.esMode,
                // v1.21.4 Phase-1 D2: sensor-degraded advisory state for the
                // ES Health surface + the menu-bar "protection degraded" flag.
                "es_sensor_degraded": esSensorDegraded,
                "es_sensor_degraded_severity": esSensorDegradedSeverity,
                "es_sensor_degraded_detail": esSensorDegradedDetail,
                // Wave 9D additions. `last_event_insert_error_kind` is
                // an empty string when no event-insert error has been
                // recorded since boot — JSONSerialization can't carry
                // Swift `nil` so we elide-by-empty-string. Dashboard
                // consumers should treat `""` and missing key
                // identically.
                "event_insert_errors_total": insertErrorSnapshot.total,
                "event_insert_error_rate_per_min": insertErrorSnapshot.ratePerMin,
                "last_event_insert_error_kind": insertErrorSnapshot.lastKind ?? "",
                "alert_insert_errors_total": alertInsertErrorSnapshot,
                "eslogger_dropped_total": esloggerDroppedTotal,
                // v1.21.4 (F3): effective vs on-disk single-event rule coverage.
                "rules_loaded": rulesLoaded,
                // Build channel of the RUNNING engine, read from this bundle's
                // Info.plist. The on-disk key says what was installed; this says
                // what is executing — the two diverge exactly when something
                // swapped the build underneath a measurement run, which is the
                // case worth catching. Absent key → "unknown", never "release":
                // a build too old to carry the marker must not be reported as a
                // shipped build.
                "build_channel": (Bundle.main.object(forInfoDictionaryKey: "MacCrabBuildChannel") as? String) ?? "unknown",
                "db_tamper_decrypt_failures": dbTamperFailures,
                // #19 (rc.4-verify): the lower-confidence substitution advisory —
                // plaintext where a ciphertext was expected (a possible substitution
                // OR a legacy pre-encryption row). Surfaced so the true-positive
                // path stays operator-visible after being decoupled from the
                // CRITICAL AES-GCM tamper alert, without re-introducing that FP.
                "db_plaintext_in_encrypted_column_total": state.dbEncryption.plaintextInEncryptedColumnCount,
                "rules_active": rulesActive,
                // Published so non-root surfaces can render EFFECTIVE coverage;
                // daemon_config.json itself is root-0600 and unreadable to them.
                "rule_profile": state.bootRuleProfile,
                // Tier-3 (sequence) state-loss gauges. `evicted_total` is
                // cumulative since boot; a sustained rise means in-flight
                // multi-step detections are being dropped before they can
                // complete. `in_flight` parked at the 10K cap is the companion
                // signal. Both were previously invisible outside one log line.
                "sequence_partials_evicted_total": sequencePartialsEvicted,
                "sequence_partials_in_flight": sequencePartialsInFlight,
                "sequence_pending_steps_current": sequencePendingStepsCurrent,
                "sequence_pending_steps_evicted_total": sequencePendingStepsEvicted,
                "sequence_checkpoint_state_weight_bytes": sequenceWeight.cachedWeight,
                "sequence_checkpoint_state_weight_recomputed_bytes": sequenceWeight.recomputedWeight,
                "sequence_checkpoint_state_weight_limit_bytes": sequenceWeight.maximumWeight,
                "sequence_state_continuity_maintained": sequenceStateContinuityMaintained,
                "sequence_state_continuity_detail": sequenceStateContinuityDetail,
                "sequence_checkpoint": sequenceCheckpointDict,
                "sequence_journal_conservation": [
                    "offered": sequenceJournalConservation.offered,
                    "completed": sequenceJournalConservation.completed,
                    "queued": sequenceJournalConservation.queued,
                    "in_flight": sequenceJournalConservation.inFlight,
                    "explicitly_shed": sequenceJournalConservation.explicitlyShed,
                ],
                "sequence_journal_conservation_by_rule": sequenceJournalByRuleDict,
                // v1.21.4 (F2/A2): split merged-stream drop attribution. Both are
                // detection-input drops folded into `events_dropped`; surfaced
                // distinctly so a file-noise flood (file) is not read as a lost
                // exec (priority). `events_storage_write_dropped_total` is the
                // batched writer's storage-layer drop — NOT a detection gap.
                "merged_priority_dropped_total": priorityDropped,
                "merged_file_dropped_total": fileDropped,
                "merged_priority_terminated_total": priorityTerminated,
                "merged_file_terminated_total": fileTerminated,
                // Every known pre-buffer, collector-buffer and merged-buffer
                // input loss, once. `events_dropped` additionally folds in the
                // CollectorRegistry's non-pipeline loss counter.
                "detection_input_dropped_total": detectionInputDroppedTotal,
                "events_storage_write_dropped_total": eventWriterTelemetry.droppedCount,
                "events_storage_write_offered_by_lane": eventWriterTelemetry.offeredByLane,
                "events_storage_write_dropped_by_lane": eventWriterTelemetry.droppedByLane,
                "events_storage_write_persisted_total": eventWriterTelemetry.persistedCount,
                "events_storage_write_persisted_by_lane": eventWriterTelemetry.persistedByLane,
                "events_storage_write_filtered_total": eventWriterTelemetry.filteredCount,
                "events_storage_write_filtered_by_lane": eventWriterTelemetry.filteredByLane,
                "events_storage_write_poisoned_total": eventWriterTelemetry.poisonedCount,
                "events_storage_write_poisoned_by_lane": eventWriterTelemetry.poisonedByLane,
                "events_storage_write_retried_total": eventWriterTelemetry.retriedCount,
                "events_storage_write_retried_by_lane": eventWriterTelemetry.retriedByLane,
                "events_storage_write_buffer_depth": eventWriterTelemetry.bufferDepth,
                "events_storage_write_buffer_depth_by_lane": eventWriterTelemetry.bufferDepthByLane,
                "events_storage_write_buffer_bytes": eventWriterTelemetry.bufferRetainedBytes,
                "events_storage_write_buffer_bytes_by_lane": eventWriterTelemetry.bufferRetainedBytesByLane,
                "events_storage_write_in_flight_depth": eventWriterTelemetry.inFlightDepth,
                "events_storage_write_in_flight_depth_by_lane": eventWriterTelemetry.inFlightDepthByLane,
                "events_storage_write_in_flight_bytes": eventWriterTelemetry.inFlightRetainedBytes,
                "events_storage_write_in_flight_bytes_by_lane": eventWriterTelemetry.inFlightRetainedBytesByLane,
                "event_terminal_revision_offered_total": eventWriterTelemetry.terminalRevisionOfferedCount,
                "event_terminal_revision_offered_by_lane": eventWriterTelemetry.terminalRevisionOfferedByLane,
                "event_terminal_revision_unchanged_total": eventWriterTelemetry.terminalRevisionUnchangedCount,
                "event_terminal_revision_unchanged_by_lane": eventWriterTelemetry.terminalRevisionUnchangedByLane,
                "event_terminal_revision_durable_total": eventWriterTelemetry.terminalRevisionDurableCount,
                "event_terminal_revision_durable_by_lane": eventWriterTelemetry.terminalRevisionDurableByLane,
                "event_terminal_revision_dropped_total": eventWriterTelemetry.terminalRevisionDroppedCount,
                "event_terminal_revision_dropped_by_lane": eventWriterTelemetry.terminalRevisionDroppedByLane,
                // v1.22.0: WHY, not just how many. `evidence_poisoned` folds a
                // shed and a genuine integrity failure into one boolean named
                // "poisoned"; this says which status actually fired, so a
                // residual drop is diagnosable from one heartbeat read.
                "event_terminal_revision_dropped_reason":
                    eventWriterTelemetry.terminalRevisionDroppedReasonCounts,
                "event_terminal_revision_poisoned_total": eventWriterTelemetry.terminalRevisionPoisonedCount,
                "event_terminal_revision_poisoned_by_lane": eventWriterTelemetry.terminalRevisionPoisonedByLane,
                "event_terminal_revision_retried_total": eventWriterTelemetry.terminalRevisionRetriedCount,
                "event_terminal_revision_retried_by_lane": eventWriterTelemetry.terminalRevisionRetriedByLane,
                "event_terminal_revision_buffer_depth": eventWriterTelemetry.terminalRevisionBufferDepth,
                "event_terminal_revision_buffer_depth_by_lane": eventWriterTelemetry.terminalRevisionBufferDepthByLane,
                "event_terminal_revision_buffer_bytes": eventWriterTelemetry.terminalRevisionBufferRetainedBytes,
                "event_terminal_revision_buffer_bytes_by_lane": eventWriterTelemetry.terminalRevisionBufferRetainedBytesByLane,
                "event_terminal_revision_in_flight_depth": eventWriterTelemetry.terminalRevisionInFlightDepth,
                "event_terminal_revision_in_flight_depth_by_lane": eventWriterTelemetry.terminalRevisionInFlightDepthByLane,
                "event_terminal_revision_in_flight_bytes": eventWriterTelemetry.terminalRevisionInFlightRetainedBytes,
                "event_terminal_revision_in_flight_bytes_by_lane": eventWriterTelemetry.terminalRevisionInFlightRetainedBytesByLane,
                "event_terminal_revision_conservation": eventWriterTelemetry.terminalRevisionConservationHolds,
                "event_terminal_revision_evidence_poisoned": eventWriterTelemetry.terminalRevisionEvidencePoisoned,
                "event_terminal_revision_storage_mutation_generation": eventWriterTelemetry.terminalStorageMutationGeneration,
                "event_journal_prepared_ownership_count": eventWriterTelemetry.preparedOwnershipCount,
                "event_journal_compact_receipt_count": eventWriterTelemetry.preparedOwnershipCompactReceiptCount,
                "event_journal_live_handle_count": eventWriterTelemetry.preparedOwnershipLiveHandleCount,
                "event_journal_prepared_ownership_bytes": eventWriterTelemetry.preparedOwnershipBytes,
                "event_journal_prepared_ownership_maximum_count": eventWriterTelemetry.preparedOwnershipMaximumCount,
                "event_journal_prepared_ownership_maximum_bytes": eventWriterTelemetry.preparedOwnershipMaximumBytes,
                "event_journal_repairable_gap_count": eventWriterTelemetry.repairableJournalGapCount,
                "event_journal_repair_payload_lease_count": eventWriterTelemetry.repairPayloadLeaseCount,
                "event_journal_repair_payload_expired_total": Int64(clamping: eventWriterTelemetry.repairPayloadExpiredTotal),
                "events_retention_budget": eventRetentionBudget,
                "alert_evidence_budget": alertEvidenceBudget,
                "trace_registry": traceRegistryDict,
                "tracegraph_storage_admission": traceGraphStorageDict,
                "traces_storage_admission": traceStoreStorageDict,
                "schema_version": 5,
            ]
            if let payloadPoisonTotal {
                payload["payload_truncated_total"] = payloadPoisonTotal
            }
            if eventTypeCountSnapshot?.isComplete == true {
                // Backward-compatible alias only when the label is literally
                // true. Short-retention or gap-bearing counts remain available
                // under `event_type_counts` with their explicit window ledger.
                payload["event_type_counts_1h"] = eventTypeCounts
            }
            // The default production EventStore has an insert filter, but a
            // test/dev store may not. Omit absent counters instead of publishing
            // fabricated zeros; optional decoders preserve honest-unknown.
            if let eventInsertFilterCounters {
                payload["events_insert_filter_dropped_total"] = eventInsertFilterCounters.dropped
                payload["events_insert_filter_passed_total"] = eventInsertFilterCounters.passed
            }
            // Journal expiry is the ONLY thing that removes journal blocks, and
            // every exact read pays for each block that survives. Its scheduling
            // health was counted but never published, so a sweep that conserved
            // or failed every tick for hours was invisible while the read cost
            // it governs grew all day.
            payload["event_journal_expiry_pending_ticks_total"] =
                journalExpiryScheduling.pendingTicks
            payload["event_journal_expiry_failed_passes_total"] =
                journalExpiryScheduling.failedPasses
            payload["event_journal_expiry_lease_deferrals_total"] =
                journalExpiryScheduling.leaseDeferrals
            if let receiver = state.otlpReceiver {
                let lifecycle = await receiver.lifecycleSnapshot()
                var otlpLifecycle: [String: Any] = [
                    "accepting_listeners": lifecycle.acceptingListeners,
                    "listeners_accepted_total": lifecycle.listenersAccepted,
                    "listeners_completed_total": lifecycle.listenersCompleted,
                    "listeners_rejected_after_seal_total":
                        lifecycle.listenersRejectedAfterSeal,
                    "active_listeners": lifecycle.activeListeners,
                    "ready_listeners": lifecycle.readyListeners,
                    "listeners_conserved": lifecycle.listenersConserved,
                    "accepting_connections": lifecycle.acceptingConnections,
                    "connections_accepted_total": lifecycle.connectionsAccepted,
                    "connections_completed_total": lifecycle.connectionsCompleted,
                    "connections_rejected_after_seal_total":
                        lifecycle.connectionsRejectedAfterSeal,
                    "connections_rejected_at_capacity_total":
                        lifecycle.connectionsRejectedAtCapacity,
                    "active_connections": lifecycle.activeConnections,
                    "connections_conserved": lifecycle.connectionsConserved,
                    "accepting_body_tasks": lifecycle.acceptingBodyTasks,
                    "body_tasks_accepted_total": lifecycle.bodyTasksAccepted,
                    "body_tasks_completed_total": lifecycle.bodyTasksCompleted,
                    "body_tasks_cancelled_total": lifecycle.bodyTasksCancelled,
                    "body_tasks_rejected_total": lifecycle.bodyTasksRejected,
                    "body_task_cancellation_requests_total":
                        lifecycle.bodyTaskCancellationRequests,
                    "body_tasks_in_flight": lifecycle.bodyTasksInFlight,
                    "maximum_body_tasks": lifecycle.maximumBodyTasks,
                    "body_tasks_conserved": lifecycle.bodyTasksConserved,
                    "accepting_callback_tasks": lifecycle.acceptingCallbackTasks,
                    "callback_tasks_accepted_total": lifecycle.callbackTasksAccepted,
                    "callback_tasks_completed_total": lifecycle.callbackTasksCompleted,
                    "callback_tasks_cancelled_total": lifecycle.callbackTasksCancelled,
                    "callback_tasks_rejected_total": lifecycle.callbackTasksRejected,
                    "callback_task_cancellation_requests_total":
                        lifecycle.callbackTaskCancellationRequests,
                    "callback_tasks_in_flight": lifecycle.callbackTasksInFlight,
                    "maximum_callback_tasks": lifecycle.maximumCallbackTasks,
                    "callback_tasks_conserved": lifecycle.callbackTasksConserved,
                    "lifecycle_operations_in_progress":
                        lifecycle.lifecycleOperationsInProgress,
                    "shutdown_timeouts_total": lifecycle.shutdownTimeouts,
                    "cleanly_stopped": lifecycle.cleanlyStopped,
                ]
                if let lastShutdownClean = lifecycle.lastShutdownClean {
                    otlpLifecycle["last_shutdown_clean"] = lastShutdownClean
                }
                payload["otlp_receiver_lifecycle"] = otlpLifecycle
            }

            // Metrics export — Prometheus-textfile-style JSON at a world-
            // readable path. Counter-style semantics: scrapers compute
            // rates from deltas. Using /var/tmp (survives reboots, no
            // privilege boundary to cross) so external collectors can
            // read without special entitlements.
            // v1.7.9: include resident memory in MB so scrapers + the
            // dashboard's diagnostic surface can plot daemon RSS over
            // time. Field-driven addition after v1.7.6→v1.7.7→v1.7.9
            // memory leak iterations: we want continuous RSS visibility
            // so the next leak shape is caught before user reports
            // climb to 1+ GB. mach_task_basic_info reads our own RSS
            // without sudo or external tools.
            var taskInfo = mach_task_basic_info()
            var taskInfoCount = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info_data_t>.size / MemoryLayout<integer_t>.size)
            let kr = withUnsafeMutablePointer(to: &taskInfo) {
                $0.withMemoryRebound(to: integer_t.self, capacity: Int(taskInfoCount)) {
                    task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &taskInfoCount)
                }
            }
            let residentMB: Int = kr == KERN_SUCCESS ? Int(taskInfo.resident_size / 1_048_576) : -1

            let metricsPayload: [String: Any] = [
                "schema": 2,
                "written_at_unix": nowUnix,
                "uptime_seconds": uptime,
                "events_total": events,
                "alerts_total": alerts,
                "events_dropped_total": droppedTotal,
                "detection_input_dropped_total": detectionInputDroppedTotal,
                // v1.21.4 Phase-0 D1/D4 scalar counters (Prometheus-style; the
                // per-type maps live in heartbeat_rich.json only).
                "es_kernel_dropped_total": esGlobalDropped,
                "es_msg_e2e_latency_p99_us": esHandlerP99Micros, // v1.21.4: end-to-end (callback→worker-done incl. queue wait), NOT inline callback wall-time

                "es_stream_yield_dropped_total": esStreamYieldDropped,
                "es_copy_backpressure_dropped_total": esCopyBackpressureDropped,
                "es_client_split_degraded": esClientSplitDegraded,
                "events_per_sec_lifetime": uptime > 0 ? Double(events) / Double(uptime) : 0,
                "resident_memory_mb": residentMB,
                "sysext_has_fda": sysextHasFDA,
                "power_state": PowerGate.stateDescription,
            ]
            // v1.8.0 audit: autoreleasepool wrap. The Task scope drains on
            // completion, but inside a long-running per-tick body the
            // JSONSerialization temporaries persist across suspension points
            // (FileManager I/O is synchronous but the Foundation API
            // returns autoreleased Data). Match the livenessTimer pattern.
            autoreleasepool {
                if let metricsData = try? JSONSerialization.data(
                    withJSONObject: metricsPayload,
                    options: [.sortedKeys]
                ) {
                    let metricsPath = "/var/tmp/maccrab.metrics.json"
                    let metricsTmp = metricsPath + ".tmp"
                    do {
                        try metricsData.write(to: URL(fileURLWithPath: metricsTmp))
                        _ = try? FileManager.default.removeItem(atPath: metricsPath)
                        try FileManager.default.moveItem(atPath: metricsTmp, toPath: metricsPath)
                    } catch {
                        // Metrics writes are best-effort — no alert if /var/tmp
                        // is unreadable for some reason; next tick will retry.
                    }
                }
            }
            guard let data = autoreleasepool(invoking: { () -> Data? in
                try? JSONSerialization.data(
                    withJSONObject: payload,
                    options: [.prettyPrinted, .sortedKeys]
                )
            }) else { return }
            // v1.7.5: rich heartbeat goes to a SEPARATE file. Liveness
            // detection (heartbeat.json) is the synchronous fast path
            // above. This file carries the rich payload (per-event-
            // category counts, collector health, drop counter) for the
            // ES Health panel. If the rich payload stalls, the
            // dashboard's "engine alive" check still works.
            let path = state.supportDir + "/heartbeat_rich.json"
            // Write via temp + rename so the dashboard never catches a
            // half-written file. Silent on failure — the next 30s tick
            // will try again.
            let tmp = path + ".tmp"
            do {
                try data.write(to: URL(fileURLWithPath: tmp))
                try FileManager.default.moveItem(atPath: tmp, toPath: path)
            } catch {
                // File may already exist; retry as overwrite.
                try? FileManager.default.removeItem(atPath: path)
                try? FileManager.default.moveItem(atPath: tmp, toPath: path)
            }

            // Run independent snapshots concurrently, but join all four to the
            // timer handler. Their per-writer in-flight guards still prevent
            // overlap; terminal shutdown can now prove none remain after the
            // timer plane joins.
            let lineagePath = state.supportDir + "/agent_lineage.json"
            async let lineageWrite: Void = state.agentLineageService
                .writeSnapshot(to: lineagePath)

            let mcpBaselinePath = state.supportDir + "/mcp_baselines.json"
            async let baselineWrite: Void = state.mcpBaseline
                .writeSnapshot(to: mcpBaselinePath)

            let ruleTelemetryPath = state.supportDir + "/rule_telemetry.json"
            async let ruleWrite: Void = state.ruleEngine
                .writeTelemetrySnapshot(to: ruleTelemetryPath)

            let tccSnapshotPath = state.supportDir + "/tcc_snapshot.json"
            async let tccWrite: Void = state.tccMonitor
                .writeSnapshot(to: tccSnapshotPath)
            _ = await (lineageWrite, baselineWrite, ruleWrite, tccWrite)
            } // end lifecycle-tracked heartbeat body
        }
        heartbeatTimer.resume()

        // v1.10.0 audit fix: file-based IPC for dashboard → root sysext.
        // The dashboard runs as the logged-in user; the sysext owns
        // alerts.db / events.db / campaigns.db as root 0600. Mutations
        // (suppress, unsuppress, delete, flush) can't be issued directly
        // from the dashboard because:
        //   - direct DB write fails with SQLITE_READONLY
        //   - POSIX signals from user → root sysext return EPERM
        //   - /tmp doesn't share namespace between user and the sysext
        //     sandbox (first attempt in v1.10.0)
        // Solution: <supportDir>/inbox/ mode 1777 (world-write + sticky;
        // sticky prevents cross-user file deletion). The sysext (this
        // poller, running as root) drains the dir every 5 s.
        //
        // v1.10.1 extended the file types accepted beyond flush requests
        // — alert suppress/unsuppress/delete + campaign suppress all
        // route through this same channel.
        let inboxDir = state.supportDir + "/inbox"
        do {
            try FileManager.default.createDirectory(
                atPath: inboxDir, withIntermediateDirectories: true
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o1777], ofItemAtPath: inboxDir
            )
        } catch {
            print("[inbox] failed to ensure inbox dir at \(inboxDir): \(error.localizedDescription)")
        }

        let inboxScanner = InboxDirectoryScanner(path: inboxDir)
        let inboxPoller = DispatchSource.makeTimerSource(queue: .global())
        // 5 s tick: a directory listing of an empty dir is cheap, and
        // dashboard users expect a suppress click to settle quickly.
        // The original 30 s value was sized for flush requests only,
        // which are infrequent and slow to run anyway. Alert mutations
        // are interactive — keep them snappy.
        inboxPoller.schedule(deadline: .now() + 5, repeating: 5)
        inboxPoller.setEventHandler {
            timerLifecycle.submit(label: "inbox") {
                // v1.11.0 (audit stability HIGH): skip this tick if a
                // previous Task is still draining (campaign suppress
                // fan-out can take tens of seconds at 5-10K alerts).
                // Without the guard, parallel Tasks raced for the same
                // request files + doubled DB write load.
                let acquired: Bool = state.inboxPollerLock.withLock { inFlight in
                    if inFlight { return false }
                    inFlight = true
                    return true
                }
                guard acquired else { return }
                defer { state.inboxPollerLock.withLock { $0 = false } }

                // v1.21.5 (audit S-08): the inbox is mode 1777, so ANY local uid can
                // drop files into it — isAuthorizedInboxRequest rejects their
                // REQUESTS, but only after root has already paid for the directory
                // listing, the lstat and the unlink. Pre-fix this tick took the whole
                // directory unbounded, ran 17 prefix filters over it, then a per-file
                // lstat + unlink in each handler, all while holding
                // `inboxPollerLock` — so a flood of a few hundred thousand files
                // wedged the privileged control plane indefinitely (every dashboard
                // suppress / config / prevention action queues behind it) and burned
                // root CPU. Bound the per-tick window instead. Every file the
                // handlers touch is unlinked whether authorized or not, so the
                // backlog still drains; a flood now costs a bounded delay rather than
                // an unbounded stall. 512 is above any legitimate burst — the largest
                // is a dashboard bulk-suppress, one file per selected alert.
                // The retained POSIX scanner resumes at its prior directory
                // offset on the next tick. That makes the delay bounded by
                // ceil(N / 512) ticks even when the leading entries are recent
                // dot-prefixed atomic temp files that must not yet be deleted.
                let maxInboxDrainPerTick = 512
                let scan = inboxScanBatch(
                    scanner: inboxScanner,
                    inboxDir: inboxDir,
                    maxEntries: maxInboxDrainPerTick
                )
                let files = scan.requestNames
                guard !files.isEmpty else { return }

                // Partition by request type so we drain in a defined order
                // (mutations first, flush last — flush can take seconds).
                let suppressAlertReqs = files.filter { $0.hasPrefix("suppress-alert-") && $0.hasSuffix(".json") }
                let unsuppressAlertReqs = files.filter { $0.hasPrefix("unsuppress-alert-") && $0.hasSuffix(".json") }
                let deleteAlertReqs = files.filter { $0.hasPrefix("delete-alert-") && $0.hasSuffix(".json") }
                let suppressCampaignReqs = files.filter { $0.hasPrefix("suppress-campaign-") && $0.hasSuffix(".json") }
                let refreshIntelReqs = files.filter { $0.hasPrefix("refresh-intel-") && $0.hasSuffix(".json") }
                let reloadRulesReqs = files.filter { $0.hasPrefix("reload-rules-") && $0.hasSuffix(".json") }
                let llmConfigReqs = files.filter { $0.hasPrefix("llm-config-") && $0.hasSuffix(".json") }
                let flushRequests = files.filter { $0.hasPrefix("flush-request-") && $0.hasSuffix(".json") }
                // v1.18: ClickFix clipboard payloads recorded in USER context (the
                // menubar app can read the GUI pasteboard; the root sysext cannot)
                // and dropped here for the exec-correlation half to use.
                let recordClipboardReqs = files.filter { $0.hasPrefix("record-clipboard-") && $0.hasSuffix(".json") }
                // v1.18: per-built-in-rule enable/disable + severity override.
                let builtinRuleReqs = files.filter { $0.hasPrefix("builtin-rule-setting-") && $0.hasSuffix(".json") }
                // v1.18 agent control-plane (MCP skill): set a whitelisted
                // daemon_config key, install a compiled user rule, remove a
                // user rule. Same uid/symlink auth gate + audit as every verb.
                let setDaemonConfigReqs = files.filter { $0.hasPrefix("set-daemon-config-") && $0.hasSuffix(".json") }
                let installRuleReqs = files.filter { $0.hasPrefix("install-rule-") && $0.hasSuffix(".json") }
                let removeRuleReqs = files.filter { $0.hasPrefix("remove-rule-") && $0.hasSuffix(".json") }
                // Agent-control state changes. Root owns
                // mcp_capabilities.json, but ownership of a file in this 1777
                // inbox does not prove dashboard use or human presence. The
                // handler therefore permits non-root revokes only; grants
                // require a root-owned request.
                let agentCapReqs = files.filter { $0.hasPrefix("set-agent-capabilities-") && $0.hasSuffix(".json") }
                // v1.21.4 (audit): the dashboard's "Clear Now" retention button
                // and the Agent-Traces receiver toggle drop these — the app
                // (uid-501) can't write the root-owned alerts.db / config, so it
                // routes through the same authorized inbox IPC as delete-alert.
                let pruneAlertsReqs = files.filter { $0.hasPrefix("prune-alerts-") && $0.hasSuffix(".json") }
                let agentTracesReqs = files.filter { $0.hasPrefix("apply-agent-traces-") && $0.hasSuffix(".json") }
                let traceDashboardKeyReqs = files.filter { $0.hasPrefix("trace-dashboard-key-") && $0.hasSuffix(".json") }
                // v1.21.4: the Prevention tab's per-module enable/disable toggle.
                // The app (uid-501) can't mutate the root-owned prevention state
                // nor SIGHUP the sysext, so it routes through this same
                // authorized inbox IPC.
                let preventionConfigReqs = files.filter { $0.hasPrefix("prevention-config-") && $0.hasSuffix(".json") }

                await handleSuppressAlertRequests(suppressAlertReqs, inboxDir: inboxDir, state: state)
                await handleUnsuppressAlertRequests(unsuppressAlertReqs, inboxDir: inboxDir, state: state)
                await handleDeleteAlertRequests(deleteAlertReqs, inboxDir: inboxDir, state: state)
                await handleSuppressCampaignRequests(suppressCampaignReqs, inboxDir: inboxDir, state: state)
                await handleRefreshIntelRequests(refreshIntelReqs, inboxDir: inboxDir, state: state)
                await handleReloadRulesRequests(reloadRulesReqs, inboxDir: inboxDir, state: state)
                await handleLLMConfigRequests(llmConfigReqs, inboxDir: inboxDir, state: state)
                await handleRecordClipboardRequests(recordClipboardReqs, inboxDir: inboxDir, state: state)
                await handleBuiltinRuleSettingRequests(builtinRuleReqs, inboxDir: inboxDir, state: state)
                await handleSetDaemonConfigRequests(setDaemonConfigReqs, inboxDir: inboxDir, state: state)
                await handleInstallRuleRequests(installRuleReqs, inboxDir: inboxDir, state: state)
                await handleRemoveRuleRequests(removeRuleReqs, inboxDir: inboxDir, state: state)
                await handleSetAgentCapabilitiesRequests(agentCapReqs, inboxDir: inboxDir, state: state)
                await handleFlushRequests(flushRequests, inboxDir: inboxDir, state: state)
                await handlePruneAlertsRequests(pruneAlertsReqs, inboxDir: inboxDir, state: state)
                await handleApplyAgentTracesRequests(agentTracesReqs, inboxDir: inboxDir, state: state)
                await handleTraceDashboardKeyRequests(traceDashboardKeyReqs, inboxDir: inboxDir, state: state)
                await handlePreventionConfigRequests(preventionConfigReqs, inboxDir: inboxDir, state: state)
            }
        }
        inboxPoller.resume()

        // v1.21.4 Phase-2 (D3): coverage-canary watchdog. On a jittered ~5-15 min
        // interval, spawn a benign probe exec and verify it reaches both the ES
        // callback and events.db (see runCoverageCanary). Jitter (a fresh random
        // deadline re-armed on each fire, one-shot repeating: .never) so the
        // probe cadence isn't predictable and doesn't phase-lock with other
        // sweeps. First fire is already 5-15 min out, clear of the 60 s warm-up.
        let coverageCanaryTimer = DispatchSource.makeTimerSource(queue: .global())
        // One-shot (repeating: .never), re-armed to a fresh random deadline on
        // each fire — this is the jitter. `canaryJitterSeconds()` returns 5-15 min.
        coverageCanaryTimer.schedule(deadline: .now() + canaryJitterSeconds(), repeating: .never)
        coverageCanaryTimer.setEventHandler {
            // Re-arm for the next jittered fire immediately; the probe itself
            // runs off-timer in a Task (spawn NEVER happens in the ES callback).
            coverageCanaryTimer.schedule(deadline: .now() + canaryJitterSeconds(), repeating: .never)
            timerLifecycle.submit(label: "coverage-canary") {
                await runCoverageCanary(state: state)
            }
        }
        coverageCanaryTimer.resume()

        let retainedTimers: [DispatchSourceTimer?] = [
            forensicTimer,
            hourlyTimer,
            statsTimer,
            deferredEnrichmentTimer,
            alertsPruneTimer,
            alertsSizeCapTimer,
            campaignsPruneTimer,
            campaignsSizeCapTimer,
            sizeCapTimer,
            eventJournalExpiryTimer,
            sizeCapWatchdogTimer,
            alertsSizeCapWatchdogTimer,
            maintenanceTimer,
            heartbeatTimer,
            tracegraphPruneTimer,
            tracesPruneTimer,
            artifactsPruneTimer,
            inboxPoller,
            coverageCanaryTimer,
        ]
        for timer in retainedTimers.compactMap({ $0 }) {
            timerLifecycle.register(timer)
        }
        livenessLifecycle.register(livenessTimer)

        return Handles(
            lifecycle: timerLifecycle,
            livenessLifecycle: livenessLifecycle,
            forensicTimer: forensicTimer,
            hourlyTimer: hourlyTimer,
            statsTimer: statsTimer,
            deferredEnrichmentTimer: deferredEnrichmentTimer,
            alertsPruneTimer: alertsPruneTimer,
            alertsSizeCapTimer: alertsSizeCapTimer,
            campaignsPruneTimer: campaignsPruneTimer,
            campaignsSizeCapTimer: campaignsSizeCapTimer,
            sizeCapTimer: sizeCapTimer,
            eventJournalExpiryTimer: eventJournalExpiryTimer,
            sizeCapWatchdogTimer: sizeCapWatchdogTimer,
            maintenanceTimer: maintenanceTimer,
            heartbeatTimer: heartbeatTimer,
            livenessTimer: livenessTimer,
            tracegraphPruneTimer: tracegraphPruneTimer,
            tracesPruneTimer: tracesPruneTimer,
            artifactsPruneTimer: artifactsPruneTimer,
            inboxPoller: inboxPoller,
            coverageCanaryTimer: coverageCanaryTimer
        )
    }

    // MARK: - v1.21.4 Phase-1 D2 helpers

    /// ES event-type names (as re-keyed in the heartbeat's `esProcessedByType`)
    /// that make up the file write-family — the D2 flood numerator.
    static let esFileEventTypeNames: [String] = [
        "NOTIFY_CREATE", "NOTIFY_WRITE", "NOTIFY_CLOSE", "NOTIFY_RENAME", "NOTIFY_UNLINK",
    ]

    /// Process/exec event-type names — the channel a file flood can starve.
    static let esProcessEventTypeNames: [String] = [
        "NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT",
    ]

    /// Known-benign high-I/O signing identifiers. When the dominant recent
    /// file writer matches one of these, a sensor-degraded episode is
    /// downgraded HIGH → LOW (still emitted). Matched as a substring of the
    /// process's `signingId` so bundle-id variants (e.g. `com.apple.mdworker`,
    /// `com.apple.mdworker_shared`) are covered.
    static let benignHighIOSignerIDs: [String] = [
        "com.apple.backupd",        // Time Machine
        "com.apple.mdworker",       // Spotlight indexing
        "com.apple.mds",            // Spotlight metadata server
        "com.apple.Spotlight",
        "com.apple.dt.Xcode",       // Xcode builds
        "com.apple.CloudDocs",      // iCloud Drive sync
        "com.apple.bird",           // CloudKit / iCloud daemon
        "com.maccrab",              // MacCrab's own copies (belt-and-braces vs Mitigation A)
    ]

    /// Best-effort: is the dominant writer across the most recent file events a
    /// known-benign high-I/O signer? Bounded (≤200 rows), off the hot path.
    /// Returns false on any query error or when no signer dominates — the
    /// safe default is "not benign" (keeps the alert at HIGH).
    static func dominantFileWriterIsBenign(state: DaemonState) async -> Bool {
        let recent = try? await state.eventStore.exactEventsPageSnapshot(
            before: nil, category: .file, pageSize: 200
        )
        guard let items = recent?.items, !items.isEmpty else { return false }
        var counts: [String: Int] = [:]
        for event in items {
            let signer = event.process.codeSignature?.signingId ?? "(unsigned)"
            counts[signer, default: 0] += 1
        }
        guard let (topSigner, topCount) = counts.max(by: { $0.value < $1.value }) else { return false }
        // Require a clear majority so a benign signer that merely appears
        // alongside the real flood-writer doesn't downgrade the alert.
        guard Double(topCount) >= Double(items.count) * 0.5 else { return false }
        let result = benignHighIOSignerIDs.contains {
            topSigner.contains($0)
        }
        withExtendedLifetime(recent) {}
        return result
    }

    // MARK: - v1.21.4 Phase-2 (D3) coverage-canary watchdog

    /// Jittered probe interval bounds (seconds): 5-15 min, like the sweep timers.
    static let canaryMinIntervalSeconds: Double = 300
    static let canaryMaxIntervalSeconds: Double = 900

    /// A fresh random interval in [min, max]. The unpredictable cadence keeps the
    /// probe from phase-locking with other sweeps and from being trivially timed
    /// around by an adversary. First fire is already ≥5 min out, clear of warm-up.
    static func canaryJitterSeconds() -> Double {
        Double.random(in: canaryMinIntervalSeconds...canaryMaxIntervalSeconds)
    }

    /// Seconds to wait after the probe spawn before checking coverage — long
    /// enough for the ES callback to latch and the async DB insert to flush.
    static let canarySettleSeconds: UInt64 = 20
    /// Extra DB re-checks (spaced by canaryDBRecheckSeconds) before concluding a
    /// store/eviction gap — tolerates insert-batch latency without crying wolf.
    static let canaryDBRecheckAttempts = 3
    static let canaryDBRecheckSeconds: UInt64 = 5

    /// One coverage-canary cycle: spawn a benign probe exec, then verify it
    /// reached BOTH the ES callback and events.db, and on a gap emit a
    /// stage-naming health alert via AlertSink (advisory — nothing auto-acts).
    ///
    /// Safety invariants (see CoverageCanary): the probe is `/usr/bin/true` +
    /// a neutral marker, so it trips no rule and no self-defense check; the
    /// exec is suppressed in NoiseFilter as belt-and-braces; and the spawn
    /// happens HERE (the timer task), never in the ES callback.
    static func runCoverageCanary(state: DaemonState) async {
        // No ES client (dev non-root fallback) ⇒ nothing to probe.
        guard let collector = state.collector else { return }

        let nonce = CoverageCanary.makeNonce()
        collector.armCanaryNonce(nonce)
        defer { collector.disarmCanaryNonce(nonce) }

        let spawnedAt = Date()
        guard spawnCanaryProbe(nonce: nonce) else {
            // A failed spawn is a local error, not a coverage gap — don't alert.
            print("[D3] coverage-canary spawn failed")
            return
        }

        // Point 1: settle, then read the callback sighting.
        try? await Task.sleep(nanoseconds: canarySettleSeconds * 1_000_000_000)
        let seenAtCallback = collector.canarySeenAtCallback(nonce)

        // Point 2: look for the exec in events.db (command line carries the
        // nonce). Re-check a few times so a slow insert batch isn't misread as
        // an eviction gap. Window starts slightly before the spawn.
        let since = spawnedAt.addingTimeInterval(-30)
        var storePresence = await canaryPresentInDB(
            state: state,
            nonce: nonce,
            since: since
        )
        var attempt = 0
        while storePresence != .present && attempt < canaryDBRecheckAttempts {
            try? await Task.sleep(nanoseconds: canaryDBRecheckSeconds * 1_000_000_000)
            storePresence = await canaryPresentInDB(
                state: state,
                nonce: nonce,
                since: since
            )
            attempt += 1
        }

        // Third point: was this probe's retained message refused at the
        // callback→worker hand-off? Read PER-NONCE, not from a
        // `es_copy_backpressure_dropped_total` delta — that counter sums BOTH
        // per-client workers, so on a host whose file worker is saturated it
        // advances during essentially every probe and would misattribute real
        // eviction gaps in the opposite direction.
        let droppedAtHandoff = collector.canaryDroppedAtHandoff(nonce)
        let verdict = CoverageCanaryEvaluator.verdict(
            seenAtCallback: seenAtCallback,
            storePresence: storePresence,
            droppedAtHandoff: droppedAtHandoff
        )
        guard verdict != .healthy, let stage = verdict.stageLabel else { return }

        // A kernel/ingest gap and a hand-off drop are both ACTIVE telemetry loss
        // (the event reached us and we lost it before evaluation); an eviction
        // gap is retention pressure — surface all three, weighted accordingly.
        let severity: Severity = (verdict == .evictionGap) ? .medium : .high
        let stageDetail: String
        switch verdict {
        case .kernelGap:
            stageDetail = "never reached the ES callback — the kernel/ingest path dropped it (per-client-queue backpressure; the same blind-spot a file-write flood exploits). "
        case .ingestHandoffGap:
            stageDetail = "reached the ES callback, but its retained message was refused at the callback→worker hand-off because the per-client ESMessageWorker was at its in-flight cap (see es_copy_backpressure_dropped_total) — so it never reached the rule engine, the sequence engine, or events.db. "
        case .evictionGap:
            stageDetail = "was seen at the ES callback but is absent from events.db — the store/eviction path lost it (retention sweep or insert gap). "
        case .storeQueryUnknown:
            stageDetail = "was seen at the ES callback, but the retained-window or sparse-projection coverage ledger cannot prove whether the empty store query means absence — storage/query coverage is incomplete. "
        case .healthy:
            stageDetail = ""
        }
        let description =
            "Coverage canary lost at the \(stage) stage: a self-generated probe exec "
            + stageDetail
            + "MacCrab's own telemetry coverage is degraded; verify what is generating load or storage pressure."

        let alert = Alert(
            // Synthetic self-defense ruleId (same convention as the D2
            // sensor-degraded meta-alert). NOT a Rules/ entry.
            ruleId: "maccrab.self-defense.coverage_gap",
            ruleTitle: "Coverage Gap: telemetry canary lost at \(stage)",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: CoverageCanary.spawnBinaryPath,
            processName: "maccrabd",
            description: description,
            mitreTactics: "attack.defense_evasion",
            mitreTechniques: "attack.t1562.001",
            suppressed: false
        )
        // Route via AlertSink so it inherits dedup/suppression (backstops the
        // per-cycle cadence if a gap persists across several probes).
        _ = try? await state.alertSink.submit(alert: alert)
    }

    /// Store-side half of the two-point check: is an event carrying `nonce`
    /// present in events.db? Uses the FTS/command-line search the hunt tool
    /// uses. An empty sparse result proves absence only when its retained-window,
    /// projection, and poison ledgers are complete. Errors and incomplete empty
    /// snapshots stay explicitly unknown instead of masquerading as eviction.
    static func canaryPresentInDB(
        state: DaemonState,
        nonce: String,
        since: Date
    ) async -> CoverageCanaryEvaluator.StorePresence {
        do {
            let snapshot = try await state.eventStore.searchSnapshot(
                text: nonce,
                since: since,
                until: Date(),
                limit: 1
            )
            if !snapshot.events.isEmpty { return .present }
            return snapshot.isComplete ? .absent : .coverageUnknown
        } catch {
            return .coverageUnknown
        }
    }

    /// posix_spawn the benign probe as `/usr/bin/env /usr/bin/true <nonce>`,
    /// detached, with a minimal environment. The `env` layer is the muteSelf
    /// work-around (see CoverageCanary): it makes the OBSERVED `/usr/bin/true`
    /// exec be initiated by `env` (unmuted) rather than the daemon (muted).
    /// Reaps the child so it can't linger as a zombie. Returns whether the
    /// spawn itself succeeded.
    static func spawnCanaryProbe(nonce: String) -> Bool {
        let spawnPath = CoverageCanary.intermediaryBinaryPath   // /usr/bin/env
        guard let cEnv = strdup(spawnPath),
              let cTrue = strdup(CoverageCanary.spawnBinaryPath),   // /usr/bin/true
              let cNonce = strdup(nonce) else { return false }
        defer { free(cEnv); free(cTrue); free(cNonce) }
        var pid: pid_t = 0
        // env <true> <nonce> → env execs /usr/bin/true with argv[1] = nonce.
        let argv: [UnsafeMutablePointer<CChar>?] = [cEnv, cTrue, cNonce, nil]
        // Empty environment — the probe needs nothing and this avoids leaking
        // the daemon's env (API keys etc.) into a child exec.
        let envp: [UnsafeMutablePointer<CChar>?] = [nil]
        let rc = argv.withUnsafeBufferPointer { aBuf in
            envp.withUnsafeBufferPointer { eBuf in
                posix_spawn(&pid, spawnPath, nil, nil,
                            UnsafeMutablePointer(mutating: aBuf.baseAddress!),
                            UnsafeMutablePointer(mutating: eBuf.baseAddress!))
            }
        }
        guard rc == 0 else { return false }
        // Best-effort reap — the probe exits immediately. ECHILD (SIGCHLD
        // auto-reaped elsewhere) is fine; we only need to avoid a zombie.
        var status: Int32 = 0
        _ = waitpid(pid, &status, 0)
        return true
    }

    // MARK: - Inbox request handlers (v1.10.1)
    //
    // Each request file is a JSON object with a single `id` field,
    // optionally accompanied by `reason` for audit-log context. The
    // handler reads it, applies the mutation through the appropriate
    // store, then removes the file (always — leaving it would
    // re-trigger on the next 5 s tick). Failures are logged but
    // don't block subsequent requests in the same tick.

    private static func handleFlushRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        // Authorization gate (parity with every other inbox verb). The inbox dir
        // is mode 1777 — any local user can drop a file — and a flush DELETES the
        // oldest events (anti-forensics value to an attacker erasing early-
        // intrusion telemetry). Flush carries no id and is a single global sweep,
        // so we run it iff at least one request is from an authorized uid (root or
        // the GUI console user); symlink/hardlink-forged files resolve to uid -1
        // and are rejected. Every request is audit-logged; all files are removed.
        var anyAuthorized = false
        for name in names {
            let path = inboxDir + "/" + name
            let uid = requestOwnerUID(at: path)
            if isAuthorizedInboxRequest(uid: uid) {
                anyAuthorized = true
                auditLogInbox(state: state, prefix: "flush", id: name, uid: uid, result: "ok")
            } else {
                print("[inbox] flush \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "flush", id: name, uid: uid, result: "rejected_uid")
            }
            removeInboxEntry(at: path)
        }
        guard anyAuthorized else {
            print("[inbox] flush: no authorized request — sweep skipped")
            return
        }
        print("[inbox] flush: running enforceDatabaseSizeCapNow")
        let beforeBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
        let started = Date()
        let didRun = await enforceDatabaseSizeCapNow(state: state)
        if didRun {
            let afterBytes = StorageFlushStatus.fileSize(at: state.supportDir + "/events.db")
            let status = StorageFlushStatus(
                inProgress: false, lastRunAt: started,
                bytesBefore: beforeBytes, bytesAfter: afterBytes, note: nil
            )
            StorageFlushStatus.write(status, to: state.supportDir)
            print("[inbox] flush sweep done: \(beforeBytes / 1_000_000) MB → \(afterBytes / 1_000_000) MB")
        } else {
            print("[inbox] flush sweep skipped — another already in progress")
        }
    }

    /// v1.18: ClickFix clipboard payloads from the user-context app. The root
    /// sysext cannot read the GUI pasteboard (no Aqua session), so the menubar
    /// app records delivery-shaped clipboard text (curl|bash, etc.) and drops it
    /// here; we feed it into the shared ClickFixDetector whose exec-correlation
    /// half runs in the event loop. Same uid/symlink auth gate as every verb.
    private static func handleRecordClipboardRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)   // lstat — rejects symlink/hardlink forgery
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] record-clipboard REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "record-clipboard", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            // v1.21.4 review fix (M1): clipboard content is bounded DOWNSTREAM by
            // GRAPHEME count (prefix(8192)), not bytes — one extended grapheme
            // cluster (combining marks / Zalgo) is unbounded in UTF-8 bytes, so
            // 8192 legit graphemes can exceed the 64 KB default cap. A ClickFix
            // page could pad the clipboard past 64 KB to make the daemon reject
            // the record and blind `maccrab.clickfix.paste-and-run`. This reader
            // authorizes by owner-uid FIRST (console-user/root), so a larger read
            // cap carries no new OOM exposure a privileged user couldn't already
            // cause; 4 MB comfortably covers 8192 graphemes of any realistic
            // clipboard while staying bounded.
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let payload = json["payload"] as? String, !payload.isEmpty else {
                print("[inbox] record-clipboard \(name): malformed payload")
                continue
            }
            // Cap so a giant clipboard can't bloat the detector buffer.
            let capped = String(payload.prefix(8192))
            if let clickFix = state.clickFix {
                let recorded = await clickFix.recordClipboard(capped, at: Date())
                auditLogInbox(state: state, prefix: "record-clipboard", id: "-", uid: uid,
                              result: recorded ? "recorded" : "filtered_by_shape")
            } else {
                auditLogInbox(state: state, prefix: "record-clipboard", id: "-", uid: uid, result: "clickfix_disabled")
            }
        }
    }

    /// v1.18: per-built-in-rule operator overrides (enable/disable + severity)
    /// written by the user-context app. The root daemon owns the support dir, so
    /// it (not the unprivileged app) writes `builtin_rules_settings.json`, which
    /// AlertSink reads at the submit chokepoint. Same auth gate as every verb.
    private static func handleBuiltinRuleSettingRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] builtin-rule-setting REJECTED uid=\(uid)")
                auditLogInbox(state: state, prefix: "builtin-rule-setting", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let ruleId = json["ruleId"] as? String, ruleId.hasPrefix("maccrab.") else {
                print("[inbox] builtin-rule-setting \(name): malformed")
                continue
            }
            var settings = BuiltinRuleSettings.load(fromDir: state.supportDir)
            var entry = settings.rules[ruleId] ?? BuiltinRuleSetting()
            if let enabled = json["enabled"] as? Bool { entry.enabled = enabled }
            if json.keys.contains("severityOverride") {
                if let raw = json["severityOverride"] as? String, let sev = Severity(rawValue: raw) {
                    entry.severityOverride = sev
                } else {
                    entry.severityOverride = nil   // explicit null = clear to default
                }
            }
            settings.rules[ruleId] = entry
            do {
                try settings.save(toDir: state.supportDir)
                auditLogInbox(state: state, prefix: "builtin-rule-setting", id: sanitizeAuditField(ruleId), uid: uid,
                              result: "enabled=\(entry.enabled) sev=\(entry.severityOverride?.rawValue ?? "default")")
            } catch {
                print("[inbox] builtin-rule-setting \(ruleId) save failed: \(error)")
            }
        }
    }

    // v1.18 agent control-plane: whitelisted daemon_config keys settable from
    // the MCP skill. Re-stated here (NOT trusting the MCP) so the daemon is the
    // authority. Safe tunables vs defense-affecting kill-switches — the MCP
    // gates the latter behind the higher 'response' tier; the daemon enforces
    // type + membership regardless.
    private static let agentSettableConfigKeys: [String: String] = [
        "behavior_alert_threshold": "double", "behavior_critical_threshold": "double",
        "statistical_z_threshold": "double", "statistical_min_samples": "int",
        "usb_poll_interval": "double", "clipboard_poll_interval": "double",
        "browser_extension_poll_interval": "double", "rootkit_poll_interval": "double",
        "event_tap_poll_interval": "double", "system_policy_poll_interval": "double",
        "prompt_injection_confidence": "int", "intent_posterior_threshold": "double",
        "subscribe_file_open_events": "bool", "subscribe_introspection_events": "bool",
        "ultrasonic_enabled": "bool",
        // v1.21.6 (audit DOC-11): the four network-enrichment switches, accepted
        // ONLY as `false` — see agentDisableOnlyConfigKeys below.
        "threat_intel_enabled": "bool", "vuln_scan_enabled": "bool",
        "package_freshness_enabled": "bool", "cert_transparency_enabled": "bool",
    ]

    /// Keys this plane accepts in the privacy-increasing direction only.
    ///
    /// The inbox authorizes on file-owner uid alone, so anything running as the
    /// console user can drive every verb here. Setting a network-enrichment
    /// switch to `false` only ever REDUCES egress — harmless for an attacker to
    /// call, and the thing PRIVACY.md needs a non-root user to be able to do.
    /// Setting one to `true` would ENABLE egress (cert-transparency publishes
    /// every domain the host resolves; osv.dev publishes the installed software
    /// inventory), which is a capability that must not be reachable from a
    /// uid-only plane. A `true` is refused and audited, not silently dropped.
    private static let agentDisableOnlyConfigKeys: Set<String> = [
        "threat_intel_enabled", "vuln_scan_enabled",
        "package_freshness_enabled", "cert_transparency_enabled",
    ]

    /// v1.19.1 (audit): detection-preserving safe ranges for agent-settable
    /// NUMERIC config. Without clamping, an agent (or any console user via the
    /// inbox) could set a threshold to a value that effectively DISABLES a tier
    /// — the live audit caught `statistical_z_threshold` pushed to 99 (anomaly
    /// tier off) with only an audit line, no alert. Requested values outside the
    /// range are CLAMPED to the nearest bound AND raise a self-protection alert.
    private static let agentConfigSafeRange: [String: (min: Double, max: Double)] = [
        "behavior_alert_threshold":        (1, 50),
        "behavior_critical_threshold":     (1, 100),
        "statistical_z_threshold":         (1.0, 6.0),
        "statistical_min_samples":         (10, 1000),
        "prompt_injection_confidence":     (1, 95),
        "intent_posterior_threshold":      (0.5, 0.99),
        "usb_poll_interval":               (1, 300),
        "clipboard_poll_interval":         (1, 60),
        "browser_extension_poll_interval": (5, 600),
        "rootkit_poll_interval":           (10, 600),
        "event_tap_poll_interval":         (1, 300),
        "system_policy_poll_interval":     (10, 1800),
    ]

    private static func handleSetDaemonConfigRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "set-daemon-config", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let key = json["key"] as? String,
                  let kind = agentSettableConfigKeys[key] else {
                auditLogInbox(state: state, prefix: "set-daemon-config", id: "-", uid: uid, result: "rejected_key")
                continue
            }
            // Coerce + validate the value to the declared kind; reject mismatches.
            var value: Any
            switch kind {
            case "bool":
                guard let b = json["value"] as? Bool else {
                    auditLogInbox(state: state, prefix: "set-daemon-config", id: sanitizeAuditField(key), uid: uid, result: "rejected_type")
                    continue
                }
                value = b
            case "int":
                guard let i = json["value"] as? Int else {
                    auditLogInbox(state: state, prefix: "set-daemon-config", id: sanitizeAuditField(key), uid: uid, result: "rejected_type")
                    continue
                }
                value = i
            default:
                if let d = json["value"] as? Double { value = d }
                else if let i = json["value"] as? Int { value = Double(i) }
                else {
                    auditLogInbox(state: state, prefix: "set-daemon-config", id: sanitizeAuditField(key), uid: uid, result: "rejected_type")
                    continue
                }
            }
            // Disable-only keys: a `true` here would turn outbound network
            // enrichment ON from a plane that authorizes on uid alone. Refuse and
            // audit it — the operator path is the dashboard or the root config.
            if agentDisableOnlyConfigKeys.contains(key), (value as? Bool) == true {
                auditLogInbox(state: state, prefix: "set-daemon-config",
                              id: sanitizeAuditField(key), uid: uid,
                              result: "rejected_enable_egress")
                await emitSelfProtectionAlert(
                    state: state, action: "Network egress enable refused",
                    detail: "An inbox request tried to set '\(key)' to true, which would enable outbound network calls. The privileged inbox authorizes on uid alone, so it accepts these switches in the disable direction only; the request was refused.")
                continue
            }
            // v1.19.1 (audit): clamp numeric thresholds to a detection-preserving
            // range so an agent / console user can't disable a tier (e.g. the
            // live-caught statistical_z_threshold=99). A clamp means the request
            // tried to weaken detection past the safe bound — make it LOUD.
            if let range = agentConfigSafeRange[key] {
                let requested = (value as? Double) ?? Double(value as? Int ?? 0)
                let clamped = Swift.min(Swift.max(requested, range.min), range.max)
                if clamped != requested {
                    value = (kind == "int") ? (Int(clamped.rounded()) as Any) : (clamped as Any)
                    auditLogInbox(state: state, prefix: "set-daemon-config",
                                  id: sanitizeAuditField(key), uid: uid,
                                  result: "clamped \(requested)->\(clamped)")
                    await emitSelfProtectionAlert(
                        state: state, action: "Detection threshold clamped",
                        detail: "Config '\(key)' was requested as \(requested), outside the detection-preserving range [\(range.min), \(range.max)] — clamped to \(clamped). A value past this bound weakens or disables a detection tier.")
                }
            }
            // Merge into daemon_config.json (root-owned). Effect on next config
            // reload / restart — these keys are read at startup.
            let cfgPath = state.supportDir + "/daemon_config.json"
            var cfg: [String: Any] = (try? Data(contentsOf: URL(fileURLWithPath: cfgPath)))
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            cfg[key] = value
            do {
                let out = try JSONSerialization.data(withJSONObject: cfg, options: [.prettyPrinted, .sortedKeys])
                let tmp = cfgPath + ".tmp"
                try out.write(to: URL(fileURLWithPath: tmp))
                _ = try? fm.removeItem(atPath: cfgPath)
                try fm.moveItem(atPath: tmp, toPath: cfgPath)
                try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: cfgPath)
                auditLogInbox(state: state, prefix: "set-daemon-config",
                              id: sanitizeAuditField(key), uid: uid, result: "set=\(value)")
                // Self-protection: disabling an ES event subscription blinds a
                // class of kernel telemetry — rare-legitimate, high-impact.
                if (key == "subscribe_file_open_events" || key == "subscribe_introspection_events"),
                   (value as? Bool) == false {
                    await emitSelfProtectionAlert(
                        state: state, action: "Endpoint Security subscription disabled",
                        detail: "ES event subscription '\(key)' was set to false (disables a class of kernel telemetry on the next daemon restart)")
                }
                // Apply the egress switches LIVE rather than on the next reload.
                // Every other key here is a threshold whose next read is soon
                // enough, but these are the ones a user reaches for when they
                // want the network calls to stop NOW — deferring that to a
                // restart would make `config set … false` look like it worked
                // while enrichment kept talking. Mirrors the SIGHUP path.
                if agentDisableOnlyConfigKeys.contains(key), (value as? Bool) == false {
                    switch key {
                    case "vuln_scan_enabled":         state.vulnScanEnabled = false
                    case "package_freshness_enabled": state.packageFreshnessEnabled = false
                    case "cert_transparency_enabled": state.certTransparencyEnabled = false
                    case "threat_intel_enabled":
                        // The feed runs its own network loop; flipping the flag
                        // alone would not stop it.
                        state.threatIntelEnabled = false
                        await state.threatIntel.setNetworkRefresh(false)
                    default: break
                    }
                    print("[inbox] \(key)=false applied live (egress stopped)")
                }
            } catch {
                print("[inbox] set-daemon-config \(key) write failed: \(error)")
            }
        }
    }

    /// v1.18 security hardening (self-protection): record an alert when an
    /// inbox request makes a high-impact change to MacCrab's OWN detection
    /// posture — granting an MCP capability tier, disabling an ES event
    /// subscription, or enabling a remote LLM endpoint. Capability grants now
    /// require a root-owned request; other permitted changes may still be
    /// driven by an authorized console-admin process, so make every accepted
    /// high-impact transition loud.
    /// Routed through AlertSink (recorded, dashboard/CLI/MCP-visible, with the
    /// same dedup/evidence/counter/gating semantics); NOT OS-notified, to avoid spamming
    /// the operator on their own legitimate changes. Observe-only — the verb
    /// itself already executed; this never blocks it.
    private static func emitSelfProtectionAlert(state: DaemonState, action: String, detail: String) async {
        let alert = Alert(
            ruleId: "maccrab.self-defense.config_modified",
            ruleTitle: "MacCrab Self-Protection: \(action)",
            severity: .high,
            eventId: UUID().uuidString,
            processPath: nil,
            processName: "maccrabd",
            description: "\(detail) via the privileged inbox. If you did not authorize this change, a local process may be weakening MacCrab — investigate.",
            mitreTactics: "attack.defense_evasion",
            mitreTechniques: "attack.t1562.001",
            suppressed: false
        )
        do { _ = try await state.alertSink.submit(alert: alert) }
        catch { print("[self-protection] failed to record '\(action)' alert: \(error)") }
    }

    /// Decision returned by the capability-inbox policy gate. Keeping the
    /// rejected case separate from the candidate grants makes the all-or-nothing
    /// rule explicit: callers must not write any subset of a rejected request.
    enum AgentCapabilityRequestDecision: Equatable {
        case apply(grants: [String: Bool], newlyGranted: [String])
        case rejectNonRootGrant(attempted: [String])
    }

    /// Evaluate a request that already passed the generic inbox owner gate.
    ///
    /// The inbox is mode 1777 and a console-admin process has no authenticated
    /// user-presence signal: malware running as that same uid can write the same
    /// request as the app. Until an authenticated authorization channel exists,
    /// only an lstat-verified root-owned request may create a false -> true
    /// capability grant. An authorized non-root owner may preserve an existing
    /// true value or revoke it, but a mixed revoke+grant request is rejected as a
    /// whole. Payload fields such as `requester` are deliberately ignored; the
    /// caller must pass the request file's owner uid, never a claimed identity.
    static func evaluateAgentCapabilityRequest(
        fileOwnerUID: Int,
        payload: [String: Any],
        previousGrants: [String: Bool]
    ) -> AgentCapabilityRequestDecision {
        let names = ["config", "authoring", "response"]
        let grants = Dictionary(uniqueKeysWithValues: names.map {
            ($0, (payload[$0] as? Bool) ?? false)
        })
        let newlyGranted = names.filter {
            (grants[$0] ?? false) && !(previousGrants[$0] ?? false)
        }

        guard fileOwnerUID == 0 || newlyGranted.isEmpty else {
            return .rejectNonRootGrant(attempted: newlyGranted)
        }
        return .apply(grants: grants, newlyGranted: newlyGranted)
    }

    /// Write agent-control capability state to root-owned
    /// mcp_capabilities.json. This is the only writer of that file. Requests
    /// arrive through a 1777 inbox, so the standard console-admin owner gate is
    /// necessary but is not authorization to GRANT a capability; the policy
    /// above restricts false -> true transitions to root-owned requests.
    private static func handleSetAgentCapabilitiesRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "set-agent-capabilities", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                auditLogInbox(state: state, prefix: "set-agent-capabilities", id: "-", uid: uid, result: "rejected_malformed")
                continue
            }
            let capPath = state.supportDir + "/mcp_capabilities.json"
            let prevGrants: [String: Bool] = (try? Data(contentsOf: URL(fileURLWithPath: capPath)))
                .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Bool] } ?? [:]
            let decision = evaluateAgentCapabilityRequest(
                fileOwnerUID: uid, payload: json, previousGrants: prevGrants
            )
            guard case let .apply(grants, newlyGranted) = decision else {
                if case let .rejectNonRootGrant(attempted) = decision {
                    auditLogInbox(
                        state: state,
                        prefix: "set-agent-capabilities",
                        id: "-",
                        uid: uid,
                        result: "rejected_grant_requires_root:\(attempted.joined(separator: ","))"
                    )
                }
                continue
            }
            do {
                let out = try JSONSerialization.data(withJSONObject: grants, options: [.prettyPrinted, .sortedKeys])
                let tmp = capPath + ".tmp"
                try out.write(to: URL(fileURLWithPath: tmp))
                _ = try? fm.removeItem(atPath: capPath)
                try fm.moveItem(atPath: tmp, toPath: capPath)
                // 0644 root-owned (the daemon runs as root): world-readable so the
                // uid-501 MCP can READ it, but only root can write it.
                try? fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: capPath)
                auditLogInbox(state: state, prefix: "set-agent-capabilities", id: "-", uid: uid,
                              result: "config=\(grants["config"]!) authoring=\(grants["authoring"]!) response=\(grants["response"]!)")
                // Only root reaches this branch with a NEW grant. Keep the
                // self-protection breadcrumb even though the grant is allowed.
                if !newlyGranted.isEmpty {
                    await emitSelfProtectionAlert(
                        state: state, action: "MCP agent capability granted",
                        detail: "MCP agent capability tier(s) [\(newlyGranted.joined(separator: ", "))] were GRANTED")
                }
            } catch {
                print("[inbox] set-agent-capabilities write failed: \(error)")
            }
        }
    }

    /// Sanitize an agent-supplied rule id to a safe user_rules basename:
    /// lowercased, only [a-z0-9-_], no path traversal. Returns nil if empty.
    private static func safeRuleBasename(_ raw: String) -> String? {
        let allowed = Set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        let s = String(raw.lowercased().filter { allowed.contains($0) })
        guard !s.isEmpty, s.count <= 128 else { return nil }
        return s
    }

    private static func handleInstallRuleRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "install-rule", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rawId = json["ruleId"] as? String, let ruleId = safeRuleBasename(rawId),
                  let jsonText = json["json"] as? String,
                  jsonText.utf8.count <= 256 * 1024,
                  ((json["yaml"] as? String) ?? "").utf8.count <= 64 * 1024 else {
                auditLogInbox(state: state, prefix: "install-rule", id: "-", uid: uid, result: "rejected_malformed")
                continue
            }
            // yaml optional: rule INSTALLS carry source yaml (write both .yml +
            // .json), but a built-in DISABLE/severity OVERRIDE is json-only.
            let yaml = (json["yaml"] as? String) ?? ""
            let userRulesDir = state.supportDir + "/user_rules"
            do {
                try fm.createDirectory(atPath: userRulesDir, withIntermediateDirectories: true)
                // v1.18: enforce secure perms (0755, daemon-owned). The engine's
                // secure-dir gate (DaemonSetup.isSecureDirectory) REFUSES a
                // group/world-writable rules dir, so a legacy app-created
                // root:admin 0775 dir meant "rule installed but never loads".
                // Routing installs through this root handler + clamping the dir to
                // 0755 makes the gate accept it — and migrates any legacy 0775 dir
                // in place on the next install.
                try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: userRulesDir)
                if !yaml.isEmpty {
                    try yaml.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/\(ruleId).yml"))
                }
                try jsonText.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/\(ruleId).json"))
                let tick = "\(Date().timeIntervalSince1970)\n"
                try? tick.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/.reload_tick"))
                auditLogInbox(state: state, prefix: "install-rule", id: sanitizeAuditField(ruleId), uid: uid, result: "installed")
            } catch {
                print("[inbox] install-rule \(ruleId) failed: \(error)")
                auditLogInbox(state: state, prefix: "install-rule", id: sanitizeAuditField(ruleId), uid: uid, result: "error")
            }
        }
    }

    private static func handleRemoveRuleRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "remove-rule", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rawId = json["ruleId"] as? String, let ruleId = safeRuleBasename(rawId) else {
                auditLogInbox(state: state, prefix: "remove-rule", id: "-", uid: uid, result: "rejected_malformed")
                continue
            }
            let userRulesDir = state.supportDir + "/user_rules"
            _ = try? fm.removeItem(atPath: userRulesDir + "/\(ruleId).yml")
            _ = try? fm.removeItem(atPath: userRulesDir + "/\(ruleId).json")
            let tick = "\(Date().timeIntervalSince1970)\n"
            try? tick.data(using: .utf8)?.write(to: URL(fileURLWithPath: userRulesDir + "/.reload_tick"))
            auditLogInbox(state: state, prefix: "remove-rule", id: sanitizeAuditField(ruleId), uid: uid, result: "removed")
        }
    }

    private static func handleSuppressAlertRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            // v1.21.4 (audit HIGH, local-DoS): authorize BEFORE reading the
            // payload. The inbox is mode 1777, so any local user can plant a
            // FIFO or multi-GB file named suppress-alert-*.json; reading it first
            // would block the poller forever (FIFO) or OOM the daemon (huge
            // file). requestOwnerUID lstat()s without opening the file, so an
            // unauthorized request is rejected + removed (via defer) WITHOUT its
            // bytes ever being read.
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] suppress-alert \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "suppress-alert", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] suppress-alert \(name): malformed payload (expected {\"id\":\"…\"})")
                continue
            }
            do {
                try await state.alertStore.suppress(alertId: id)
                print("[inbox] suppress-alert id=\(id) uid=\(uid) ok")
                auditLogInbox(state: state, prefix: "suppress-alert", id: id, uid: uid, result: "ok")
            } catch {
                print("[inbox] suppress-alert id=\(id) uid=\(uid) failed: \(error)")
                auditLogInbox(state: state, prefix: "suppress-alert", id: id, uid: uid, result: "failed:\(error)")
            }
        }
    }

    private static func handleUnsuppressAlertRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            // v1.21.4 (audit HIGH, local-DoS): authorize before reading — see
            // handleSuppressAlertRequests. A 1777-inbox FIFO / oversized file
            // must never reach readIdRequest on an unauthorized request.
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] unsuppress-alert \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "unsuppress-alert", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] unsuppress-alert \(name): malformed payload")
                continue
            }
            do {
                try await state.alertStore.unsuppress(alertId: id)
                print("[inbox] unsuppress-alert id=\(id) uid=\(uid) ok")
                auditLogInbox(state: state, prefix: "unsuppress-alert", id: id, uid: uid, result: "ok")
            } catch {
                print("[inbox] unsuppress-alert id=\(id) uid=\(uid) failed: \(error)")
                auditLogInbox(state: state, prefix: "unsuppress-alert", id: id, uid: uid, result: "failed:\(error)")
            }
        }
    }

    private static func handleDeleteAlertRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            // v1.21.4 (audit HIGH, local-DoS): authorize before reading — see
            // handleSuppressAlertRequests. A 1777-inbox FIFO / oversized file
            // must never reach readIdRequest on an unauthorized request.
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] delete-alert \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "delete-alert", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] delete-alert \(name): malformed payload")
                continue
            }
            do {
                let removed = try await state.alertStore.delete(alertId: id)
                // Schema-v8 alert-owned evidence cascades atomically with the
                // parent row. Preserve the explicit events.db cleanup for legacy
                // evidence that is intentionally not auto-migrated; a user-
                // initiated wipe must remove both generations. Best-effort:
                // failure here cannot undo the already-complete alert/new-
                // evidence transaction.
                var evidenceRemoved = 0
                do {
                    evidenceRemoved = try await state.eventStore.deleteEvidence(alertId: id)
                } catch {
                    print("[inbox] delete-alert id=\(id) evidence purge failed: \(error)")
                }
                print("[inbox] delete-alert id=\(id) uid=\(uid) removed=\(removed) evidence=\(evidenceRemoved)")
                auditLogInbox(state: state, prefix: "delete-alert", id: id, uid: uid, result: "removed=\(removed) evidence=\(evidenceRemoved)")
            } catch {
                print("[inbox] delete-alert id=\(id) uid=\(uid) failed: \(error)")
                auditLogInbox(state: state, prefix: "delete-alert", id: id, uid: uid, result: "failed:\(error)")
            }
        }
    }

    /// v1.21.4 (audit): bulk retention prune of alerts older than N days.
    /// The dashboard "Clear Now" button owns only a read-only alerts.db handle
    /// (the root daemon owns the writable one), so it drops a `prune-alerts-*`
    /// request here. Same uid/symlink auth + audit as delete-alert. Coalesces to
    /// the largest window requested in one tick.
    private static func handlePruneAlertsRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        var chosenDays: Int?
        var chosenUID = -1
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "prune-alerts", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            // v1.21.5 (audit S-05): floor the window at 1 day. `days >= 0` let a
            // single 40-byte file drop set cutoff == now — i.e. DELETE THE ENTIRE
            // ALERT HISTORY, the most valuable anti-forensic action in the product,
            // for free and with no alert. Nothing legitimate ever asks for 0: the
            // dashboard's retention picker (SettingsView) offers only 7 / 30 / 90 /
            // 365, and there is no other caller. A genuine "wipe everything"
            // operation, if we ever want one, needs its own explicit verb with
            // operator presence — not a silent edge case of the retention window.
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let days = json["olderThanDays"] as? Int, days >= 1 else {
                auditLogInbox(state: state, prefix: "prune-alerts", id: "-", uid: uid, result: "malformed")
                continue
            }
            // Prune the SMALLEST window (most aggressive) requested this tick.
            if chosenDays == nil || days < chosenDays! { chosenDays = days; chosenUID = uid }
        }
        guard let days = chosenDays else { return }
        let cutoff = Date().addingTimeInterval(-Double(days) * 86_400)
        do {
            let removed = try await state.alertStore.prune(olderThan: cutoff)
            print("[inbox] prune-alerts olderThanDays=\(days) uid=\(chosenUID) removed=\(removed)")
            auditLogInbox(state: state, prefix: "prune-alerts", id: "\(days)d", uid: chosenUID, result: "removed=\(removed)")
            // v1.21.5 (audit S-05): bulk alert deletion is evidence destruction —
            // the highest-value action available to post-compromise code holding
            // this control plane — and it produced only a rotatable audit line,
            // while the far less consequential act of nudging a numeric threshold
            // is both clamped AND alerted. Record it like the other self-defense
            // events. Emitted AFTER the prune so the alert itself cannot be caught
            // by its own cutoff (which the `days >= 1` floor already keeps in the
            // past). Recorded-only, not OS-notified — same as every other
            // self-protection alert — so an operator's own "Clear Now" click costs
            // one dashboard-visible row, not a notification.
            if removed > 0 {
                await emitSelfProtectionAlert(
                    state: state, action: "Alert history pruned",
                    detail: "\(removed) alert(s) older than \(days) day(s) were deleted from the alert store")
            }
        } catch {
            print("[inbox] prune-alerts olderThanDays=\(days) uid=\(chosenUID) failed: \(error)")
            auditLogInbox(state: state, prefix: "prune-alerts", id: "\(days)d", uid: chosenUID, result: "failed:\(error)")
        }
    }

    /// v1.21.4 (audit): apply the Agent-Traces OTLP-receiver toggle. The app
    /// (uid-501) can't write the root-owned config nor SIGHUP the sysext
    /// (EPERM), so the toggle drops an `apply-agent-traces-*` request; the
    /// daemon persists it to the system config and restarts the receiver.
    /// Coalesces to the newest request.
    private static func handleApplyAgentTracesRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        var newest: (mtime: Date, payload: [String: Any], uid: Int)?
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "apply-agent-traces", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                auditLogInbox(state: state, prefix: "apply-agent-traces", id: "-", uid: uid, result: "malformed")
                continue
            }
            let mtime = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date
                ?? Date(timeIntervalSince1970: 0)
            if newest == nil || mtime > newest!.mtime { newest = (mtime, json, uid) }
        }
        guard let chosen = newest else { return }

        // Preserve the master `enabled` (env/config seed); override only the
        // receiver toggle + port from the request.
        let current = AgentTracesConfigStore.loadEffective()
        let receiverEnabled = (chosen.payload["receiverEnabled"] as? Bool) ?? current.receiverEnabled
        let port = (chosen.payload["port"] as? Int).map { UInt16(clamping: $0) } ?? current.port
        let updated = AgentTracesConfig(enabled: current.enabled, receiverEnabled: receiverEnabled, port: port)
        let wrote = AgentTracesConfigStore.write(updated, to: AgentTracesConfigStore.systemPath)
        guard wrote else {
            auditLogInbox(state: state, prefix: "apply-agent-traces", id: "-", uid: chosen.uid, result: "write_failed")
            return
        }
        await DaemonSetup.applyAgentTracesConfig(
            state: state, supportDir: state.supportDir, dbEncryption: state.dbEncryption
        )
        print("[inbox] apply-agent-traces receiver=\(receiverEnabled) port=\(port) uid=\(chosen.uid) applied")
        auditLogInbox(state: state, prefix: "apply-agent-traces", id: "-", uid: chosen.uid, result: "receiver=\(receiverEnabled) port=\(port)")
    }

    /// Issue the root process's trace-database AES key only as an X25519/AES-GCM
    /// envelope addressed to the requesting dashboard's public key. The request
    /// passes the same regular-file, owner-UID and local-admin gate as every
    /// privileged inbox verb. The private recipient key never leaves the login
    /// dashboard process and the response contains no plaintext key material.
    private static func handleTraceDashboardKeyRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "trace-dashboard-key", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let encodedPublicKey = json["publicKey"] as? String,
                  let publicKey = Data(base64Encoded: encodedPublicKey),
                  publicKey.count == 32
            else {
                auditLogInbox(state: state, prefix: "trace-dashboard-key", id: "-", uid: uid, result: "malformed")
                continue
            }

            do {
                let envelope = try state.dbEncryption.dashboardKeyEnvelope(
                    for: publicKey
                )
                let response = try JSONEncoder().encode(envelope)
                let responsePath = state.supportDir
                    + "/dashboard_trace_key_\(uid).json"
                var existing = stat()
                if lstat(responsePath, &existing) == 0,
                   ((existing.st_mode & S_IFMT) != S_IFREG
                    || existing.st_nlink != 1) {
                    throw TraceDashboardKeyExchangeError.invalidEnvelope
                }
                try response.write(
                    to: URL(fileURLWithPath: responsePath),
                    options: [.atomic]
                )
                guard chmod(responsePath, 0o644) == 0 else {
                    throw CocoaError(.fileWriteNoPermission)
                }
                auditLogInbox(
                    state: state,
                    prefix: "trace-dashboard-key",
                    id: envelope.recipientKeyID,
                    uid: uid,
                    result: "issued"
                )
            } catch {
                auditLogInbox(
                    state: state,
                    prefix: "trace-dashboard-key",
                    id: "-",
                    uid: uid,
                    result: "failed:\(error)"
                )
            }
        }
    }

    /// v1.21.4: apply the Prevention tab's per-module enable/disable toggle.
    /// The app (uid-501) can't mutate the root-owned prevention state nor SIGHUP
    /// the sysext (EPERM), so each toggle drops a `prevention-config-*.json`
    /// request; the daemon applies it LIVE to the sinkhole / network-blocker /
    /// persistence-guard actors it already owns. Same uid/symlink auth + admin
    /// gate + audit as every verb. Coalesces to the newest authorized request.
    ///
    /// Only the module keys present in the payload are touched (a missing key
    /// leaves that module untouched). Enabling the sinkhole/blocker repopulates
    /// them from the CURRENT threat-intel set (empty when feeds are off — a
    /// harmless empty enforcement section); persistence-guard takes no seed.
    ///
    /// SCOPING RESIDUALS (honest): this applies LIVE only — it is NOT persisted
    /// across a daemon restart (startup is governed by the boot-time
    /// `MACCRAB_PREVENTION` gate, see DaemonSetup), so a disable survives only
    /// until the engine restarts. Persisting it needs a `prevention_config.json`
    /// read at boot, which changes what the shipped env gate means — still open.
    ///
    /// The feed-refresh leak IS fixed: the `threatIntel.onUpdate` callback in
    /// DaemonSetup now calls `refreshFromFeed(...)`, which honours the operator
    /// disable latch that `disable()` sets, so a live "disable" of the
    /// sinkhole/blocker is no longer silently re-armed on the next feed refresh.
    private static func handlePreventionConfigRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        // MERGE partial per-key payloads (pre-GA review fix). The app sends ONE
        // module per request (V2DaemonControl.sendPreventionConfig), so
        // coalescing to a single newest-mtime request would silently DROP a
        // second module toggled in the same 5s poll window, leaving the
        // enforcing engine in a state that contradicts the user's action + the
        // UI overlay. Collect all authorized requests, apply per-module
        // last-write-wins by mtime.
        var requests: [(mtime: Date, payload: [String: Any], uid: Int)] = []
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "prevention-config", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                auditLogInbox(state: state, prefix: "prevention-config", id: "-", uid: uid, result: "malformed")
                continue
            }
            let mtime = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date
                ?? Date(timeIntervalSince1970: 0)
            requests.append((mtime, json, uid))
        }
        guard !requests.isEmpty else { return }
        requests.sort { $0.mtime < $1.mtime }
        // Last-write-wins per module key across the batch, in mtime order.
        var merged: [String: Bool] = [:]
        for req in requests {
            for key in ["sinkhole", "network_blocker", "persistence_guard"] {
                if let v = req.payload[key] as? Bool { merged[key] = v }
            }
        }
        let latestUID = requests.last!.uid
        let chosen = (payload: merged as [String: Any], uid: latestUID)

        var applied: [String] = []
        // v1.21.4 (audit LOW #15): disabling enforcement is the security-
        // sensitive direction, so record each module DISABLE as its OWN
        // explicit, greppable audit event — not just folded into the coalesced
        // `applied` summary line below (which mixes enables + disables and is
        // attributed only to the batch's newest uid). The module actors don't
        // expose their pre-toggle `isEnabled` to this handler, so the recorded
        // transition is `enforcement=off` rather than a literal old→new.
        // v1.21.5 (audit S-05): also collect the disabled modules so the batch can
        // raise a self-protection ALERT below. v1.21.4 LOW #15 correctly made each
        // disable its own greppable audit event, but an audit line is a rotatable
        // log file — turning off enforcement is a defense-degrading change of the
        // same class as an ES-subscription disable, which has alerted since v1.18.
        var disabledModules: [String] = []
        func auditDisable(_ module: String) {
            disabledModules.append(module)
            auditLogInbox(state: state, prefix: "prevention-disable",
                          id: module, uid: chosen.uid,
                          result: "action=disable module=\(module) enforcement=off")
        }
        if let on = chosen.payload["sinkhole"] as? Bool {
            if on {
                let domains = await state.threatIntel.maliciousDomainSet()
                await state.dnsSinkhole.enable(domains: domains)
            } else {
                await state.dnsSinkhole.disable()
                auditDisable("sinkhole")
            }
            applied.append("sinkhole=\(on)")
        }
        if let on = chosen.payload["network_blocker"] as? Bool {
            if on {
                let ips = await state.threatIntel.maliciousIPSet()
                await state.networkBlocker.enable(ips: ips)
            } else {
                await state.networkBlocker.disable()
                auditDisable("network_blocker")
            }
            applied.append("network_blocker=\(on)")
        }
        if let on = chosen.payload["persistence_guard"] as? Bool {
            if on { await state.persistenceGuard.enable() }
            else {
                await state.persistenceGuard.disable()
                auditDisable("persistence_guard")
            }
            applied.append("persistence_guard=\(on)")
        }
        guard !applied.isEmpty else {
            auditLogInbox(state: state, prefix: "prevention-config", id: "-", uid: chosen.uid, result: "no_recognized_keys")
            return
        }
        let summary = applied.joined(separator: " ")
        print("[inbox] prevention-config uid=\(chosen.uid) applied \(summary)")
        auditLogInbox(state: state, prefix: "prevention-config", id: "-", uid: chosen.uid, result: summary)
        // v1.21.5 (audit S-05): one alert per batch, disables only. Turning off
        // the DNS sinkhole / network blocker / persistence guard is rare and
        // deliberate for an operator, so this cannot storm; for an attacker it is
        // the step that clears the way for the next one, and it was previously
        // silent. Enables are not alerted — restoring enforcement is not a
        // defense-degrading change.
        if !disabledModules.isEmpty {
            await emitSelfProtectionAlert(
                state: state, action: "Prevention module disabled",
                detail: "Enforcement was turned off for: \(disabledModules.joined(separator: ", "))")
        }
    }

    /// v1.17: threat-intel refresh over the inbox channel. The
    /// dashboard "Refresh now" button and `maccrabctl intel refresh`
    /// used to `pkill -USR1` the sysext, which fails EPERM (user →
    /// uid-0 sysext) and never fired refreshNow(). Now they drop a
    /// `refresh-intel-<token>.json` here. Unlike the alert verbs this
    /// request is parameterless (no `id`) — we authorize by file owner
    /// uid and ignore the body. Multiple files in one tick COALESCE:
    /// refreshNow() runs once regardless of how many landed, so rapid
    /// re-clicking can't stack redundant URLhaus/MalwareBazaar/Feodo
    /// fetches. Every file is removed each tick so it can't re-trigger.
    private static func handleRefreshIntelRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        var anyAuthorized = false
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] refresh-intel \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "refresh-intel", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            anyAuthorized = true
            auditLogInbox(state: state, prefix: "refresh-intel", id: "-", uid: uid, result: "ok")
        }
        guard anyAuthorized else { return }
        print("[inbox] refresh-intel: \(names.count) request(s) — running ThreatIntelFeed.refreshNow (coalesced)")
        await state.threatIntel.refreshNow()
        print("[inbox] refresh-intel: refreshNow complete")
    }

    /// Handle `reload-rules-<token>.json` requests. The app can't pkill
    /// the root sysext cross-uid (and a sandboxed app can't spawn pkill
    /// at all), so the dashboard's Reload button drops a request here
    /// instead. We reuse the existing SIGHUP rule-reload path in-process
    /// by raising SIGHUP to ourselves — no logic duplication: the
    /// SignalHandlers SIGHUP DispatchSource does the full single /
    /// sequence / graph reload + suppression refresh. Coalesced: many
    /// requests in one tick raise a single SIGHUP.
    private static func handleReloadRulesRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        var anyAuthorized = false
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] reload-rules \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "reload-rules", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            anyAuthorized = true
            auditLogInbox(state: state, prefix: "reload-rules", id: "-", uid: uid, result: "ok")
        }
        guard anyAuthorized else { return }
        print("[inbox] reload-rules: \(names.count) request(s) — raising SIGHUP to self")
        kill(getpid(), SIGHUP)
    }

    /// v1.17.4: apply a dashboard-pushed LLM backend config. The app writes
    /// the uid-501 user-dir llm_config.json, which the ROOT sysext never
    /// reads (it reads <support>/llm_config.json). This bridges the
    /// NON-SECRET fields over the privileged inbox so engine-side LLM
    /// features become reachable. Security posture: a uid-501 file steering
    /// a root process's outbound URL is an SSRF/exfil surface, so any
    /// non-loopback ollama_url/openai_url is DEFAULT-DENIED unless the
    /// payload sets allow_remote_endpoint=true. Cloud API keys never travel
    /// this channel (keychain leg). Takes effect on the next engine restart.
    private static func handleLLMConfigRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        guard !names.isEmpty else { return }
        let fm = FileManager.default
        // Coalesce: apply only the newest authorized request.
        var newest: (mtime: Date, payload: [String: Any], uid: Int)?
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                auditLogInbox(state: state, prefix: "llm-config", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let data = safeReadInboxRequestData(at: path),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                auditLogInbox(state: state, prefix: "llm-config", id: "-", uid: uid, result: "malformed")
                continue
            }
            let mtime = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date
                ?? Date(timeIntervalSince1970: 0)
            if newest == nil || mtime > newest!.mtime { newest = (mtime, json, uid) }
            auditLogInbox(state: state, prefix: "llm-config", id: "-", uid: uid, result: "ok")
        }
        guard let chosen = newest else { return }

        // Whitelist NON-SECRET keys; default-deny non-loopback endpoints.
        let allowRemote = (chosen.payload["allow_remote_endpoint"] as? Bool) ?? false
        let urlKeys: Set<String> = ["ollama_url", "openai_url"]
        // v1.21.6 (SU-04): `agentic_investigation_enabled` removed from the
        // allowlist. It gated an app-side AgenticInvestigator that had zero call
        // sites and has been deleted; the sysext never read the key, so bridging
        // it to the root config only made a no-op look like a supported control.
        let allowedKeys = ["enabled", "provider", "ollama_url", "ollama_model",
                           "openai_url", "openai_model", "claude_model",
                           "mistral_model", "gemini_model"]
        // Reject the request atomically when it tries to steer a remote URL
        // without explicit approval. Applying provider/model while silently
        // skipping only the endpoint leaves the engine on a stale/default URL
        // and makes Settings disagree with production.
        let unapprovedRemoteKeys = urlKeys.sorted().filter { key in
            guard let url = chosen.payload[key] as? String else { return false }
            return !isLoopbackEndpoint(url) && !allowRemote
        }
        if !unapprovedRemoteKeys.isEmpty {
            for key in unapprovedRemoteKeys {
                auditLogInbox(
                    state: state,
                    prefix: "llm-config",
                    id: key,
                    uid: chosen.uid,
                    result: "request_rejected_nonloopback"
                )
            }
            print("[inbox] llm-config: rejected entire request; remote endpoint approval missing for \(unapprovedRemoteKeys.joined(separator: ","))")
            return
        }
        var sanitized: [String: Any] = [:]
        for key in allowedKeys {
            guard let value = chosen.payload[key] else { continue }
            sanitized[key] = value
        }
        guard !sanitized.isEmpty else { return }

        // Merge onto the existing root config while preserving unknown
        // NON-SECRET fields. The shared loader actively scrubs plaintext keys
        // left by old releases and refuses config-file symlinks.
        let rootPath = state.supportDir + "/llm_config.json"
        var merged = (try? LLMConfigFile.loadAndScrub(
            atPath: rootPath,
            legacySecretMigration: .sharedKeychain(interaction: .disallowed),
            onScrubFailure: { error in
                print("[inbox] llm-config: legacy-secret scrub failed: \(error)")
            }
        )) ?? [:]
        // v1.21.5 (audit S-02): note whether this request actually CHANGES the
        // provider, an endpoint or the master enable (vs. an idempotent rewrite of
        // the same values), so the self-protection alert below fires on real
        // reconfiguration only and never on the dashboard re-saving what is
        // already there. Compared as strings because the payload values are Any
        // (String for provider/urls, Bool for enabled).
        let endpointOrProviderChanged = ["provider", "ollama_url", "openai_url", "enabled"].contains { key in
            guard let updated = sanitized[key] else { return false }
            return "\(merged[key] ?? "")" != "\(updated)"
        }
        for (k, v) in sanitized { merged[k] = v }
        do {
            try LLMConfigFile.writeNonSecretJSON(
                merged,
                toPath: rootPath,
                legacySecretMigration: .sharedKeychain(interaction: .disallowed)
            )
            print("[inbox] llm-config: applied \(sanitized.count) field(s) → \(rootPath) (effective next engine restart)")
            // Self-protection: a non-loopback endpoint accepted under
            // allow_remote_endpoint=true means future engine LLM prompt traffic
            // may leave the host — surface it (rare-legitimate, exfil-relevant).
            let remoteApplied = sanitized.contains { (k, v) in
                urlKeys.contains(k) && ((v as? String).map { !isLoopbackEndpoint($0) } ?? false)
            }
            if allowRemote && remoteApplied {
                await emitSelfProtectionAlert(
                    state: state, action: "Remote LLM endpoint enabled",
                    detail: "A non-loopback LLM endpoint was configured with allow_remote_endpoint=true (engine prompt traffic may leave the host)")
            } else if endpointOrProviderChanged {
                // v1.21.5 (audit S-02): a LOOPBACK endpoint is not benign either.
                // The gate above only speaks about non-loopback URLs, so a drop of
                // {"enabled":true,"provider":"ollama","ollama_url":"http://127.0.0.1:9999"}
                // applied silently with nothing but an audit line reading "ok" —
                // and a loopback Ollama is exactly what LLMService.shouldSanitize
                // treats as "local, nothing leaves the host", i.e. sanitization
                // OFF. Post-compromise code owning uid 501 could therefore point
                // the ROOT engine at its own listener and receive every prompt
                // verbatim after the next restart (reboot or Sparkle update). The
                // companion trustLocalEndpoint change now keeps the sanitizer on
                // for that case; this makes the reconfiguration itself LOUD, which
                // is the whole point of the self-protection alert.
                await emitSelfProtectionAlert(
                    state: state, action: "LLM endpoint or provider changed",
                    detail: "The engine's LLM provider/endpoint was reconfigured over the privileged inbox — engine analysis prompts (process paths, command lines, user names) will be sent to the newly configured endpoint")
            }
        } catch {
            print("[inbox] llm-config: secure write failed: \(error)")
        }
    }

    /// A URL string whose host is genuinely loopback (localhost / ::1 /
    /// an IPv4 literal in 127.0.0.0/8). Default-deny gate for engine-side
    /// LLM endpoints (SSRF/exfil guard). Delegates to the shared strict
    /// validator so a hostname like `127.0.0.1.evil.com` is rejected — a
    /// textual `hasPrefix("127.")` test would have let it through.
    private static func isLoopbackEndpoint(_ urlString: String) -> Bool {
        return LoopbackEndpoint.isLoopback(urlString: urlString)
    }

    private static func handleSuppressCampaignRequests(
        _ names: [String], inboxDir: String, state: DaemonState
    ) async {
        for name in names {
            let path = inboxDir + "/" + name
            defer { removeInboxEntry(at: path) }
            // v1.21.4 (audit HIGH, local-DoS): authorize before reading — see
            // handleSuppressAlertRequests. A 1777-inbox FIFO / oversized file
            // must never reach readIdRequest on an unauthorized request.
            let uid = requestOwnerUID(at: path)
            guard isAuthorizedInboxRequest(uid: uid) else {
                print("[inbox] suppress-campaign \(name) REJECTED uid=\(uid) (not console-user or root)")
                auditLogInbox(state: state, prefix: "suppress-campaign", id: "-", uid: uid, result: "rejected_uid")
                continue
            }
            guard let id = readIdRequest(at: path) else {
                print("[inbox] suppress-campaign \(name): malformed payload")
                continue
            }
            // Suppress the campaign-as-alert row (campaigns have a
            // `maccrab.campaign.*` rule_id and live alongside regular
            // alerts in alerts.db). Best-effort — pre-v1.8 campaigns
            // exist only in campaigns.db and have no alerts.db row.
            try? await state.alertStore.suppress(alertId: id)

            // Fan out: every alert whose campaignId matches this
            // campaign also gets suppressed. The dashboard used to
            // do this loop itself; moving it server-side means one
            // round trip instead of N over file IPC.
            var fanOut = 0
            do {
                let alerts = try await state.alertStore.alerts(
                    since: Date.distantPast,
                    severity: nil, suppressed: false, limit: 10_000
                )
                for a in alerts where a.campaignId == id {
                    do {
                        try await state.alertStore.suppress(alertId: a.id)
                        fanOut += 1
                    } catch {
                        // One bad row shouldn't abort the rest.
                        print("[inbox] suppress-campaign fan-out id=\(a.id) failed: \(error)")
                    }
                }
            } catch {
                print("[inbox] suppress-campaign contributors lookup failed: \(error)")
            }

            // Flip the persistent campaigns.db row so the dashboard's
            // campaigns list reflects suppressed state across restarts.
            if let cs = state.campaignStore {
                try? await cs.setSuppressed(id: id, true)
            }
            print("[inbox] suppress-campaign id=\(id) uid=\(uid) fanOut=\(fanOut)")
            auditLogInbox(state: state, prefix: "suppress-campaign", id: id, uid: uid, result: "ok fanOut=\(fanOut)")
        }
    }

    /// Byte caps by request shape. Rule-install envelopes legitimately contain
    /// a compiled rule plus source YAML, and clipboard records may contain large
    /// Unicode grapheme clusters; both remain finite and substantially below an
    /// OOM-relevant allocation. Every other request is tiny control JSON.
    static let maximumInboxRequestBytes: off_t = 4 * 1024 * 1024

    static func inboxRequestMaxBytes(for name: String) -> off_t? {
        guard isClaimedInboxRequestName(name) else { return nil }
        if name.hasPrefix("record-clipboard-") { return maximumInboxRequestBytes }
        if name.hasPrefix("install-rule-") { return 2 * 1024 * 1024 }
        return 64 * 1024
    }

    /// Safely read a claimed inbox request using the cap for its request shape.
    /// Unknown names are refused so callers cannot accidentally turn this into
    /// a general root-context file reader.
    static func safeReadInboxRequestData(at path: String) -> Data? {
        let name = URL(fileURLWithPath: path).lastPathComponent
        guard let maxBytes = inboxRequestMaxBytes(for: name) else { return nil }
        return safeReadInboxData(at: path, maxBytes: maxBytes)
    }

    /// Safely read an inbox request file's bytes. The single hardened read path
    /// shared by EVERY inbox reader (id-based and arbitrary-JSON alike), so the
    /// 1777-inbox FIFO-wedge / OOM defense can never be reintroduced by a future
    /// caller that reaches for a plain `Data(contentsOf:)`:
    ///   - `O_NONBLOCK`: opening a FIFO returns immediately (never blocks on a
    ///     writer) — a plain open would hang the poller and wedge the whole
    ///     control plane while `inboxPollerLock`'s inFlight is held.
    ///   - `O_NOFOLLOW`: a symlink dir entry is refused at open (ELOOP).
    ///   - `fstat` the OPENED fd (no lstat→open TOCTOU) and accept only a
    ///     regular file whose size is within a tiny cap (64 KB default) — no
    ///     multi-GB wholesale read into memory.
    /// Returns nil on any rejection. `internal` for unit-testing.
    static func safeReadInboxData(at path: String, maxBytes: off_t = 64 * 1024) -> Data? {
        guard maxBytes >= 0, maxBytes <= maximumInboxRequestBytes else { return nil }
        // O_CLOEXEC keeps a privileged inbox descriptor out of any helper or
        // sandbox-host process spawned concurrently by the daemon.
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0,
              (st.st_mode & S_IFMT) == S_IFREG,   // regular file only — no FIFO/socket/dir
              st.st_size >= 0,
              st.st_size <= maxBytes
        else { return nil }
        // Do not rely on the pre-read fstat alone: an authorized writer can
        // append after it. Read at most cap+1 bytes and reject growth past the
        // cap instead of letting `readToEnd()` allocate without a hard ceiling.
        var data = Data()
        data.reserveCapacity(Int(st.st_size))
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let remainingWithSentinel = Int(maxBytes) - data.count + 1
            guard remainingWithSentinel > 0 else { return nil }
            let requested = min(buffer.count, remainingWithSentinel)
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                read(fd, rawBuffer.baseAddress, requested)
            }
            if count == 0 { return data }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            data.append(contentsOf: buffer[0..<count])
            if data.count > Int(maxBytes) { return nil }
        }
    }

    /// Read a `{"id":"…"}` request file. Returns nil for missing, malformed,
    /// empty-id, non-regular, symlinked, or oversized payloads.
    /// `internal` so the DoS hardening is testable against real hostile files.
    static func readIdRequest(at path: String) -> String? {
        guard let data = safeReadInboxRequestData(at: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = json["id"] as? String,
              !id.isEmpty
        else { return nil }
        return id
    }

    /// Stat the request file to get the UID of whoever dropped it.
    /// Used by `isAuthorizedInboxRequest(uid:)` below.
    ///
    /// **v1.11.0 RC2 ship-blocker fix:** uses `lstat()` (not `stat()`)
    /// so a symlink in the 1777 inbox dir CANNOT be used to forge a
    /// root UID — pre-fix `stat()` followed symlinks, so an attacker
    /// could symlink `suppress-alert-X.json → /Library/Application
    /// Support/MacCrab/agent_lineage.json` (root-owned) and the gate
    /// authorised the request as root. Now: lstat returns the symlink
    /// owner (the attacker's uid), and the regular-file-only check rejects
    /// symlinks and every other non-regular carrier before processing.
    /// Hardlinks are also rejected (st_nlink > 1) so an attacker can't
    /// hardlink a root-owned file into the inbox either.
    /// Returns -1 on stat failure or any rejection condition — that
    /// value never satisfies the gate.
    // `internal` (not private) so the symlink/hardlink forgery rejection is
    // unit-tested against real on-disk files — this is the gate that stops a
    // local user from forging root ownership of an inbox request.
    static func requestOwnerUID(at path: String) -> Int {
        var st = stat()
        guard lstat(path, &st) == 0 else { return -1 }
        // Refuse every non-regular object. In particular, a FIFO owned by an
        // otherwise authorized uid must not pass the owner gate and reach a
        // handler read; sockets/devices/directories are equally invalid request
        // carriers. The opened-fd reader repeats this check after open.
        if (st.st_mode & S_IFMT) != S_IFREG { return -1 }
        // Refuse hardlinked files: st_nlink > 1 means the inode also
        // exists elsewhere in the filesystem; the attacker may have
        // hardlinked a root-owned file into the world-writable inbox.
        if st.st_nlink > 1 { return -1 }
        return Int(st.st_uid)
    }

    /// Returns the UID of the user logged in at the macOS GUI console.
    /// `loginwindow` (or nil result) means no user is logged in — e.g.
    /// during early boot. Returns nil in that case so the gate falls
    /// back to root-only.
    private static func consoleUserUID() -> uid_t? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        let store = SCDynamicStoreCreate(nil, "MacCrabInboxGate" as CFString, nil, nil)
        guard let user = SCDynamicStoreCopyConsoleUser(store, &uid, &gid) else { return nil }
        let userStr = user as String
        if userStr.isEmpty || userStr == "loginwindow" { return nil }
        return uid
    }

    /// v1.19.1 (audit): true if `uid` belongs to the macOS `admin` group
    /// (gid 80). The control plane must accept mutating verbs only from an
    /// ADMIN console user (or root) — on a shared / managed / kiosk Mac a
    /// standard, non-admin user at the keyboard must not be able to suppress
    /// alerts, install rules, or weaken config via the 1777 inbox.
    static func isAdminUID(_ uid: uid_t) -> Bool {   // internal for @testable
        guard let pw = getpwuid(uid) else { return false }
        let name = String(cString: pw.pointee.pw_name)
        let baseGID = Int32(bitPattern: pw.pointee.pw_gid)
        var ngroups: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(ngroups))
        if getgrouplist(name, baseGID, &groups, &ngroups) == -1 {
            // Buffer was too small; ngroups now holds the needed size — retry.
            groups = [Int32](repeating: 0, count: Int(ngroups))
            guard getgrouplist(name, baseGID, &groups, &ngroups) != -1 else { return false }
        }
        return groups.prefix(Int(ngroups)).contains(80)   // gid 80 == admin
    }

    /// v1.10.2 (audit BLOCKER): the inbox dir at
    /// `/Library/Application Support/MacCrab/inbox/` is mode 1777 so
    /// any local user can drop request files. Without a UID gate at
    /// the handler level, a logged-in standard / guest / kiosk user
    /// could blind the EDR by suppressing or deleting alerts (or
    /// fan-out-suppressing whole campaigns). We accept requests only
    /// from:
    ///   - root (uid 0): launchd / sudo flows + the daemon itself
    ///   - the GUI console user: the human at the keyboard, who is
    ///     also the user running MacCrab.app
    /// Anything else is rejected and audit-logged.
    static func isAuthorizedInboxRequest(uid: Int) -> Bool {
        if uid < 0 { return false }                  // stat failed
        if uid == 0 { return true }                  // root
        // v1.19.1 (audit): the console user must ALSO be an admin to issue
        // control verbs. Pre-fix any foreground console user — incl. a standard
        // non-admin user on a shared/managed Mac — could suppress/delete alerts,
        // suppress campaigns, install rules, or weaken config. Now: root, or the
        // GUI console user AND that user is in the admin group.
        if let console = consoleUserUID(), Int(console) == uid, isAdminUID(console) { return true }
        return false
    }

    /// Append a single line to the inbox audit log. Format is
    /// space-separated `key=value` pairs, ISO 8601 timestamp first.
    /// The MCP path uses a similar `dashboard_audit.log` in
    /// `<supportDir>` — keep them in the same file so operators have
    /// a single tail target for "who changed alert state".
    nonisolated(unsafe) private static let _inboxAuditFmt: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Sanitize an attacker-controlled string before it lands in the
    /// audit log. v1.11.0 RC2 ship-blocker fix: a request id like
    /// `valid-uuid\nresult=ok uid=0` would have forged a fake "ok"
    /// audit line, since the audit format is one line-per-mutation
    /// space-separated key=value pairs. Reject newlines / carriage
    /// returns / non-printable ASCII; cap length at 128 (alert ids
    /// are UUIDs, well under that). Replacement makes the truncation
    /// visible to operators tailing the log.
    static func sanitizeAuditField(_ s: String, max: Int = 128) -> String {
        let scrubbed = String(s.unicodeScalars.prefix(max).map { scalar -> Character in
            if scalar == "\n" || scalar == "\r" { return "_" }
            if !scalar.isASCII { return "?" }
            if scalar.value < 0x20 { return "_" }
            return Character(scalar)
        })
        return scrubbed
    }

    /// v1.21.4 (G-04): size-based rotation for `dashboard_audit.log`. The log
    /// is plain-appended one line per privileged mutation and previously had no
    /// cap, so it grew without bound. When the live file passes `maxBytes`,
    /// shift `.N → .(N+1)` (oldest falls off the end) and move the live file to
    /// `.1`, mirroring the FileOutput rotation idiom. `maxArchives` rotated
    /// generations are kept.
    ///
    /// Best-effort and intentionally NON-tamper-evident: this is a forensic
    /// breadcrumb (a single tail target for "who changed alert state"), not a
    /// hash-chained ledger — rotation discards the oldest generation. Operators
    /// needing durable retention should export via the daemon's syslog/SIEM
    /// sinks.
    static func rotateAuditLogIfNeeded(
        path: String, maxBytes: UInt64 = 5 * 1024 * 1024, maxArchives: Int = 3
    ) {
        let fm = FileManager.default
        guard maxArchives >= 1,
              let attrs = try? fm.attributesOfItem(atPath: path),
              let size = attrs[.size] as? UInt64, size > maxBytes else { return }
        // Shift .N → .(N+1) from the oldest so nothing is overwritten.
        for i in stride(from: maxArchives, to: 0, by: -1) {
            let src = "\(path).\(i)"
            guard fm.fileExists(atPath: src) else { continue }
            if i == maxArchives {
                try? fm.removeItem(atPath: src)          // oldest falls off the end
            } else {
                try? fm.moveItem(atPath: src, toPath: "\(path).\(i + 1)")
            }
        }
        try? fm.moveItem(atPath: path, toPath: "\(path).1")
    }

    private static func auditLogInbox(
        state: DaemonState, prefix: String, id: String, uid: Int, result: String
    ) {
        let logPath = state.supportDir + "/dashboard_audit.log"
        rotateAuditLogIfNeeded(path: logPath)
        // Sanitize all attacker-controlled fields so log-injection
        // attempts (newlines, ANSI escapes, control chars in the id
        // / result string) can't forge subsequent log lines.
        let safeId = sanitizeAuditField(id)
        let safeResult = sanitizeAuditField(result, max: 256)
        let line = "\(_inboxAuditFmt.string(from: Date())) source=inbox prefix=\(prefix) id=\(safeId) uid=\(uid) result=\(safeResult)\n"
        guard let data = line.data(using: .utf8) else { return }
        let url = URL(fileURLWithPath: logPath)
        if let handle = try? FileHandle(forWritingTo: url) {
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
            try? handle.close()
        } else {
            // First-time write (file doesn't exist yet).
            try? data.write(to: url, options: .atomic)
        }
        // rw-r-----: this is the privileged-mutation trail (which alert or
        // campaign was suppressed/deleted, by which uid). Created under the
        // root daemon's default umask it landed 0o644, so every local
        // account could read which detections the operator has already
        // silenced — a map of the blind spots. Re-applied on every append
        // (mutations are rare, so the cost is nil) so an existing 0o644 log
        // from an older build is tightened in place; rotateAuditLogIfNeeded
        // uses moveItem, which carries the mode onto the .1/.2/.3 archives.
        // Readers are `maccrabctl audit`, the MCP get_audit_log tool and the
        // dashboard's System → Health audit card, all uid-501 admin-group
        // processes that already read the 0o640 stores. The 0o640 group bit is
        // load-bearing for the two HUMAN surfaces — tightening this to 0o600
        // would silently return the audit trail to agent-only readability.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o640], ofItemAtPath: logPath
        )
    }
}

// MARK: - DB footprint measurement (v1.6.14)

/// Return the authoritative SQLite database-family footprint in bytes. This is
/// deliberately the same hardened `db + wal + shm + journal` probe used by the
/// hot write-admission gate: unsafe/partial families and probe failures throw
/// instead of being misreported as a zero-byte healthy store.
func measureDatabaseFootprintBytes(dbPath: String) throws -> Int64 {
    try SQLitePersistentStoreAdmission.measureFamily(dbPath)
}

/// Return the SQLite database footprint in decimal MB, summing the main
/// `.db` file plus its `-wal`, `-shm`, and rollback-journal sidecars. v1.6.14: earlier
/// releases measured only the main `.db`, so a 480 MB main file
/// plus a 40 MB WAL presented as "under cap" despite consuming
/// 520 MB on disk. Operators setting a tight cap were surprised
/// when `du` and the daemon's cap disagreed; now they match.
///
/// Returns 0 on stat failure — downstream callers already treat
/// 0 as "skip enforcement" via the `> maxSizeMB` guard.
func measureDatabaseFootprintMB(dbPath: String) -> Int {
    guard let bytes = try? measureDatabaseFootprintBytes(dbPath: dbPath) else {
        return 0
    }
    return Int(bytes / 1_000_000)
}

/// The `-wal` sidecar size alone, in MB. Used by the size-cap sweep to tell a
/// reclaimable free-page overage (fix with VACUUM) apart from a reader-pinned
/// WAL (which VACUUM cannot fix — see the sweep's back-off below).
func measureWalMB(dbPath: String) -> Int {
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: dbPath + "-wal"),
          let b = attrs[.size] as? UInt64 else { return 0 }
    return Int(b / 1_000_000)
}

/// Exact WAL size in bytes, for comparison against byte-denominated limits.
/// `measureWalMB` is decimal MB and is display-only: comparing it to a MiB
/// limit misclassified a normally-parked WAL as reader-pinned.
func measureWalBytes(dbPath: String) -> Int64 {
    guard let attrs = try? FileManager.default.attributesOfItem(atPath: dbPath + "-wal"),
          let b = attrs[.size] as? UInt64 else { return 0 }
    return Int64(b)
}

// MARK: - Adaptive rollup sweep (v1.8.0)

/// Freelist slack at or above which the size-cap sweep runs `incremental_vacuum`
/// regardless of where its instantaneous footprint sample landed.
///
/// 16 MiB is deliberately well above what one sweep of ordinary retention churn
/// frees (hundreds of pages on a measured installed host) and far below the
/// hundreds of megabytes a store strands once its high-water mark and its live
/// working set diverge. Raising it strands more space; lowering it toward zero
/// makes the file truncate and regrow every sweep for no gain.
let reclaimableSlackFloorBytes: Int64 = 16 * 1_024 * 1_024

/// Whether the size-cap sweep should run `incremental_vacuum` this pass.
///
/// Pure so the decision can be discriminated deterministically instead of being
/// inferred from a 300-line sweep whose only reclaim log fires on success. Three
/// independent reasons to reclaim, any one sufficient:
///
///   1. `totalPruned > 0` — retention just freed pages; return them.
///   2. `footprintBytes > targetBytes` — over target on this sample.
///   3. `reclaimableSlackBytes >= slackFloorBytes` — the file is holding space it
///      does not use, whatever this sample says.
///
/// Reason 3 exists because reasons 1 and 2 can BOTH be false while the store is
/// stranding hundreds of megabytes: the footprint is sampled straight after a
/// WAL truncate (the trough), while storage admission judges the family at its
/// peak, and a store whose retained rows all sit inside the forensic floor
/// prunes nothing. See the call site for the measured installed-host case.
///
/// A reader-pinned WAL still vetoes everything: the reclaim cannot truncate
/// pages the pin holds alive and would only grow the sidecar.
enum StorageReclaimDecision {
    static func shouldReclaim(
        totalPruned: Int,
        footprintBytes: Int64,
        targetBytes: Int64,
        reclaimableSlackBytes: Int64,
        slackFloorBytes: Int64 = reclaimableSlackFloorBytes,
        walPinned: Bool
    ) -> Bool {
        guard !walPinned else { return false }
        if totalPruned > 0 { return true }
        if footprintBytes > targetBytes { return true }
        guard slackFloorBytes > 0 else { return false }
        return reclaimableSlackBytes >= slackFloorBytes
    }
}


/// Three-layer storage discipline: pre-insert filter (Layer 1) → adaptive
/// retention (this function, Layer 2) → defense-in-depth size cap (also
/// here, Layer 3).
///
/// Tries the configured `hotTierMinutes` cutoff first. If the DB is still
/// over `targetSizeBytes` afterwards, tightens the cutoff progressively
/// (hotTier, /2, /4) — but never below the 15-minute raw-event forensic and
/// correlation floor.
///
/// If after the tightest cutoff the DB STILL exceeds `capSizeBytes` (the
/// proactive reserve boundary, before hard admission pauses ingestion), Layer
/// 3 kicks in: pruneOldest() to bring file size under cap by sheer row count,
/// followed by VACUUM if disk has the headroom.
///
/// All steps are best-effort; failures log + continue. The next 6-hourly
/// tick retries the same logic from scratch — idempotent by design.
func runAdaptiveRollupSweep(
    eventStore: EventStore,
    dbPath: String,
    targetSizeBytes: Int64,
    capSizeBytes: Int64,
    hotTierMinutes: Int = 30,
    aggregateDays: Int = 90,
    alertsRetentionDays: Int = 365,
    // v1.21.7: 50 -> 16. The legacy `events.db.alert_evidence` table froze at
    // 93.4 MB / 36,322 rows across 729 alerts when schema v8 sent NEW evidence to
    // alerts.db. It is size-pruned only when it exceeds its OWN sub-cap
    // (evidenceMaxSizeMB = 100 MiB) and it sits just under that, so it never
    // prunes — while consuming 29% of the 320 MiB events-family budget and
    // draining otherwise only as alerts age out on a 365-day clock.
    //
    // 16 is chosen against what is actually consumed, not arbitrarily: the sole
    // production reader chain renders `evidence.prefix(8)`
    // (EventStore.evidenceFor -> AlertEvidence -> AppState -> V2AlertsWorkspace),
    // so 16 keeps double what any surface displays. Measured on the live store:
    // 36,322 rows -> 11,651, ~70 MB reclaimed through the incremental_vacuum
    // already running every sweep — no full VACUUM, no 2x transient spike, no
    // migration. 98.90% of displayed evidence rows are byte-identical
    // (5,763 of 5,827); the 64 that change are replaced by HIGHER-severity
    // events, because pruneAlertEvidenceCap ranks by severity then timestamp.
    //
    // This reclaims disk. It does NOT move the hard admission gate (+0.28 MB) —
    // do not read it as a fix for the write-drop rate.
    evidencePerAlertCap: Int = 16,
    evidenceMaxSizeMB: Int = 100,
    processFloorMinutes: Int = 0
) async {
    // v1.21.4 per-category retention floor. When > 0, spare process/exec rows
    // newer than this cutoff from BOTH the time-based rollup (Layer 2) and the
    // oldest-first row-count fallback (Layer 3) so a cheap file-write flood
    // can't collapse the low-volume process channel as collateral. Layer 3's
    // pruneOldest carries a soft-floor valve, so the cap still converges even
    // when the protected rows alone exceed it. 0 = category-blind (unchanged).
    let processFloorCategory: EventCategory? = processFloorMinutes > 0 ? .process : nil
    let processFloorCutoff: Date? = processFloorMinutes > 0
        ? Date().addingTimeInterval(-Double(processFloorMinutes) * 60)
        : nil
    func currentFootprint(_ phase: String) -> Int64? {
        do {
            return try measureDatabaseFootprintBytes(dbPath: dbPath)
        } catch {
            logger.fault("Tier-rollup \(phase, privacy: .public): authoritative SQLite family probe failed; refusing further maintenance: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }
    // Probe before the first DELETE. Unsafe/partial families and stat failures
    // must never be converted into a zero-byte reading that authorizes mutation.
    guard let startSizeBytes = currentFootprint("start") else { return }
    // v1.8.0-rc6: Prune oversized alert_evidence FIRST. On the field test
    // host, a single sweep found 802K evidence rows / 2.4 GB — the storage
    // split decoupled evidence (in events.db) from its parent alerts (now
    // in alerts.db) without any retention bridging the two. Two prune steps:
    //   - Per-alert row cap (existing oversize from pre-rc6 captures)
    //   - Time-based prune (orphans whose parent alert was deleted from alerts.db)
    do {
        let evidenceCutoff = Date().addingTimeInterval(-Double(alertsRetentionDays) * 86400)
        let evictedByAge = (try? await eventStore.pruneAlertEvidence(olderThan: evidenceCutoff)) ?? 0
        let evictedByCap = (try? await eventStore.pruneAlertEvidenceCap(perAlertMax: evidencePerAlertCap)) ?? 0
        // RC H2: total-size cap. Age + per-alert-cap don't bound total size,
        // so on a busy host alert_evidence outgrew the events cap (194 MB).
        let evidenceCapBytes = SQLitePersistentStorePolicy.capBytes(
            maxSizeMiB: max(10, evidenceMaxSizeMB)
        )
        let evictedBySize = (try? await eventStore.pruneAlertEvidenceBySize(maxBytes: evidenceCapBytes)) ?? 0
        if evictedByAge > 0 || evictedByCap > 0 || evictedBySize > 0 {
            logger.notice("alert_evidence prune: \(evictedByAge) by age (>\(alertsRetentionDays)d), \(evictedByCap) by per-alert cap (>\(evidencePerAlertCap) rows), \(evictedBySize) by size (>\(evidenceMaxSizeMB) MB)")
        }
    }

    // Tighten only to the hard forensic/correlation floor. The previous code
    // deliberately generated [15, 14, 13] at a configured 15-minute floor;
    // runtime measurement then retained just 101–221 seconds because Layer 3's
    // valve continued through the remaining recent rows. A byte budget that
    // cannot hold the floor must be surfaced as degraded/infeasible and shed
    // future persistence honestly — it must not falsify the window by deleting
    // newer evidence until the file happens to fit.
    let cutoffsMinutes = EventRetentionFloor
        .adaptiveCutoffs(hotTierMinutes: hotTierMinutes)
        .map(Double.init)
    var totalPruned = 0

    for minutes in cutoffsMinutes {
        guard let beforeBytes = currentFootprint("before adaptive cutoff") else {
            return
        }
        if beforeBytes <= targetSizeBytes && minutes != cutoffsMinutes.first {
            // Don't tighten further than needed. Only the first cutoff
            // (the configured hot tier) always runs; tighter cutoffs only
            // kick in if the DB is still over target.
            break
        }
        do {
            let cutoff = Date().addingTimeInterval(-minutes * 60)
            let pruned = try await eventStore.rollUpAndPrune(
                olderThan: cutoff,
                aggregateRetentionDays: aggregateDays,
                protecting: processFloorCategory,
                newerThan: processFloorCutoff
            )
            totalPruned += pruned
            if pruned > 0 {
                logger.notice("Adaptive rollup: cutoff \(Int(minutes))m pruned \(pruned) events")
            }
            if minutes == cutoffsMinutes.first {
                continue   // always do the configured pass; the loop's guard checks AFTER
            }
            // Re-check size after each tighter pass.
            guard let afterBytes = currentFootprint("after adaptive cutoff") else {
                return
            }
            if afterBytes <= targetSizeBytes {
                logger.notice("Adaptive rollup: DB \(beforeBytes) bytes → \(afterBytes) bytes at \(Int(minutes))m cutoff (target \(targetSizeBytes) bytes) — done.")
                break
            }
        } catch {
            logger.error("Adaptive rollup at cutoff \(Int(minutes))m failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // Layer 3: defense-in-depth cap. After all the time-based cutoffs, if
    // the DB still exceeds the hard ceiling, prune by row count until it
    // fits. Last-resort guarantee that the user's disk-budget is honored.
    guard let sizeAfterAdaptiveBytes = currentFootprint("after adaptive passes") else {
        return
    }
    if sizeAfterAdaptiveBytes > capSizeBytes {
        logger.warning("Adaptive rollup left DB at \(sizeAfterAdaptiveBytes) bytes (proactive boundary \(capSizeBytes) bytes) — engaging Layer 3 row-count cap.")
        do {
            // Estimate how many rows to drop: the over-cap fraction × row count.
            let total: Int
            do {
                total = try await eventStore.maintenanceRetainedRecordCount()
            } catch {
                logger.fault("Layer 3 cap: retained-record count unavailable; refusing zero-derived prune: \(error.localizedDescription, privacy: .public)")
                return
            }
            let overFraction = Double(sizeAfterAdaptiveBytes - capSizeBytes)
                / Double(sizeAfterAdaptiveBytes)
            let dropTarget = max(10_000, Int(Double(total) * (overFraction + 0.1)))
            let hardFloorCutoff = Date().addingTimeInterval(
                -Double(EventRetentionFloor.minutes) * 60
            )
            let dropped = (try? await eventStore.pruneOldest(
                count: dropTarget,
                protecting: processFloorCategory,
                newerThan: processFloorCutoff,
                preservingAllNewerThan: hardFloorCutoff
            )) ?? 0
            logger.notice("Layer 3 cap: pruned \(dropped) oldest events (target \(dropTarget))")
            if dropped < dropTarget {
                logger.fault("Layer 3 cap stopped at the \(EventRetentionFloor.minutes)-minute raw-event floor after pruning \(dropped)/\(dropTarget) rows. The configured events.db budget is currently infeasible without shedding new persistence; recent evidence was NOT deleted to manufacture convergence.")
            }
            // v1.10.0 audit fix: feed Layer 3's drop count into the
            // shared totalPruned counter so the VACUUM gate below
            // ("if totalPruned > 0") fires. Pre-fix Layer 3 deleted
            // millions of rows but the gate stayed false (because
            // the adaptive loop hadn't pruned anything — table
            // already inside hot tier), so VACUUM was skipped and
            // the file stayed at the high-water mark. Field-
            // observed: a manual flush at 2.3 GB returned 2.5 GB
            // afterAfter (the difference being inserts that
            // accumulated during the no-op-VACUUM sweep window).
            totalPruned += dropped
        }
    }

    // Single VACUUM at the end of the sweep to actually reclaim the
    // pages freed by the prune steps. Without this, DELETE marks pages
    // free for future reuse but the file size on disk stays at the
    // high-water mark — so the adaptive logic above sees the file as
    // still over target on every subsequent tick and keeps tightening
    // pointlessly. Matches the v1.6.13 legacy design ("prune everything
    // first, then VACUUM once at the end").
    //
    // Wave 9B (v1.12.6): incremental_vacuum first so we (a) shrink
    // the file even when disk is too tight for full VACUUM, and (b)
    // reduce the headroom requirement for the full VACUUM below by
    // pre-truncating end-of-file freelist pages.
    //
    // Full VACUUM skipped if no rows were pruned, if free disk is too
    // tight (the shared boundary preserves the floor plus 2x the
    // authoritative main-file size), or both. On skip we still run a
    // wal_checkpoint(TRUNCATE) so any drained pages migrate from the
    // WAL into the main file — a cheap partial cleanup.
    //
    // v1.21.5-rc.3 (#21, broadening the rc.2 pinned-WAL back-off): probe WAL
    // drainability ONCE up front. Every write-amplifying maintenance op below —
    // incremental_vacuum, the full VACUUM, AND the FTS merge — can only reclaim
    // space if the WAL can be checkpoint-truncated. Under a reader pin (typically
    // the dashboard's read-only events.db connection) it cannot, so running them
    // reclaims nothing and only grows the pinned sidecar further — the exact CPU/
    // WAL churn we are trying to avoid. rc.2 skipped only the full VACUUM; skip
    // all three under a pin and defer to a sweep where the reader has released
    // (the prune above already bounded the working set).
    await eventStore.walCheckpointTruncate()
    let walPinnedMB = measureWalMB(dbPath: dbPath)
    // rc.36: compare against the WAL's own configured limit, in the same units.
    // This was `walPinnedMB > 64`, but measureWalMB returns DECIMAL MB while
    // journalSizeLimitBytes is 67_108_864 (64 MiB). SQLite truncates an
    // oversized WAL down to exactly that limit, which measures as 67 decimal MB
    // — so a WAL resting at its designed ceiling reported itself as
    // reader-pinned, and incremental_vacuum / VACUUM / FTS merge were skipped
    // on every sweep with no reader involved at all.
    // Mirrors StoragePragmas.journalSizeLimitBytes (64 MiB). That type is
    // internal to MacCrabCore, so the value is restated rather than widening
    // its visibility for one comparison.
    let walLimitBytes: Int64 = 64 * 1_024 * 1_024
    let walBytes = measureWalBytes(dbPath: dbPath)
    let walPinned = walBytes > walLimitBytes
    if walPinned {
        logger.warning("Tier-rollup: events.db-wal measured \(walPinnedMB) MB, above its \(walLimitBytes / 1_048_576) MiB limit — consistent with a reader holding a read transaction on events.db (typically the dashboard's read-only connection), though this is a size measurement rather than a confirmed reader. incremental_vacuum / full VACUUM / FTS-merge are SKIPPED this sweep (they cannot reclaim a reader-pinned WAL and would only grow it); they resume once the WAL drains.")
    }

    // Power/thermal gate for the heavy maintenance below (also gates the FTS
    // optimize). A whole-file rewrite / full index compaction is non-urgent.
    let underPowerPressure = PowerGate.pollIntervalMultiplier > 1.0

    // rc.3+ perf (on-device): the reclaim must also run when the DB is over cap
    // WITHOUT any event prune. The events_fts index accumulates delete-marker
    // segments faster than the bounded incremental merge compacts them, so on a
    // churned DB it can dwarf the live events (measured: 400 MB FTS / ~104K
    // segments backing a near-empty events table → 500 MB total, permanently over
    // the 420 MB cap and inflating RSS via the mmap). The old `totalPruned > 0`
    // gate never reclaimed that — nothing was being pruned. Compact the FTS with a
    // full `optimize` (frees its pages to the freelist), then let the
    // incremental_vacuum / VACUUM below return them to the OS.
    guard let footprintBeforeReclaimBytes = currentFootprint("before reclaim") else {
        return
    }
    let overCap = footprintBeforeReclaimBytes > targetSizeBytes
    // v1.21.7: `overCap` deliberately REMOVED from the optimize condition.
    //
    // Gating compaction on already being over cap creates a failure class where
    // a host that stays under cap never compacts — so events_fts accumulates
    // tombstones untouched until the INDEX ITSELF forces the crossing. Measured
    // trajectory before this: the index reached 180.6 MB in ~81 days, at which
    // point it was 44% of the store and the dominant reason the cap was
    // unreachable. Compacting only once the damage is done is the same
    // wait-for-the-fire posture the admission deadlock had.
    //
    // `optimizeFTS` carries its own 6-hour rate limit, which is the real
    // governor and is well calibrated: measured over a full interval it held the
    // index to a 3.90-28.81 MB sawtooth, and the post-optimize floor FELL across
    // five passes. Cost is 4 passes/day at 0.138-0.399 s each — about 1.6 s/day
    // of actor time. `walPinned` and `underPowerPressure` still apply, so this
    // never runs while a reader pins the WAL or the machine is under thermal or
    // battery pressure.
    if !walPinned && !underPowerPressure {
        guard let ftsStart = currentFootprint("before FTS optimize") else {
            return
        }
        if await eventStore.optimizeFTS() {
            _ = await eventStore.walCheckpoint()   // move optimize's freed pages out of the WAL
            logger.notice("Tier-rollup: FTS optimize compacted events_fts (\(ftsStart) byte footprint, \(targetSizeBytes)-byte target, overCap=\(overCap)) — pages freed for reclamation")
        }
    }

    // v1.21.6-rc.45: reclaim ALSO when the file is holding reclaimable slack,
    // even if this sample says we are under target.
    //
    // `overCap` is measured immediately after `walCheckpointTruncate()` above —
    // the TROUGH of the cycle. Storage admission judges the family at its PEAK
    // (main + a regrown WAL + one transaction reserve). A store can therefore
    // sit permanently a megabyte or two under `targetSizeBytes` at this sample
    // instant, skip the reclaim on every sweep, and still pause ingestion
    // seconds later when the WAL grows back.
    //
    // Measured on an installed host (rc.44, 2026-08-30): events.db was
    // 350,703,616 bytes of which 79,300 of 85,621 pages were freelist — 311 MiB
    // of reclaimable slack behind live data of 23 MiB. The post-truncate
    // footprint landed at 350,834,688 against a 352,321,536 target, i.e. 1.4 MiB
    // UNDER, so `overCap` was false; nothing was prunable either, because every
    // retained row was inside the 15-minute forensic floor, so `totalPruned` was
    // 0. The gate below was therefore false on 309 consecutive sweeps across 8
    // hours while the engine shed 48,193 events under `footprint_limit`. One
    // unbounded `incremental_vacuum` on a byte-identical copy returned all of it
    // in 3.0 s (350,703,616 -> 31,264,768 bytes).
    //
    // This is the same failure class the FTS-optimize condition twelve lines
    // above was corrected for ("gating compaction on already being over cap
    // creates a failure class where a host that stays under cap never
    // compacts"), and the same aliased-instant error as the runtime drain fix.
    // Free pages must never be the reason admission refuses a write.
    //
    // The floor keeps ordinary retention churn from truncating and regrowing the
    // file every sweep: slack has to accumulate to `reclaimableSlackFloorBytes`
    // again before this fires a second time. Each call is independently bounded
    // by EventStore's admission-derived page plan (~one transaction reserve),
    // so a large backlog drains over several sweeps rather than in one stall.
    let reclaimableSlackBytes = await eventStore.reclaimableFreelistBytes()
    let hasReclaimableSlack = reclaimableSlackBytes >= reclaimableSlackFloorBytes
    if StorageReclaimDecision.shouldReclaim(
        totalPruned: totalPruned,
        footprintBytes: footprintBeforeReclaimBytes,
        targetBytes: targetSizeBytes,
        reclaimableSlackBytes: reclaimableSlackBytes,
        walPinned: walPinned
    ) {
        guard let dbSizeBeforePrune = currentFootprint("before incremental vacuum") else {
            return
        }
        let reclaimed = (try? await eventStore.incrementalVacuum(maxPages: 200_000)) ?? 0
        guard let dbSizeAfterIncremental = currentFootprint("after incremental vacuum") else {
            return
        }
        if reclaimed > 0 {
            logger.notice("Tier-rollup: incremental_vacuum reclaimed \(reclaimed) pages, \(dbSizeBeforePrune) bytes → \(dbSizeAfterIncremental) bytes")
        } else if hasReclaimableSlack {
            // Never let this be invisible again. The old code logged only on
            // success, so a reclaim that was skipped and a reclaim that failed
            // produced byte-identical logs: nothing at all.
            logger.warning("Tier-rollup: incremental_vacuum reclaimed NOTHING while \(reclaimableSlackBytes) bytes of freelist slack were available (footprint \(dbSizeBeforePrune) bytes, target \(targetSizeBytes) bytes). The store cannot return space it already owns; ingestion may pause under a footprint limit that is mostly reclaimable slack.")
        }

        let vacuumHeadroom = fullVacuumHeadroom(dbPath: dbPath)
        // v1.18 (audit): incremental_vacuum (above) already returns freed pages to
        // the OS, so a DB that is now under target needs no full-file rebuild.
        // Reserve the expensive full VACUUM (whole-file copy — ~3 min + a pinned
        // CPU core on a ~400MB DB, and it trips the macOS disk-writes monitor) for
        // the genuinely-still-over-target case; otherwise just checkpoint the WAL.
        // This ends the hourly full-VACUUM write-amplification the audit found
        // (which was driven by the evidence-cap bug keeping the DB permanently
        // over cap → Layer-3 firing every tick → totalPruned>0 → VACUUM every tick).
        // v1.19.1 (audit): also defer the heavy full VACUUM under battery /
        // thermal pressure. A whole-file rewrite (~3 min, a pinned core, hundreds
        // of MB of writes) is non-urgent maintenance that shouldn't run on
        // battery or while thermally throttled — incremental_vacuum already
        // reclaimed pages above and the WAL is checkpointed below, so the cap
        // still trends down; the full rebuild waits for AC / nominal thermal.
        // (`underPowerPressure` is computed once above, before the FTS optimize.)

        // The full VACUUM only helps when its pre/post checkpoint can drain the
        // WAL; the up-front `walPinned` probe already gated this whole block on
        // that (a reader-pinned WAL is skipped entirely), so here we only choose
        // between the full rebuild and a cheap checkpoint.
        if dbSizeAfterIncremental > targetSizeBytes
            && vacuumHeadroom?.admitted == true
            && !underPowerPressure {
            // Only rebuild while rebuilding is actually converging. When the
            // configured cap puts `targetSizeBytes` below the events.db footprint
            // floor, this branch is true on EVERY sweep forever and the
            // whole-file VACUUM becomes perpetual write amplification. See
            // SizeCapConvergence for the measurement and why a load-time clamp
            // can't substitute for it.
            if SizeCapConvergence.shouldFullVacuum() {
                do {
                    // Serialize checkpoint -> operation-boundary headroom probe
                    // -> VACUUM on the writer actor. A detached connection could
                    // race arbitrarily many ingestion commits between its stat
                    // and SQLite acquiring the writer lock, invalidating the
                    // disk-safety proof.
                    try await eventStore.vacuum()
                } catch {
                    logger.warning("Tier-rollup VACUUM failed: \(error.localizedDescription, privacy: .public)")
                }
                guard let afterVacuumBytes = currentFootprint("after full vacuum") else {
                    return
                }
                if SizeCapConvergence.record(converged: afterVacuumBytes <= targetSizeBytes) {
                    logger.error("Tier-rollup: events.db size cap is UNREACHABLE — \(SizeCapConvergence.failureLimit) consecutive full VACUUMs left the footprint at \(afterVacuumBytes) bytes against a \(targetSizeBytes)-byte target. The measured floor (schema + legacy alert_evidence + events_fts + retained rows + WAL) exceeds the effective event-family target, so rebuilding cannot converge and was rewriting the whole file every sweep. Full VACUUM suppressed for \(Int(SizeCapConvergence.backoffSeconds / 3600)) h. Adjust the legacy events envelope/evidence allocation or reduce indexed event bytes.")
                }
            } else {
                logger.notice("Tier-rollup: full VACUUM suppressed — the size cap was measured unreachable (see the cap-unreachable error). Checkpointing the WAL instead; prune + incremental_vacuum still ran, so the working set stays bounded.")
                await eventStore.walCheckpoint()
            }
        } else if dbSizeAfterIncremental > targetSizeBytes && underPowerPressure {
            logger.notice("Tier-rollup: deferring full VACUUM under power/thermal pressure (poll-multiplier \(PowerGate.pollIntervalMultiplier)); incremental_vacuum reclaimed \(reclaimed) pages → \(dbSizeAfterIncremental) bytes. Checkpointing WAL; full rebuild will run on AC / nominal thermal.")
            await eventStore.walCheckpoint()
        } else if dbSizeAfterIncremental > targetSizeBytes {
            let freeMB = Int((vacuumHeadroom?.freeSpaceBytes ?? 0) / 1_000_000)
            let needMB = Int((vacuumHeadroom?.requiredFreeBytes ?? Int64.max) / 1_000_000)
            logger.warning("Tier-rollup: full VACUUM skipped by shared headroom gate (need \(needMB) MB free, have \(freeMB) MB); incremental_vacuum remains the low-space recovery path.")
            await eventStore.walCheckpoint()
        } else {
            logger.notice("Tier-rollup: incremental_vacuum reclaimed \(reclaimed) pages → \(dbSizeAfterIncremental) bytes (target \(targetSizeBytes) bytes); full VACUUM not needed, running checkpoint(TRUNCATE) for WAL cleanup.")
            await eventStore.walCheckpoint()
        }
    }

    // v1.21.4 Tier-A perf: compact the events_fts index OFF the hot write
    // path. Its per-insert automerge is deferred to the crisismerge threshold
    // (16) in EventStore.openDatabase, so the index is merged here on the background
    // sweep cadence instead of on every insert flush. Runs unconditionally
    // (segments accrue from inserts, not from prunes) with a bounded page
    // budget so the actor stays responsive; a no-op when there is nothing to
    // merge. DETECTION-SAFE: events_fts feeds only search()/hunt, never the
    // detection engine — this changes hunt latency, never any detection result.
    // #21: skipped under a reader pin — its merge frames can't be checkpointed
    // out of a pinned WAL and would only grow it; deferred to an unpinned sweep.
    // rc.36: ceiling recovery runs UNCONDITIONALLY, ahead of the walPinned gate.
    // rc.34 put `recoverExhaustedFTSIndexIfNeeded()` inside mergeFTS, which sits
    // behind this gate — so the one operation that rescues an index stuck at its
    // 2000-segid ceiling was skipped exactly when a pinned WAL made the store
    // most stressed. A rebuild is not a merge: it is the escape hatch, and
    // deferring it can leave the engine unable to boot at all.
    await eventStore.recoverExhaustedFTSIndexIfNeededForSweep()
    if !walPinned {
        await eventStore.mergeFTS()
    }

    // v1.21.4 perf (#23): reclaim the events.db-wal sidecar. Raising
    // `eventWalAutocheckpointPages` to 16 MB lets the WAL settle at a ~16 MB
    // high-water mark (vs ~4 MB before) to cut per-write PASSIVE-checkpoint
    // frequency during the flood. A RESTART checkpoint drains WAL *content*
    // but leaves the *file* at that mark; TRUNCATE zeroes the sidecar. Run it
    // once per sweep (unconditionally, like the trace/tracegraph sweeps above)
    // so the raise is footprint-neutral in steady state. Placed after
    // mergeFTS() so the merge's own WAL frames are drained too, and before the
    // endMB measurement so the log reflects the reclaimed sidecar. Best-effort;
    // degrades to RESTART-like progress under an active reader.
    await eventStore.walCheckpointTruncate()

    guard let endBytes = currentFootprint("finish") else { return }
    if startSizeBytes != endBytes || totalPruned > 0 {
        logger.notice("Tier-rollup sweep complete: DB \(startSizeBytes) bytes → \(endBytes) bytes, pruned \(totalPruned) events total.")
    }
}

/// Free disk space at the volume containing `path`, in megabytes.
/// Returns 0 on stat failure (VACUUM callers treat 0 as "not enough headroom";
/// BatchedEventWriter's admission check treats 0 as "probe failed, allow the
/// write" — halting all telemetry on a transient stat glitch would be worse
/// than the disk pressure it guards against).
func freeDiskMB(forPath path: String) -> Int {
    var stat = statvfs()
    guard statvfs((path as NSString).utf8String, &stat) == 0 else { return 0 }
    let bytes = UInt64(stat.f_bavail) * UInt64(stat.f_frsize)
    return Int(bytes / 1_000_000)
}

/// Exact-byte advisory preflight for whole-file VACUUM branch selection.
/// Store methods repeat the same shared probe immediately before executing
/// VACUUM so a caller-side success can never authorize a raced low-space run.
func fullVacuumHeadroom(
    dbPath: String
) -> SQLiteFullVacuumAdmissionSnapshot? {
    try? SQLitePersistentStoreAdmission.inspectFullVacuumHeadroom(
        databasePath: dbPath,
        storageVolumePath: (dbPath as NSString).deletingLastPathComponent,
        freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes
    )
}

// MARK: - Alerts family recovery

/// Enforce the two logical alerts.db ownership budgets and the stricter
/// physical family boundary used by ordinary write admission.
///
/// Returns `true` when a checkpoint or mutation/reclaim pass ran. A false
/// result means the exact family and both ownership budgets already needed no
/// work (or the authoritative family could not be measured safely).
@discardableResult
/// Shared alerts-family overhead that belongs to NEITHER component budget:
/// SQLite indexes, the WAL, and freelist pages.
///
/// The family cap is exactly `alertsMaxSizeMB + evidenceMaxSizeMB`, so with
/// both components at their own caps the family necessarily exceeds the
/// boundary that gates writes, both component enforcers correctly do nothing,
/// and only the family pass can clear it. Measured on the reference host at the
/// moment alert-evidence writes paused: `alert_evidence` 99.9 MB (at its cap),
/// `alerts` 78.3 MB (under its cap), indexes ~4.6 MB and WAL ~4.3 MB on top,
/// family 1,592 bytes past the admission boundary.
///
/// Trim each component by a share of this instead of enlarging the family, so
/// the operator still gets exactly the total they configured and the two
/// components can coexist inside it. Proportional with a ceiling so a small
/// configured cap is not trimmed to nothing.
func alertsFamilyComponentTrimBytes(componentCapBytes: Int64) -> Int64 {
    // 12 MiB, not 8. At the shipped 100 MiB component caps an 8 MiB trim leaves
    // 2 x 92 + 9 = 193 MiB against a 192 MiB admission boundary -- still over,
    // by a megabyte, and that is before freelist pages are counted at all.
    // 12 MiB gives 2 x 88 = 176 MiB, so the measured ~9 MiB of indexes and WAL
    // fit with room for the freelist to breathe.
    let ceiling = 12 * SQLitePersistentStorePolicy.bytesPerMiB
    return max(0, min(ceiling, componentCapBytes / 8))
}

func enforceAlertsSizeCap(
    alertStore: AlertStore,
    dbPath: String,
    alertCapBytes: Int64,
    evidenceCapBytes: Int64,
    boundary: AlertsSizeCapBoundary,
    forceConvergenceToTarget: Bool = false
) async -> Bool {
    var changed = false
    var maintenanceRan = false

    // Leave room for the shared family overhead so both components can sit at
    // their targets without pushing the family past the write boundary.
    let evidenceTargetBytes = max(
        SQLitePersistentStorePolicy.bytesPerMiB,
        evidenceCapBytes - alertsFamilyComponentTrimBytes(
            componentCapBytes: evidenceCapBytes
        )
    )
    let alertTargetBytes = max(
        SQLitePersistentStorePolicy.bytesPerMiB,
        alertCapBytes - alertsFamilyComponentTrimBytes(
            componentCapBytes: alertCapBytes
        )
    )

    do {
        let pruned = try await alertStore.enforceAlertEvidenceBudget(
            maxBytes: evidenceTargetBytes
        )
        if pruned.perAlert > 0 || pruned.bySize > 0 {
            changed = true
            logger.warning("Alert evidence cap: pruned \(pruned.perAlert) over per-alert row ceiling and \(pruned.bySize) over the \(evidenceTargetBytes)-byte evidence target (cap \(evidenceCapBytes) less shared family overhead)")
        }
    } catch {
        logger.error("Alert evidence cap enforcement failed: \(error.localizedDescription, privacy: .public)")
    }

    // Enforce the alert-row ownership budget using DBSTAT pages belonging only
    // to alerts + its indexes (not evidence).
    if let alertOwned = try? await alertStore.alertsAllocatedBytes(),
       alertOwned > alertTargetBytes {
        let total = (try? await alertStore.count()) ?? 0
        let overFraction = Double(alertOwned - alertTargetBytes)
            / Double(max(1, alertOwned))
        let dropTarget = max(
            1,
            Int(Double(total) * min(1, overFraction + 0.1))
        )
        let dropped = (try? await alertStore.pruneOldest(
            count: dropTarget
        )) ?? 0
        changed = changed || dropped > 0
        logger.warning("Alert-row cap: pruned \(dropped) oldest alerts (owned=\(alertOwned) bytes > target \(alertTargetBytes), cap \(alertCapBytes); rows=\(dropTarget)); evidence cascaded with each parent")
    }

    var beforeFamily: Int64
    do {
        beforeFamily = try measureDatabaseFootprintBytes(dbPath: dbPath)
    } catch {
        logger.fault("Alerts family cap: authoritative DB+WAL+SHM probe failed; refusing family maintenance: \(error.localizedDescription, privacy: .public)")
        return changed
    }

    // A WAL-only excursion can clear without sacrificing alert history. Drain
    // it once before selecting parents, then make the deletion decision from a
    // fresh exact-family measurement. Failure is non-fatal: deletion and
    // incremental reclaim remain the bounded recovery route.
    func requiresFamilyRecovery(_ footprintBytes: Int64) -> Bool {
        boundary.requiresMaintenance(footprintBytes: footprintBytes)
            || (forceConvergenceToTarget
                && boundary.requiresStartupConvergence(
                    footprintBytes: footprintBytes
                ))
    }
    var familyPressure = requiresFamilyRecovery(beforeFamily)
    if familyPressure {
        maintenanceRan = true
    }
    if familyPressure, await alertStore.walCheckpointTruncate() {
        do {
            beforeFamily = try measureDatabaseFootprintBytes(dbPath: dbPath)
            familyPressure = requiresFamilyRecovery(beforeFamily)
        } catch {
            logger.fault("Alerts family cap: post-checkpoint family probe failed; refusing row deletion: \(error.localizedDescription, privacy: .public)")
            return true
        }
    }

    // Defense in depth for allocator/index/freelist overhead. This must use the
    // ordinary write boundary (cap - transaction reserve), not the nominal cap:
    // the interval between those values is already shed-only.
    if familyPressure {
        let total = (try? await alertStore.count()) ?? 0
        let overFraction = Double(
            max(0, beforeFamily - boundary.recoveryTargetBytes)
        ) / Double(max(1, beforeFamily))
        let dropTarget = max(
            1,
            Int(Double(total) * min(1, overFraction + 0.1))
        )
        let dropped = (try? await alertStore.pruneOldest(
            count: dropTarget
        )) ?? 0
        changed = changed || dropped > 0
        let triggerBoundary = forceConvergenceToTarget
            ? boundary.recoveryTargetBytes
            : boundary.hardAdmissionBoundaryBytes
        logger.warning("Alerts family admission recovery: pruned \(dropped) oldest alerts (db+wal+shm=\(beforeFamily) bytes > trigger boundary \(triggerBoundary), recovery target \(boundary.recoveryTargetBytes), row target \(dropTarget))")
    }

    guard changed || familyPressure else { return maintenanceRan }

    let postPruneBytes = (try? measureDatabaseFootprintBytes(
        dbPath: dbPath
    )) ?? beforeFamily
    let reclaimed = (try? await alertStore.incrementalVacuum(
        maxPages: 200_000
    )) ?? 0
    guard let postIncrementalBytes = try? measureDatabaseFootprintBytes(
        dbPath: dbPath
    ) else {
        logger.fault("Alerts size cap: post-incremental family probe failed; refusing full VACUUM")
        return true
    }
    if reclaimed > 0 {
        logger.notice("Alerts size cap: incremental_vacuum reclaimed \(reclaimed) pages, \(postPruneBytes) bytes → \(postIncrementalBytes) bytes")
    }

    var finalBytes = postIncrementalBytes
    if familyPressure,
       postIncrementalBytes > boundary.recoveryTargetBytes {
        // Caller-side selection uses the same exact-byte requirement as the
        // operation-time gate inside AlertStore.
        let headroom = fullVacuumHeadroom(dbPath: dbPath)
        let freeMB = Int((headroom?.freeSpaceBytes ?? 0) / 1_000_000)
        let needMB = Int(
            (headroom?.requiredFreeBytes ?? Int64.max) / 1_000_000
        )
        if headroom?.admitted == true {
            do {
                try await alertStore.vacuum()
                finalBytes = (try? measureDatabaseFootprintBytes(
                    dbPath: dbPath
                )) ?? finalBytes
                logger.notice("Alerts size cap: full VACUUM complete — \(postIncrementalBytes) bytes → \(finalBytes) bytes")
            } catch {
                logger.warning("Alerts size cap: full VACUUM failed (\(error.localizedDescription)). incremental_vacuum reclaimed \(reclaimed) pages.")
            }
        } else if reclaimed == 0 {
            logger.warning("Alerts size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB) AND incremental_vacuum was no-op. File size unchanged.")
        } else {
            logger.warning("Alerts size cap: full VACUUM skipped (need \(needMB) MB free, have \(freeMB) MB). incremental_vacuum still reclaimed \(reclaimed) pages.")
        }
    }

    if requiresFamilyRecovery(finalBytes) {
        let requiredBoundary = forceConvergenceToTarget
            ? boundary.recoveryTargetBytes
            : boundary.hardAdmissionBoundaryBytes
        logger.fault("Alerts size cap: recovery left db+wal+shm at \(finalBytes) bytes above the \(requiredBoundary)-byte required boundary; alert persistence remains unready until a later maintenance pass succeeds")
    } else if familyPressure {
        logger.notice("Alerts size cap: family recovered \(beforeFamily) bytes → \(finalBytes) bytes (write boundary \(boundary.hardAdmissionBoundaryBytes), target \(boundary.recoveryTargetBytes))")
    }
    return true
}

/// Periodic production entry point. Setup uses the bounded pre-construction
/// wrapper below; the hourly timer retains this helper's historical `didRun`
/// meaning. Derive the boundary from the actor's live admission snapshot so a
/// SIGHUP policy and the maintenance decision cannot disagree about reserve.
@discardableResult
/// Whether the alerts family currently sits above the boundary that gates
/// alert-evidence writes.
///
/// The scheduled family pass runs hourly with a one-hour first fire, but the
/// condition it repairs PAUSES evidence persistence for as long as it lasts.
/// Observed on the reference host: writes paused with the family 1,592 bytes
/// over the admission boundary while BOTH component budgets were individually
/// satisfied -- `alert_evidence` at its 100 MiB cap and `alerts` under its own
/// -- because the family cap is exactly their sum and carries the indexes, WAL,
/// free pages and transaction reserve on top. Only the family pass can clear
/// that, so waiting up to an hour for it is a visible loss of evidence capture.
func alertsFamilyBlocksWrites(state: DaemonState) async -> Bool {
    let admission = await state.alertStore.storageAdmissionSnapshot()
    let boundary = AlertsSizeCapBoundary(
        nominalCapBytes: admission?.maxFootprintBytes
            ?? AlertStore.combinedFamilyCapBytes(
                alertsMaxSizeMiB: state.storage.alertsMaxSizeMB,
                evidenceMaxSizeMiB: state.storage.evidenceMaxSizeMB
            ),
        transactionReserveBytes: admission?.transactionReserveBytes
            ?? 8 * SQLitePersistentStorePolicy.bytesPerMiB
    )
    guard let footprint = try? measureDatabaseFootprintBytes(
        dbPath: state.supportDir + "/alerts.db"
    ) else {
        // An unreadable probe is not evidence of pressure; the hourly pass owns
        // that case and logs it.
        return false
    }
    return boundary.requiresMaintenance(footprintBytes: footprint)
}

func enforceAlertsSizeCapNow(state: DaemonState) async -> Bool {
    let alertsPath = state.supportDir + "/alerts.db"
    let evidenceCapBytes = SQLitePersistentStorePolicy.capBytes(
        maxSizeMiB: state.storage.evidenceMaxSizeMB
    )
    let alertCapBytes = SQLitePersistentStorePolicy.capBytes(
        maxSizeMiB: state.storage.alertsMaxSizeMB
    )
    let configuredFamilyCap = AlertStore.combinedFamilyCapBytes(
        alertsMaxSizeMiB: state.storage.alertsMaxSizeMB,
        evidenceMaxSizeMiB: state.storage.evidenceMaxSizeMB
    )
    let admission = await state.alertStore.storageAdmissionSnapshot()
    let boundary = AlertsSizeCapBoundary(
        nominalCapBytes: admission?.maxFootprintBytes
            ?? configuredFamilyCap,
        transactionReserveBytes: admission?.transactionReserveBytes
            ?? 8 * SQLitePersistentStorePolicy.bytesPerMiB
    )
    return await enforceAlertsSizeCap(
        alertStore: state.alertStore,
        dbPath: alertsPath,
        alertCapBytes: alertCapBytes,
        evidenceCapBytes: evidenceCapBytes,
        boundary: boundary
    )
}

/// Setup-time recovery that runs before collector construction. Unlike the
/// hourly helper, its result means ordinary write readiness, not merely that a
/// maintenance pass ran.
func recoverAlertStoreBeforeProducers(
    alertStore: AlertStore,
    dbPath: String,
    alertCapBytes: Int64,
    evidenceCapBytes: Int64,
    boundary: AlertsSizeCapBoundary,
    maximumPasses: Int = preIngestionStorageRecoveryMaximumPasses
) async -> PreIngestionStorageRecoveryResult {
    await runBoundedPreIngestionStorageRecovery(
        component: "AlertStore",
        maximumPasses: maximumPasses,
        measureFootprint: {
            try measureDatabaseFootprintBytes(dbPath: dbPath)
        },
        maintenance: {
            // v1.22.0 (item 2, boot <3s): mirror recoverEventStoreBeforeProducers,
            // which gates its WAL checkpoint behind requiresStartupConvergence. An
            // already-converged alerts family needs neither the WAL TRUNCATE (a
            // real fsync) nor a family prune, so skip the checkpoint when the
            // family sits under the maintenance/convergence boundary — this was
            // unconditional on every boot before. Per-alert evidence enforcement
            // inside enforceAlertsSizeCap stays unconditional (a single alert can
            // exceed the per-alert row cap while the family is under its cap).
            //
            // A GUI/read-only transaction can pin the WAL. Prove drainability
            // before the enforcer is allowed to prune any parent rows; a
            // failed preflight gets a short bounded no-delete grace in the
            // outer loop instead of repeating destructive maintenance.
            let footprint = (try? measureDatabaseFootprintBytes(dbPath: dbPath))
                ?? boundary.nominalCapBytes
            if boundary.requiresMaintenance(footprintBytes: footprint)
                || boundary.requiresStartupConvergence(footprintBytes: footprint) {
                guard await alertStore.walCheckpointTruncate() else {
                    return .transientlyPinned
                }
            }
            let ran = await enforceAlertsSizeCap(
                alertStore: alertStore,
                dbPath: dbPath,
                alertCapBytes: alertCapBytes,
                evidenceCapBytes: evidenceCapBytes,
                boundary: boundary,
                forceConvergenceToTarget: true
            )
            return ran ? .ran : .didNotRun
        },
        reprobeOrdinaryAdmission: {
            let snapshot = try await alertStore
                .reprobeStorageAdmissionForWrite()
            guard snapshot.maxFootprintBytes == boundary.nominalCapBytes,
                  snapshot.transactionReserveBytes
                    == boundary.transactionReserveBytes else {
                throw PreIngestionStorageRecoveryError
                    .admissionPolicyMismatch(
                        component: "AlertStore",
                        expectedCapBytes: boundary.nominalCapBytes,
                        actualCapBytes: snapshot.maxFootprintBytes,
                        expectedReserveBytes:
                            boundary.transactionReserveBytes,
                        actualReserveBytes:
                            snapshot.transactionReserveBytes
                    )
            }
            let footprint = try measureDatabaseFootprintBytes(dbPath: dbPath)
            guard !boundary.requiresStartupConvergence(
                footprintBytes: footprint
            ) else {
                throw PreIngestionStorageRecoveryError
                    .startupTargetNotReached(
                        component: "AlertStore",
                        footprintBytes: footprint,
                        targetBytes: boundary.recoveryTargetBytes
                    )
            }
        }
    )
}

// MARK: - On-demand sweep entry point (v1.6.14)

/// Trigger a size-cap sweep immediately, outside the hourly timer.
/// Used by the SIGHUP handler so operators can lower the cap in
/// Settings, send SIGHUP, and see the DB shrink in seconds instead
/// of waiting up to an hour for the next tick. Reads cap + target
/// from `state` so the freshly-reloaded `DaemonConfig` is honored.
///
/// v1.9.0 (audit Stab-M1): returns `true` when the sweep actually
/// ran, `false` when it was skipped because another sweep was
/// already in progress (`EventStore.beginSizeCapPrune` returned
/// false). Callers (SIGUSR2 handler) use the return value to avoid
/// overwriting the running sweep's pending status snapshot with a
/// stale "after" measurement.
@discardableResult
func enforceDatabaseSizeCapNow(state: DaemonState) async -> Bool {
    let boundary = EventsSizeCapBoundary(
        maxSizeMiB: state.storage.effectiveEventsFamilyMaxSizeMB(
            appliedLegacyEvidenceTransitionReserveMiB:
                state.legacyEvidenceTransitionBudget.snapshot()
                    .appliedReserveMiB
        )
    )
    let dbFilePath = state.supportDir + "/events.db"
    let ran = await enforceDatabaseSizeCap(
        dbPath: dbFilePath,
        boundary: boundary,
        eventStore: state.eventStore,
        processFloorMinutes: max(0, state.storage.processEventsFloorMinutes)
    )
    if ran {
        state.eventRetentionBudgetHealth.recordSweep(
            observedFootprintBytes: try? measureDatabaseFootprintBytes(
                dbPath: dbFilePath
            ),
            boundary: boundary
        )
    }
    return ran
}

/// Setup-time events.db recovery. The signal/hourly entry point above retains
/// its historical `didRun` Bool; this wrapper instead requires normal priority
/// and file admission at their complete transaction reserves before it reports
/// a writable first epoch.
func recoverEventStoreBeforeProducers(
    eventStore: EventStore,
    dbPath: String,
    boundary: EventsSizeCapBoundary,
    processFloorMinutes: Int,
    retentionBudgetHealth: EventRetentionBudgetHealth,
    maximumPasses: Int = preIngestionStorageRecoveryMaximumPasses,
    onTransientPinRetry: @Sendable (Int) -> Void = { _ in }
) async -> PreIngestionStorageRecoveryResult {
    let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
    return await runBoundedPreIngestionStorageRecovery(
        component: "EventStore",
        maximumPasses: maximumPasses,
        onTransientPinRetry: onTransientPinRetry,
        measureFootprint: {
            try measureDatabaseFootprintBytes(dbPath: dbPath)
        },
        maintenance: {
            guard let footprint = try? measureDatabaseFootprintBytes(
                dbPath: dbPath
            ) else {
                return .didNotRun
            }
            if boundary.requiresStartupConvergence(
                footprintBytes: footprint
            ) {
                // The enforcer prunes rows before its own checkpoint. A
                // reader-pinned WAL therefore has to be detected here, while
                // it is still safe to retry without repeating any deletion.
                guard await eventStore.walCheckpointTruncate() else {
                    return .transientlyPinned
                }
            }
            let ran = await enforceDatabaseSizeCap(
                dbPath: dbPath,
                boundary: boundary,
                eventStore: eventStore,
                processFloorMinutes: max(0, processFloorMinutes),
                forceConvergenceToTarget: true
            )
            if ran {
                retentionBudgetHealth.recordSweep(
                    observedFootprintBytes:
                        try? measureDatabaseFootprintBytes(dbPath: dbPath),
                    boundary: boundary
                )
                // The UI can acquire a new read snapshot after the safe
                // preflight but while prune/vacuum maintenance is running.
                // A partial checkpoint then temporarily materializes the same
                // committed pages in both the main file and its pinned WAL.
                // Detect that post-maintenance race explicitly so the bounded
                // outer loop gives the reader its no-delete grace instead of
                // misclassifying the doubled family as permanent no-progress.
                if let after = try? measureDatabaseFootprintBytes(
                    dbPath: dbPath
                ), boundary.requiresStartupConvergence(
                    footprintBytes: after
                ), await eventStore.walCheckpointTruncate() == false {
                    return .ranThenTransientlyPinned
                }
            }
            return ran ? .ran : .didNotRun
        },
        reprobeOrdinaryAdmission: {
            let priority = try await eventStore
                .reprobeStorageAdmissionForWrite(lane: .priority)
            guard priority.maxFootprintBytes == boundary.nominalCapBytes,
                  priority.transactionReserveBytes == reserve else {
                throw PreIngestionStorageRecoveryError
                    .admissionPolicyMismatch(
                        component: "EventStore priority lane",
                        expectedCapBytes: boundary.nominalCapBytes,
                        actualCapBytes: priority.maxFootprintBytes,
                        expectedReserveBytes: reserve,
                        actualReserveBytes:
                            priority.transactionReserveBytes
                    )
            }
            let file = try await eventStore
                .reprobeStorageAdmissionForWrite(lane: .file)
            guard file.maxFootprintBytes == boundary.nominalCapBytes,
                  file.transactionReserveBytes == reserve else {
                throw PreIngestionStorageRecoveryError
                    .admissionPolicyMismatch(
                        component: "EventStore file lane",
                        expectedCapBytes: boundary.nominalCapBytes,
                        actualCapBytes: file.maxFootprintBytes,
                        expectedReserveBytes: reserve,
                        actualReserveBytes: file.transactionReserveBytes
                    )
            }
            let footprint = try measureDatabaseFootprintBytes(dbPath: dbPath)
            guard !boundary.requiresStartupConvergence(
                footprintBytes: footprint
            ) else {
                throw PreIngestionStorageRecoveryError
                    .startupTargetNotReached(
                        component: "EventStore",
                        footprintBytes: footprint,
                        targetBytes: boundary.targetBytes
                    )
            }
        }
    )
}

/// Fresh no-maintenance proof taken at the last activation boundary. Recovery
/// may have completed much earlier while other actors were constructed, so its
/// retained result cannot authorize collectors after a sidecar/free-space
/// drift. The exact target check also refreshes the first heartbeat's sticky
/// retention-budget truth.
func reprobeEventStoreAtActivationBoundary(
    eventStore: EventStore,
    dbPath: String,
    boundary: EventsSizeCapBoundary,
    retentionBudgetHealth: EventRetentionBudgetHealth
) async throws -> EventStoreActivationProof {
    let reserve = SQLitePersistentStorePolicy.eventTransactionReserveBytes
    let priority = try await eventStore.reprobeStorageAdmissionForWrite(
        lane: .priority
    )
    guard priority.maxFootprintBytes == boundary.nominalCapBytes,
          priority.transactionReserveBytes == reserve else {
        throw PreIngestionStorageRecoveryError.admissionPolicyMismatch(
            component: "EventStore priority lane",
            expectedCapBytes: boundary.nominalCapBytes,
            actualCapBytes: priority.maxFootprintBytes,
            expectedReserveBytes: reserve,
            actualReserveBytes: priority.transactionReserveBytes
        )
    }

    let file = try await eventStore.reprobeStorageAdmissionForWrite(
        lane: .file
    )
    guard file.maxFootprintBytes == boundary.nominalCapBytes,
          file.transactionReserveBytes == reserve else {
        throw PreIngestionStorageRecoveryError.admissionPolicyMismatch(
            component: "EventStore file lane",
            expectedCapBytes: boundary.nominalCapBytes,
            actualCapBytes: file.maxFootprintBytes,
            expectedReserveBytes: reserve,
            actualReserveBytes: file.transactionReserveBytes
        )
    }

    let footprint = try measureDatabaseFootprintBytes(dbPath: dbPath)
    retentionBudgetHealth.recordSweep(
        observedFootprintBytes: footprint,
        boundary: boundary
    )
    guard !boundary.requiresStartupConvergence(
        footprintBytes: footprint
    ) else {
        throw PreIngestionStorageRecoveryError.startupTargetNotReached(
            component: "EventStore activation boundary",
            footprintBytes: footprint,
            targetBytes: boundary.targetBytes
        )
    }

    return EventStoreActivationProof(
        footprintBytes: footprint,
        priorityAdmission: priority,
        fileAdmission: file
    )
}

func reprobeAlertStoreAtActivationBoundary(
    alertStore: AlertStore,
    dbPath: String,
    boundary: AlertsSizeCapBoundary
) async throws -> AlertStoreActivationProof {
    let admission = try await alertStore.reprobeStorageAdmissionForWrite()
    guard admission.maxFootprintBytes == boundary.nominalCapBytes,
          admission.transactionReserveBytes
            == boundary.transactionReserveBytes else {
        throw PreIngestionStorageRecoveryError.admissionPolicyMismatch(
            component: "AlertStore",
            expectedCapBytes: boundary.nominalCapBytes,
            actualCapBytes: admission.maxFootprintBytes,
            expectedReserveBytes: boundary.transactionReserveBytes,
            actualReserveBytes: admission.transactionReserveBytes
        )
    }

    let footprint = try measureDatabaseFootprintBytes(dbPath: dbPath)
    guard !boundary.requiresStartupConvergence(
        footprintBytes: footprint
    ) else {
        throw PreIngestionStorageRecoveryError.activationBoundaryExceeded(
            component: "AlertStore",
            footprintBytes: footprint,
            boundaryBytes: boundary.recoveryTargetBytes
        )
    }

    return AlertStoreActivationProof(
        footprintBytes: footprint,
        admission: admission
    )
}

// MARK: - Size-cap enforcement (hardened in v1.6.13)

/// Hardened size-cap enforcer. Runs on the hourly timer and from
/// any on-demand entry point. Design goals (v1.6.13):
///
/// - **Bounded blast radius.** Delete at most 50% of rows per sweep;
///   if still over cap, next tick does another 50%. Converges to the
///   target across a few hours instead of wiping in one pass.
/// - **Never crash on out-of-disk.** VACUUM may require two copies of the
///   main DB in free scratch space. The shared exact-byte preflight preserves
///   the configured floor and skips VACUUM below that threshold. Row deletion
///   still happened (pages are freed internally), so the cap closes over later
///   ticks as disk frees up.
/// - **Single VACUUM per sweep.** Prune everything first, then
///   VACUUM once at the end. Previous v1.6.12 code called VACUUM
///   per iteration — up to 8× full-file rewrites on a big DB.
/// - **WAL-aware.** Checkpoint the WAL (PASSIVE → RESTART
///   fallback) before and after VACUUM so the main .db file (what
///   the Settings UI measures) actually reflects the shrink.
/// - **Reentrancy-safe.** Hourly timer + on-demand "prune now"
///   can collide; guard via `EventStore.beginSizeCapPrune()`.
/// - **Structured log output.** Every sweep emits one line with
///   starting/ending sizes, rows pruned, disk-space decision, and
///   vacuum result. Operators can `log show --predicate 'subsystem
///   == "com.maccrab.agent"'` and see exactly what the enforcer
///   did.
private func enforceDatabaseSizeCap(
    dbPath: String,
    boundary: EventsSizeCapBoundary,
    eventStore: EventStore,
    processFloorMinutes: Int = 0,
    forceConvergenceToTarget: Bool = false
) async -> Bool {
    // Reentrancy: if another sweep is already running (hourly timer
    // + on-demand invocation can race), exit cleanly. v1.9.0
    // (audit Stab-M1): return false so the SIGUSR2 caller can skip
    // the status-snapshot write — pre-fix the second SIGUSR2 within
    // ~2 s of the first wrote a stale `bytesAfter` mid-sweep.
    guard await eventStore.beginSizeCapPrune() else {
        logger.info("Size-cap enforcer: another sweep already active, skipping")
        return false
    }
    let result = await { () async -> Bool in

    func currentSizeBytes(_ phase: String) -> Int64? {
        do {
            return try measureDatabaseFootprintBytes(dbPath: dbPath)
        } catch {
            logger.fault("Size-cap \(phase, privacy: .public): authoritative SQLite family probe failed; refusing further maintenance: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    guard let initialBytes = currentSizeBytes("start") else { return false }
    let requiresPeriodicMaintenance = boundary.requiresMaintenance(
        footprintBytes: initialBytes
    )
    let requiresStartupConvergence = forceConvergenceToTarget
        && boundary.requiresStartupConvergence(footprintBytes: initialBytes)
    guard requiresPeriodicMaintenance || requiresStartupConvergence else {
        // Quiet no-op. Normal hourly tick on a well-sized DB. We did
        // acquire the lock — that counts as "ran" for SIGUSR2's
        // purposes (the dashboard sees the under-cap measurement).
        return true
    }

    let trigger = requiresPeriodicMaintenance
        ? "proactive boundary \(boundary.proactiveSweepBoundaryBytes)"
        : "startup convergence target \(boundary.targetBytes)"
    logger.warning("Size-cap enforcer armed: events.db family \(initialBytes) bytes exceeds \(trigger) bytes (file admission at \(boundary.fileLaneAdmissionBoundaryBytes), hard admission at \(boundary.hardAdmissionBoundaryBytes), nominal cap \(boundary.nominalCapBytes)); target \(boundary.targetBytes) bytes.")

    // --- Phase 1: prune rows (bounded at 50% of total per sweep) ---
    //
    // Deleting more than half the rows in one go is almost always a
    // bug: either the overage estimate is wrong, or the cap changed
    // radically. Cap per-sweep deletion so a misestimate never
    // wipes the whole store.

    let totalEventsBefore: Int
    do {
        totalEventsBefore = try await eventStore
            .maintenanceRetainedRecordCount()
    } catch {
        logger.fault("Size-cap enforcer: retained-record count unavailable; refusing zero-derived prune: \(error.localizedDescription, privacy: .public)")
        return false
    }
    let maxPerSweep = totalEventsBefore / 2
    let overageFraction = Double(initialBytes - boundary.targetBytes)
        / Double(initialBytes)
    let estimatedPrune = max(10_000, Int(Double(totalEventsBefore) * min(0.6, overageFraction + 0.1)))
    let pruneCount = min(estimatedPrune, maxPerSweep)

    // v1.21.4 per-category floor: spare recent process/exec rows, spilling
    // into them only when the eligible (file) rows can't satisfy the drop
    // count (pruneOldest's soft-floor valve — keeps the cap converging).
    let processFloorCutoff: Date? = processFloorMinutes > 0
        ? Date().addingTimeInterval(-Double(processFloorMinutes) * 60)
        : nil
    let pruned = (try? await eventStore.pruneOldest(
        count: pruneCount,
        protecting: processFloorMinutes > 0 ? .process : nil,
        newerThan: processFloorCutoff,
        preservingAllNewerThan: Date().addingTimeInterval(
            -Double(EventRetentionFloor.minutes) * 60
        )
    )) ?? 0
    guard let sizeAfterPruneBytes = currentSizeBytes("after row prune") else {
        return true
    }
    logger.notice("Size-cap phase 1: pruned \(pruned) rows (estimated \(estimatedPrune), cap \(maxPerSweep)); logical size now \(sizeAfterPruneBytes) bytes")

    // --- Phase 2a: incremental_vacuum pre-flight (Wave 9B, v1.12.6) ---
    //
    // BEFORE attempting a full VACUUM, run incremental_vacuum to
    // trim end-of-file freelist pages in place. This is free
    // (no scratch disk) and:
    //   1. On a 7 GB events.db with 1.7M freelist pages, this can
    //      drop the file to ~500 MB BEFORE the full VACUUM runs,
    //      making the subsequent full-rewrite cheap.
    //   2. If disk is too tight for full VACUUM, this is our only
    //      path to actually shrinking the file. Without it, the
    //      `.db` file grew unbounded between sweeps because every
    //      VACUUM attempt failed the headroom check.
    //
    // 200K-page cap (set in StoragePragmas.incrementalVacuumHardCap)
    // bounds the wall-clock so a runaway freelist on a huge file
    // doesn't stall the actor for minutes. At ~4 KB/page that's up
    // to ~800 MB of file truncation per call, which on commodity SSDs
    // takes ~5-30 s. The next scheduled sweep continues if more
    // pages remain.
    let preVacuumBytes = sizeAfterPruneBytes
    let preReclaimed: Int
    do {
        preReclaimed = try await eventStore.incrementalVacuum(maxPages: 200_000)
    } catch {
        logger.warning("Size-cap phase 2a: incremental_vacuum threw \(error.localizedDescription) — continuing")
        preReclaimed = 0
    }
    guard let sizeAfterIncrementalBytes = currentSizeBytes("after incremental vacuum") else {
        return true
    }
    if preReclaimed > 0 {
        logger.notice("Size-cap phase 2a: incremental_vacuum reclaimed \(preReclaimed) pages, \(preVacuumBytes) bytes → \(sizeAfterIncrementalBytes) bytes")
    } else {
        let mode = await eventStore.autoVacuumMode()
        if mode != 2 {
            logger.warning("Size-cap phase 2a: incremental_vacuum unavailable (auto_vacuum mode=\(mode), need 2/INCREMENTAL). Run `maccrabctl maintenance vacuum events` once to convert.")
        }
    }

    // --- Phase 2b: full VACUUM if we have the disk headroom ---
    //
    // The shared boundary requires the configured floor plus 2x the
    // authoritative main-file size, recomputed AFTER phase 2a so the
    // incremental truncate shrinks our headroom requirement. If the volume is
    // still tight, we skip VACUUM entirely — the file has been
    // partially shrunk by phase 2a (or by no-op if INCREMENTAL is
    // off), and the next hourly tick (or once disk frees) revisits.

    let headroom = fullVacuumHeadroom(dbPath: dbPath)
    let needMB = Int((headroom?.requiredFreeBytes ?? Int64.max) / 1_000_000)
    let freeMB = Int((headroom?.freeSpaceBytes ?? 0) / 1_000_000)
    let canVacuum = headroom?.admitted == true

    if !canVacuum {
        logger.warning("Size-cap phase 2b: skipping full VACUUM — need \(needMB) MB free, have \(freeMB) MB. Phase 2a reclaimed \(preReclaimed) pages; will retry next tick.")
        guard let endBytes = currentSizeBytes("finish after skipped vacuum") else {
            return true
        }
        logger.notice("Size-cap sweep complete: \(initialBytes) bytes → \(endBytes) bytes (rows pruned: \(pruned), incremental_vacuum: \(preReclaimed) pages, full vacuum: skipped)")
        return true
    }

    // Checkpoint the WAL first so VACUUM sees all committed pages
    // consolidated in the main file.
    let checkpointBefore = await eventStore.walCheckpoint()
    do {
        // Keep the whole checkpoint/gate/rewrite sequence actor-serialized;
        // see the corresponding hourly roll-up path above.
        try await eventStore.vacuum()
    } catch {
        logger.error("Size-cap phase 2b: VACUUM failed (\(error.localizedDescription)). Phase 2a reclaimed \(preReclaimed) pages; will retry next tick.")
        guard let endBytes = currentSizeBytes("finish after failed vacuum") else {
            return true
        }
        logger.notice("Size-cap sweep complete: \(initialBytes) bytes → \(endBytes) bytes (rows pruned: \(pruned), incremental_vacuum: \(preReclaimed) pages, full vacuum: failed)")
        return true
    }

    // Second checkpoint drains any WAL left by the VACUUM itself.
    _ = await eventStore.walCheckpoint()

    guard let finalBytes = currentSizeBytes("finish after full vacuum") else {
        return true
    }
    logger.notice("Size-cap sweep complete: \(initialBytes) bytes → \(finalBytes) bytes (rows pruned: \(pruned), incremental_vacuum: \(preReclaimed) pages, full vacuum: success, checkpoint_before_drained: \(checkpointBefore))")
    return true
    }()
    await eventStore.endSizeCapPrune()
    return result
}

/// Probe whether this sysext process currently has Full Disk Access.
///
/// Strategy: try to open `/Library/Application Support/com.apple.TCC/TCC.db`
/// and execute a trivial query. That database is TCC-protected under the
/// `kTCCServiceSystemPolicyAllFiles` (FDA) service, so:
///   • With FDA → TCC allows the open → query succeeds → return true
///   • Without FDA → TCC denies (EPERM) → sqlite3_open_v2 or the first
///     prepare fails → return false
///
/// This is authoritative for the sysext because it runs as root (so Unix
/// permissions are not the gate — TCC is). It's cheap (< 1 ms) and is run
/// every 30 s inside the heartbeat timer.
///
/// Intentionally file-scope (not inside the enum) so it remains callable
/// from the DispatchSource closure without `self.` captures.
private func probeSysextFDA() -> Bool {
    let systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"
    guard FileManager.default.fileExists(atPath: systemTCC) else { return false }
    var db: OpaquePointer?
    guard SQLiteOpenPathPolicy.open(
        systemTCC,
        database: &db,
        flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX
    ) == SQLITE_OK else { return false }
    defer { sqlite3_close(db) }
    // A bare SELECT on the access table confirms real read access —
    // on older macOS versions, sqlite3_open might return OK for a
    // path the process can't actually read, with prepare being the
    // real gate.
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(
        db,
        "SELECT 1 FROM access LIMIT 1",
        -1,
        &stmt,
        nil
    ) == SQLITE_OK else { return false }
    defer { sqlite3_finalize(stmt) }
    let rc = sqlite3_step(stmt)
    return rc == SQLITE_ROW || rc == SQLITE_DONE
}
