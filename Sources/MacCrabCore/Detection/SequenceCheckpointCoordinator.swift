// SequenceCheckpointCoordinator.swift
// MacCrabCore
//
// Off-engine orchestration for bounded periodic and graceful SequenceEngine
// recovery checkpoints. The detection actor only copies state; this actor owns
// hashing/compression/I/O scheduling and publishes honest crash-RPO telemetry.

import Foundation
import Darwin
import os.log

public actor SequenceCheckpointCoordinator {
    /// Stable support-directory carrier name used by every daemon deployment.
    /// Keeping this at the owner type prevents the system-extension and
    /// standalone launch paths from silently choosing different recovery files.
    public static let defaultFileName = "sequence-engine.checkpoint"

    private struct PeriodicWriteRecord: Sendable {
        let monotonicTick: TimeInterval
        let bytes: Int
    }

    public let checkpointURL: URL
    public let policy: SequenceCheckpointPolicy
    private let monotonicNow: @Sendable () -> TimeInterval

    private let logger = Logger(
        subsystem: "com.maccrab.detection",
        category: "SequenceCheckpoint"
    )

    private var operationInProgress = false
    private var periodicTask: Task<Void, Never>?
    private var periodicStartInProgress = false
    private var periodicLifecycleGeneration: UInt64 = 0
    private var periodicWriteRecords: [PeriodicWriteRecord] = []

    private var restoreStatus: SequenceCheckpointRestoreStatus = .notAttempted
    private var restoreDetail: String?
    private var lastRestoreAt: Date?
    private var lastAttemptAt: Date?
    private var lastPeriodicAttemptTick: TimeInterval?
    private var lastObservedMonotonicTick: TimeInterval?
    private var lastSuccessAt: Date?
    private var lastSuccessTick: TimeInterval?
    private var lastFailureAt: Date?
    private var lastFailure: String?
    private var checkpointCapturedAt: Date?
    private var checkpointBytes = 0
    private var durableCarrierValid = false
    private var dirty = true
    private var currentSemanticDigest: String?
    private var durableSemanticDigest: String?
    private var currentGeneration: UInt64 = 0
    private var durableGeneration: UInt64?
    private var writesTotal: UInt64 = 0
    private var bytesWrittenTotal: UInt64 = 0
    private var unchangedSkipsTotal: UInt64 = 0
    private var budgetDeferralsTotal: UInt64 = 0
    private var orphanFilesCurrent = 0
    private var orphanBytesCurrent = 0
    private var orphanFilesRemovedTotal: UInt64 = 0
    private var orphanBytesRemovedTotal: UInt64 = 0
    private var orphanCleanupScanTruncated = false
    private var lastOrphanCleanupAt: Date?
    private var carrierInvalidationsTotal: UInt64 = 0
    private var lastCarrierInvalidationReason: SequenceCheckpointCarrierInvalidationReason?
    private var lastCarrierInvalidationAt: Date?

    private enum CarrierValidationOutcome: Sendable {
        case valid
        case invalid(SequenceCheckpointCarrierInvalidationReason)
    }

    public init(
        checkpointURL: URL,
        policy: SequenceCheckpointPolicy = SequenceCheckpointPolicy()
    ) {
        self.checkpointURL = checkpointURL
        self.policy = policy
        self.monotonicNow = { Foundation.ProcessInfo.processInfo.systemUptime }
    }

    /// Deterministic seam for rollback/budget tests. Production always uses
    /// systemUptime, which is monotonic across wall-clock corrections.
    init(
        checkpointURL: URL,
        policy: SequenceCheckpointPolicy = SequenceCheckpointPolicy(),
        monotonicNow: @escaping @Sendable () -> TimeInterval
    ) {
        self.checkpointURL = checkpointURL
        self.policy = policy
        self.monotonicNow = monotonicNow
    }

    /// Restore must be called after the complete active sequence-rule corpus is
    /// loaded and before event ingestion starts. A malformed or incompatible
    /// file never mutates engine state and is surfaced as `.rejected`.
    @discardableResult
    public func restore(
        into engine: SequenceEngine,
        now: Date = Date()
    ) async -> SequenceCheckpointRestoreResult {
        guard !operationInProgress else {
            return .rejected("another sequence checkpoint operation is in progress")
        }
        operationInProgress = true
        defer { operationInProgress = false }

        lastAttemptAt = now
        lastRestoreAt = now
        do {
            let checkpointURL = self.checkpointURL
            let cleanup = try await Task.detached(priority: .utility) {
                try SequenceCheckpointFileStore.cleanupOrphans(
                    near: checkpointURL,
                    now: now
                )
            }.value
            recordOrphanCleanup(cleanup, at: now)
            let decoded = try await Task.detached(priority: .utility) {
                guard let file = try SequenceCheckpointFileStore.read(from: checkpointURL) else {
                    return Optional<(SequenceCheckpointPayload, Int, String)>.none
                }
                let payload = try SequenceCheckpointCodec.decode(file)
                let digest = try SequenceCheckpointCodec.semanticDigest(of: payload)
                return (payload, file.count, digest)
            }.value

            guard let (payload, fileBytes, diskSemanticDigest) = decoded else {
                restoreStatus = .absent
                restoreDetail = nil
                currentGeneration = await engine.checkpointGenerationSnapshot()
                dirty = true
                currentSemanticDigest = nil
                durableSemanticDigest = nil
                durableGeneration = nil
                checkpointCapturedAt = nil
                checkpointBytes = 0
                durableCarrierValid = false
                return .absent
            }

            let applied = try await engine.restoreCheckpoint(payload, now: now)
            restoreStatus = .restored
            restoreDetail = "restored \(applied.partialCount) partial(s), \(applied.pendingCount) pending step(s); pruned \(applied.expiredPartialCount + applied.expiredPendingCount) expired item(s)"
            checkpointCapturedAt = payload.capturedAt
            checkpointBytes = fileBytes
            durableCarrierValid = true
            durableSemanticDigest = diskSemanticDigest
            // sourceGeneration belongs to the prior process epoch and is not
            // numerically comparable with this engine's new generation.
            durableGeneration = nil
            currentGeneration = applied.generation
            lastSuccessTick = sampleMonotonicTick()
            lastFailure = nil

            let pruned = applied.expiredPartialCount > 0 || applied.expiredPendingCount > 0
            currentSemanticDigest = pruned ? nil : diskSemanticDigest
            dirty = pruned
            logger.info("Sequence checkpoint restored: \(applied.partialCount) partials, \(applied.pendingCount) pending, \(applied.expiredPartialCount + applied.expiredPendingCount) expired pruned")
            return .restored(
                partials: applied.partialCount,
                pendingSteps: applied.pendingCount,
                expiredPartials: applied.expiredPartialCount,
                expiredPendingSteps: applied.expiredPendingCount
            )
        } catch {
            let detail = error.localizedDescription
            restoreStatus = .rejected
            restoreDetail = detail
            currentGeneration = await engine.checkpointGenerationSnapshot()
            recordFailure(detail, at: now)
            dirty = true
            currentSemanticDigest = nil
            durableCarrierValid = false
            durableSemanticDigest = nil
            durableGeneration = nil
            checkpointCapturedAt = nil
            checkpointBytes = 0
            recordCarrierInvalidation(
                Self.carrierInvalidationReason(for: error),
                at: now
            )
            logger.error("Sequence checkpoint restore rejected: \(detail)")
            return .rejected(detail)
        }
    }

    /// Attempt one automatic checkpoint. Calls before `policy.cadence` elapses
    /// return `.notDue`; unchanged semantic state returns `.unchanged` without
    /// replacing/fsyncing the file.
    @discardableResult
    public func checkpointIfDue(
        engine: SequenceEngine,
        now: Date = Date()
    ) async -> SequenceCheckpointWriteResult {
        await writeCheckpoint(engine: engine, now: now, forced: false)
    }

    /// Graceful-shutdown flush. It bypasses only the periodic cadence and
    /// rolling budget, never schema/integrity/file-size limits. A bounded second
    /// pass closes the race when ingestion was still finishing during pass one.
    @discardableResult
    public func forceFlush(
        engine: SequenceEngine,
        now: Date = Date()
    ) async -> SequenceCheckpointWriteResult {
        var result: SequenceCheckpointWriteResult = .unchanged
        for pass in 0..<policy.maximumForcedPasses {
            let passNow = now.addingTimeInterval(Double(pass) * 0.000_001)
            result = await writeCheckpoint(engine: engine, now: passNow, forced: true)
            switch result {
            case .written, .unchanged:
                if !dirty { return result }
            case .failed, .alreadyInProgress:
                return result
            case .notDue, .budgetDeferred:
                // Forced writes cannot return either result.
                return result
            }
        }
        return result
    }

    /// Optional self-scheduling lane for daemon integration. It has no file I/O
    /// on the SequenceEngine actor and never overlaps its own prior operation.
    public func startPeriodicCheckpointing(engine: SequenceEngine) async {
        guard periodicTask == nil, !periodicStartInProgress else { return }
        periodicStartInProgress = true
        let lifecycleGeneration = periodicLifecycleGeneration

        // Seed durable state before returning to the bootstrap caller. Sleeping
        // first left every fresh install truthfully degraded for at least 30s
        // and opened an avoidable startup crash-RPO gap.
        _ = await checkpointIfDue(engine: engine)
        guard lifecycleGeneration == periodicLifecycleGeneration else {
            periodicStartInProgress = false
            return
        }

        let cadenceNanoseconds = UInt64(policy.cadence * 1_000_000_000)
        periodicTask = Task { [weak self, weak engine] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: cadenceNanoseconds)
                } catch {
                    break
                }
                guard let self, let engine else { break }
                _ = await self.checkpointIfDue(engine: engine)
            }
        }
        periodicStartInProgress = false
    }

    /// Cancel and JOIN the automatic lane. Returning only after the task exits
    /// is essential: a periodic capture may already be inside compression or
    /// fsync when shutdown begins. A fire-and-forget cancellation let an
    /// immediately following `forceFlush` observe `operationInProgress` and
    /// skip the newest graceful state.
    ///
    /// Call `forceFlush` separately after event ingestion has stopped so
    /// shutdown ordering remains explicit to callers.
    public func stopPeriodicCheckpointing() async {
        incrementSaturating(&periodicLifecycleGeneration)
        periodicStartInProgress = false
        guard let task = periodicTask else { return }
        periodicTask = nil
        task.cancel()
        await task.value
    }

    public func telemetry(now: Date = Date()) -> SequenceCheckpointTelemetry {
        let monotonicTick = sampleMonotonicTick()
        prunePeriodicWriteRecords(monotonicTick: monotonicTick)
        let periodicBytes = periodicWriteRecords.reduce(0) { partial, record in
            partial > Int.max - record.bytes ? Int.max : partial + record.bytes
        }
        let budgetAvailable = periodicWriteRecords.count < policy.maximumPeriodicWritesPerHour
            && periodicBytes < policy.maximumPeriodicBytesPerHour
        let rpoMaintained: Bool
        if durableCarrierValid, !dirty, durableSemanticDigest != nil {
            rpoMaintained = true
        } else if durableCarrierValid, let lastSuccessTick {
            rpoMaintained = budgetAvailable
                && monotonicTick - lastSuccessTick <= policy.cadence
        } else {
            rpoMaintained = false
        }

        return SequenceCheckpointTelemetry(
            restoreStatus: restoreStatus,
            restoreDetail: restoreDetail,
            lastRestoreAt: lastRestoreAt,
            lastAttemptAt: lastAttemptAt,
            lastSuccessAt: lastSuccessAt,
            lastFailureAt: lastFailureAt,
            lastFailure: lastFailure,
            checkpointCapturedAt: checkpointCapturedAt,
            checkpointAgeSeconds: checkpointCapturedAt.map {
                max(0, now.timeIntervalSince($0))
            },
            checkpointBytes: checkpointBytes,
            durableCarrierValid: durableCarrierValid,
            dirty: dirty,
            currentSemanticDigest: currentSemanticDigest,
            durableSemanticDigest: durableSemanticDigest,
            currentGeneration: currentGeneration,
            durableGeneration: durableGeneration,
            configuredCrashRPOSeconds: policy.cadence,
            crashRPOBoundCurrentlyMaintained: rpoMaintained,
            periodicWritesLastHour: periodicWriteRecords.count,
            periodicBytesLastHour: periodicBytes,
            writesTotal: writesTotal,
            bytesWrittenTotal: bytesWrittenTotal,
            unchangedSkipsTotal: unchangedSkipsTotal,
            budgetDeferralsTotal: budgetDeferralsTotal,
            orphanFilesCurrent: orphanFilesCurrent,
            orphanBytesCurrent: orphanBytesCurrent,
            orphanFilesRemovedTotal: orphanFilesRemovedTotal,
            orphanBytesRemovedTotal: orphanBytesRemovedTotal,
            orphanCleanupScanTruncated: orphanCleanupScanTruncated,
            lastOrphanCleanupAt: lastOrphanCleanupAt,
            carrierInvalidationsTotal: carrierInvalidationsTotal,
            lastCarrierInvalidationReason: lastCarrierInvalidationReason,
            lastCarrierInvalidationAt: lastCarrierInvalidationAt
        )
    }

    /// Heartbeat-facing form: first sample the engine's cheap generation so a
    /// mutation that happened after the coordinator's last periodic snapshot is
    /// immediately reported dirty (with an unknown current digest), rather than
    /// appearing clean until the next checkpoint cadence.
    public func telemetry(
        engine: SequenceEngine,
        now: Date = Date()
    ) async -> SequenceCheckpointTelemetry {
        let observedGeneration = await engine.checkpointGenerationSnapshot()
        if observedGeneration != currentGeneration {
            currentGeneration = observedGeneration
            currentSemanticDigest = nil
            dirty = true
        }
        return telemetry(now: now)
    }

    private func writeCheckpoint(
        engine: SequenceEngine,
        now: Date,
        forced: Bool
    ) async -> SequenceCheckpointWriteResult {
        guard !operationInProgress else { return .alreadyInProgress }
        let monotonicTick = sampleMonotonicTick()
        if !forced,
           let lastPeriodicAttemptTick,
           monotonicTick - lastPeriodicAttemptTick < policy.cadence {
            return .notDue
        }

        operationInProgress = true
        defer { operationInProgress = false }
        lastAttemptAt = now
        if !forced { lastPeriodicAttemptTick = monotonicTick }

        do {
            let capture = try await engine.checkpointCapture(at: now)
            let prepared = try await Task.detached(priority: .utility) {
                try SequenceCheckpointCodec.prepare(capture)
            }.value
            let checkpointURL = self.checkpointURL
            let cleanup = try await Task.detached(priority: .utility) {
                try SequenceCheckpointFileStore.cleanupOrphans(
                    near: checkpointURL,
                    now: now
                )
            }.value
            recordOrphanCleanup(cleanup, at: now)

            currentGeneration = capture.sourceGeneration
            currentSemanticDigest = prepared.semanticDigest
            dirty = durableSemanticDigest != prepared.semanticDigest
            if !dirty {
                // In-memory equality is not durable evidence. Revalidate the
                // no-follow carrier and its complete envelope before skipping;
                // deletion, chmod, replacement, or in-place corruption must
                // cause an immediate rewrite instead of a permanently green RPO.
                let expectedDigest = prepared.semanticDigest
                let carrierValidation = await Task.detached(priority: .utility) {
                    do {
                        guard let file = try SequenceCheckpointFileStore.read(from: checkpointURL) else {
                            return CarrierValidationOutcome.invalid(.missing)
                        }
                        let payload = try SequenceCheckpointCodec.decode(file)
                        return try SequenceCheckpointCodec.semanticDigest(of: payload)
                            == expectedDigest
                            ? CarrierValidationOutcome.valid
                            : CarrierValidationOutcome.invalid(.semanticMismatch)
                    } catch {
                        return CarrierValidationOutcome.invalid(
                            SequenceCheckpointCoordinator.carrierInvalidationReason(for: error)
                        )
                    }
                }.value
                if case .valid = carrierValidation {
                    durableCarrierValid = true
                    lastSuccessTick = monotonicTick
                    incrementSaturating(&unchangedSkipsTotal)
                    lastFailure = nil
                    return .unchanged
                }
                if case .invalid(let reason) = carrierValidation {
                    recordCarrierInvalidation(reason, at: now)
                }
                dirty = true
                durableCarrierValid = false
                durableSemanticDigest = nil
                durableGeneration = nil
                checkpointBytes = 0
            }

            if !forced {
                prunePeriodicWriteRecords(monotonicTick: monotonicTick)
                let usedBytes = periodicWriteRecords.reduce(0) { partial, record in
                    partial > Int.max - record.bytes ? Int.max : partial + record.bytes
                }
                let usedBytesIncludingOrphans = usedBytes > Int.max - orphanBytesCurrent
                    ? Int.max : usedBytes + orphanBytesCurrent
                let exceedsCount = periodicWriteRecords.count
                    >= policy.maximumPeriodicWritesPerHour
                let exceedsBytes = usedBytesIncludingOrphans > policy.maximumPeriodicBytesPerHour
                    - min(prepared.encodedFile.count, policy.maximumPeriodicBytesPerHour)
                if exceedsCount || exceedsBytes {
                    incrementSaturating(&budgetDeferralsTotal)
                    recordFailure(
                        SequenceCheckpointError.periodicBudgetExceeded.localizedDescription,
                        at: now
                    )
                    return .budgetDeferred
                }
            }

            let file = prepared.encodedFile
            try await Task.detached(priority: .utility) {
                try SequenceCheckpointFileStore.write(file, to: checkpointURL)
            }.value

            if !forced {
                periodicWriteRecords.append(
                    PeriodicWriteRecord(monotonicTick: monotonicTick, bytes: file.count)
                )
            }
            checkpointCapturedAt = prepared.payload.capturedAt
            checkpointBytes = file.count
            durableCarrierValid = true
            durableSemanticDigest = prepared.semanticDigest
            durableGeneration = capture.sourceGeneration
            lastSuccessAt = now
            lastSuccessTick = monotonicTick
            lastFailure = nil
            if restoreStatus == .rejected {
                restoreStatus = .recovered
            } else if restoreStatus == .absent {
                restoreStatus = .initialized
            }
            incrementSaturating(&writesTotal)
            addSaturating(UInt64(file.count), to: &bytesWrittenTotal)

            let generationAfterWrite = await engine.checkpointGenerationSnapshot()
            currentGeneration = generationAfterWrite
            if generationAfterWrite == capture.sourceGeneration {
                currentSemanticDigest = prepared.semanticDigest
                dirty = false
            } else {
                // The just-written checkpoint remains a valid point-in-time
                // snapshot, but newer state exists and its digest is not known
                // until the next bounded capture.
                currentSemanticDigest = nil
                dirty = true
            }
            logger.debug("Sequence checkpoint wrote \(file.count) bytes (generation \(capture.sourceGeneration), dirty after write: \(self.dirty))")
            return .written(bytes: file.count)
        } catch {
            let detail = error.localizedDescription
            currentGeneration = await engine.checkpointGenerationSnapshot()
            currentSemanticDigest = nil
            dirty = true
            recordFailure(detail, at: now)
            logger.error("Sequence checkpoint write failed: \(detail)")
            return .failed(detail)
        }
    }

    private func recordFailure(_ detail: String, at date: Date) {
        lastFailureAt = date
        lastFailure = detail
    }

    private func sampleMonotonicTick() -> TimeInterval {
        let raw = monotonicNow()
        let finiteNonnegative = raw.isFinite && raw >= 0
            ? raw
            : (lastObservedMonotonicTick ?? 0)
        let sampled = max(lastObservedMonotonicTick ?? finiteNonnegative, finiteNonnegative)
        lastObservedMonotonicTick = sampled
        return sampled
    }

    private func prunePeriodicWriteRecords(monotonicTick: TimeInterval) {
        let cutoff = monotonicTick - 3_600
        periodicWriteRecords.removeAll { $0.monotonicTick <= cutoff }
    }

    private func recordOrphanCleanup(
        _ report: SecureFileIO.TemporaryCleanupReport,
        at date: Date
    ) {
        orphanFilesCurrent = report.remainingFiles
        orphanBytesCurrent = report.remainingBytes
        orphanCleanupScanTruncated = report.scanTruncated
        lastOrphanCleanupAt = date
        addSaturating(UInt64(report.removedFiles), to: &orphanFilesRemovedTotal)
        addSaturating(UInt64(report.removedBytes), to: &orphanBytesRemovedTotal)
    }

    private func recordCarrierInvalidation(
        _ reason: SequenceCheckpointCarrierInvalidationReason,
        at date: Date
    ) {
        incrementSaturating(&carrierInvalidationsTotal)
        lastCarrierInvalidationReason = reason
        lastCarrierInvalidationAt = date
    }

    private nonisolated static func carrierInvalidationReason(
        for error: Error
    ) -> SequenceCheckpointCarrierInvalidationReason {
        // Orphan cleanup walks the same parent chain before the checkpoint
        // reader. Preserve its typed carrier rejection instead of collapsing a
        // symlinked parent into a generic I/O failure merely because cleanup
        // reached the unsafe component first.
        if let fileError = error as? SecureFileIO.Error {
            switch fileError {
            case .symlinkRefused, .pathOutsideScope, .invalidScope:
                return .unsafeCarrier
            case .openFailed(_, let code):
                if code == ENOENT { return .missing }
                if code == ELOOP || code == ENOTDIR || code == EINVAL {
                    return .unsafeCarrier
                }
                return .ioFailure
            case .fileAlreadyExists, .writeFailed, .readFailed:
                return .ioFailure
            }
        }
        guard let checkpointError = error as? SequenceCheckpointError else {
            return .ioFailure
        }
        switch checkpointError {
        case .absent:
            return .missing
        case .unsafeCarrier, .invalidPath:
            return .unsafeCarrier
        case .insecurePermissions:
            return .insecurePermissions
        case .foreignOwner:
            return .foreignOwner
        case .fileTooLarge, .payloadTooLarge:
            return .oversized
        case .integrityMismatch:
            return .integrityMismatch
        case .ruleFingerprintMismatch:
            return .semanticMismatch
        case .invalidMagic, .unsupportedEnvelopeVersion, .unsupportedCodec,
             .invalidLength, .truncated, .decompressionFailed, .invalidPayload,
             .unsupportedSchemaVersion,
             .rulesNotLoaded, .engineAlreadyActive, .periodicBudgetExceeded:
            return .malformedEnvelope
        case .ioFailure:
            return .ioFailure
        }
    }

    private func incrementSaturating(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }

    private func addSaturating(_ delta: UInt64, to value: inout UInt64) {
        value = value > UInt64.max - delta ? UInt64.max : value + delta
    }
}
