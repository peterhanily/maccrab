// SequenceCheckpointModel.swift
// MacCrabCore
//
// Durable, rule-definition-bound recovery state for SequenceEngine. This is
// deliberately a compact engine checkpoint, not an events.db replay contract:
// only live partials and the bounded out-of-order later-step history survive a
// restart. Rule telemetry is cumulative process telemetry and is not restored.

import Foundation

// MARK: - Persisted model

struct SequenceCheckpointMatchedStep: Codable, Sendable, Equatable {
    let stepID: String
    let eventID: UUID
    let timestamp: Date
    let processPID: Int32
    let processParentPID: Int32
    /// Whether ProcessLineage had the direct parent as a tracked node when the
    /// event was evaluated. A numeric PPID alone is not sibling evidence: the
    /// live engine deliberately requires both parents to be lineage-observed.
    let processParentWasTracked: Bool
    let processAncestorPIDs: [Int32]
    let filePath: String?
    let networkDestination: String?
}

struct SequenceCheckpointPartial: Codable, Sendable, Equatable {
    let id: UUID
    let ruleID: String
    let createdAt: Date
    let matchedSteps: [SequenceCheckpointMatchedStep]
    let correlationKey: String?
}

struct SequenceCheckpointPendingStep: Codable, Sendable, Equatable {
    let ruleID: String
    let stepID: String
    let matched: SequenceCheckpointMatchedStep
    let arrivedAt: Date
}

struct SequenceCheckpointPartialBucket: Codable, Sendable, Equatable {
    let ruleID: String
    let partials: [SequenceCheckpointPartial]
}

struct SequenceCheckpointPendingBucket: Codable, Sendable, Equatable {
    let ruleID: String
    let steps: [SequenceCheckpointPendingStep]
}

/// Stable identity for the global oldest-first pending-history queue. Per-rule
/// arrays preserve their own FIFO semantics; this second order is required to
/// make global-cap eviction choose the exact same item after a restart.
struct SequenceCheckpointPendingIdentity: Codable, Sendable, Equatable, Hashable {
    let ruleID: String
    let stepID: String
    let eventID: UUID
}

/// Canonical payload protected by the outer compressed envelope. Arrays are
/// emitted in deterministic order by SequenceEngine; no JSON dictionary order
/// participates in the semantic digest.
struct SequenceCheckpointPayload: Codable, Sendable, Equatable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let capturedAt: Date
    let ruleFingerprint: String
    let sourceGeneration: UInt64
    let partialBuckets: [SequenceCheckpointPartialBucket]
    let pendingBuckets: [SequenceCheckpointPendingBucket]
    let evictionOrder: [UUID]
    let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]
}

/// Actor-isolated state copied from SequenceEngine. JSON encoding, hashing,
/// compression, and disk I/O happen only after this value leaves the engine.
struct SequenceCheckpointCapture: Sendable {
    let capturedAt: Date
    let sourceGeneration: UInt64
    let rules: [SequenceRule]
    let partialBuckets: [SequenceCheckpointPartialBucket]
    let pendingBuckets: [SequenceCheckpointPendingBucket]
    let evictionOrder: [UUID]
    let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]
}

struct PreparedSequenceCheckpoint: Sendable {
    let payload: SequenceCheckpointPayload
    let semanticDigest: String
    let encodedFile: Data
}

struct ValidatedSequenceCheckpoint: Sendable {
    let payload: SequenceCheckpointPayload
    let partialBuckets: [SequenceCheckpointPartialBucket]
    let pendingBuckets: [SequenceCheckpointPendingBucket]
    let evictionOrder: [UUID]
    let pendingEvictionOrder: [SequenceCheckpointPendingIdentity]
    let expiredPartialCount: Int
    let expiredPendingCount: Int
}

struct SequenceCheckpointApplyResult: Sendable, Equatable {
    let partialCount: Int
    let pendingCount: Int
    let expiredPartialCount: Int
    let expiredPendingCount: Int
    let generation: UInt64
}

// MARK: - Public policy and observability

/// Automatic checkpointing is intentionally low-frequency and byte-budgeted.
/// The default 30-second cadence is the advertised best-case crash RPO; if the
/// rolling safety budget is exhausted, telemetry explicitly reports degraded
/// recovery instead of pretending the RPO still holds. A graceful forced flush
/// bypasses the automatic cadence/budget but never the hard file-size ceiling.
public struct SequenceCheckpointPolicy: Sendable, Equatable {
    public static let defaultCadence: TimeInterval = 30
    public static let defaultMaximumPeriodicWritesPerHour = 120
    public static let defaultMaximumPeriodicBytesPerHour = 256 * 1_024 * 1_024
    public static let defaultMaximumForcedPasses = 2

    public let cadence: TimeInterval
    public let maximumPeriodicWritesPerHour: Int
    public let maximumPeriodicBytesPerHour: Int
    public let maximumForcedPasses: Int

    public init(
        cadence: TimeInterval = Self.defaultCadence,
        maximumPeriodicWritesPerHour: Int = Self.defaultMaximumPeriodicWritesPerHour,
        maximumPeriodicBytesPerHour: Int = Self.defaultMaximumPeriodicBytesPerHour,
        maximumForcedPasses: Int = Self.defaultMaximumForcedPasses
    ) {
        self.cadence = min(max(cadence.isFinite ? cadence : Self.defaultCadence, 1), 3_600)
        self.maximumPeriodicWritesPerHour = min(max(maximumPeriodicWritesPerHour, 1), 3_600)
        self.maximumPeriodicBytesPerHour = min(
            max(maximumPeriodicBytesPerHour, 1),
            1_024 * 1_024 * 1_024
        )
        self.maximumForcedPasses = min(max(maximumForcedPasses, 1), 3)
    }
}

public enum SequenceCheckpointRestoreResult: Sendable, Equatable {
    case absent
    case restored(
        partials: Int,
        pendingSteps: Int,
        expiredPartials: Int,
        expiredPendingSteps: Int
    )
    case rejected(String)
}

public enum SequenceCheckpointWriteResult: Sendable, Equatable {
    case written(bytes: Int)
    case unchanged
    case notDue
    case budgetDeferred
    case alreadyInProgress
    case failed(String)
}

public enum SequenceCheckpointRestoreStatus: String, Codable, Sendable {
    case notAttempted = "not_attempted"
    case absent
    case restored
    case rejected
    case initialized
    /// A missing/rejected startup carrier was subsequently replaced by a
    /// verified current checkpoint. restoreDetail retains the historical cause.
    case recovered
}

public enum SequenceCheckpointCarrierInvalidationReason: String, Codable, Sendable {
    case missing
    case unsafeCarrier = "unsafe_carrier"
    case insecurePermissions = "insecure_permissions"
    case foreignOwner = "foreign_owner"
    case oversized
    case malformedEnvelope = "malformed_envelope"
    case integrityMismatch = "integrity_mismatch"
    case semanticMismatch = "semantic_mismatch"
    case ioFailure = "io_failure"
}

/// A point-in-time telemetry view suitable for heartbeat publication. Digest
/// fields are optional when engine mutations occurred after the last bounded
/// snapshot; that means "not observed yet", never "clean".
public struct SequenceCheckpointTelemetry: Codable, Sendable, Equatable {
    public let restoreStatus: SequenceCheckpointRestoreStatus
    public let restoreDetail: String?
    public let lastRestoreAt: Date?
    public let lastAttemptAt: Date?
    public let lastSuccessAt: Date?
    public let lastFailureAt: Date?
    public let lastFailure: String?
    public let checkpointCapturedAt: Date?
    public let checkpointAgeSeconds: TimeInterval?
    public let checkpointBytes: Int
    public let durableCarrierValid: Bool
    public let dirty: Bool
    public let currentSemanticDigest: String?
    public let durableSemanticDigest: String?
    public let currentGeneration: UInt64
    public let durableGeneration: UInt64?
    public let configuredCrashRPOSeconds: TimeInterval
    public let crashRPOBoundCurrentlyMaintained: Bool
    public let periodicWritesLastHour: Int
    public let periodicBytesLastHour: Int
    public let writesTotal: UInt64
    public let bytesWrittenTotal: UInt64
    public let unchangedSkipsTotal: UInt64
    public let budgetDeferralsTotal: UInt64
    public let orphanFilesCurrent: Int
    public let orphanBytesCurrent: Int
    public let orphanFilesRemovedTotal: UInt64
    public let orphanBytesRemovedTotal: UInt64
    public let orphanCleanupScanTruncated: Bool
    public let lastOrphanCleanupAt: Date?
    public let carrierInvalidationsTotal: UInt64
    public let lastCarrierInvalidationReason: SequenceCheckpointCarrierInvalidationReason?
    public let lastCarrierInvalidationAt: Date?
}

// MARK: - Errors and fixed resource ceilings

enum SequenceCheckpointError: Error, LocalizedError, Equatable {
    case absent
    case invalidPath
    case unsafeCarrier
    case insecurePermissions(UInt16)
    case foreignOwner(expected: UInt32, actual: UInt32)
    case fileTooLarge(actual: Int, maximum: Int)
    case truncated
    case invalidMagic
    case unsupportedEnvelopeVersion(Int)
    case unsupportedCodec(Int)
    case invalidLength
    case decompressionFailed
    case integrityMismatch
    case payloadTooLarge(actual: Int, maximum: Int)
    case invalidPayload(String)
    case unsupportedSchemaVersion(Int)
    case rulesNotLoaded
    case ruleFingerprintMismatch(expected: String, actual: String)
    case engineAlreadyActive
    case periodicBudgetExceeded
    case ioFailure(String)

    var errorDescription: String? {
        switch self {
        case .absent:
            return "Sequence checkpoint is absent"
        case .invalidPath:
            return "Sequence checkpoint path is not an absolute regular-file path"
        case .unsafeCarrier:
            return "Sequence checkpoint carrier is a symlink, hard link, or non-regular file"
        case .insecurePermissions(let mode):
            return String(format: "Sequence checkpoint permissions are not private (mode %04o)", mode)
        case .foreignOwner(let expected, let actual):
            return "Sequence checkpoint owner mismatch (expected uid \(expected), found \(actual))"
        case .fileTooLarge(let actual, let maximum):
            return "Sequence checkpoint is oversized (\(actual) bytes; maximum \(maximum))"
        case .truncated:
            return "Sequence checkpoint is truncated"
        case .invalidMagic:
            return "Sequence checkpoint magic is invalid"
        case .unsupportedEnvelopeVersion(let version):
            return "Sequence checkpoint envelope version \(version) is unsupported"
        case .unsupportedCodec(let codec):
            return "Sequence checkpoint codec \(codec) is unsupported"
        case .invalidLength:
            return "Sequence checkpoint length fields are inconsistent"
        case .decompressionFailed:
            return "Sequence checkpoint decompression failed or exceeded its declared bound"
        case .integrityMismatch:
            return "Sequence checkpoint integrity digest does not match"
        case .payloadTooLarge(let actual, let maximum):
            return "Sequence checkpoint payload is oversized (\(actual) bytes; maximum \(maximum))"
        case .invalidPayload(let detail):
            return "Sequence checkpoint payload is invalid: \(detail)"
        case .unsupportedSchemaVersion(let version):
            return "Sequence checkpoint schema version \(version) is unsupported"
        case .rulesNotLoaded:
            return "Sequence checkpoint restore requires the active sequence rules to be loaded first"
        case .ruleFingerprintMismatch(let expected, let actual):
            return "Sequence checkpoint rule fingerprint mismatch (active \(expected), checkpoint \(actual))"
        case .engineAlreadyActive:
            return "Sequence checkpoint restore refused because the sequence engine already has live state"
        case .periodicBudgetExceeded:
            return "Sequence checkpoint periodic write budget is exhausted"
        case .ioFailure(let detail):
            return "Sequence checkpoint I/O failed: \(detail)"
        }
    }
}

enum SequenceCheckpointLimits {
    static let maximumRules = 4_096
    static let maximumRuleFingerprintBytes = 8 * 1_024 * 1_024
    static let maximumSingleRuleFingerprintBytes = 4 * 1_024 * 1_024
    static let maximumStepsPerRule = 256
    static let maximumPredicatesPerRule = 4_096
    static let maximumPredicateValuesPerRule = 32_768
    static let maximumTagsPerRule = 4_096
    // The serialized-state weight budget makes 65,536 records impossible to
    // preserve even when each record is minimal. 8,192 remains generous while
    // keeping the count cap reachable and round-trippable under the byte cap.
    static let maximumTotalPendingSteps = 8_192
    static let maximumIdentifierBytes = 1_024
    static let maximumValueBytes = 16 * 1_024
    static let maximumProcessAncestors = 64
    static let futureTimestampTolerance: TimeInterval = 300
}
