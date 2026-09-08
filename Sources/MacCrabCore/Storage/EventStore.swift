// EventStore.swift
// MacCrabCore
//
// SQLite-backed event store using the sqlite3 C API directly (no dependencies).
// Uses WAL journal mode for concurrent reads during writes.
// Thread-safe via Swift actor isolation.

import Foundation
import Darwin
import CSQLCipher
import CryptoKit
import os

/// Connection-local capability used by schema-v8 write guards. The function
/// is registered only by an rc.13 EventStore read-write connection. Older
/// binaries do not know the symbol, so SQLite aborts their guarded DML before
/// it can desynchronise the append journal, projection, FTS, or coverage
/// ledger. A noncapturing C callback keeps the guard independent of actor
/// lifetime and makes registration possible immediately after sqlite3_open.
private let macCrabEventJournalWriterV8SQLFunction:
    @convention(c) (
        OpaquePointer?,
        Int32,
        UnsafeMutablePointer<OpaquePointer?>?
    ) -> Void = { context, _, _ in
        sqlite3_result_int(context, 1)
    }

// MARK: - EventStoreError

/// Errors that can occur during event store operations.
public enum EventStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case prepareFailed(String)
    case stepFailed(String)
    case encodingFailed(String)
    case decodingFailed(String)
    case canonicalPayloadTooLarge(
        eventID: UUID,
        bytes: Int,
        maximumBytes: Int
    )
    case immutableEventConflict(eventID: UUID)
    case terminalRevisionRequiresBase(eventID: UUID)
    case terminalRevisionConflict(eventID: UUID)
    /// Internal formation signal: the append itself fits, but committing this
    /// exact prefix would leave a block whose authenticated rollup/expiry
    /// cannot fit the fixed transaction reserve. Callers must deterministically
    /// reform a smaller prefix; they must never retry the identical block.
    case journalBlockRequiresSplit(eventCount: Int)
    /// Another rc.13 writer changed the append-local UUID roster after this
    /// connection built its exact locator but before it acquired the SQLite
    /// writer lock. The caller must rebuild identity truth and reform the
    /// uncommitted prefix; committing against the stale locator could create a
    /// duplicate UUID in two independently authenticated blocks.
    case journalBlockRequiresIdentityRefresh
    case terminalRevisionRequiresIdentityRefresh
    case projectionPromotionRequiresIdentityRefresh
    case exactEvidenceGap(
        poisonRecords: Int,
        corruptLegacyRecords: Int,
        inheritedLegacyLossRecords: Int,
        resourceLimitedRecords: Int
    )
    case aggregateEvidenceGap(records: Int)
    /// A bare compatibility reader cannot carry the retained-window boundary
    /// needed to interpret its value. Callers must use the typed snapshot and
    /// label the effective interval instead of treating an expired prefix as
    /// observed zero.
    case incompleteRetentionWindow(
        requestedSince: Date,
        effectiveSince: Date
    )
    /// Full-text search is deliberately a bounded sparse projection. A bare
    /// `[Event]` result cannot distinguish "no canonical match" from "matching
    /// canonical rows were omitted", so it fails closed whenever coverage is
    /// not complete for the requested retained window.
    case sparseProjectionIncomplete(
        omittedRecords: Int,
        requestedWindowComplete: Bool
    )
    /// Returning a bare Event graph would detach it from the shared live-memory
    /// lease acquired before journal decode. Use the corresponding typed
    /// snapshot, whose lifetime owns that credit.
    case resourceOwnershipRequired(String)
    /// A crash-resumable storage transition could not reach a drained, bounded
    /// boundary yet (for example a reader pins WAL frames). This is operational
    /// readiness, not corruption, and daemon startup must stop before producers
    /// instead of quarantining evidence or returning a writer with nil statements.
    case storageNotReady(String)
    /// v1.12.0 RC28: distinguish disk-full from generic step failures
    /// so the daemon's insert path can degrade gracefully instead of
    /// silently dropping events under storage exhaustion.
    case diskFull(String, failure: SQLiteFailureDetails? = nil)
    /// v1.21.5-rc.3 (#13): SQLITE_BUSY / SQLITE_LOCKED — a TRANSIENT lock
    /// contention (typically a reader/writer contending the WAL beyond the 5s
    /// busy_timeout). Distinct from `stepFailed` so a batched writer can RETRY
    /// instead of dropping the batch (retrying a transient lock succeeds once the
    /// contention clears; retrying a permanent failure does not).
    case busy(String, failure: SQLiteFailureDetails? = nil)
    /// v1.21.6-rc.32: in-process event-pipeline memory/ownership lease
    /// exhaustion. Previously reported as `busy`, which made every caller treat
    /// it as clearing SQLite contention and retry it — but no amount of retrying
    /// releases a credit the retrying task is itself holding, so those retries
    /// burned their whole deadline per event and collapsed priority-lane
    /// throughput. Callers must take a BOUNDED, accounted exit instead.
    case memoryLeaseUnavailable(String, failure: SQLiteFailureDetails? = nil)
    case sqliteFailure(
        context: String,
        message: String,
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    )

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let msg):  return "Database open failed: \(msg)"
        case .prepareFailed(let msg):       return "Prepare failed: \(msg)"
        case .stepFailed(let msg):          return "Step failed: \(msg)"
        case .diskFull(let msg, _):         return "Disk full: \(msg)"
        case .busy(let msg, _):             return "Database busy (transient): \(msg)"
        case .memoryLeaseUnavailable(let msg, _):
            return "Event pipeline memory lease unavailable: \(msg)"
        case let .sqliteFailure(context, message, rc, extended, systemErrno):
            return "SQLite \(context) failed (rc=\(rc), extended=\(extended), system_errno=\(systemErrno)): \(message)"
        case .encodingFailed(let msg):      return "Encoding failed: \(msg)"
        case .decodingFailed(let msg):      return "Decoding failed: \(msg)"
        case let .canonicalPayloadTooLarge(eventID, bytes, maximumBytes):
            return "Canonical event \(eventID.uuidString) is \(bytes) bytes, above the source-bound journal ceiling of \(maximumBytes) bytes"
        case .immutableEventConflict(let eventID):
            return "Immutable event UUID \(eventID.uuidString) was reused with a different canonical payload"
        case .terminalRevisionRequiresBase(let eventID):
            return "Terminal revision \(eventID.uuidString) has no durable base journal event"
        case .terminalRevisionConflict(let eventID):
            return "Terminal revision \(eventID.uuidString) was already finalized with different canonical evidence"
        case .journalBlockRequiresSplit(let eventCount):
            return "Canonical journal block of \(eventCount) event(s) must be split to preserve bounded expiry"
        case .journalBlockRequiresIdentityRefresh:
            return "Canonical journal identity changed before the append acquired the writer lock"
        case .terminalRevisionRequiresIdentityRefresh:
            return "Terminal journal identity changed before the revision acquired the writer lock"
        case .projectionPromotionRequiresIdentityRefresh:
            return "Reviewed projection identity changed before the promotion acquired the writer lock"
        case let .exactEvidenceGap(
            poisonRecords,
            corruptLegacyRecords,
            inheritedLegacyLossRecords,
            resourceLimitedRecords
        ):
            return "Exact event query intersects \(poisonRecords) canonical-overflow record(s), \(corruptLegacyRecords) preserved corrupt legacy record(s), \(inheritedLegacyLossRecords) rc.12 inherited-loss record(s), and \(resourceLimitedRecords) byte-budget-limited record(s)"
        case .aggregateEvidenceGap(let records):
            return "Aggregate query intersects \(records) explicitly conserved canonical/compaction gap record(s)"
        case let .incompleteRetentionWindow(requested, effective):
            return "Requested event window begins at \(requested), before the exact retained boundary \(effective)"
        case let .sparseProjectionIncomplete(omitted, windowComplete):
            return "Sparse event projection omitted \(omitted) retained record(s); requested-window-complete=\(windowComplete)"
        case .resourceOwnershipRequired(let operation):
            return "\(operation) requires a lease-owning typed event snapshot"
        case .storageNotReady(let msg):     return "Storage not ready: \(msg)"
        }
    }
}

public enum EventJournalInsertDisposition: Sendable, Equatable {
    case durable(eventID: UUID)
    /// A compact, content-bound gap record and durable poison ledger row were
    /// committed, but the original source Event was outside the canonical
    /// ingress envelope. This is settled storage, never exact verification.
    case poisoned(EventJournalOverflowEvidence)
    case filtered(eventID: UUID)
    case uncommitted(eventID: UUID)
}

public enum EventJournalEnsureReason: Sendable, Equatable {
    case ordinary
    /// A late reviewed match, high severity, or direct durable alert must not
    /// remain excluded merely because its early routine base hit the noise
    /// filter. This mode bypasses only EventInsertFilter; cap/integrity checks
    /// remain identical.
    case securityRelevant
}

public enum EventJournalEnsureOutcome: Sendable, Equatable {
    case durable(eventID: UUID)
    case poisoned(EventJournalOverflowEvidence)
    case filtered(eventID: UUID)
}

public struct EventJournalVerification: Sendable, Equatable {
    public enum Disposition: Sendable, Equatable {
        case durable(eventID: UUID)
        case poisoned(EventJournalOverflowEvidence)
        case missing(eventID: UUID)
        case conflict(eventID: UUID)
    }

    public let disposition: Disposition
    public let storageMutationGeneration: UInt64
}

public enum EventTerminalRevisionOutcome: Sendable, Equatable {
    /// The terminal canonical representation equals the immutable base, so no
    /// overlay row or WAL traffic was created.
    case unchangedBase(eventID: UUID)
    case inserted(eventID: UUID)
    case alreadyDurable(eventID: UUID)
    /// The terminal source exceeded the ingress envelope. Its content-bound
    /// identity is durably poisoned, but no terminal Event revision is exact.
    case poisoned(EventJournalOverflowEvidence)
}

public struct EventTerminalRevisionBatchResult: Sendable, Equatable {
    public let inputCount: Int
    public let outcomes: [EventTerminalRevisionOutcome]
    public let durableEventIDs: Set<UUID>
    public let insertedEventIDs: Set<UUID>
    public let idempotentEventIDs: Set<UUID>
    public let committedTransactionCount: Int
    public let storageMutationGeneration: UInt64

    public init(
        inputCount: Int,
        outcomes: [EventTerminalRevisionOutcome],
        durableEventIDs: Set<UUID>,
        insertedEventIDs: Set<UUID>,
        idempotentEventIDs: Set<UUID>,
        committedTransactionCount: Int,
        storageMutationGeneration: UInt64
    ) {
        self.inputCount = inputCount
        self.outcomes = outcomes
        self.durableEventIDs = durableEventIDs
        self.insertedEventIDs = insertedEventIDs
        self.idempotentEventIDs = idempotentEventIDs
        self.committedTransactionCount = committedTransactionCount
        self.storageMutationGeneration = storageMutationGeneration
    }
}

/// Storage-facing terminal input. The preparation-time typed delta graph is
/// deliberately absent: callers compact to this value, release that graph,
/// then transfer the same live-memory lease from J to EventStore workspace
/// before crossing the actor boundary. Storage decodes the canonical delta
/// only while it owns the exact base record's single J lease.
public struct EventTerminalDeltaStoragePreparation: Sendable, Equatable {
    public let eventID: UUID
    public let baseCanonicalSHA256: Data
    public let sourceIdentitySHA256: Data
    public let canonicalDeltaJSON: Data
    public let canonicalDeltaSHA256: Data
    public let compactRetainedByteEstimate: Int
    public let deltaGraphRetainedByteEstimate: Int
    public let overflow: EventTerminalDeltaOverflowEvidence?

    public init(compacting preparation: EventTerminalDeltaPreparation) {
        eventID = preparation.eventID
        baseCanonicalSHA256 = preparation.baseCanonicalSHA256
        sourceIdentitySHA256 = preparation.sourceIdentitySHA256
        canonicalDeltaJSON = preparation.canonicalDeltaJSON
        canonicalDeltaSHA256 = preparation.canonicalDeltaSHA256
        overflow = preparation.overflow

        let compact = preparation.canonicalDeltaJSON.count
            .addingReportingOverflow(4_096)
        compactRetainedByteEstimate = compact.overflow
            ? Int.max : compact.partialValue

        let encodedAndFixed = preparation.canonicalDeltaJSON.count
            .addingReportingOverflow(4_096)
        if encodedAndFixed.overflow {
            deltaGraphRetainedByteEstimate = Int.max
        } else {
            deltaGraphRetainedByteEstimate = max(
                0,
                preparation.retainedByteEstimate
                    - encodedAndFixed.partialValue
            )
        }
    }
}

public struct EventTerminalRevisionBatchFailure: Error, LocalizedError,
    SQLiteFailureReporting, @unchecked Sendable {
    public let progress: EventTerminalRevisionBatchResult
    public let uncommittedEvents: [Event]
    public let underlyingError: any Error

    public var errorDescription: String? {
        "Terminal revision batch stopped after \(progress.outcomes.count) settled input(s): \(underlyingError.localizedDescription)"
    }

    public var sqliteFailureDetails: SQLiteFailureDetails? {
        SQLiteFailureClassifier.details(from: underlyingError)
    }
}

public struct ProjectionPromotionOutcome: Sendable, Equatable {
    public let eventID: UUID
    public let insertedMatchCount: Int
    public let totalReviewedMatchCount: Int
    public let projectionMaterialized: Bool
    /// Non-nil means reviewed evidence could not fit the bounded append-local
    /// overlay/expiry envelope. The content-bound gap is durable and sticky;
    /// callers must not treat this outcome as exact promotion success.
    public let evidenceGap: EventJournalOverflowEvidence?
    public let storageMutationGeneration: UInt64

    public init(
        eventID: UUID,
        insertedMatchCount: Int,
        totalReviewedMatchCount: Int,
        projectionMaterialized: Bool,
        evidenceGap: EventJournalOverflowEvidence? = nil,
        storageMutationGeneration: UInt64
    ) {
        self.eventID = eventID
        self.insertedMatchCount = insertedMatchCount
        self.totalReviewedMatchCount = totalReviewedMatchCount
        self.projectionMaterialized = projectionMaterialized
        self.evidenceGap = evidenceGap
        self.storageMutationGeneration = storageMutationGeneration
    }
}

public struct EventJournalPoisonRecord: Sendable, Equatable {
    public enum Kind: String, Sendable, Equatable {
        case base
        case terminal
        case promotion
    }

    public let eventID: UUID
    public let kind: Kind
    public let originalBytes: Int
    public let originalSHA256: Data
    public let digestKind: EventJournalOverflowEvidence.DigestKind
}

public struct ExactEventQuerySnapshot: Sendable, Equatable {
    public let events: [Event]
    public let mutationGeneration: UInt64
    public let poisonRecords: [EventJournalPoisonRecord]
    public let corruptLegacyRecords: Int
    public let inheritedLegacyLossRecords: Int
    public let resourceLimitedRecords: Int
    /// Keeps every returned Event graph charged to the shared process budget.
    /// Equality deliberately compares evidence only, not lease identity.
    private let ownershipLeases: [EventPipelineMemoryLease]

    fileprivate init(
        events: [Event],
        mutationGeneration: UInt64,
        poisonRecords: [EventJournalPoisonRecord],
        corruptLegacyRecords: Int,
        inheritedLegacyLossRecords: Int,
        resourceLimitedRecords: Int,
        ownershipLeases: [EventPipelineMemoryLease]
    ) {
        self.events = events
        self.mutationGeneration = mutationGeneration
        self.poisonRecords = poisonRecords
        self.corruptLegacyRecords = corruptLegacyRecords
        self.inheritedLegacyLossRecords = inheritedLegacyLossRecords
        self.resourceLimitedRecords = resourceLimitedRecords
        self.ownershipLeases = ownershipLeases
    }

    public static func == (
        lhs: ExactEventQuerySnapshot,
        rhs: ExactEventQuerySnapshot
    ) -> Bool {
        lhs.events == rhs.events
            && lhs.mutationGeneration == rhs.mutationGeneration
            && lhs.poisonRecords == rhs.poisonRecords
            && lhs.corruptLegacyRecords == rhs.corruptLegacyRecords
            && lhs.inheritedLegacyLossRecords
                == rhs.inheritedLegacyLossRecords
            && lhs.resourceLimitedRecords == rhs.resourceLimitedRecords
    }

    public var isComplete: Bool {
        poisonRecords.isEmpty && corruptLegacyRecords == 0
            && inheritedLegacyLossRecords == 0
            && resourceLimitedRecords == 0
    }
}

public struct ExactAlertEvidenceSnapshot: Sendable, Equatable {
    public let candidates: [AlertEvidenceCandidate]
    public let mutationGeneration: UInt64
    public let poisonRecords: [EventJournalPoisonRecord]
    public let corruptLegacyRecords: Int
    public let inheritedLegacyLossRecords: Int
    public let resourceLimitedRecords: Int

    public var isComplete: Bool {
        poisonRecords.isEmpty && corruptLegacyRecords == 0
            && inheritedLegacyLossRecords == 0
            && resourceLimitedRecords == 0
    }
}

public struct ExactEventLookupSnapshot: Sendable, Equatable {
    public let event: Event?
    public let mutationGeneration: UInt64
    private let ownershipLeases: [EventPipelineMemoryLease]

    fileprivate init(
        event: Event?,
        mutationGeneration: UInt64,
        ownershipLeases: [EventPipelineMemoryLease]
    ) {
        self.event = event
        self.mutationGeneration = mutationGeneration
        self.ownershipLeases = ownershipLeases
    }

    public static func == (
        lhs: ExactEventLookupSnapshot,
        rhs: ExactEventLookupSnapshot
    ) -> Bool {
        lhs.event == rhs.event
            && lhs.mutationGeneration == rhs.mutationGeneration
    }
}

public struct ExactEventPageSnapshot: Sendable, Equatable {
    public let query: ExactEventQuerySnapshot
    public let nextCursor: PaginationCursor?

    public var items: [Event] { query.events }
    public var mutationGeneration: UInt64 { query.mutationGeneration }
    public var isComplete: Bool { query.isComplete }
}

/// Explicitly conserved reasons that a retained query cannot prove absence.
/// Counts are transactionally bound to the snapshot's mutation generation.
public struct EventQueryGapCounts: Sendable, Equatable {
    public let canonicalPoisonRecords: Int
    public let corruptLegacyRecords: Int
    public let inheritedLegacyLossRecords: Int
    public let resourceLimitedRecords: Int

    public init(
        canonicalPoisonRecords: Int,
        corruptLegacyRecords: Int,
        inheritedLegacyLossRecords: Int,
        resourceLimitedRecords: Int
    ) {
        self.canonicalPoisonRecords = canonicalPoisonRecords
        self.corruptLegacyRecords = corruptLegacyRecords
        self.inheritedLegacyLossRecords = inheritedLegacyLossRecords
        self.resourceLimitedRecords = resourceLimitedRecords
    }

    public var total: Int {
        [
            canonicalPoisonRecords,
            corruptLegacyRecords,
            inheritedLegacyLossRecords,
            resourceLimitedRecords,
        ].reduce(0) { partial, value in
            let next = partial.addingReportingOverflow(max(0, value))
            return next.overflow ? Int.max : next.partialValue
        }
    }
}

/// Exact category counts in durable-admission time (not attacker-controlled
/// source time) for the portion of a requested interval the journal can still
/// prove. `counts` never imply that time before `effectiveSince` was observed
/// zero.
public struct EventCategoryCountSnapshot: Sendable, Equatable {
    public let counts: [String: Int]
    public let mutationGeneration: UInt64
    public let requestedSince: Date
    public let requestedUntil: Date
    public let effectiveSince: Date
    public let effectiveUntil: Date
    public let retainedOldest: Date?
    public let retainedNewest: Date?
    public let retainedAdmissionOldest: Date?
    public let retainedAdmissionNewest: Date?
    public let requestedWindowComplete: Bool
    public let gaps: EventQueryGapCounts

    public var isComplete: Bool {
        requestedWindowComplete && gaps.total == 0
    }
}

/// Source-time bounds for one retained event category. `spanSeconds` describes
/// the distance between retained observations; `lookbackSeconds` describes how
/// far the oldest observation reaches back from the caller's snapshot time.
/// Retention-health decisions use lookback: an active stream's newest event is
/// normally behind `asOf`, so its inter-observation span is necessarily shorter
/// than the retention window even when the full window is present.
public struct EventCategoryRetentionWindow: Sendable, Equatable {
    public let spanSeconds: Int
    public let lookbackSeconds: Int
}

public struct EventHistogramBin: Sendable, Equatable {
    public let start: Date
    public let count: Int

    public init(start: Date, count: Int) {
        self.start = start
        self.count = count
    }
}

/// Source-time histogram paired with the same admission-retention proof as
/// category counts. Callers must not synthesize zero bins before
/// `effectiveSince` when `requestedWindowComplete` is false.
public struct EventHistogramSnapshot: Sendable, Equatable {
    public let bins: [EventHistogramBin]
    public let mutationGeneration: UInt64
    public let requestedSince: Date
    public let requestedUntil: Date
    public let effectiveSince: Date
    public let effectiveUntil: Date
    public let retainedOldest: Date?
    public let retainedNewest: Date?
    public let retainedAdmissionOldest: Date?
    public let retainedAdmissionNewest: Date?
    public let requestedWindowComplete: Bool
    public let gaps: EventQueryGapCounts

    public var isComplete: Bool {
        requestedWindowComplete && gaps.total == 0
    }
}

/// Honest result for the bounded sparse FTS/typed projection. Projection
/// coverage is the complete retained admission-domain ledger, not an estimate
/// inferred from the number of matches returned by FTS.
public struct EventSearchSnapshot: Sendable, Equatable {
    public let events: [Event]
    public let mutationGeneration: UInt64
    public let requestedSince: Date
    public let requestedUntil: Date
    public let effectiveSince: Date
    public let effectiveUntil: Date
    public let retainedOldest: Date?
    public let retainedNewest: Date?
    public let retainedAdmissionOldest: Date?
    public let retainedAdmissionNewest: Date?
    public let projectionConsidered: Int
    public let projectionMaterialized: Int
    public let projectionOmittedQuota: Int
    public let projectionOmittedReplaced: Int
    public let projectionOmittedPhysical: Int
    public let projectionOmittedExternal: Int
    public let projectionOmittedMigration: Int
    public let projectionPending: Int
    public let requestedWindowComplete: Bool
    public let gaps: EventQueryGapCounts
    private let ownershipLeases: [EventPipelineMemoryLease]

    fileprivate init(
        events: [Event],
        mutationGeneration: UInt64,
        requestedSince: Date,
        requestedUntil: Date,
        effectiveSince: Date,
        effectiveUntil: Date,
        retainedOldest: Date?,
        retainedNewest: Date?,
        retainedAdmissionOldest: Date?,
        retainedAdmissionNewest: Date?,
        projectionConsidered: Int,
        projectionMaterialized: Int,
        projectionOmittedQuota: Int,
        projectionOmittedReplaced: Int,
        projectionOmittedPhysical: Int,
        projectionOmittedExternal: Int,
        projectionOmittedMigration: Int,
        projectionPending: Int,
        requestedWindowComplete: Bool,
        gaps: EventQueryGapCounts,
        ownershipLeases: [EventPipelineMemoryLease]
    ) {
        self.events = events
        self.mutationGeneration = mutationGeneration
        self.requestedSince = requestedSince
        self.requestedUntil = requestedUntil
        self.effectiveSince = effectiveSince
        self.effectiveUntil = effectiveUntil
        self.retainedOldest = retainedOldest
        self.retainedNewest = retainedNewest
        self.retainedAdmissionOldest = retainedAdmissionOldest
        self.retainedAdmissionNewest = retainedAdmissionNewest
        self.projectionConsidered = projectionConsidered
        self.projectionMaterialized = projectionMaterialized
        self.projectionOmittedQuota = projectionOmittedQuota
        self.projectionOmittedReplaced = projectionOmittedReplaced
        self.projectionOmittedPhysical = projectionOmittedPhysical
        self.projectionOmittedExternal = projectionOmittedExternal
        self.projectionOmittedMigration = projectionOmittedMigration
        self.projectionPending = projectionPending
        self.requestedWindowComplete = requestedWindowComplete
        self.gaps = gaps
        self.ownershipLeases = ownershipLeases
    }

    public static func == (
        lhs: EventSearchSnapshot,
        rhs: EventSearchSnapshot
    ) -> Bool {
        lhs.events == rhs.events
            && lhs.mutationGeneration == rhs.mutationGeneration
            && lhs.requestedSince == rhs.requestedSince
            && lhs.requestedUntil == rhs.requestedUntil
            && lhs.effectiveSince == rhs.effectiveSince
            && lhs.effectiveUntil == rhs.effectiveUntil
            && lhs.retainedOldest == rhs.retainedOldest
            && lhs.retainedNewest == rhs.retainedNewest
            && lhs.retainedAdmissionOldest == rhs.retainedAdmissionOldest
            && lhs.retainedAdmissionNewest == rhs.retainedAdmissionNewest
            && lhs.projectionConsidered == rhs.projectionConsidered
            && lhs.projectionMaterialized == rhs.projectionMaterialized
            && lhs.projectionOmittedQuota == rhs.projectionOmittedQuota
            && lhs.projectionOmittedReplaced == rhs.projectionOmittedReplaced
            && lhs.projectionOmittedPhysical == rhs.projectionOmittedPhysical
            && lhs.projectionOmittedExternal == rhs.projectionOmittedExternal
            && lhs.projectionOmittedMigration == rhs.projectionOmittedMigration
            && lhs.projectionPending == rhs.projectionPending
            && lhs.requestedWindowComplete == rhs.requestedWindowComplete
            && lhs.gaps == rhs.gaps
    }

    public var projectionOmitted: Int {
        [
            projectionOmittedQuota,
            projectionOmittedReplaced,
            projectionOmittedPhysical,
            projectionOmittedExternal,
            projectionOmittedMigration,
            projectionPending,
        ].reduce(0) { partial, value in
            let next = partial.addingReportingOverflow(max(0, value))
            return next.overflow ? Int.max : next.partialValue
        }
    }

    public var isComplete: Bool {
        requestedWindowComplete
            && gaps.total == 0
            && projectionConsidered == projectionMaterialized
            && projectionOmitted == 0
    }
}

public struct EventBatchInsertResult: Sendable, Equatable {
    public let inputCount: Int
    public let persistedCount: Int
    public let filteredCount: Int
    public let committedTransactionCount: Int
    /// One outcome per input ordinal. UUID sets are insufficient because a
    /// legal caller may submit the same UUID more than once, including a
    /// filter-distinct or canonical-conflicting value. On partial failure the
    /// durable prefix and exact unresolved suffix remain identity-bound.
    public let inputDispositions: [EventJournalInsertDisposition]

    public init(
        inputCount: Int,
        persistedCount: Int,
        filteredCount: Int,
        committedTransactionCount: Int,
        inputDispositions: [EventJournalInsertDisposition] = []
    ) {
        self.inputCount = inputCount
        self.persistedCount = persistedCount
        self.filteredCount = filteredCount
        self.committedTransactionCount = committedTransactionCount
        self.inputDispositions = inputDispositions
    }
}

/// A reserve-chunked batch can commit a prefix before a later chunk fails.
/// The exact uncommitted, insert-filter-passing suffix is carried so callers
/// never retry or count the already-durable prefix as shed.
public struct EventBatchInsertFailure: Error, LocalizedError,
    SQLiteFailureReporting, @unchecked Sendable {
    public let progress: EventBatchInsertResult
    public let uncommittedEvents: [Event]
    public let underlyingError: any Error
    /// True when corruption recovery quarantined the database that contained
    /// any previously committed chunks. In that case `progress.persistedCount`
    /// is reset to zero and `uncommittedEvents` contains every filter-passing
    /// candidate, because the old prefix is no longer in the active store.
    public let activeDatabaseWasReplaced: Bool
    /// A replacement database was opened and prepared successfully, so a
    /// bounded caller may retry `uncommittedEvents` immediately.
    public let replacementReadyForRetry: Bool

    public init(
        progress: EventBatchInsertResult,
        uncommittedEvents: [Event],
        underlyingError: any Error,
        activeDatabaseWasReplaced: Bool = false,
        replacementReadyForRetry: Bool = false
    ) {
        self.progress = progress
        self.uncommittedEvents = uncommittedEvents
        self.underlyingError = underlyingError
        self.activeDatabaseWasReplaced = activeDatabaseWasReplaced
        self.replacementReadyForRetry = replacementReadyForRetry
    }

    public var errorDescription: String? {
        "Event batch stopped after \(progress.persistedCount) persisted row(s); \(uncommittedEvents.count) row(s) remain: \(underlyingError.localizedDescription)"
    }

    /// Preserve SQLite's primary/extended/VFS classification through the
    /// partial-progress envelope. Recovery and telemetry callers must never
    /// lose BUSY/FULL/corruption identity merely because earlier chunks
    /// committed successfully.
    public var sqliteFailureDetails: SQLiteFailureDetails? {
        SQLiteFailureClassifier.details(from: underlyingError)
    }
}

// MARK: - EventStore

/// A SQLite-backed store for security events.
///
/// The store writes events into a structured schema with individual columns
/// for commonly-queried fields, while also storing the full JSON representation
/// in `raw_json` for lossless retrieval. An FTS5 virtual table enables
/// full-text search across process names, paths, command lines, and other
/// string fields.
public actor EventStore {

    // MARK: Properties

    private var db: OpaquePointer?
    private nonisolated let retiredReadOnlyReads = OSAllocatedUnfairLock(initialState: false)

    /// Retire a dashboard reader without waiting behind its synchronous actor
    /// work. Verification cooperates at statement/record boundaries, finalizing
    /// its statements as it unwinds. This neither closes a live SQLite handle
    /// from another thread nor affects writable engine connections.
    public nonisolated func retireReadOnlyReads() {
        retiredReadOnlyReads.withLock { $0 = true }
    }

    private func checkReadOnlyRetirement() throws {
        if isReadOnly && (Task.isCancelled || retiredReadOnlyReads.withLock({ $0 })) {
            throw CancellationError()
        }
    }
    private var checkpointController: SQLiteControlledCheckpointController?
    private let databasePath: String
    /// Production stores share one process-wide envelope. Tests may inject an
    /// equivalent isolated envelope so independently scheduled fixture suites
    /// cannot manufacture cross-suite backpressure.
    private let liveMemoryBudget: EventPipelineLiveMemoryBudget
    /// Deterministic actor-isolated seam for proving that a concurrent owner
    /// taking freshly released decode credit is transient, never poison.
    private var terminalDeltaOwnershipGrowthHookForTesting:
        (@Sendable () -> Void)?
    /// Deterministic seam for pinning the WAL after an expiry COMMIT but
    /// before its checkpoint. Production leaves this nil.
    private var journalExpiryPostCommitHookForTesting:
        (@Sendable () -> Void)?
    /// Observes actual expiry checkpoint attempts; production leaves this nil.
    private var journalExpiryCheckpointHookForTesting:
        (@Sendable () -> Void)?
    private var storagePolicy: SQLitePersistentStorePolicy?
    private var storageAdmission: SQLitePersistentStoreAdmission?
    /// Authoritative PRAGMA page_size captured at each open/reopen. Transaction
    /// estimates use this value rather than assuming the usual 4 KiB so legacy
    /// databases with larger pages remain safely bounded.
    private var sqlitePageSizeBytes: Int64
    /// Lazily scanned high-water estimate for maintenance rewrites/deletes.
    /// New writes can raise it; deletes deliberately do not lower it.
    private var maintenanceRowMutationHighWaterBytes: Int64? = nil
    private var maintenanceHighWaterScannedExistingRows = false
    private var committedBatchInsertTransactions: UInt64 = 0
    /// Incremented when corruption quarantine removes the active DB family.
    /// Batch progress is meaningful only within one generation.
    private var activeDatabaseGeneration: UInt64 = 0
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    /// Dictionary key order is not semantic Event identity. Journal UUID
    /// idempotence hashes this canonical representation so a retry whose
    /// enrichment dictionary was built in a different insertion order dedupes,
    /// while a genuinely different value for the same UUID fails loudly.
    private let journalEncoder: JSONEncoder = {
        let value = JSONEncoder()
        value.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return value
    }()

    // MARK: Lossless journal + bounded interactive projection (schema v8)

    /// Every filter-passing Event is retained in this block journal. `events`
    /// remains a deliberately sparse interactive/FTS projection; it is never
    /// the source for correlation, alert evidence, exact export or health
    /// counts once a row has entered the journal.
    internal static let journalRetentionSeconds: TimeInterval = 15 * 60
    internal static let projectionBucketSeconds: TimeInterval = 1
    internal static let projectionRowsPerBucket = 4
    internal static let projectionBytesPerBucket = 12 * 1_024
    internal static let projectionPhysicalLimitBytes: Int64 = 48 * 1_024 * 1_024
    /// Terminal and reviewed-match overlays share one strict retained-payload
    /// budget per canonical block. Without this bound, 128 individually valid
    /// terminal rows could make one exact decode/cascade several GiB. Eight
    /// MiB keeps base+overlay retention work inside the fixed 32-MiB
    /// transaction reserve even on a 64-KiB-page legacy store.
    private static let journalOverlayPayloadLimitBytes = 8 * 1_024 * 1_024
    private static let projectionCanaryReserveBytes: Int64 = 4 * 1_024 * 1_024
    private static let projectionPhysicalRemeasureBlockInterval = 64
    // 1,274/s × (900 s retention + 300 s sweep overhang) plus block/jitter.
    // Overflow never makes the store unreopenable: IDs beyond this fixed-workload
    // qualification ceiling use a partitioned Bloom + roster scan restricted
    // to overflow blocks.
    private static let journalInMemoryLocationLimit = 1_600_000

    /// rc.41: rows collected per journal-scan statement before it is finalized
    /// and its implicit read transaction (and WAL read-mark) released. Small
    /// enough that each statement lives milliseconds; large enough that a full
    /// 100k-block rebuild needs only a few hundred statements.
    private static let journalScanBatchBlocks = 256

    /// rc.41 test seam: invoked once per verified scan batch with whether the
    /// connection is currently inside a SQLite transaction. The WAL-pin
    /// regression test asserts this is FALSE during heavy verification — the
    /// entire point of the chunked scan and the hoisted verify.
    var journalIndexRebuildHookForTesting: ((Bool) -> Void)?

    func setJournalIndexRebuildHookForTesting(_ hook: ((Bool) -> Void)?) {
        journalIndexRebuildHookForTesting = hook
    }

    func setJournalRebuildFailAfterPartialForTesting(_ on: Bool) {
        journalRebuildFailAfterPartialForTesting = on
    }
    private static let maximumPackedJournalBlockID: Int64 = (1 << 56) - 1
    /// Array-returning exact APIs are bounded by owned decoded graphs as well
    /// as row count. A caller that asks for more receives a typed evidence gap;
    /// export must page/stream instead of retaining the journal in one array.
    private static let exactQueryResultByteLimit = 16 * 1_024 * 1_024
    /// Legacy detection-era indexes duplicate the compact journal and turn
    /// every sparse projection row into avoidable B-tree/WAL writes. Upgrade
    /// may defer an individually large DROP until transcode has removed the
    /// wide legacy rows, but pre-producer recovery requires this exact set to
    /// be absent before it reports ready.
    private static let supersededEventIndexes = [
        "idx_events_process_path",
        "idx_events_ts_severity",
        "idx_events_category",
        "idx_events_severity",
        "idx_events_ts_category",
        "idx_events_process_ts",
        "idx_events_ts_sev_cat",
        "idx_events_mcp_server",
        "idx_events_trace",
        "idx_events_user_id",
        "idx_events_ai_tool_ts",
        "idx_events_parent_exe_ts",
        "idx_events_ai_session",
    ]
    /// Retained for empty-store bootstrap and compatibility with older stores.
    /// Existing v8 stores do not require or rebuild this optional index.
    private static let journalCategoryIndexSQL =
        "CREATE INDEX IF NOT EXISTS idx_events_cat_sev_ts ON events(event_category, severity, timestamp)"
    /// Read-only inventory that a durable `schema_finalized = 1` marker must
    /// prove before routine reopen may bypass rc.12 -> rc.13 transition work.
    /// The pre-producer recovery path repeats this validation and adds the
    /// full FTS external-content integrity check before any producer starts.
    private static let finalizedJournalSchemaObjects: [(String, String)] = [
        ("idx_events_timestamp", "view"),
        ("idx_event_projection_timestamp", "index"),
        ("idx_event_projection_locator", "index"),
        ("idx_event_projection_victim", "index"),
        ("event_journal_blocks", "table"),
        ("event_journal_terminal_revisions", "table"),
        ("event_journal_projection_promotions", "table"),
        ("event_journal_payload_poison", "table"),
        ("event_journal_inherited_loss", "table"),
        ("event_aggregate_gaps", "table"),
        ("event_projection_coverage", "table"),
        ("event_projection_block_coverage", "table"),
        ("event_storage_state", "table"),
    ]
    private static let rollbackBarrierViewSQL =
        "CREATE VIEW idx_events_timestamp AS SELECT 'maccrab_rc13_write_barrier' AS marker"
    private struct RollbackGuardDefinition: Sendable {
        let name: String
        let table: String
        let operation: String
        let sql: String
    }
    private nonisolated static let rollbackGuardDefinitions:
        [RollbackGuardDefinition] = [
            ("events", "INSERT", "i"),
            ("events", "UPDATE", "u"),
            ("events", "DELETE", "d"),
            ("alert_evidence", "INSERT", "i"),
            ("alert_evidence", "UPDATE", "u"),
            ("alert_evidence", "DELETE", "d"),
            ("event_aggregates", "INSERT", "i"),
            ("event_aggregates", "UPDATE", "u"),
            ("event_aggregates", "DELETE", "d"),
            ("attribution_overrides", "INSERT", "i"),
            ("attribution_overrides", "UPDATE", "u"),
            ("attribution_overrides", "DELETE", "d"),
        ].map { value in
            let (table, operation, suffix) = value
            let name = "\(table)_rc13_write_guard_b\(suffix)"
            return RollbackGuardDefinition(
                name: name,
                table: table,
                operation: operation,
                sql: """
                    CREATE TRIGGER IF NOT EXISTS \(name)
                    BEFORE \(operation) ON \(table) BEGIN
                        SELECT CASE WHEN maccrab_event_journal_writer_v8() != 1
                            THEN RAISE(ABORT, 'rc.13 event journal writer required') END;
                    END
                    """
            )
        }

    private enum ProjectionState: Int32 {
        case pending = 0
        case materialized = 1
        case omitted = 2
    }

    private enum ProjectionReason: Int32 {
        case pending = 0
        case quota = 1
        case rankReplacement = 2
        case physicalBudget = 3
        case selected = 4
        case coverageCanary = 5
        case reviewedRuleMatch = 6
        case restartFinalized = 7
        case externalDeletion = 8
    }

    /// Ordinal-aligned, authenticated search-tier disposition stored in each
    /// journal block. Three bits leave an explicit state for downgrade/external
    /// projection deletion; silently relabeling that evidence gap as quota would
    /// make coverage appear healthier than it is.
    private enum JournalProjectionDisposition: UInt8 {
        case materialized = 0
        case quota = 1
        case replaced = 2
        case physical = 3
        case externalDeletion = 4
        /// Upgrade-only: canonical journal admission had to commit separately
        /// from deletion of a wide legacy projection row. The old row cannot
        /// coexist with a new projection row of the same UUID, so this is an
        /// explicit, final and operator-visible search omission.
        case migrationSplit = 5
    }

    private struct JournalLocation: Sendable, Hashable {
        let blockID: Int64
        let ordinal: Int
    }

    /// A fixed-width UUID/location entry. Swift Dictionary measured ~140.7
    /// MiB at the 1.6M retention+sweep envelope; this representation is exactly
    /// 24 bytes/entry and supports binary-search lookup without object/hash
    /// bucket overhead. New blocks enter a small open-address delta until the
    /// next retention/startup rebuild.
    private struct PackedJournalEntry: Sendable, Equatable {
        let high: UInt64
        let low: UInt64
        let packedLocation: UInt64

        static let empty = PackedJournalEntry(
            high: 0,
            low: 0,
            packedLocation: 0
        )

        init(id: UUID, location: JournalLocation) {
            let halves = Self.halves(id)
            self.high = halves.0
            self.low = halves.1
            self.packedLocation = (UInt64(location.blockID) << 8)
                | UInt64(location.ordinal & 0xff)
        }

        init(key id: UUID) {
            let halves = Self.halves(id)
            self.high = halves.0
            self.low = halves.1
            self.packedLocation = 0
        }

        private static func halves(_ id: UUID) -> (UInt64, UInt64) {
            var tuple = id.uuid
            return withUnsafeBytes(of: &tuple) { bytes -> (UInt64, UInt64) in
                func half(_ offset: Int) -> UInt64 {
                    var value: UInt64 = 0
                    for index in 0..<8 {
                        value = (value << 8) | UInt64(bytes[offset + index])
                    }
                    return value
                }
                return (half(0), half(8))
            }
        }

        private init(high: UInt64, low: UInt64, packedLocation: UInt64) {
            self.high = high
            self.low = low
            self.packedLocation = packedLocation
        }

        var location: JournalLocation {
            JournalLocation(
                blockID: Int64(packedLocation >> 8),
                ordinal: Int(packedLocation & 0xff)
            )
        }

        func precedes(_ other: PackedJournalEntry) -> Bool {
            high < other.high || (high == other.high && low < other.low)
        }

        func sameID(as other: PackedJournalEntry) -> Bool {
            high == other.high && low == other.low
        }

        var hash: UInt64 {
            var value = high ^ (low &* 0x9e37_79b9_7f4a_7c15)
            value ^= value >> 30
            value &*= 0xbf58_476d_1ce4_e5b9
            value ^= value >> 27
            value &*= 0x94d0_49bb_1331_11eb
            return value ^ (value >> 31)
        }
    }

    private struct PackedJournalDelta: Sendable {
        private(set) var slots: [PackedJournalEntry] = []
        private(set) var count = 0

        var allocatedBytes: Int {
            slots.capacity * MemoryLayout<PackedJournalEntry>.stride
        }

        mutating func removeAll() {
            slots.removeAll(keepingCapacity: false)
            count = 0
        }

        mutating func remove(blockIDs: [Int64]) {
            guard !blockIDs.isEmpty, !slots.isEmpty else { return }
            func contains(_ value: Int64) -> Bool {
                var lower = 0
                var upper = blockIDs.count
                while lower < upper {
                    let middle = lower + (upper - lower) / 2
                    if blockIDs[middle] < value {
                        lower = middle + 1
                    } else {
                        upper = middle
                    }
                }
                return lower < blockIDs.count && blockIDs[lower] == value
            }
            let old = slots
            slots = [PackedJournalEntry](
                repeating: .empty,
                count: old.count
            )
            count = 0
            for entry in old where entry.packedLocation != 0 {
                let blockID = entry.location.blockID
                guard !contains(blockID) else {
                    continue
                }
                insertWithoutGrowing(entry)
            }
        }

        /// v1.21.6-rc.45: drop every slot whose block id is below `minimum`.
        ///
        /// The sibling `remove(blockIDs:)` takes an explicit expired set, which
        /// only the WRITER has (it created the tombstones). A read-only handle
        /// learns about expiry as a raised `journal_min_block_id` in the
        /// topology row and has no such list, so it needs the threshold form.
        /// Same rebuild-in-place shape, same invariants.
        mutating func removeBlocks(below minimum: Int64) {
            guard !slots.isEmpty else { return }
            let old = slots
            slots = [PackedJournalEntry](repeating: .empty, count: old.count)
            count = 0
            for entry in old where entry.packedLocation != 0 {
                guard entry.location.blockID >= minimum else { continue }
                insertWithoutGrowing(entry)
            }
        }

        func location(for key: PackedJournalEntry) -> JournalLocation? {
            guard !slots.isEmpty else { return nil }
            var index = Int(key.hash & UInt64(slots.count - 1))
            for _ in 0..<slots.count {
                let candidate = slots[index]
                if candidate.packedLocation == 0 { return nil }
                if candidate.sameID(as: key) { return candidate.location }
                index = (index + 1) & (slots.count - 1)
            }
            return nil
        }

        mutating func insert(_ entry: PackedJournalEntry) {
            // 85% avoids a 2^22-slot (~96 MiB) resize at the declared 1.6M
            // ceiling while UUID hashing still keeps expected probe runs
            // bounded. The 2^21 table is 48 MiB at maximum qualification load.
            if slots.isEmpty || (count + 1) * 20 > slots.count * 17 {
                resize(to: max(256, slots.count * 2))
            }
            insertWithoutGrowing(entry)
        }

        private mutating func resize(to requested: Int) {
            var capacity = 1
            while capacity < requested { capacity <<= 1 }
            let old = slots
            slots = [PackedJournalEntry](
                repeating: .empty,
                count: capacity
            )
            count = 0
            for entry in old where entry.packedLocation != 0 {
                insertWithoutGrowing(entry)
            }
        }

        private mutating func insertWithoutGrowing(
            _ entry: PackedJournalEntry
        ) {
            var index = Int(entry.hash & UInt64(slots.count - 1))
            while slots[index].packedLocation != 0 {
                if slots[index].sameID(as: entry) {
                    slots[index] = entry
                    return
                }
                index = (index + 1) & (slots.count - 1)
            }
            slots[index] = entry
            count += 1
        }
    }

    private struct JournalBloom {
        // 2^25 bits = 4 MiB. At the 1.1466M-event burst ceiling and four
        // probes this keeps false positives low while remaining fixed-memory.
        private static let bitCount = 1 << 25
        private static let wordCount = bitCount / 64
        private var words = [UInt64](repeating: 0, count: wordCount)

        var allocatedBytes: Int {
            words.capacity * MemoryLayout<UInt64>.stride
        }

        mutating func insert(_ id: UUID) {
            for probe in 0..<4 {
                let bit = bitPosition(id, probe: probe)
                words[bit >> 6] |= UInt64(1) << UInt64(bit & 63)
            }
        }

        func mightContain(_ id: UUID) -> Bool {
            for probe in 0..<4 {
                let bit = bitPosition(id, probe: probe)
                if words[bit >> 6] & (UInt64(1) << UInt64(bit & 63)) == 0 {
                    return false
                }
            }
            return true
        }

        /// Hash the UUID tuple in place. Startup can inspect 1.5M roster IDs;
        /// allocating Data, [UInt8], and [Int] for every probe otherwise turns
        /// the fixed 4-MiB Bloom into an allocation storm.
        private func bitPosition(_ id: UUID, probe: Int) -> Int {
            var tuple = id.uuid
            return withUnsafeBytes(of: &tuple) { bytes in
                func u64(_ offset: Int) -> UInt64 {
                    var value: UInt64 = 0
                    for index in 0..<8 {
                        value |= UInt64(bytes[offset + index])
                            << UInt64(index * 8)
                    }
                    return value
                }
                var h1 = u64(0) &* 0x9e37_79b9_7f4a_7c15
                var h2 = u64(8) &* 0xc2b2_ae3d_27d4_eb4f
                h1 ^= h1 >> 33
                h2 ^= h2 >> 29
                return Int(
                    (h1 &+ UInt64(probe) &* h2)
                        & UInt64(Self.bitCount - 1)
                )
            }
        }
    }

    /// Exact UUID idempotence without a random-key SQLite B-tree write for
    /// every event. Each block stores its 16-byte UUIDs append-locally; this
    /// bounded index is rebuilt and globally validated from those blobs on
    /// first use after every open or uncertain commit.
    private var journalBaseLocations: [PackedJournalEntry] = []
    private var journalDeltaLocations = PackedJournalDelta()
    private var journalIndexedLocationCount = 0
    private var journalOverflowBloom = JournalBloom()
    private var journalOverflowFirstBlockID: Int64?
    private var journalIndexLoaded = false
    private var journalIndexTopologyGeneration: Int64?
    private var journalIndexedBlockCount: Int64 = 0
    private var journalIndexedMinimumBlockID: Int64?
    private var journalIndexedMaximumBlockID: Int64?
    private var journalIndexOverflowed = false
    /// Expiry removes whole blocks in small fair quanta. Keep fixed-width
    /// locations for those blocks as cheap tombstones until the frozen-cutoff
    /// drain finishes, then rebuild once. This makes a drain O(retained +
    /// expired), not one full retained-corpus rebuild per 64-block quantum.
    private var journalExpiredBlockTombstones: [Int64] = []
    /// One timer task freezes a cutoff and drains it across fair quanta. Keep
    /// the metadata scan cursor with that cutoff so every retained summary is
    /// visited at most once during the drain rather than rescanning the prefix
    /// on each 64-block call.
    private var journalExpirySummaryCursor = 0
    private var journalExpirySummaryCutoff: TimeInterval?
    private var journalOverflowFallbackScans: UInt64 = 0
    private var journalVerifiedBlocks = 0
    private var journalVerifiedTerminalRevisions = 0
    private var journalIntegrityFailures = 0
    private var verifiedJournalSummaries: [VerifiedJournalSummary] = []
    private var journalExactQueryBlockDecodes: UInt64 = 0
    /// Completed base authentications, including startup verification. Kept
    /// internal so ordinary cold-read tests can pin redundant decode work.
    private(set) var journalBaseBlockDecodesForTesting: UInt64 = 0
    private var projectionOwnedUpperBoundBytes: Int64?
    private var projectionBlocksSincePhysicalMeasure = 0
    private var projectionDBStatProbeCount: UInt64 = 0
    /// Runtime writers must preserve enough family/WAL headroom to settle one
    /// maximum terminal batch as exact deltas or durable poison. The only
    /// exemption is the explicitly pre-producer migration/finalization phase,
    /// where no accepted base can be awaiting terminal settlement.
    private var terminalSettlementProtectionActive = true

    // MARK: Payload size cap (v1.12.6)

    /// Hard cap on per-event raw_json bytes after encoding. Events exceeding
    /// this are truncated at the per-arg level before re-encoding; the
    /// `payload.truncated` enrichment is set to record the truncation.
    ///
    /// Field-measured background: median exec raw_json is ~700B; P99 is under
    /// 16KB. The cap sits well above the long tail but well below the
    /// 1 MB outliers we've seen (e.g. base64-encoded appcast.xml passed via
    /// `python3 -c '...'`). Keeps the DB / FTS5 index / dashboard from
    /// being blinded by a single misbehaving caller.
    internal static let maxRawJsonBytes: Int = 65_536

    /// Threshold above which a single `process.args` entry gets replaced with
    /// a `<truncated:N bytes>` marker. Chosen to match the
    /// UnifiedLogCollector message cap convention so per-arg behaviour is
    /// predictable across collectors.
    internal static let argTruncationThreshold: Int = 4_096

    /// Hard cap on the bytes bound into the indexed `process_commandline`
    /// column (audit corr-storage). `raw_json` is bounded by
    /// `maxRawJsonBytes`, but the command line is bound to its OWN column and
    /// tokenized into the `events_fts` index independently of raw_json, so an
    /// oversized argv (e.g. an inline base64 payload) blows up both the column
    /// and the FTS index — defeating the raw_json cap for the exact vector it
    /// cites. 16 KB comfortably fits any real command line (P99 raw_json is
    /// <16 KB and the command line is only part of that) while bounding the
    /// pathological case. Applied to the stored + indexed copy only; the full
    /// (still per-arg-truncated) command line remains in raw_json.
    internal static let maxIndexedCommandLineBytes: Int = 16_384

    /// Truncate `s` so its UTF-8 encoding is at most `maxBytes`, cutting on a
    /// Character boundary (never mid-scalar) and appending a byte-count marker
    /// when truncation occurs. The common case (short command line) returns the
    /// input untouched after a single O(n) length check.
    static func boundIndexedText(_ s: String, maxBytes: Int) -> String {
        let utf8Count = s.utf8.count
        if utf8Count <= maxBytes { return s }
        let marker = "…<truncated:\(utf8Count) bytes>"
        let budget = max(0, maxBytes - marker.utf8.count)
        var kept = 0
        var end = s.startIndex
        var idx = s.startIndex
        while idx < s.endIndex {
            let n = String(s[idx]).utf8.count
            if kept + n > budget { break }
            kept += n
            idx = s.index(after: idx)
            end = idx
        }
        return String(s[s.startIndex..<end]) + marker
    }

    // MARK: Prepared statement cache

    private var insertStmt: OpaquePointer?

    /// Whether this store was opened in read-only mode (fallback for non-owner access).
    private var isReadOnly = false

    /// v1.8.0 Layer 1: pre-insert filter. Nil = no filtering (legacy behavior).
    /// Set after init via `setInsertFilter` so `init(path:)` test paths can
    /// bypass filtering. The daemon's bootstrap installs the default filter
    /// + any operator-extended patterns.
    private var insertFilter: EventInsertFilter?

    // MARK: - Schema migrations

    /// Ordered list of schema migrations applied on top of the baseline
    /// `CREATE TABLE IF NOT EXISTS events` statements in `openDatabase`.
    ///
    /// Each entry bumps `PRAGMA user_version` atomically. Fresh DBs run all
    /// migrations in order; existing DBs skip ones already applied.
    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "baseline",
            sql: []
        ),
        // v1.7.2: promote MCP attribution from raw_json to indexed
        // columns. v1.7.0 carried these in `event.enrichments` only;
        // the dashboard's MCPActivityView pre-v1.7.2 had to
        // json_extract over raw_json to filter by server. Now they're
        // top-level indexed columns with their own composite index.
        Migration(
            version: 2,
            name: "add_mcp_attribution_columns",
            sql: [
                "ALTER TABLE events ADD COLUMN mcp_server_name TEXT",
                "ALTER TABLE events ADD COLUMN mcp_server_category TEXT",
                "ALTER TABLE events ADD COLUMN ai_tool_session_id TEXT",
            ]
        ),
        // v1.8.0: tiered retention model. The `events` table becomes a
        // 24-hour hot tier; older rows get aggregated into
        // `event_aggregates` (≤30 day rollup) and the events LEADING UP TO an
        // alert get copied into `alert_evidence` (kept forever, bounded by
        // alert count). Capture is synchronous at alert-fire time, so it is
        // BACKWARD-looking — the ~windowSeconds of already-persisted events
        // before the alert; events after the alert have not happened yet.
        // (audit corr-storage: earlier "±60s"/"~120s" framing overstated a
        // forward window that is always empty at capture time.)
        //
        // Replaces the size-cap-and-VACUUM dance at DaemonTimers.swift —
        // pre-fix that approach silently let the file grow to 1.8 GB+ on
        // busy machines because per-tick VACUUM kept failing or being
        // skipped. The tier model is bounded by design: events table
        // never holds more than ~24h, aggregates are <5 MB, evidence
        // grows as alerts × ~windowSeconds of preceding events.
        Migration(
            version: 3,
            name: "add_tiered_retention_tables",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS alert_evidence (
                    alert_id TEXT NOT NULL,
                    id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    event_category TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_action TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    process_pid INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    process_commandline TEXT,
                    process_ppid INTEGER,
                    process_signer TEXT,
                    process_team_id TEXT,
                    process_signing_id TEXT,
                    file_path TEXT,
                    file_action TEXT,
                    network_dest_ip TEXT,
                    network_dest_port INTEGER,
                    tcc_service TEXT,
                    tcc_client TEXT,
                    raw_json TEXT NOT NULL,
                    mcp_server_name TEXT,
                    mcp_server_category TEXT,
                    ai_tool_session_id TEXT,
                    PRIMARY KEY (alert_id, id)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_evidence_alert_ts ON alert_evidence(alert_id, timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_evidence_event ON alert_evidence(id)",
                """
                CREATE TABLE IF NOT EXISTS event_aggregates (
                    day TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    process_signer TEXT NOT NULL DEFAULT '',
                    process_path TEXT NOT NULL DEFAULT '',
                    count INTEGER NOT NULL,
                    PRIMARY KEY (day, event_category, process_signer, process_path)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_aggregates_day ON event_aggregates(day)",
                "CREATE INDEX IF NOT EXISTS idx_aggregates_day_category ON event_aggregates(day, event_category)",
            ] + rollbackGuardDefinitions.filter {
                $0.table == "alert_evidence"
                    || $0.table == "event_aggregates"
            }.map(\.sql)
        ),
        // v1.9 Agent Traces (PR-1): additive columns for AI-agent attribution
        // surfaced via W3C TRACEPARENT propagation and lineage walks. Columns
        // are nullable; absence means "no agent trace was bound to this event."
        // The partial index covers only rows with an attached trace_id, which
        // is a tiny fraction of total events on a typical machine — keeping
        // the index size proportional to agent activity.
        //
        // `machine_agent_confidence` is immutable after the row is written;
        // user reattribute verdicts (PR-4) live in a separate
        // `attribution_overlay` table so the original attribution is always
        // auditable.
        Migration(
            version: 4,
            name: "add_agent_trace_columns",
            sql: [
                "ALTER TABLE events ADD COLUMN agent_trace_id TEXT",
                "ALTER TABLE events ADD COLUMN agent_span_id TEXT",
                "ALTER TABLE events ADD COLUMN agent_tool TEXT",
                "ALTER TABLE events ADD COLUMN machine_agent_confidence TEXT",
                "ALTER TABLE events ADD COLUMN agent_evidence_json TEXT",
            ]
        ),
        // v1.9 Agent Traces (PR-4): operator-recorded verdict overlay on
        // top of an event's machine-emitted attribution. Co-located with
        // events.db so retention coupling can run inside a single
        // transaction (Pass 12 invariant: every override row has a
        // matching event row). Single PRIMARY KEY column means a second
        // verdict for the same event REPLACES the first — single source
        // of truth per event, simpler quality metric.
        Migration(
            version: 5,
            name: "add_attribution_overrides_table",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS attribution_overrides (
                    event_id TEXT PRIMARY KEY,
                    machine_confidence TEXT,
                    user_verdict TEXT NOT NULL,
                    user_note TEXT,
                    schema_version INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_overrides_verdict ON attribution_overrides(user_verdict)",
                "CREATE INDEX IF NOT EXISTS idx_overrides_updated ON attribution_overrides(updated_at)",
            ] + rollbackGuardDefinitions.filter {
                $0.table == "attribution_overrides"
            }.map(\.sql)
        ),
        // v1.12.6 Wave 2A: promote user / architecture / notarization /
        // ai_tool / parent / session fields from raw_json into indexed
        // columns. Pre-fix, rules predicating on `User`, `Architecture`,
        // `NotarizationStatus`, etc. silently fell through to
        // `event.enrichments[fieldName]` (never populated for these keys
        // -- e.g. NotarizationChecker writes `notarization.status`, not
        // `NotarizationStatus`). Result: rosetta_binary_from_downloads,
        // notarization_absent_non_system, and the rosetta / notarized-
        // dropper sequence rules never fired in production.
        //
        // Migration is ADDITIVE: pre-v6 rows keep NULL for the new
        // columns, and RuleEngine falls back to raw_json extraction
        // for those rows so historical events remain matchable.
        Migration(
            version: 6,
            name: "promote_raw_json_to_indexed_columns",
            sql: [
                "ALTER TABLE events ADD COLUMN user_id INTEGER",
                "ALTER TABLE events ADD COLUMN user_name TEXT",
                "ALTER TABLE events ADD COLUMN group_id INTEGER",
                "ALTER TABLE events ADD COLUMN working_directory TEXT",
                "ALTER TABLE events ADD COLUMN responsible_pid INTEGER",
                "ALTER TABLE events ADD COLUMN architecture TEXT",
                "ALTER TABLE events ADD COLUMN is_platform_binary INTEGER",
                "ALTER TABLE events ADD COLUMN is_notarized INTEGER",
                "ALTER TABLE events ADD COLUMN process_sha256 TEXT",
                "ALTER TABLE events ADD COLUMN parent_name TEXT",
                "ALTER TABLE events ADD COLUMN parent_executable TEXT",
                "ALTER TABLE events ADD COLUMN parent_signer_type TEXT",
                "ALTER TABLE events ADD COLUMN ai_tool TEXT",
                "ALTER TABLE events ADD COLUMN ai_tool_child INTEGER",
                "ALTER TABLE events ADD COLUMN session_launch_source TEXT",
                "ALTER TABLE events ADD COLUMN tcc_decision TEXT",
            ]
        ),
        // v1.21.5 PERF: index hygiene on `events`, the highest-insert-rate table
        // in the product — every index on it is a B-tree write per row.
        // This describes v7's query layout. v8 exact queries use the journal,
        // so existing-store upgrades no longer require the replacement index.
        //
        // Drops two indexes that were strict prefixes of wider ones and so were
        // pure insert cost with no possible read benefit (see the baseline schema
        // in `openDatabase` for the prefix argument).
        //
        // Adds the index the dashboard's paged Events query actually needs.
        // `EventStore.events(before:category:severity:)` — re-run every 5 s by the
        // V2 Events workspace — builds
        //     WHERE event_category = ? AND severity IN (…) ORDER BY timestamp DESC
        // and the only composite available led with `timestamp`, so the planner
        // fell back to idx_events_category. That index has 3 distinct values, so
        // it visited ~1/3 of the table and temp-sorted those wide rows to return
        // 100. Leading with the equality column bounds the scan to rows that can
        // actually match; the residual ORDER BY sort is then over a handful of
        // rows instead of thousands.
        //
        // `DROP INDEX IF EXISTS` is idempotent, which matters here: SchemaMigrator
        // re-applies EVERY migration on EVERY open (see its v1.7.6 co-resident-
        // store fix), so a non-idempotent DROP would be a bug. These are safe.
        Migration(
            version: 7,
            name: "prune_redundant_event_indexes",
            sql: [
                "DROP INDEX IF EXISTS idx_events_process_path",
                "DROP INDEX IF EXISTS idx_events_ts_severity",
                journalCategoryIndexSQL,
            ]
        ),
        // v1.21.6-rc.13: complete, checksummed block journal plus a bounded
        // interactive projection. The legacy `events` table is retained as an
        // on-disk compatibility/search surface, but production rows carry a
        // journal reference instead of duplicating full raw JSON. Exact APIs
        // use `event_journal_blocks` + the UUID locator below.
        Migration(
            version: 8,
            name: "add_lossless_event_journal",
            sql: [
                // This name deliberately collides with rc.12's first legacy
                // CREATE INDEX. It is the schema-path downgrade barrier; the
                // DML guards below additionally cover rc.12 shed-mode opens
                // that skip schema setup and proceed directly to maintenance.
                "CREATE VIEW IF NOT EXISTS idx_events_timestamp AS SELECT 'maccrab_rc13_write_barrier' AS marker",
                "ALTER TABLE events ADD COLUMN journal_block_id INTEGER",
                "ALTER TABLE events ADD COLUMN journal_quarantine_marker BLOB",
                "ALTER TABLE events ADD COLUMN journal_ordinal INTEGER",
                "ALTER TABLE events ADD COLUMN projection_reason INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE events ADD COLUMN projection_estimated_bytes INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE events ADD COLUMN projection_rank INTEGER NOT NULL DEFAULT 100",
                "ALTER TABLE events ADD COLUMN projection_bucket INTEGER",
                """
                CREATE TABLE IF NOT EXISTS event_journal_blocks (
                    block_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    min_timestamp REAL NOT NULL,
                    max_timestamp REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    admission_bucket INTEGER NOT NULL,
                    event_count INTEGER NOT NULL CHECK(event_count > 0 AND event_count <= 128),
                    process_count INTEGER NOT NULL DEFAULT 0,
                    process_min_timestamp REAL,
                    process_max_timestamp REAL,
                    file_count INTEGER NOT NULL DEFAULT 0,
                    file_min_timestamp REAL,
                    file_max_timestamp REAL,
                    network_count INTEGER NOT NULL DEFAULT 0,
                    network_min_timestamp REAL,
                    network_max_timestamp REAL,
                    authentication_count INTEGER NOT NULL DEFAULT 0,
                    authentication_min_timestamp REAL,
                    authentication_max_timestamp REAL,
                    tcc_count INTEGER NOT NULL DEFAULT 0,
                    tcc_min_timestamp REAL,
                    tcc_max_timestamp REAL,
                    registry_count INTEGER NOT NULL DEFAULT 0,
                    registry_min_timestamp REAL,
                    registry_max_timestamp REAL,
                    event_ids BLOB NOT NULL CHECK(length(event_ids) = event_count * 16),
                    source_identity_sha256s BLOB NOT NULL CHECK(length(source_identity_sha256s) = event_count * 32),
                    projection_dispositions BLOB NOT NULL CHECK(length(projection_dispositions) = ((event_count * 3 + 7) / 8)),
                    projection_dispositions_sha256 BLOB NOT NULL CHECK(length(projection_dispositions_sha256) = 32),
                    raw_bytes INTEGER NOT NULL CHECK(raw_bytes > 0 AND raw_bytes <= 25165824),
                    codec INTEGER NOT NULL CHECK(codec IN (0, 1)),
                    sha256 BLOB NOT NULL UNIQUE CHECK(length(sha256) = 32),
                    metadata_sha256 BLOB NOT NULL CHECK(length(metadata_sha256) = 32),
                    payload BLOB NOT NULL CHECK(length(payload) > 0 AND length(payload) <= 25165824)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS event_journal_terminal_revisions (
                    block_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 128),
                    event_id BLOB NOT NULL CHECK(length(event_id) = 16),
                    base_sha256 BLOB NOT NULL CHECK(length(base_sha256) = 32),
                    terminal_sha256 BLOB NOT NULL CHECK(length(terminal_sha256) = 32),
                    framed_sha256 BLOB NOT NULL CHECK(length(framed_sha256) = 32),
                    raw_bytes INTEGER NOT NULL CHECK(raw_bytes > 0 AND raw_bytes <= 25165824),
                    codec INTEGER NOT NULL CHECK(codec IN (0, 1)),
                    payload BLOB NOT NULL CHECK(length(payload) > 0 AND length(payload) <= 25165824),
                    created_at REAL NOT NULL,
                    PRIMARY KEY(block_id, ordinal),
                    FOREIGN KEY(block_id) REFERENCES event_journal_blocks(block_id) ON DELETE CASCADE
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS event_journal_projection_promotions (
                    block_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 128),
                    event_id BLOB NOT NULL CHECK(length(event_id) = 16),
                    matches_sha256 BLOB NOT NULL CHECK(length(matches_sha256) = 32),
                    matches_json BLOB NOT NULL CHECK(length(matches_json) > 0 AND length(matches_json) <= 12582912),
                    created_at REAL NOT NULL,
                    PRIMARY KEY(block_id, ordinal),
                    FOREIGN KEY(block_id) REFERENCES event_journal_blocks(block_id) ON DELETE CASCADE
                ) WITHOUT ROWID
                """,
                """
                CREATE TABLE IF NOT EXISTS event_journal_payload_poison (
                    block_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 128),
                    event_id BLOB NOT NULL CHECK(length(event_id) = 16),
                    poison_kind TEXT NOT NULL CHECK(poison_kind IN ('base', 'terminal', 'promotion')),
                    replacement_sha256 BLOB NOT NULL CHECK(length(replacement_sha256) = 32),
                    original_sha256 BLOB NOT NULL CHECK(length(original_sha256) = 32),
                    source_identity_sha256 BLOB NOT NULL CHECK(length(source_identity_sha256) = 32),
                    original_bytes INTEGER NOT NULL CHECK(original_bytes >= 0),
                    digest_kind TEXT NOT NULL CHECK(digest_kind IN ('canonical_json', 'structural_preflight')),
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 1 CHECK(attempt_count > 0),
                    PRIMARY KEY(block_id, ordinal, poison_kind),
                    UNIQUE(event_id, poison_kind),
                    FOREIGN KEY(block_id) REFERENCES event_journal_blocks(block_id) ON DELETE CASCADE
                ) WITHOUT ROWID
                """,
                """
                CREATE TABLE IF NOT EXISTS event_journal_inherited_loss (
                    block_id INTEGER NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0 AND ordinal < 128),
                    event_id BLOB NOT NULL CHECK(length(event_id) = 16),
                    loss_kind TEXT NOT NULL CHECK(loss_kind IN ('structured_truncation', 'sanitizer_rebuild')),
                    original_bytes INTEGER CHECK(original_bytes IS NULL OR original_bytes > 0),
                    original_sha256 BLOB CHECK(original_sha256 IS NULL OR length(original_sha256) = 32),
                    recovered_fields_json BLOB NOT NULL CHECK(length(recovered_fields_json) BETWEEN 2 AND 8192),
                    unavailable_fields_json BLOB NOT NULL CHECK(length(unavailable_fields_json) BETWEEN 2 AND 8192),
                    ledger_sha256 BLOB NOT NULL CHECK(length(ledger_sha256) = 32),
                    created_at REAL NOT NULL,
                    PRIMARY KEY(block_id, ordinal),
                    FOREIGN KEY(block_id) REFERENCES event_journal_blocks(block_id) ON DELETE CASCADE
                ) WITHOUT ROWID
                """,
                """
                CREATE TABLE IF NOT EXISTS event_aggregate_gaps (
                    day TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    reason TEXT NOT NULL CHECK(reason IN ('canonical_poison', 'aggregate_key_compacted', 'inherited_legacy_loss')),
                    count INTEGER NOT NULL CHECK(count > 0),
                    PRIMARY KEY(day, event_category, reason)
                ) WITHOUT ROWID
                """,
                """
                CREATE TABLE IF NOT EXISTS event_projection_coverage (
                    bucket_start INTEGER PRIMARY KEY,
                    considered_count INTEGER NOT NULL DEFAULT 0 CHECK(considered_count >= 0),
                    materialized_count INTEGER NOT NULL DEFAULT 0 CHECK(materialized_count >= 0),
                    materialized_bytes INTEGER NOT NULL DEFAULT 0 CHECK(materialized_bytes >= 0),
                    omitted_quota_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_quota_count >= 0),
                    omitted_replaced_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_replaced_count >= 0),
                    omitted_physical_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_physical_count >= 0),
                    omitted_external_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_external_count >= 0),
                    omitted_migration_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_migration_count >= 0),
                    pending_count INTEGER NOT NULL DEFAULT 0 CHECK(pending_count >= 0),
                    replacement_total INTEGER NOT NULL DEFAULT 0 CHECK(replacement_total >= 0),
                    updated_at REAL NOT NULL,
                    CHECK(considered_count = materialized_count + omitted_quota_count + omitted_replaced_count + omitted_physical_count + omitted_external_count + omitted_migration_count + pending_count)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS event_projection_block_coverage (
                    block_id INTEGER PRIMARY KEY,
                    bucket_start INTEGER NOT NULL,
                    considered_count INTEGER NOT NULL DEFAULT 0 CHECK(considered_count >= 0),
                    materialized_count INTEGER NOT NULL DEFAULT 0 CHECK(materialized_count >= 0),
                    materialized_bytes INTEGER NOT NULL DEFAULT 0 CHECK(materialized_bytes >= 0),
                    omitted_quota_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_quota_count >= 0),
                    omitted_replaced_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_replaced_count >= 0),
                    omitted_physical_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_physical_count >= 0),
                    omitted_external_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_external_count >= 0),
                    omitted_migration_count INTEGER NOT NULL DEFAULT 0 CHECK(omitted_migration_count >= 0),
                    pending_count INTEGER NOT NULL DEFAULT 0 CHECK(pending_count >= 0),
                    replacement_total INTEGER NOT NULL DEFAULT 0 CHECK(replacement_total >= 0),
                    CHECK(considered_count = materialized_count + omitted_quota_count + omitted_replaced_count + omitted_physical_count + omitted_external_count + omitted_migration_count + pending_count),
                    FOREIGN KEY(block_id) REFERENCES event_journal_blocks(block_id) ON DELETE CASCADE
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS event_journal_migration (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    last_legacy_rowid INTEGER NOT NULL DEFAULT 0 CHECK(last_legacy_rowid >= 0),
                    stage INTEGER NOT NULL DEFAULT 0 CHECK(stage IN (0, 1, 2)),
                    source_events INTEGER NOT NULL DEFAULT 0 CHECK(source_events >= 0),
                    migrated_events INTEGER NOT NULL DEFAULT 0 CHECK(migrated_events >= 0),
                    rolled_expired_events INTEGER NOT NULL DEFAULT 0 CHECK(rolled_expired_events >= 0),
                    corrupt_preserved_events INTEGER NOT NULL DEFAULT 0 CHECK(corrupt_preserved_events >= 0),
                    remaining_events INTEGER NOT NULL DEFAULT 0 CHECK(remaining_events >= 0),
                    reopen_epochs INTEGER NOT NULL DEFAULT 0 CHECK(reopen_epochs >= 0),
                    schema_finalized INTEGER NOT NULL DEFAULT 0 CHECK(schema_finalized IN (0, 1)),
                    started_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    CHECK(source_events = migrated_events + rolled_expired_events + corrupt_preserved_events + remaining_events)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS event_journal_legacy_quarantine (
                    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_marker BLOB NOT NULL UNIQUE CHECK(length(source_marker) = 32),
                    legacy_rowid INTEGER NOT NULL,
                    legacy_id_bytes BLOB NOT NULL,
                    identity_kind TEXT NOT NULL CHECK(identity_kind IN ('id', 'rowid')),
                    legacy_timestamp REAL NOT NULL,
                    legacy_category_bytes BLOB NOT NULL,
                    raw_json BLOB NOT NULL,
                    raw_sha256 BLOB NOT NULL CHECK(length(raw_sha256) = 32),
                    typed_row_sha256 BLOB NOT NULL CHECK(length(typed_row_sha256) = 32),
                    reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 1024),
                    quarantined_at REAL NOT NULL,
                    UNIQUE(legacy_rowid)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_event_journal_legacy_quarantine_id ON event_journal_legacy_quarantine(legacy_id_bytes) WHERE identity_kind = 'id'",
                """
                CREATE TABLE IF NOT EXISTS event_storage_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    mutation_generation INTEGER NOT NULL DEFAULT 0 CHECK(mutation_generation >= 0),
                    journal_topology_generation INTEGER NOT NULL DEFAULT 0 CHECK(journal_topology_generation >= 0),
                    journal_block_count INTEGER NOT NULL DEFAULT 0 CHECK(journal_block_count >= 0),
                    journal_min_block_id INTEGER CHECK(journal_min_block_id IS NULL OR journal_min_block_id > 0),
                    journal_max_block_id INTEGER CHECK(journal_max_block_id IS NULL OR journal_max_block_id > 0),
                    payload_poison_total INTEGER NOT NULL DEFAULT 0 CHECK(payload_poison_total >= 0),
                    updated_at REAL NOT NULL,
                    CHECK((journal_block_count = 0 AND journal_min_block_id IS NULL AND journal_max_block_id IS NULL) OR (journal_block_count > 0 AND journal_min_block_id IS NOT NULL AND journal_max_block_id IS NOT NULL AND journal_min_block_id <= journal_max_block_id))
                )
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_blocks_generation_ai
                AFTER INSERT ON event_journal_blocks BEGIN
                    UPDATE event_storage_state SET
                        mutation_generation = mutation_generation + 1,
                        journal_topology_generation = journal_topology_generation + 1,
                        journal_block_count = journal_block_count + 1,
                        journal_min_block_id = CASE WHEN journal_min_block_id IS NULL OR NEW.block_id < journal_min_block_id THEN NEW.block_id ELSE journal_min_block_id END,
                        journal_max_block_id = CASE WHEN journal_max_block_id IS NULL OR NEW.block_id > journal_max_block_id THEN NEW.block_id ELSE journal_max_block_id END,
                        updated_at = CAST(strftime('%s','now') AS REAL)
                    WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_blocks_generation_au
                AFTER UPDATE ON event_journal_blocks BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_blocks_generation_ad
                AFTER DELETE ON event_journal_blocks BEGIN
                    UPDATE event_storage_state SET
                        mutation_generation = mutation_generation + 1,
                        journal_topology_generation = journal_topology_generation + 1,
                        journal_block_count = journal_block_count - 1,
                        journal_min_block_id = (SELECT MIN(block_id) FROM event_journal_blocks),
                        journal_max_block_id = (SELECT MAX(block_id) FROM event_journal_blocks),
                        updated_at = CAST(strftime('%s','now') AS REAL)
                    WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_terminal_generation_ai
                AFTER INSERT ON event_journal_terminal_revisions BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_terminal_generation_au
                AFTER UPDATE ON event_journal_terminal_revisions BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_terminal_generation_ad
                AFTER DELETE ON event_journal_terminal_revisions BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_promotion_generation_ai
                AFTER INSERT ON event_journal_projection_promotions BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_promotion_generation_au
                AFTER UPDATE ON event_journal_projection_promotions BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_promotion_generation_ad
                AFTER DELETE ON event_journal_projection_promotions BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_poison_generation_ai
                AFTER INSERT ON event_journal_payload_poison BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_poison_generation_au
                AFTER UPDATE ON event_journal_payload_poison BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_poison_generation_ad
                AFTER DELETE ON event_journal_payload_poison BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_inherited_loss_generation_ai
                AFTER INSERT ON event_journal_inherited_loss BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_inherited_loss_generation_au
                AFTER UPDATE ON event_journal_inherited_loss BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_journal_inherited_loss_generation_ad
                AFTER DELETE ON event_journal_inherited_loss BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_aggregate_gaps_generation_ai
                AFTER INSERT ON event_aggregate_gaps BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_aggregate_gaps_generation_au
                AFTER UPDATE ON event_aggregate_gaps BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS event_aggregate_gaps_generation_ad
                AFTER DELETE ON event_aggregate_gaps BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS events_generation_ai
                AFTER INSERT ON events BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS events_generation_au
                AFTER UPDATE ON events BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS events_generation_ad
                AFTER DELETE ON events BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS projection_coverage_generation_ai
                AFTER INSERT ON event_projection_coverage BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS projection_coverage_generation_au
                AFTER UPDATE ON event_projection_coverage BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS projection_coverage_generation_ad
                AFTER DELETE ON event_projection_coverage BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS projection_block_coverage_generation_ai
                AFTER INSERT ON event_projection_block_coverage BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS projection_block_coverage_generation_au
                AFTER UPDATE ON event_projection_block_coverage BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS projection_block_coverage_generation_ad
                AFTER DELETE ON event_projection_block_coverage BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS journal_migration_generation_ai
                AFTER INSERT ON event_journal_migration BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS journal_migration_generation_au
                AFTER UPDATE ON event_journal_migration BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS journal_migration_generation_ad
                AFTER DELETE ON event_journal_migration BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS journal_quarantine_generation_ai
                AFTER INSERT ON event_journal_legacy_quarantine BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS journal_quarantine_generation_au
                AFTER UPDATE ON event_journal_legacy_quarantine BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                """
                CREATE TRIGGER IF NOT EXISTS journal_quarantine_generation_ad
                AFTER DELETE ON event_journal_legacy_quarantine BEGIN
                    UPDATE event_storage_state SET mutation_generation = mutation_generation + 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1;
                END
                """,
                "CREATE INDEX IF NOT EXISTS idx_event_projection_timestamp ON events(timestamp) WHERE journal_block_id IS NOT NULL",
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_event_projection_locator ON events(journal_block_id, journal_ordinal) WHERE journal_block_id IS NOT NULL",
                "CREATE INDEX IF NOT EXISTS idx_event_projection_victim ON events(projection_bucket, projection_rank DESC, id DESC) WHERE journal_block_id IS NOT NULL",
            ] + rollbackGuardDefinitions.map(\.sql)
        ),
    ]

    // MARK: Initialization

    /// Throw `EventStoreError.databaseOpenFailed` if `path` exists and is a
    /// symbolic link. A missing file is always OK — SQLite will create it.
    private static func rejectIfSymlink(_ path: String) throws {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path) else {
            return // does not exist yet — safe
        }
        if (attrs[.type] as? FileAttributeType) == .typeSymbolicLink {
            throw EventStoreError.databaseOpenFailed("refusing to open: \(path) is a symlink")
        }
    }

    private static func defaultStoragePolicy(
        for databasePath: String
    ) -> SQLitePersistentStorePolicy {
        SQLitePersistentStorePolicy(
            // DaemonConfig's 476 MiB envelope reserves 100 MiB for
            // alert-owned evidence after the schema-v8 file split.
            maxFootprintBytes: 376 * SQLitePersistentStorePolicy.bytesPerMiB,
            freeSpaceFloorBytes: SQLitePersistentStorePolicy.freeSpaceFloorBytes,
            transactionReserveBytes: SQLitePersistentStorePolicy
                .eventTransactionReserveBytes,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent
        )
    }

    /// Measure preserved `events.db.alert_evidence` before opening the normal
    /// EventStore writer. The only permitted mutation is a fully admitted WAL
    /// TRUNCATE checkpoint: schema, rows and pragmas are otherwise untouched.
    /// This uses the same NOFOLLOW path boundary, vendored CSQLCipher runtime,
    /// checkpoint ownership hook and configured policy as the real store. A
    /// pinned reader is a typed startup-not-ready result, never permission to
    /// fall back to the historical 100-MiB transition allowance.
    /// Whether a WAL checkpoint left the store safe to open.
    ///
    /// "Drained" means no un-checkpointed frames remain — NOT that the WAL file
    /// also shrank. `SQLITE_CHECKPOINT_TRUNCATE` copies every frame into the
    /// main database and then resets the file; the reset needs a moment with no
    /// readers and returns SQLITE_BUSY *without undoing the copy*.
    ///
    /// Requiring `rc == SQLITE_OK` therefore refused stores that were completely
    /// consistent. An installed host returned `busy=1, log=31225,
    /// checkpointed=31225` — every frame durable in the main database, only the
    /// truncate blocked by the dashboard's read connection — and the daemon
    /// refused to boot, relaunching every ~10s. Each relaunch then took the lock
    /// the truncate needed, so the loop sustained itself and the machine
    /// collected nothing until an operator ran a checkpoint by hand.
    ///
    /// A still-allocated WAL file is a space concern the ordinary checkpoint
    /// path reclaims later. It is not a reason to refuse to start.
    nonisolated static func walDrainSatisfied(
        resultCode: Int32,
        logFrames: Int32,
        checkpointedFrames: Int32
    ) -> Bool {
        if resultCode == SQLITE_OK,
           logFrames == 0 || logFrames == checkpointedFrames {
            return true
        }
        if resultCode == SQLITE_BUSY || resultCode == SQLITE_LOCKED,
           logFrames > 0, logFrames == checkpointedFrames {
            return true
        }
        return false
    }

    public nonisolated static func preopenLegacyAlertEvidenceTransitionMeasurement(
        path: String,
        maxBytes: Int64,
        checkpointPolicy: SQLitePersistentStorePolicy
    ) throws -> LegacyAlertEvidenceTransitionMeasurement {
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")
        guard try SQLitePersistentStoreAdmission.mainFileExists(path) else {
            return LegacyAlertEvidenceTransitionMeasurement(
                evidence: AlertEvidenceBudgetSnapshot(
                    rowCount: 0,
                    logicalBytes: 0,
                    allocatedBytes: 0,
                    chargedBytes: 0,
                    maxBytes: max(0, maxBytes)
                ),
                familyFootprintBytes: 0,
                walCheckpointDrained: true,
                pageSizeBytes: 4_096,
                pageCount: 0,
                freelistCount: 0
            )
        }

        _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        var handle: OpaquePointer?
        let openRC = SQLiteOpenPathPolicy.open(
            path,
            database: &handle,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
        )
        guard openRC == SQLITE_OK, let handle else {
            if let handle { sqlite3_close(handle) }
            throw EventStoreError.storageNotReady(
                "pre-open evidence measurement could not open events.db read-write (rc=\(openRC))"
            )
        }
        var controller: SQLiteControlledCheckpointController?
        defer {
            controller?.detach(from: handle)
            sqlite3_close(handle)
        }
        controller = try SQLiteControlledCheckpointController.install(
            on: handle,
            thresholdPages: StoragePragmas.eventWalAutocheckpointPages,
            families: [
                "main": SQLiteControlledCheckpointFamily(
                    databasePath: path,
                    policy: checkpointPolicy
                ),
            ]
        )
        try Self.exec(handle, "PRAGMA busy_timeout = 5000")
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: path,
            policy: checkpointPolicy,
            maintenance: true
        )
        try admission.admitCheckpoint()

        var checkpointRC: Int32 = SQLITE_BUSY
        var logFrames: Int32 = 0
        var checkpointedFrames: Int32 = 0
        var checkpointDrained = false
        // A dashboard snapshot can momentarily pin the WAL exactly as the
        // daemon upgrades. Give that benign race the same bounded grace as the
        // pre-producer no-delete recovery path: three probes separated by
        // 250 ms. A persistent pin still fails before any v8 schema/data write.
        // v1.21.6-rc.37: DRAINED means "no un-checkpointed frames remain", not
        // "the file also shrank".
        //
        // `SQLITE_CHECKPOINT_TRUNCATE` does two things: copy every WAL frame
        // into the main database, then reset the file to zero length. The second
        // step needs a moment with no readers, and returns SQLITE_BUSY without
        // undoing the first. On an installed host this returned
        // `busy=1, log=31225, checkpointed=31225` — every frame durable in the
        // main DB, only the truncate lost the race — and boot refused to start,
        // relaunching every ~10s. Each relaunch then took the lock the truncate
        // needed, so the loop sustained itself.
        //
        // Frames copied is the correctness condition and is what this check
        // exists to establish. A WAL file that is merely still allocated is a
        // space concern the ordinary checkpoint path reclaims later.
        //
        // The window also has to be realistic: three attempts 250 ms apart is
        // 750 ms, while a dashboard snapshot holds a read transaction for far
        // longer. Manual recovery on the same host needed a 20-second timeout.
        var backoffMicroseconds: useconds_t = 250_000
        for attempt in 0..<6 {
            logFrames = 0
            checkpointedFrames = 0
            checkpointRC = sqlite3_wal_checkpoint_v2(
                handle,
                nil,
                SQLITE_CHECKPOINT_TRUNCATE,
                &logFrames,
                &checkpointedFrames
            )
            if Self.walDrainSatisfied(
                resultCode: checkpointRC,
                logFrames: logFrames,
                checkpointedFrames: checkpointedFrames
            ) {
                checkpointDrained = true
                break
            }
            guard checkpointRC == SQLITE_BUSY
                    || checkpointRC == SQLITE_LOCKED else {
                break
            }
            if attempt < 5 {
                usleep(backoffMicroseconds)
                backoffMicroseconds = min(backoffMicroseconds * 2, 4_000_000)
            }
        }
        guard checkpointDrained else {
            let detail = checkpointRC == SQLITE_BUSY
                    || checkpointRC == SQLITE_LOCKED
                ? "a reader pinned WAL frames after six bounded attempts "
                    + "(\(checkpointedFrames) of \(logFrames) frames copied)"
                : "checkpoint rc=\(checkpointRC)"
            throw EventStoreError.storageNotReady(
                "pre-open evidence measurement did not fully drain WAL: \(detail)"
            )
        }

        func scalar(_ sql: String) throws -> Int64 {
            var statement: OpaquePointer?
            let prepareRC = sqlite3_prepare_v2(
                handle, sql, -1, &statement, nil
            )
            guard prepareRC == SQLITE_OK, let statement else {
                sqlite3_finalize(statement)
                throw EventStoreError.stepFailed(
                    "pre-open transition query prepare failed"
                )
            }
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "pre-open transition query returned no row"
                )
            }
            return sqlite3_column_int64(statement, 0)
        }
        let tableExists = try scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alert_evidence'"
        ) == 1
        let rowCount = tableExists
            ? Int(try scalar("SELECT COUNT(*) FROM alert_evidence")) : 0
        let logicalBytes = tableExists && rowCount > 0
            ? max(0, try scalar(
                "SELECT COALESCE(SUM(LENGTH(CAST(raw_json AS BLOB))), 0) FROM alert_evidence"
            )) : 0
        let allocatedBytes = tableExists && rowCount > 0
            ? max(0, try scalar(
                """
                SELECT COALESCE(SUM(pgsize), 0) FROM dbstat
                WHERE name = 'alert_evidence'
                   OR name IN (SELECT name FROM sqlite_master
                               WHERE type='index' AND tbl_name='alert_evidence')
                """
            )) : 0
        let pageSize = try scalar("PRAGMA page_size")
        let pageCount = try scalar("PRAGMA page_count")
        let freelistCount = try scalar("PRAGMA freelist_count")
        guard pageSize > 0, pageCount >= 0, freelistCount >= 0,
              freelistCount <= pageCount else {
            throw EventStoreError.storageNotReady(
                "pre-open evidence page accounting is invalid"
            )
        }
        return LegacyAlertEvidenceTransitionMeasurement(
            evidence: AlertEvidenceBudgetSnapshot(
                rowCount: rowCount,
                logicalBytes: logicalBytes,
                allocatedBytes: allocatedBytes,
                chargedBytes: max(logicalBytes, allocatedBytes),
                maxBytes: max(0, maxBytes)
            ),
            familyFootprintBytes:
                try SQLitePersistentStoreAdmission.measureFamily(path),
            walCheckpointDrained: true,
            pageSizeBytes: pageSize,
            pageCount: pageCount,
            freelistCount: freelistCount
        )
    }

    private final class TransitionReclaimDeadline {
        let end = ContinuousClock.now.advanced(by: .seconds(30))
        var expired: Bool { ContinuousClock.now >= end }
    }

    private struct LegacyBootstrapReclaimPlan {
        let indexes: Set<String>
        let metadataAllocationBytes: Int64
        let metadataTransactionBytes: Int64
        let maximumTransactionBytes: Int64
    }

    private static func transitionScalar(
        _ db: OpaquePointer, _ sql: String, allowNegative: Bool = false
    ) throws -> Int64 {
        var raw: OpaquePointer?
        let prepared = sqlite3_prepare_v2(db, sql, -1, &raw, nil)
        guard prepared == SQLITE_OK, let statement = raw else {
            sqlite3_finalize(raw)
            throw EventStoreError.storageNotReady("legacy bootstrap scalar could not be prepared")
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW,
              sqlite3_column_type(statement, 0) == SQLITE_INTEGER else {
            throw EventStoreError.storageNotReady("legacy bootstrap scalar was unavailable")
        }
        let result = sqlite3_column_int64(statement, 0)
        guard (allowNegative || result >= 0), sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.storageNotReady("legacy bootstrap scalar was invalid")
        }
        return result
    }

    private static func withLegacyBootstrapWorkspace<Result>(
        on db: OpaquePointer,
        budget: EventPipelineLiveMemoryBudget,
        _ body: (EventPipelineMemoryLease, TransitionReclaimDeadline) throws -> Result
    ) throws -> Result {
        guard try transitionScalar(db, "SELECT COUNT(*) FROM pragma_journal_mode WHERE journal_mode='wal'") == 1,
              sqlite3_compileoption_used("TEMP_STORE=2") == 1 else {
            throw EventStoreError.storageNotReady("legacy bootstrap requires its verified WAL and memory-journal configuration")
        }
        var powersafe: Int32 = -1
        guard sqlite3_file_control(db, "main", SQLITE_FCNTL_POWERSAFE_OVERWRITE, &powersafe) == SQLITE_OK,
              powersafe == 1,
              let lease = budget.tryAcquire(bytes: EventJournalCodec.maximumWorkspaceBytes,
                  owner: .eventStoreWorkspace) else {
            throw EventStoreError.storageNotReady("legacy bootstrap is waiting for verified bounded storage workspace")
        }
        defer { withExtendedLifetime(lease) {} }
        let spill = try transitionScalar(db, "PRAGMA cache_spill")
        let cache = try transitionScalar(db, "PRAGMA cache_size", allowNegative: true)
        let mmap = try transitionScalar(db, "PRAGMA mmap_size")
        let timeout = try transitionScalar(db, "PRAGMA busy_timeout")
        let temp = try transitionScalar(db, "PRAGMA temp_store")
        let deadline = TransitionReclaimDeadline()
        func restore() throws {
            sqlite3_progress_handler(db, 0, nil, nil)
            if sqlite3_get_autocommit(db) == 0 { try Self.exec(db, "ROLLBACK") }
            try Self.exec(db, "PRAGMA cache_spill=\(spill)")
            try Self.exec(db, "PRAGMA cache_size=\(cache)")
            try Self.exec(db, "PRAGMA mmap_size=\(mmap)")
            try Self.exec(db, "PRAGMA busy_timeout=\(timeout)")
            try Self.exec(db, "PRAGMA temp_store=\(temp)")
        }
        do {
            try Self.exec(db, "PRAGMA cache_size=-1024")
            try Self.exec(db, "PRAGMA mmap_size=0")
            try Self.exec(db, "PRAGMA cache_spill=OFF")
            try Self.exec(db, "PRAGMA busy_timeout=250")
            // DROP/CREATE use an automatic statement journal even with cache
            // spills disabled. Keep its before-images in the leased memory.
            try Self.exec(db, "PRAGMA temp_store=MEMORY")
            // Cooperative VM/statement deadline; an internal b-tree traversal
            // or blocked filesystem operation is not a strict wall-time bound.
            sqlite3_progress_handler(db, 1000, { pointer in
                guard let pointer else { return 1 }
                return Unmanaged<TransitionReclaimDeadline>.fromOpaque(pointer)
                    .takeUnretainedValue().expired ? 1 : 0
            }, Unmanaged.passUnretained(deadline).toOpaque())
            defer {
                sqlite3_progress_handler(db, 0, nil, nil)
                withExtendedLifetime(deadline) {}
            }
            try Task.checkCancellation()
            let result = try body(lease, deadline)
            try Task.checkCancellation()
            try restore()
            guard !deadline.expired else {
                throw EventStoreError.storageNotReady("legacy bootstrap reached its cooperative work deadline; committed progress is preserved")
            }
            return result
        } catch {
            let original = error
            try restore()
            if deadline.expired {
                throw EventStoreError.storageNotReady("legacy bootstrap reached its cooperative work deadline; committed progress is preserved")
            }
            throw original
        }
    }

    /// One-time structural validation before the legacy rollback barrier.
    /// This reserves an estimate of the valid published format's live SQLite
    /// workspace, not an allocator/RSS limit for malformed encoded lengths.
    /// The complete main database is checked together, including cross-tree
    /// page ownership. FTS external-content equivalence is checked separately
    /// during journal finalization; SQLite quick_check does not prove it.
    private static func checkLegacySQLiteStructure(
        on db: OpaquePointer,
        budget: EventPipelineLiveMemoryBudget,
        existingWorkspace: EventPipelineMemoryLease?,
        existingDeadline: TransitionReclaimDeadline?
    ) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else {
            throw SQLitePersistentStoreAdmissionError.schemaTransactionNotSerialized
        }
        var leases: [EventPipelineMemoryLease] = []
        defer { withExtendedLifetime(leases) {}; withExtendedLifetime(existingWorkspace) {} }
        if existingWorkspace == nil {
            guard let initial = budget.tryAcquire(bytes: 2 * 1_048_576, owner: .eventStoreWorkspace) else {
                throw EventStoreError.storageNotReady("legacy structural check is waiting for initial owned workspace")
            }
            leases.append(initial)
        }
        let deadline = existingDeadline ?? TransitionReclaimDeadline()
        defer { withExtendedLifetime(deadline) {} }
        let cache = try transitionScalar(db, "PRAGMA cache_size", allowNegative: true)
        let mmap = try transitionScalar(db, "PRAGMA mmap_size")
        func restore() throws {
            if existingDeadline == nil { sqlite3_progress_handler(db, 0, nil, nil) }
            try Self.exec(db, "PRAGMA cache_size=\(cache)")
            try Self.exec(db, "PRAGMA mmap_size=\(mmap)")
        }
        func sqliteError(_ rc: Int32) -> EventStoreError {
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            return .sqliteFailure(context: "legacy structural quick_check",
                message: "SQLite structural check did not complete",
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno)
        }
        do {
            try Task.checkCancellation()
            try Self.exec(db, "PRAGMA cache_size=-1024")
            try Self.exec(db, "PRAGMA mmap_size=0")
            if existingDeadline == nil {
                sqlite3_progress_handler(db, 1000, { pointer in
                    guard let pointer else { return 1 }
                    return Unmanaged<TransitionReclaimDeadline>.fromOpaque(pointer)
                        .takeUnretainedValue().expired ? 1 : 0
                }, Unmanaged.passUnretained(deadline).toOpaque())
            }
            let expectedFTS = """
                CREATE VIRTUAL TABLE events_fts USING fts5(
                    process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client,
                    content=events, content_rowid=rowid
                )
                """
            guard let fts = try Self.schemaObject(on: db, named: "events_fts"),
                  fts.type == "table",
                  Self.canonicalSchemaSQL(fts.sql) == Self.canonicalSchemaSQL(expectedFTS),
                  try transitionScalar(db, "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND lower(sql) LIKE 'create virtual table %'") == 1,
                  try transitionScalar(db, "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('events_fts_data','events_fts_idx','events_fts_docsize','events_fts_config')") == 4,
                  try transitionScalar(db, "SELECT COUNT(*) FROM events_fts_data WHERE typeof(block)!='blob' OR (id NOT IN (1,10) AND (id>>37 NOT BETWEEN 1 AND 2000))") == 0 else {
                throw EventStoreError.storageNotReady("legacy structural check requires the published FTS storage format")
            }
            let pageCount = try transitionScalar(db, "PRAGMA page_count")
            let schemaBytes = try transitionScalar(db,
                "SELECT COALESCE(SUM(COALESCE(octet_length(sql),0)+256),0) FROM sqlite_schema")
            let encoded = try transitionScalar(db,
                "SELECT COALESCE(SUM(octet_length(block)),0) FROM events_fts_data")
            let maximumPage = try transitionScalar(db,
                "SELECT COALESCE(MAX(octet_length(block)),0) FROM events_fts_data")
            var segments: Int64 = 0
            var maximumSegment: Int64 = 0
            var firstID: Int64 = 137_438_953_472
            // Seek each segment through the INTEGER PRIMARY KEY, then sum only
            // its rowid range. No GROUP BY/DISTINCT sorter or segment array is
            // allocated before the final workspace reservation.
            while true {
                let segment = try transitionScalar(db, """
                    SELECT COALESCE((SELECT id>>37 FROM events_fts_data
                        WHERE id>=\(firstID) ORDER BY id LIMIT 1),0)
                    """)
                if segment == 0 { break }
                guard segment <= 2_000, segments < 2_000 else {
                    throw EventStoreError.storageNotReady("legacy structural check segment inventory is invalid")
                }
                let nextID = (segment + 1) << 37
                let bytes = try transitionScalar(db, """
                    SELECT COALESCE(SUM(octet_length(block)),0) FROM events_fts_data
                    WHERE id>=\(firstID) AND id<\(nextID)
                    """)
                maximumSegment = max(maximumSegment, bytes)
                segments += 1
                firstID = nextID
            }
            // Bundled fts5_dri uses a 37-bit segment suffix; dlidx height has
            // five bits. Each forward segment iterator retains at most two leaf
            // pages plus a 32-level doclist index. Direct blob reads do not make
            // a VDBE payload copy. Term/position buffers round up by powers of two;
            // NOOUTPUT integrity traversal materializes one segment's position
            // list at a time. SQLITE_DEBUG's nested query checks are not enabled.
            let dataBuffers = min(encoded, SQLitePersistentStoreAdmission.saturatingMultiply(
                maximumPage, by: SQLitePersistentStoreAdmission.saturatingAdd(segments * 34, 2)))
            let termBuffers = SQLitePersistentStoreAdmission.saturatingMultiply(
                min(encoded, SQLitePersistentStoreAdmission.saturatingMultiply(segments + 2, by: 32_769)), by: 2)
            let positionBuffer = SQLitePersistentStoreAdmission.saturatingMultiply(
                SQLitePersistentStoreAdmission.saturatingAdd(maximumSegment, 8), by: 2)
            var estimate = SQLitePersistentStoreAdmission.saturatingAdd(dataBuffers, termBuffers)
            for bytes in [positionBuffer, segments * 8_192, pageCount / 8 + 1,
                          SQLitePersistentStoreAdmission.saturatingMultiply(schemaBytes, by: 4),
                          Int64(2 * 1_048_576)] {
                estimate = SQLitePersistentStoreAdmission.saturatingAdd(estimate, bytes)
            }
            // Multiple individually bounded S leases can use the existing shared
            // startup envelope. This does not change any owner or process limit.
            guard estimate <= Int64(budget.snapshot().maximumBytes) else {
                throw EventStoreError.storageNotReady("legacy structural check workspace exceeds the existing memory envelope")
            }
            let alreadyOwned = (existingWorkspace?.bytes ?? 0) + leases.reduce(0) { $0 + $1.bytes }
            var remaining = max(0, Int(estimate) - alreadyOwned)
            while remaining > 0 {
                let bytes = min(remaining, EventJournalCodec.maximumWorkspaceBytes)
                guard let lease = budget.tryAcquire(bytes: bytes, owner: .eventStoreWorkspace) else {
                    throw EventStoreError.storageNotReady("legacy structural check is waiting for owned memory workspace")
                }
                leases.append(lease)
                remaining -= bytes
            }
            try Task.checkCancellation()
            var raw: OpaquePointer?
            let prepared = sqlite3_prepare_v2(db, "PRAGMA main.quick_check(1)", -1, &raw, nil)
            guard prepared == SQLITE_OK else {
                sqlite3_finalize(raw)
                throw sqliteError(prepared)
            }
            guard let statement = raw else {
                throw EventStoreError.storageNotReady("legacy structural check returned no statement")
            }
            defer { sqlite3_finalize(statement) }
            let result = sqlite3_step(statement)
            guard result != SQLITE_DONE else {
                throw EventStoreError.storageNotReady("legacy structural check returned no verdict")
            }
            guard result == SQLITE_ROW else { throw sqliteError(result) }
            // Do not copy or expose SQLite's possibly user-derived diagnostic,
            // and never turn a non-ok row into synthetic SQLITE_CORRUPT.
            guard sqlite3_column_type(statement, 0) == SQLITE_TEXT,
                  sqlite3_column_bytes(statement, 0) == 2,
                  let value = sqlite3_column_text(statement, 0),
                  value[0] == 111, value[1] == 107 else {
                throw EventStoreError.storageNotReady("legacy structural quick_check reported an issue; original storage is preserved")
            }
            let completed = sqlite3_step(statement)
            guard completed != SQLITE_ROW else {
                throw EventStoreError.storageNotReady("legacy structural check did not return one complete verdict")
            }
            guard completed == SQLITE_DONE else { throw sqliteError(completed) }
            try Task.checkCancellation()
            guard !deadline.expired else {
                throw EventStoreError.storageNotReady("legacy structural check reached its cooperative deadline; retry preserves storage")
            }
            try restore()
        } catch {
            let original = error
            try restore()
            if deadline.expired {
                throw EventStoreError.storageNotReady("legacy structural check reached its cooperative deadline; retry preserves storage")
            }
            throw original
        }
    }

    /// The exception is deliberately limited to the measured published format.
    /// It does not lower the policy reserve or authorize a partially proved
    /// barrier. All inventory, allocation and headroom probes share its writer
    /// snapshot. The existing bootstrap then retires only the indexes this
    /// plan proved sufficient, and restores ordinary admission before return.
    private static func legacyBootstrapReclaimPlan(
        on db: OpaquePointer,
        path: String,
        policy: SQLitePersistentStorePolicy
    ) throws -> LegacyBootstrapReclaimPlan {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else {
            throw SQLitePersistentStoreAdmissionError.schemaTransactionNotSerialized
        }
        let pageSize = try transitionScalar(db, "PRAGMA page_size")
        let pageCount = try transitionScalar(db, "PRAGMA page_count")
        let freelist = try transitionScalar(db, "PRAGMA freelist_count")
        guard pageSize == 4_096, pageCount > 0, freelist < pageCount,
              try transitionScalar(db, "PRAGMA auto_vacuum") == 2,
              try SchemaMigrator.readVersion(db: db) == 6,
              try transitionScalar(db, "SELECT COUNT(*) FROM pragma_encoding WHERE encoding='UTF-8'") == 1,
              try transitionScalar(db, "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('sqlite_stat1','sqlite_stat2','sqlite_stat3','sqlite_stat4')") == 0 else {
            throw EventStoreError.storageNotReady("legacy bootstrap cannot prove this dense store's preserving reclaim budget")
        }
        if try transitionScalar(db,
            "SELECT COUNT(*) FROM pragma_table_info('events') WHERE name='journal_block_id'") != 0 {
            guard try transitionScalar(db,
                "SELECT EXISTS(SELECT 1 FROM events WHERE journal_block_id IS NOT NULL LIMIT 1)") == 0 else {
                throw EventStoreError.storageNotReady("legacy bootstrap cannot treat a populated journal projection as empty metadata")
            }
        }
        let family = try SQLitePersistentStoreAdmission.measureFamily(path)
        let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
        let free = try SQLitePersistentStoreAdmission.measureFreeSpace(policy.storageVolumePath)
        guard family >= main, family <= policy.maxFootprintBytes,
              try transitionScalar(db, "PRAGMA max_page_count") == pageCount else {
            throw EventStoreError.storageNotReady("legacy bootstrap requires its original bounded main-file ceiling")
        }
        let sidecars = family - main
        let capRoom = policy.maxFootprintBytes - family
        let freeRoom = max(0, free - policy.freeSpaceFloorBytes)
        guard capRoom > sidecars, freeRoom > sidecars else {
            throw EventStoreError.storageNotReady("legacy bootstrap cannot reserve a write and its checkpoint")
        }
        let storageBudget = min(policy.transactionReserveBytes,
            min((capRoom - sidecars) / 2, (freeRoom - sidecars) / 2))

        let schemaRows = try transitionScalar(db, "SELECT COUNT(*) FROM sqlite_schema")
        let schemaBytes = try transitionScalar(db, """
            SELECT COALESCE(SUM(COALESCE(octet_length(type),0)
                + COALESCE(octet_length(name),0) + COALESCE(octet_length(tbl_name),0)
                + COALESCE(octet_length(sql),0) + 256),0) FROM sqlite_schema
            """)
        var recordCount = schemaRows
        var encodedBytes = schemaBytes
        var emptyRoots: Int64 = 1 // sqlite_sequence may be created by AUTOINCREMENT.
        guard let migration = Self.schemaMigrations.first(where: { $0.version == 8 }) else {
            throw EventStoreError.storageNotReady("legacy bootstrap migration definition is missing")
        }
        for sql in migration.sql {
            let normalized = Self.canonicalSchemaSQL(sql)
            if normalized.hasPrefix("create table ") {
                let table = String(normalized.split(separator: " ")[2])
                if table != "event_storage_state",
                   let existing = try Self.schemaObject(on: db, named: table) {
                    guard existing.type == "table",
                          try transitionScalar(db,
                            "SELECT EXISTS(SELECT 1 FROM \(table) LIMIT 1)") == 0 else {
                        throw EventStoreError.storageNotReady("legacy bootstrap cannot treat populated journal tables as empty metadata")
                    }
                }
            }
            guard try !SchemaMigrator.pendingStorageWork(on: db, statements: [sql]).isEmpty else { continue }
            let newRecords: Int64
            if normalized.hasPrefix("create table ") {
                // The fixed v8 table definitions have at most two automatic
                // indexes. Count three roots/records even for WITHOUT ROWID.
                newRecords = 3
                emptyRoots += 3
            } else if normalized.hasPrefix("create ") {
                newRecords = 1
                if normalized.hasPrefix("create index ")
                    || normalized.hasPrefix("create unique index ") {
                    emptyRoots += 1
                }
            } else {
                newRecords = 0 // ADD COLUMN only extends an existing schema record.
            }
            recordCount += newRecords
            encodedBytes = SQLitePersistentStoreAdmission.saturatingAdd(encodedBytes,
                Int64(sql.utf8.count) + 256 * max(1, newRecords))
        }
        recordCount += 1 // Possible sqlite_sequence schema record.
        encodedBytes = SQLitePersistentStoreAdmission.saturatingAdd(encodedBytes, 256)
        guard recordCount <= 512 else {
            throw EventStoreError.storageNotReady("legacy bootstrap schema exceeds its bounded inventory")
        }
        // Bound the entire resulting sqlite_schema, including the existing
        // records, rather than pretending each DDL allocates 256 KiB. At most
        // one leaf and one interior page per record overcounts a valid table
        // b-tree; the doubled encoded bytes cover overflow representation.
        // Every new empty data/index root is charged separately. Existing
        // roots moved by mode-2 allocation change locations, not root count.
        let schemaAllocation = SQLitePersistentStoreAdmission.conservativeEncodedRowMutationBytes(
            logicalRepresentationBytes: encodedBytes,
            pageSizeBytes: pageSize,
            maximumLeafPageTouches: Int(recordCount * 2)
        )
        let metadataAllocation = SQLitePersistentStoreAdmission.saturatingAdd(
            schemaAllocation,
            SQLitePersistentStoreAdmission.saturatingAdd(emptyRoots * pageSize,
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes)
        )
        let pointerMapPages = pageCount / ((pageSize - 255) / 5 + 1) + 2
        // Charge the complete resulting schema and all possible pointer maps
        // for each independent DDL, with both retained/rollback images. With
        // <=512 schema records, height is <=10; 52 extra pages cover two new
        // balance siblings per level plus three root allocations/relocations
        // (eight non-map pages each). Cache spills must remain disabled.
        let metadataTransaction = SQLitePersistentStoreAdmission.saturatingAdd(
            SQLitePersistentStoreAdmission.saturatingMultiply(
                SQLitePersistentStoreAdmission.saturatingAdd(metadataAllocation,
                    pointerMapPages * pageSize), by: 2),
            SQLitePersistentStoreAdmission.saturatingAdd(
                SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
                    pageSizeBytes: pageSize, maximumTreePathPageTouches: 48), 65_536)
        )
        func fits(_ estimate: Int64) -> Bool {
            // Two page images are already in the storage estimate. Charge
            // their cache bookkeeping and the separate 1-MiB clean cache.
            let memory = SQLitePersistentStoreAdmission.saturatingAdd(
                SQLitePersistentStoreAdmission.saturatingAdd(estimate, estimate / 8), 1_114_112)
            let writeAndCheckpoint = SQLitePersistentStoreAdmission.saturatingAdd(
                SQLitePersistentStoreAdmission.saturatingMultiply(estimate, by: 2), sidecars)
            return estimate <= storageBudget
                && writeAndCheckpoint <= policy.transactionReserveBytes
                && memory <= Int64(EventJournalCodec.maximumWorkspaceBytes)
        }
        guard fits(metadataTransaction) else {
            throw EventStoreError.storageNotReady("legacy bootstrap metadata cannot fit its storage and owned-memory budgets")
        }
        var selected = Set<String>()
        var reclaimable = freelist * pageSize
        for name in ["idx_events_timestamp"] + Self.supersededEventIndexes {
            guard let object = try Self.schemaObject(on: db, named: name) else { continue }
            if name == "idx_events_timestamp", object.type == "view" {
                guard Self.canonicalSchemaSQL(object.sql) == Self.canonicalSchemaSQL(Self.rollbackBarrierViewSQL) else {
                    throw EventStoreError.storageNotReady("legacy bootstrap timestamp barrier is invalid")
                }
                continue
            }
            // Literal names come exclusively from this fixed source allowlist.
            guard object.type == "index",
                  try transitionScalar(db, "SELECT COUNT(*) FROM sqlite_schema WHERE name='\(name)' AND type='index' AND tbl_name='events'") == 1,
                  try transitionScalar(db, "SELECT COUNT(*) FROM pragma_index_list('events') WHERE name='\(name)' AND \"unique\"=0 AND origin='c'") == 1 else {
                throw EventStoreError.storageNotReady("legacy bootstrap index ownership or uniqueness is invalid: \(name)")
            }
            let allocated = try transitionScalar(db,
                "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name='\(name)'")
            guard allocated > 0, allocated % pageSize == 0 else {
                throw EventStoreError.storageNotReady("legacy bootstrap index allocation is invalid")
            }
            let indexBytes = SQLitePersistentStoreAdmission.saturatingMultiply(allocated, by: 2)
            var estimate = SQLitePersistentStoreAdmission.saturatingAdd(indexBytes,
                SQLitePersistentStoreAdmission.saturatingAdd(metadataTransaction,
                    SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
                        pageSizeBytes: pageSize, maximumTreePathPageTouches: 8)))
            if name == "idx_events_timestamp" {
                let guards = try Self.missingRollbackGuards(on: db, existingTablesOnly: true).count
                let ordinaryBarrier = SQLitePersistentStoreAdmission.conservativeTransactionBytes(
                    rowMutationBytes: SQLitePersistentStoreAdmission.saturatingAdd(indexBytes,
                        Int64(guards + 1) * SQLitePersistentStoreAdmission.conservativeRowMutationBytes),
                    pageSizeBytes: pageSize, maximumTreePathPageTouches: 8 + guards)
                estimate = max(estimate, ordinaryBarrier)
            }
            if fits(estimate) {
                selected.insert(name)
                reclaimable = SQLitePersistentStoreAdmission.saturatingAdd(reclaimable, allocated)
            } else if name == "idx_events_timestamp" {
                throw EventStoreError.storageNotReady("legacy bootstrap timestamp barrier cannot fit its bounded transaction")
            }
        }
        let deficit = max(0, family - (policy.maxFootprintBytes - policy.transactionReserveBytes))
        let needed = SQLitePersistentStoreAdmission.saturatingAdd(deficit,
            SQLitePersistentStoreAdmission.saturatingAdd(metadataAllocation, 65_536))
        guard reclaimable >= needed else {
            throw EventStoreError.storageNotReady("legacy bootstrap has insufficient proven index/freelist bytes to restore ordinary admission before producers")
        }
        return LegacyBootstrapReclaimPlan(indexes: selected,
            metadataAllocationBytes: metadataAllocation,
            metadataTransactionBytes: metadataTransaction,
            maximumTransactionBytes: storageBudget)
    }

    /// Recover only unused mode-2 pages before installing the one-way barrier.
    /// Each independent transaction preserves every row and schema object.
    /// A pin, exhausted budget or partial failure leaves resumable SQLite state.
    /// The time deadline is cooperative: VM/statement boundaries cannot interrupt
    /// a blocked filesystem call or one internal b-tree freelist traversal.
    private static func reclaimLegacyTransitionHeadroom(
        on handle: OpaquePointer,
        path: String,
        admission: inout SQLitePersistentStoreAdmission,
        liveMemoryBudget: EventPipelineLiveMemoryBudget
    ) throws {
        let policy = admission.policy
        let reserve = policy.transactionReserveBytes
        let cap = policy.maxFootprintBytes
        let initialFamily = try SQLitePersistentStoreAdmission.measureFamily(path)
        guard initialFamily > cap - reserve else { return }
        guard initialFamily <= cap else {
            throw SQLitePersistentStoreAdmissionError.footprintLimit(
                footprintBytes: initialFamily, reserveBytes: 0,
                maxFootprintBytes: cap
            )
        }
        func scalar(_ name: String) throws -> Int64 {
            var statement: OpaquePointer?
            let rc = sqlite3_prepare_v2(handle, "PRAGMA \(name)", -1, &statement, nil)
            guard rc == SQLITE_OK, let statement else {
                sqlite3_finalize(statement)
                throw EventStoreError.storageNotReady("pre-transition reclaim pragma unavailable: \(name)")
            }
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW,
                  sqlite3_column_type(statement, 0) == SQLITE_INTEGER else {
                throw EventStoreError.storageNotReady("pre-transition reclaim pragma invalid: \(name)")
            }
            return sqlite3_column_int64(statement, 0)
        }
        guard try scalar("auto_vacuum") == 2 else { return }
        var journal: OpaquePointer?
        guard sqlite3_prepare_v2(handle, "PRAGMA journal_mode", -1, &journal, nil) == SQLITE_OK,
              let journal else {
            sqlite3_finalize(journal)
            throw EventStoreError.storageNotReady("pre-transition reclaim journal mode unavailable")
        }
        let journalStep = sqlite3_step(journal)
        let isWAL = journalStep == SQLITE_ROW
            && sqlite3_column_text(journal, 0).map { String(cString: $0).lowercased() == "wal" } == true
        sqlite3_finalize(journal)
        guard isWAL else { return }
        // Read capability; never force PSOW on. Otherwise sector co-writes
        // and FULL-sync padding require a different physical-write bound.
        var powersafe: Int32 = -1
        guard sqlite3_file_control(handle, "main", SQLITE_FCNTL_POWERSAFE_OVERWRITE, &powersafe) == SQLITE_OK,
              powersafe == 1 else {
            throw EventStoreError.storageNotReady("pre-transition reclaim requires verified powersafe-overwrite support")
        }
        guard let workspace = liveMemoryBudget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ) else {
            throw EventStoreError.memoryLeaseUnavailable("pre-transition reclaim is waiting for bounded workspace")
        }
        defer { withExtendedLifetime(workspace) {} }
        let savedSpill = try scalar("cache_spill")
        let savedCache = try scalar("cache_size")
        let savedMmap = try scalar("mmap_size")
        let savedTimeout = try scalar("busy_timeout")
        let deadline = TransitionReclaimDeadline()
        func checkDeadline() throws {
            try Task.checkCancellation()
            guard !deadline.expired else {
                throw EventStoreError.storageNotReady("pre-transition reclaim reached its 30-second work deadline; retry preserves committed progress")
            }
        }
        func restore() throws {
            sqlite3_progress_handler(handle, 0, nil, nil)
            if sqlite3_get_autocommit(handle) == 0 {
                try Self.exec(handle, "ROLLBACK")
            }
            try Self.exec(handle, "PRAGMA cache_spill = \(savedSpill)")
            try Self.exec(handle, "PRAGMA cache_size = \(savedCache)")
            try Self.exec(handle, "PRAGMA mmap_size = \(savedMmap)")
            try Self.exec(handle, "PRAGMA busy_timeout = \(savedTimeout)")
        }
        func checkpoint() throws {
            try checkDeadline()
            let result = try Self.truncateCheckpoint(on: handle) {
                let snapshot = try admission.admitCheckpoint()
                let peak = snapshot.familyFootprintBytes.addingReportingOverflow(snapshot.sidecarBytes)
                guard !peak.overflow, peak.partialValue <= cap else {
                    throw SQLitePersistentStoreAdmissionError.footprintLimit(
                        footprintBytes: snapshot.familyFootprintBytes,
                        reserveBytes: snapshot.sidecarBytes,
                        maxFootprintBytes: cap
                    )
                }
            }
            try result.requireTruncated(context: "pre-transition reclaim checkpoint")
            guard try SQLitePersistentStoreAdmission.measureFamily(path) <= cap else {
                throw EventStoreError.storageNotReady("pre-transition reclaim checkpoint exceeded its family cap")
            }
        }
        do {
            try Self.exec(handle, "PRAGMA busy_timeout = 250")
            try Self.exec(handle, "PRAGMA cache_size = -1024")
            try Self.exec(handle, "PRAGMA mmap_size = 0")
            try Self.exec(handle, "PRAGMA cache_spill = OFF")
            sqlite3_progress_handler(handle, 1000, { pointer in
                guard let pointer else { return 1 }
                return Unmanaged<TransitionReclaimDeadline>.fromOpaque(pointer)
                    .takeUnretainedValue().expired ? 1 : 0
            }, Unmanaged.passUnretained(deadline).toOpaque())
            defer {
                sqlite3_progress_handler(handle, 0, nil, nil)
                withExtendedLifetime(deadline) {}
            }
            try checkpoint()
            var family = try SQLitePersistentStoreAdmission.measureFamily(path)
            // A stale WAL alone can consume the original headroom.
            if family > cap - reserve {
                let target = max(0, cap - min(cap, SQLitePersistentStoreAdmission.saturatingMultiply(reserve, by: 2)))
                var batches = 0
                while family > target {
                    try checkDeadline()
                    guard batches < 256 else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim reached its 256-batch work limit; retry preserves committed progress")
                    }
                    guard sqlite3_get_autocommit(handle) != 0 else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim requires a standalone transaction")
                    }
                    try Self.exec(handle, "BEGIN IMMEDIATE TRANSACTION")
                    try admission.admitSerializedIncrementalReclaim(estimatedTransactionBytes: 0, on: handle)
                    let pageSize = try scalar("page_size")
                    let pageCount = try scalar("page_count")
                    let freelist = try scalar("freelist_count")
                    let measuredFamily = admission.lastFootprintBytes ?? Int64.max
                    guard pageCount > 0, freelist >= 0, freelist < pageCount else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim page accounting is invalid")
                    }
                    if freelist == 0 {
                        try Self.exec(handle, "ROLLBACK")
                        if measuredFamily <= cap - reserve { break }
                        throw EventStoreError.storageNotReady("pre-transition reclaim has insufficient reusable pages for transition headroom")
                    }
                    let free = admission.lastFreeSpaceBytes ?? 0
                    let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
                    guard measuredFamily >= main else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim family measurement is inconsistent")
                    }
                    let sidecars = measuredFamily - main
                    let capRoom = cap - measuredFamily
                    let freeRoom = max(0, free - policy.freeSpaceFloorBytes)
                    guard capRoom > sidecars, freeRoom > sidecars else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim cannot reserve its transaction and checkpoint")
                    }
                    let budget = min(reserve, min((capRoom - sidecars) / 2, (freeRoom - sidecars) / 2))
                    let plan = SQLitePersistentStoreAdmission.boundedIncrementalReclaimPlan(
                        requestedPages: Int(clamping: min(freelist, 128)),
                        pageCount: pageCount, pageSizeBytes: pageSize,
                        budgetBytes: budget, workspaceBytes: Int64(workspace.bytes)
                    )
                    guard plan.pages > 0 else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim has no bounded page quantum within its storage and memory budgets")
                    }
                    try admission.admitSerializedIncrementalReclaim(
                        estimatedTransactionBytes: plan.estimatedTransactionBytes, on: handle
                    )
                    _ = try StoragePragmas.runIncrementalVacuum(on: handle, maxPages: plan.pages)
                    let afterPages = try scalar("page_count")
                    let afterFreelist = try scalar("freelist_count")
                    guard afterPages < pageCount, afterFreelist < freelist else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim made no page progress")
                    }
                    try checkDeadline()
                    try Self.exec(handle, "COMMIT")
                    try checkpoint()
                    let afterFamily = try SQLitePersistentStoreAdmission.measureFamily(path)
                    guard afterFamily < family else {
                        throw EventStoreError.storageNotReady("pre-transition reclaim made no physical progress")
                    }
                    family = afterFamily
                    batches += 1
                }
            }
            // Only physical recovery can clear the original pressure latch and
            // retry the lower max_page_count that was impossible before reclaim.
            try admission.admitWrite(estimatedTransactionBytes: 0, on: handle)
            try restore()
        } catch {
            let original = error
            try restore()
            if deadline.expired {
                throw EventStoreError.storageNotReady("pre-transition reclaim reached its 30-second work deadline; retry preserves committed progress")
            }
            throw original
        }
    }

    /// Opens a SQLite database before actor isolation begins.
    /// Returns (db handle, isReadOnly) so init can assign to stored properties.
    ///
    /// - Parameter forceReadOnly: When `true`, skip the RW open attempt and
    ///   open with `SQLITE_OPEN_READONLY` directly. Used by the dashboard
    ///   (MacCrabApp/V2LiveDataProvider) to ensure its long-lived connection
    ///   never holds the shared/upgrade lock that blocks the daemon's
    ///   `VACUUM` and `wal_checkpoint(TRUNCATE)` operations.
    ///   (v1.12.6 RC2, Wave 9A — see lsof field background in v1.12.6 RC1
    ///   recovery notes.)
    private static func openDatabase(
        at path: String,
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil,
        liveMemoryBudget: EventPipelineLiveMemoryBudget
    ) throws -> (
        OpaquePointer,
        Bool,
        OpaquePointer?,
        SQLitePersistentStoreAdmission?,
        Int64,
        SQLiteControlledCheckpointController?
    ) {
        // Preflight the DB path and its WAL/SHM/journal sidecars for clear
        // diagnostics and reject multiply-linked family members. The actual
        // SQLite open also uses NOFOLLOW through SQLiteOpenPathPolicy, closing
        // symlink races at the open boundary. Non-symlink replacement safety
        // relies on the shipping owner-controlled support directory.
        try rejectIfSymlink(path)
        try rejectIfSymlink(path + "-wal")
        try rejectIfSymlink(path + "-shm")
        try rejectIfSymlink(path + "-journal")

        // Admission is deliberately evaluated before SQLite can create or
        // mutate any family member. Explicit read-only consumers skip it and
        // never install the mutating max_page_count PRAGMA.
        _ = try SQLitePersistentStoreAdmission.measureFamily(path)
        let existingDatabase = try SQLitePersistentStoreAdmission
            .mainFileExists(path)
        let effectivePolicy = forceReadOnly
            ? nil : (storagePolicy ?? Self.defaultStoragePolicy(for: path))
        var admission = try effectivePolicy.map {
            try SQLitePersistentStoreAdmission(
                databasePath: path,
                policy: $0,
                latchOperationalPressure: existingDatabase
            )
        }

        var db: OpaquePointer?
        var isReadOnly = false
        var flags: Int32
        var rc: Int32
        if forceReadOnly {
            // Explicit RO open — no RW attempt. The dashboard never writes
            // to this store (mutations route through the inbox file-IPC
            // channel per v1.10.1), so we skip the RW open and the lock
            // it would imply.
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
            isReadOnly = true
        } else {
            flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX
            if !existingDatabase { flags |= SQLITE_OPEN_CREATE }
            rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
            if rc != SQLITE_OK {
                if let handle = db { sqlite3_close(handle) }
                db = nil
                flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
                rc = SQLiteOpenPathPolicy.open(path, database: &db, flags: flags)
                isReadOnly = true
                admission = nil
            }
        }
        guard rc == SQLITE_OK, let handle = db else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            if let db { sqlite3_close(db) }
            throw EventStoreError.sqliteFailure(
                context: "database open",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
        var checkpointController: SQLiteControlledCheckpointController?
        var returnHandleToCaller = false
        defer {
            if !returnHandleToCaller {
                checkpointController?.detach(from: handle)
                sqlite3_close(handle)
            }
        }
        if !isReadOnly {
            let functionRC = sqlite3_create_function_v2(
                handle,
                "maccrab_event_journal_writer_v8",
                0,
                SQLITE_UTF8 | SQLITE_DETERMINISTIC | SQLITE_INNOCUOUS,
                nil,
                macCrabEventJournalWriterV8SQLFunction,
                nil,
                nil,
                nil
            )
            guard functionRC == SQLITE_OK else {
                throw EventStoreError.sqliteFailure(
                    context: "register rc.13 event journal writer guard",
                    message: String(cString: sqlite3_errmsg(handle)),
                    resultCode: sqlite3_errcode(handle),
                    extendedResultCode: sqlite3_extended_errcode(handle),
                    systemErrno: sqlite3_system_errno(handle)
                )
            }
        }
        var eventTableProbe: OpaquePointer?
        let eventTableProbeRC = sqlite3_prepare_v2(
            handle,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events' LIMIT 1",
            -1,
            &eventTableProbe,
            nil
        )
        guard eventTableProbeRC == SQLITE_OK, let eventTableProbe else {
            let failure = SQLiteFailureDetails(
                resultCode: eventTableProbeRC,
                db: handle
            )
            let message = String(cString: sqlite3_errmsg(handle))
            sqlite3_finalize(eventTableProbe)
            throw EventStoreError.sqliteFailure(
                context: "events substrate probe prepare",
                message: message,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
        let eventTableStep = sqlite3_step(eventTableProbe)
        let eventTableFailure = eventTableStep == SQLITE_ROW
                || eventTableStep == SQLITE_DONE
            ? nil
            : SQLiteFailureDetails(resultCode: eventTableStep, db: handle)
        let eventTableFailureMessage = eventTableFailure == nil
            ? nil : String(cString: sqlite3_errmsg(handle))
        sqlite3_finalize(eventTableProbe)
        if let failure = eventTableFailure {
            throw EventStoreError.sqliteFailure(
                context: "events substrate probe step",
                message: eventTableFailureMessage ?? "unknown error",
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
        let existingEventSubstrate = eventTableStep == SQLITE_ROW
        if !isReadOnly, let effectivePolicy {
            checkpointController = try .install(
                on: handle,
                thresholdPages: StoragePragmas.eventWalAutocheckpointPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: path,
                        policy: effectivePolicy
                    ),
                ]
            )
        }

        if !isReadOnly {
            do {
                try admission?.installPageLimit(on: handle)
            } catch let error as SQLitePersistentStoreAdmissionError
                where error.isOperationalPressure {
                // Existing oversized databases open in shed mode so bounded
                // retention can reclaim them. No schema/growth writes run.
            }
        }

        var deferredLegacyBootstrap = false
        if !isReadOnly, existingEventSubstrate,
           try !Self.journalSchemaIsFinalized(on: handle),
           var current = admission {
            do {
                let family = try SQLitePersistentStoreAdmission.measureFamily(path)
                let deficit = max(0, family - (current.policy.maxFootprintBytes
                    - current.transactionReserveBytes))
                let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
                let reusable = try Self.transitionScalar(handle, "PRAGMA freelist_count")
                    * Self.transitionScalar(handle, "PRAGMA page_size")
                if deficit > 0, reusable < deficit,
                   main > current.policy.maxFootprintBytes - current.transactionReserveBytes {
                    // No mutation is authorized by this flag. The barrier's
                    // writer snapshot must first prove enough admissible index
                    // retirement to reclaim the complete ordinary reserve.
                    deferredLegacyBootstrap = true
                } else {
                    try Self.reclaimLegacyTransitionHeadroom(
                        on: handle, path: path, admission: &current,
                        liveMemoryBudget: liveMemoryBudget
                    )
                }
            } catch {
                admission = current
                throw error
            }
            admission = current
        }

        var writerInitializationAllowed = !isReadOnly
            && !(admission?.growthBlocked ?? false)

        func admitSchemaWork(_ rawWork: SchemaStorageWork) throws {
            guard var current = admission else { return }
            defer { admission = current }
            // A brand-new file has no user rows for CREATE INDEX to scan; treat
            // all bootstrap/migration DDL as bounded metadata. Existing stores
            // route every missing CREATE/DROP INDEX through the rebuild gate.
            let work = existingEventSubstrate ? rawWork : SchemaStorageWork(
                boundedMetadataStatementCount:
                    rawWork.boundedMetadataStatementCount
                        + rawWork.rebuildStatementCount,
                rebuildStatementCount: 0
            )
            if work.rebuildStatementCount > 0 {
                try current.admitSchemaRebuild(
                    operationCount: work.rebuildStatementCount
                )
            }
            if work.boundedMetadataStatementCount > 0 {
                try current.admitWrite(
                    estimatedTransactionBytes:
                        work.boundedTransactionEstimateBytes,
                    on: handle
                )
            }
        }

        if writerInitializationAllowed {
            try admitSchemaWork(SchemaStorageWork(
                boundedMetadataStatementCount: 1,
                rebuildStatementCount: 0
            ))
            // v1.6.22: pragmas centralized in StoragePragmas.applyEventStorePragmas.
            // Cut from 64 MB cache + 256 MB mmap (v1.6.21) to 16 MB + 64 MB after
            // 2.76 GB resident observation on a test host with 2 long-lived
            // connections to events.db (EventStore + AlertStore).
            do {
                try StoragePragmas.applyEventStorePragmasChecked(to: handle)
            } catch let failure as StoragePragmas.ApplicationFailure {
                throw EventStoreError.sqliteFailure(
                    context: failure.sql,
                    message: String(cString: sqlite3_errmsg(handle)),
                    resultCode: failure.metadata.resultCode,
                    extendedResultCode: failure.metadata.extendedResultCode,
                    systemErrno: failure.metadata.systemErrno
                )
            }
        }
        // v1.4.4: `busy_timeout = 5000` tells SQLite to retry a busy-lock
        // for up to 5 seconds instead of failing immediately with
        // SQLITE_BUSY. Default is 0 (no retry). Fixes the class of
        // transient "database is locked" errors v1.4.3's fail-loud
        // banner surfaced — WAL autocheckpoint briefly holds the write
        // lock, and without a timeout the next insert fails.
        try Self.exec(handle, "PRAGMA busy_timeout = 5000")
        try Self.exec(handle, "PRAGMA foreign_keys = ON")

        // rc.13 transition bootstrap. Installed rc.12 stores can already be
        // above the normal growth threshold, which is exactly when the compact
        // journal is needed. SchemaMigrator's generic rebuild classifier must
        // not aggregate DROP INDEX as N whole-store copies and refuse before
        // the first beneficial statement. Drop only the superseded event
        // indexes, one autocommitted operation at a time, under maintenance
        // admission; then install the bounded additive v8 metadata/tables the
        // same way. Every boundary is idempotent and crash-resumable.
        if !isReadOnly, existingEventSubstrate {
            func performJournalTransition(
                workspace: EventPipelineMemoryLease? = nil,
                deadline: TransitionReclaimDeadline? = nil
            ) throws {
            var bootstrapPlan: LegacyBootstrapReclaimPlan?
            // A completed schema-v8 transition is a validation-only reopen.
            // Probe its durable marker before any TRUNCATE checkpoint or
            // transaction-reserve gate: a dashboard reader may legitimately
            // pin a healthy WAL, and no transition mutation remains to justify
            // making that pin a permanent cold-start failure. Never trust the
            // marker alone; its exact final schema inventory and rollback
            // guards must still be present before this fast path is allowed.
            let journalSchemaIsFinalized = try Self
                .journalSchemaIsFinalized(on: handle)
            if journalSchemaIsFinalized {
                try Self.validateFinalizedJournalSchemaInventory(on: handle)
            }
            // Daemon startup historically opens with the full 420-MiB combined
            // transition envelope and narrows it only after measuring legacy
            // evidence. Never let journal DDL borrow that later alert-owned
            // space. The caller supplies the exact whole-family transition
            // ceiling proven before this open; custom/test policies below that
            // remain authoritative.
            let journalTransitionCap = effectivePolicy?.maxFootprintBytes
                ?? Int64.max
            var journalTransitionReady = true

            func transitionBoundaryIsDrained() throws -> Bool {
                if deferredLegacyBootstrap, var current = admission {
                    defer { admission = current }
                    let snapshot = try current.admitCheckpoint()
                    let peak = SQLitePersistentStoreAdmission.saturatingAdd(
                        snapshot.familyFootprintBytes, snapshot.sidecarBytes)
                    guard peak <= journalTransitionCap else {
                        throw EventStoreError.storageNotReady("legacy bootstrap checkpoint does not fit the unchanged family cap")
                    }
                }
                var logFrames: Int32 = 0
                var checkpointedFrames: Int32 = 0
                let checkpointRC = sqlite3_wal_checkpoint_v2(
                    handle,
                    nil,
                    SQLITE_CHECKPOINT_TRUNCATE,
                    &logFrames,
                    &checkpointedFrames
                )
                let footprint = try SQLitePersistentStoreAdmission
                    .measureFamily(path)
                guard footprint <= journalTransitionCap else {
                    throw SQLitePersistentStoreAdmissionError.footprintLimit(
                        footprintBytes: footprint,
                        reserveBytes: 0,
                        maxFootprintBytes: journalTransitionCap
                    )
                }
                if checkpointRC == SQLITE_BUSY || checkpointRC == SQLITE_LOCKED {
                    return false
                }
                guard checkpointRC == SQLITE_OK else {
                    let failure = SQLiteFailureDetails(
                        resultCode: checkpointRC,
                        db: handle
                    )
                    throw EventStoreError.sqliteFailure(
                        context: "journal transition checkpoint",
                        message: String(cString: sqlite3_errmsg(handle)),
                        resultCode: failure.resultCode,
                        extendedResultCode: failure.extendedResultCode,
                        systemErrno: failure.systemErrno
                    )
                }
                return logFrames == 0 || logFrames == checkpointedFrames
            }

            func transitionCanStartNextStatement(estimatedBytes: Int64 = 0) throws -> Bool {
                let footprint = try SQLitePersistentStoreAdmission
                    .measureFamily(path)
                let reserve = deferredLegacyBootstrap ? estimatedBytes
                    : (admission?.transactionReserveBytes
                        ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes)
                guard footprint <= journalTransitionCap,
                      reserve <= journalTransitionCap - footprint else {
                    return false
                }
                return true
            }

            func admitDeferredTransition(_ estimate: Int64) throws {
                guard let bootstrapPlan, estimate <= bootstrapPlan.maximumTransactionBytes,
                      var current = admission else {
                    throw EventStoreError.storageNotReady("legacy bootstrap transaction lacks its preserving preflight")
                }
                defer { admission = current }
                let family = try SQLitePersistentStoreAdmission.measureFamily(path)
                let main = try SQLitePersistentStoreAdmission.measureMainFile(path)
                guard family >= main else {
                    throw EventStoreError.storageNotReady("legacy bootstrap family accounting is inconsistent")
                }
                // Fund the write and its conservative checkpoint separately.
                // This never borrows the maintenance cap/floor relaxation.
                let combined = SQLitePersistentStoreAdmission.saturatingAdd(
                    SQLitePersistentStoreAdmission.saturatingMultiply(estimate, by: 2), family - main)
                try current.admitSerializedLegacyTransition(
                    estimatedTransactionBytes: combined, on: handle)
            }

            func applyTransitionStatement(
                _ sql: String,
                estimatedTransactionBytes: Int64? = nil
            ) throws -> Bool {
                let pending = try SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: [sql]
                )
                guard !pending.isEmpty else { return true }
                let estimate = estimatedTransactionBytes
                    ?? (deferredLegacyBootstrap ? bootstrapPlan?.metadataTransactionBytes : nil)
                    ?? admission?.transactionReserveBytes
                    ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
                guard try transitionCanStartNextStatement(estimatedBytes: estimate) else { return false }
                if !deferredLegacyBootstrap, var current = admission {
                    guard estimate <= current.transactionReserveBytes else {
                        return false
                    }
                    try current.admitMaintenanceWrite(
                        estimatedTransactionBytes: estimate
                    )
                    admission = current
                }
                try Self.exec(handle, "BEGIN IMMEDIATE TRANSACTION")
                do {
                    if deferredLegacyBootstrap {
                        try admitDeferredTransition(estimate)
                    } else if var current = admission {
                        try current.admitSerializedWrite(
                            estimatedTransactionBytes: estimate,
                            maintenance: true,
                            on: handle
                        )
                        admission = current
                    } else {
                        let family = try SQLitePersistentStoreAdmission
                            .measureFamily(path)
                        guard SQLitePersistentStoreAdmission.saturatingAdd(
                            family,
                            estimate
                        ) <= journalTransitionCap else {
                            throw SQLitePersistentStoreAdmissionError
                                .footprintLimit(
                                    footprintBytes: family,
                                    reserveBytes: estimate,
                                    maxFootprintBytes: journalTransitionCap
                                )
                        }
                    }
                    try Self.exec(handle, sql)
                    try Self.exec(handle, "COMMIT")
                } catch {
                    try? Self.exec(handle, "ROLLBACK")
                    throw error
                }
                return try transitionBoundaryIsDrained()
            }

            if journalSchemaIsFinalized {
                journalTransitionReady = true
            } else {
                journalTransitionReady = try transitionBoundaryIsDrained()
            }
            func installRollbackBarrier() throws -> Bool {
                guard try transitionCanStartNextStatement() else { return false }
                try Self.exec(handle, "BEGIN IMMEDIATE TRANSACTION")
                // Every inventory and sizing query below observes the same
                // serialized schema that will be changed. Any early error
                // releases the lock without leaving a partial barrier.
                defer {
                    if sqlite3_get_autocommit(handle) == 0 {
                        try? Self.exec(handle, "ROLLBACK")
                    }
                }
                if let legacyAlerts = try Self.schemaObject(
                    on: handle,
                    named: "alerts"
                ), legacyAlerts.type == "table" {
                    throw EventStoreError.storageNotReady(
                        "legacy events.db alerts table must be relocated before the rc.13 rollback barrier"
                    )
                }
                let barrier = try Self.schemaObject(
                    on: handle,
                    named: "idx_events_timestamp"
                )
                if let barrier, barrier.type == "view" {
                    guard Self.canonicalSchemaSQL(barrier.sql)
                            == Self.canonicalSchemaSQL(
                                Self.rollbackBarrierViewSQL
                            ) else {
                        throw EventStoreError.decodingFailed(
                            "idx_events_timestamp is not the rc.13 rollback barrier"
                        )
                    }
                }
                guard barrier == nil || barrier?.type == "index"
                        || barrier?.type == "view" else {
                    throw EventStoreError.decodingFailed(
                        "idx_events_timestamp has an unexpected schema type"
                    )
                }
                if barrier?.type != "view" {
                    try Self.checkLegacySQLiteStructure(on: handle, budget: liveMemoryBudget,
                        existingWorkspace: workspace, existingDeadline: deadline)
                }
                if deferredLegacyBootstrap {
                    guard let policy = effectivePolicy else {
                        throw EventStoreError.storageNotReady("legacy bootstrap policy is missing")
                    }
                    bootstrapPlan = try Self.legacyBootstrapReclaimPlan(
                        on: handle, path: path, policy: policy)
                }
                let missingGuards = try Self.missingRollbackGuards(
                    on: handle,
                    existingTablesOnly: true
                )
                if barrier?.type == "view", missingGuards.isEmpty {
                    try Self.validateRollbackProtection(
                        on: handle,
                        requireAllGuards: false
                    )
                    try Self.exec(handle, "COMMIT")
                    return true
                }
                var sizeStatement: OpaquePointer?
                guard sqlite3_prepare_v2(
                    handle,
                    "SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = 'idx_events_timestamp'",
                    -1,
                    &sizeStatement,
                    nil
                ) == SQLITE_OK, let sizeStatement else {
                    sqlite3_finalize(sizeStatement)
                    throw EventStoreError.prepareFailed(
                        "rc.13 rollback-barrier sizing failed"
                    )
                }
                guard sqlite3_step(sizeStatement) == SQLITE_ROW else {
                    sqlite3_finalize(sizeStatement)
                    throw EventStoreError.stepFailed(
                        "rc.13 rollback-barrier sizing failed"
                    )
                }
                let allocated = max(
                    0, sqlite3_column_int64(sizeStatement, 0)
                )
                sqlite3_finalize(sizeStatement)
                let pageSize = try Self.readPositivePragma(
                    handle, name: "page_size"
                )
                let metadataBytes = SQLitePersistentStoreAdmission
                    .saturatingMultiply(
                        SQLitePersistentStoreAdmission
                            .conservativeRowMutationBytes,
                        by: Int64(
                            missingGuards.count
                                + (barrier?.type == "view" ? 0 : 1)
                        )
                    )
                var estimate = SQLitePersistentStoreAdmission
                    .conservativeTransactionBytes(
                        rowMutationBytes:
                            SQLitePersistentStoreAdmission
                                .saturatingAdd(
                                    SQLitePersistentStoreAdmission
                                        .saturatingMultiply(allocated, by: 2),
                                    metadataBytes
                                ),
                        pageSizeBytes: pageSize,
                        maximumTreePathPageTouches:
                            8 + missingGuards.count
                    )
                if let bootstrapPlan {
                    estimate = max(estimate, SQLitePersistentStoreAdmission.saturatingAdd(
                        SQLitePersistentStoreAdmission.saturatingMultiply(allocated, by: 2),
                        bootstrapPlan.metadataTransactionBytes))
                }
                do {
                    // A large legacy index needs a schema budget, not the
                    // small fixed reserve used for ordinary event writes.
                    // Keep the entire drop/view/guards transaction bounded by
                    // fresh family and free-space measurements under this lock.
                    if deferredLegacyBootstrap {
                        try admitDeferredTransition(estimate)
                    } else if var current = admission {
                        try current.admitSerializedSchemaWrite(
                            estimatedTransactionBytes: estimate,
                            on: handle
                        )
                        admission = current
                    } else {
                        let family = try SQLitePersistentStoreAdmission
                            .measureFamily(path)
                        guard SQLitePersistentStoreAdmission.saturatingAdd(
                            family,
                            estimate
                        ) <= journalTransitionCap else {
                            throw SQLitePersistentStoreAdmissionError
                                .footprintLimit(
                                    footprintBytes: family,
                                    reserveBytes: estimate,
                                    maxFootprintBytes: journalTransitionCap
                                )
                        }
                    }
                    if barrier?.type == "index" {
                        try Self.exec(
                            handle,
                            "DROP INDEX idx_events_timestamp"
                        )
                    }
                    if barrier?.type != "view" {
                        try Self.exec(handle, Self.rollbackBarrierViewSQL)
                    }
                    for definition in missingGuards {
                        try Self.exec(handle, definition.sql)
                    }
                    try Self.exec(handle, "COMMIT")
                } catch {
                    try? Self.exec(handle, "ROLLBACK")
                    throw error
                }
                try Self.validateRollbackProtection(
                    on: handle,
                    requireAllGuards: false
                )
                return try transitionBoundaryIsDrained()
            }
            if !journalSchemaIsFinalized, journalTransitionReady {
                journalTransitionReady = try installRollbackBarrier()
            }
            if deferredLegacyBootstrap, !journalSchemaIsFinalized, journalTransitionReady {
                // The deferred main-file ceiling remains the original page
                // count. Retire the preflight-selected indexes before adding
                // journal roots, so those roots can reuse the proved pages.
                journalTransitionReady = try retireSupersededIndexes()
            }
            // Normal admission installs the additive journal substrate first.
            // The deferred branch has already retired its proved index set.
            // If one other legacy
            // index is too large to drop within the transaction reserve, a
            // later pre-producer transcode can empty it before retrying the
            // idempotent DROP; the upgrade never has to guess at scratch.
            if !journalSchemaIsFinalized, journalTransitionReady,
               let journalMigration = Self.schemaMigrations.first(where: {
                $0.version == 8
            }) {
                let rollbackGuardSQL = Set(
                    Self.rollbackGuardDefinitions.map(\.sql)
                )
                for sql in journalMigration.sql
                    where !rollbackGuardSQL.contains(sql) {
                    guard try applyTransitionStatement(sql) else {
                        journalTransitionReady = false
                        break
                    }
                }
            }
            if !journalSchemaIsFinalized, journalTransitionReady {
                var singletonStatement: OpaquePointer?
                let singletonPrepare = sqlite3_prepare_v2(
                    handle,
                    "SELECT 1 FROM event_storage_state WHERE singleton = 1 LIMIT 1",
                    -1,
                    &singletonStatement,
                    nil
                )
                guard singletonPrepare == SQLITE_OK,
                      let singletonStatement else {
                    throw EventStoreError.prepareFailed(
                        "event storage state singleton probe failed"
                    )
                }
                let singletonExists = sqlite3_step(singletonStatement)
                    == SQLITE_ROW
                sqlite3_finalize(singletonStatement)
                if !singletonExists {
                    journalTransitionReady = try applyTransitionStatement(
                        "INSERT INTO event_storage_state (singleton, mutation_generation, updated_at) VALUES (1, 0, 0)"
                    )
                }
            }
            func retireSupersededIndexes() throws -> Bool {
                func indexDropEstimate(_ name: String) throws -> Int64 {
                    var statement: OpaquePointer?
                    let rc = sqlite3_prepare_v2(
                        handle,
                        "SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?1",
                        -1,
                        &statement,
                        nil
                    )
                    guard rc == SQLITE_OK, let statement else {
                        sqlite3_finalize(statement)
                        throw EventStoreError.prepareFailed(
                            "journal transition index sizing failed"
                        )
                    }
                    defer { sqlite3_finalize(statement) }
                    sqlite3_bind_text(
                        statement,
                        1,
                        name,
                        -1,
                        unsafeBitCast(
                            OpaquePointer(bitPattern: -1)!,
                            to: sqlite3_destructor_type.self
                        )
                    )
                    guard sqlite3_step(statement) == SQLITE_ROW else {
                        throw EventStoreError.stepFailed(
                            "journal transition index sizing returned no row"
                        )
                    }
                    let allocated = max(0, sqlite3_column_int64(statement, 0))
                    return SQLitePersistentStoreAdmission
                        .conservativeTransactionBytes(
                            rowMutationBytes:
                                SQLitePersistentStoreAdmission
                                    .saturatingMultiply(allocated, by: 2),
                            pageSizeBytes: try Self.readPositivePragma(
                                handle, name: "page_size"
                            ),
                            maximumTreePathPageTouches: 8
                        )
                }
                for name in Self.supersededEventIndexes {
                    if let bootstrapPlan, !bootstrapPlan.indexes.contains(name) { continue }
                    var estimate = try indexDropEstimate(name)
                    if let bootstrapPlan {
                        estimate = SQLitePersistentStoreAdmission.saturatingAdd(
                            estimate, bootstrapPlan.metadataTransactionBytes)
                    }
                    let reserve = admission?.transactionReserveBytes
                        ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
                    // Leave an individually-too-large index intact until the
                    // pre-producer transcode has removed its legacy entries.
                    // Normal admission has already made the additive schema
                    // durable. A deferred transition must retain its proof.
                    if estimate > reserve {
                        guard !deferredLegacyBootstrap else {
                            throw EventStoreError.storageNotReady("legacy bootstrap index estimate no longer fits its preserving plan")
                        }
                        continue
                    }
                    guard try applyTransitionStatement(
                        "DROP INDEX IF EXISTS \(name)",
                        estimatedTransactionBytes: estimate
                    ) else {
                        return false
                    }
                }
                return true
            }
            if !deferredLegacyBootstrap, !journalSchemaIsFinalized, journalTransitionReady {
                journalTransitionReady = try retireSupersededIndexes()
            }
            guard journalTransitionReady else {
                throw EventStoreError.storageNotReady(
                    "event journal transition is waiting for a drained, cap-bounded boundary"
                )
            }
            if !writerInitializationAllowed, !journalSchemaIsFinalized,
               !deferredLegacyBootstrap,
               var current = admission {
                do {
                    try current.admitWrite(
                        estimatedTransactionBytes:
                            current.transactionReserveBytes,
                        on: handle
                    )
                    admission = current
                    writerInitializationAllowed = true
                } catch let error as SQLitePersistentStoreAdmissionError
                    where error.isOperationalPressure {
                    throw EventStoreError.storageNotReady(
                        "event journal transition completed but writer admission remains blocked: \(error.localizedDescription)"
                    )
                }
            }
            }
            if deferredLegacyBootstrap {
                try Self.withLegacyBootstrapWorkspace(on: handle, budget: liveMemoryBudget) { workspace, deadline in
                    try performJournalTransition(workspace: workspace, deadline: deadline)
                }
                guard var current = admission else {
                    throw EventStoreError.storageNotReady("legacy bootstrap lost its storage admission")
                }
                do {
                    try Self.reclaimLegacyTransitionHeadroom(on: handle, path: path,
                        admission: &current, liveMemoryBudget: liveMemoryBudget)
                    admission = current
                    try StoragePragmas.applyEventStorePragmasChecked(to: handle)
                    writerInitializationAllowed = true
                } catch {
                    admission = current
                    throw error
                }
            } else {
                try performJournalTransition()
            }
        }

        // Create schema
        let schemaSQLs = [
            """
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY, timestamp REAL NOT NULL,
                event_category TEXT NOT NULL, event_type TEXT NOT NULL,
                event_action TEXT NOT NULL, severity TEXT NOT NULL,
                process_pid INTEGER, process_name TEXT, process_path TEXT,
                process_commandline TEXT, process_ppid INTEGER,
                process_signer TEXT, process_team_id TEXT, process_signing_id TEXT,
                file_path TEXT, file_action TEXT,
                network_dest_ip TEXT, network_dest_port INTEGER,
                tcc_service TEXT, tcc_client TEXT, raw_json TEXT NOT NULL
            )
            """,
            // v1.21.5 PERF: idx_events_process_path (process_path) and
            // idx_events_ts_severity (timestamp, severity) are no longer created.
            // Each is a STRICT PREFIX of a wider index that already exists
            // (idx_events_process_ts = (process_path, timestamp);
            // idx_events_ts_sev_cat = (timestamp, severity, event_category)), so
            // neither could ever be the planner's best choice for any query the
            // wider index doesn't serve — while both cost a B-tree write on every
            // insert, at ~220 inserts/s on a developer host. Migration v7 drops
            // them from existing databases; see `schemaMigrations`.
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                process_name, process_path, process_commandline,
                file_path, network_dest_ip, tcc_service, tcc_client,
                content=events, content_rowid=rowid
            )
            """,
            """
            CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES (new.rowid, new.process_name, new.process_path, new.process_commandline,
                    new.file_path, new.network_dest_ip, new.tcc_service, new.tcc_client);
            END
            """,
            // events_au AFTER UPDATE (audit corr-storage): keep the external-
            // content FTS index in sync when an existing event row is UPDATED
            // directly. Normal event insertion treats duplicate immutable ids
            // as no-ops, but maintenance or future SQL UPDATE surfaces must not
            // orphan old FTS postings. This trigger removes the stale postings
            // (via the FTS5 'delete' command with old.* values, which does not
            // depend on the content row) and re-adds the fresh ones. The prune
            // paths delete FTS rows explicitly (while the content row is still
            // present) and are unaffected — no AFTER DELETE trigger exists, so
            // there is no double-delete.
            """
            CREATE TRIGGER IF NOT EXISTS events_au AFTER UPDATE ON events BEGIN
                INSERT INTO events_fts(events_fts, rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES ('delete', old.rowid, old.process_name, old.process_path, old.process_commandline,
                    old.file_path, old.network_dest_ip, old.tcc_service, old.tcc_client);
                INSERT INTO events_fts(rowid, process_name, process_path, process_commandline,
                    file_path, network_dest_ip, tcc_service, tcc_client)
                VALUES (new.rowid, new.process_name, new.process_path, new.process_commandline,
                    new.file_path, new.network_dest_ip, new.tcc_service, new.tcc_client);
            END
            """,
        ]
        if writerInitializationAllowed {
            try admitSchemaWork(
                SchemaMigrator.pendingStorageWork(
                    on: handle,
                    statements: schemaSQLs
                )
            )
            for sql in schemaSQLs { try Self.exec(handle, sql) }
        }

        // Sparse FTS maintenance is never allowed to turn one admitted row
        // into an unbounded hot-path segment rewrite. rc.35 note: the fix for
        // that was originally to disable automerge entirely and raise
        // crisismerge to 1999, relying on off-path merges. That produced a
        // WORSE failure — see the rc.35 comment on the config write below — so
        // the defaults are now asserted instead. Probe the persisted config
        // first so a routine fully-v8 reopen is read-only.
        //
        // DETECTION-SAFE: `events_fts` is read ONLY by `search()` (threat
        // hunting) — the detection engine never queries it. `automerge` /
        // `merge` change only the index's physical segment layout on disk,
        // never which rowids a MATCH returns, so this alters hunt latency,
        // never any detection outcome. The value persists in FTS5's `%_config`
        // shadow table; we (re)assert it on each read-write open so existing
        // DBs pick up the new value. Skipped on read-only opens (the
        // dashboard's connection), which cannot write the shadow table.
        //
        // Best-effort: a bare `sqlite3_exec` (not `Self.exec`) so a refused
        // write stays silent — this is a non-load-bearing perf tuning, and if
        // it can't be applied (e.g. a user-uid CLI opened the root daemon's DB
        // RW) the index just keeps the correct default automerge=4. Distinct
        // from the load-bearing schema statements above, whose failures log.
        if writerInitializationAllowed {
            func ftsConfig(_ key: String) -> Int64? {
                var statement: OpaquePointer?
                guard sqlite3_prepare_v2(
                    handle,
                    "SELECT v FROM events_fts_config WHERE k = ?1",
                    -1,
                    &statement,
                    nil
                ) == SQLITE_OK, let statement else {
                    sqlite3_finalize(statement)
                    return nil
                }
                defer { sqlite3_finalize(statement) }
                sqlite3_bind_text(
                    statement, 1, key, -1,
                    unsafeBitCast(
                        OpaquePointer(bitPattern: -1)!,
                        to: sqlite3_destructor_type.self
                    )
                )
                guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
                return sqlite3_column_int64(statement, 0)
            }
            // v1.21.6-rc.35: RESTORED TO FTS5's DEFAULTS. The v1.21.4 tuning
            // above (automerge=0, crisismerge=1999) traded a bounded per-insert
            // merge cost for unbounded segment growth, on the assumption that
            // "bounded explicit merge work runs off-path well before that
            // threshold". Measured on an installed host, it does not:
            //
            //   - segments accrue at roughly one per two rows with automerge=0
            //   - ingestion drove 1165 -> 1999 segments in ~30 seconds
            //   - the off-path sweep runs on a far slower cadence, so the index
            //     hit the 2000-segid ceiling every ~4 minutes
            //   - at the ceiling every write fails SQLITE_FULL: persistence
            //     stalled and ~1000 events were dropped per cycle
            //
            // crisismerge=1999 also disabled the safety net, leaving a margin of
            // exactly one below a hard ceiling. automerge=4 / crisismerge=16 are
            // FTS5's defaults; they keep segment count bounded during writes,
            // which is the only thing that actually holds at real event rates.
            // The explicit off-path mergeFTS remains as an optimisation and the
            // rebuild path remains as a safety net — but neither can substitute
            // for inline merging.
            let needsFTSConfig = ftsConfig("automerge") != 4
                || ftsConfig("crisismerge") != 16
            if needsFTSConfig,
               (try? admission?.admitWrite(
                    estimatedTransactionBytes:
                        SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
                    on: handle
               )) != nil {
                // Best-effort, as this block's own comment has always claimed —
                // but `try Self.exec` made it load-bearing, so a refused write
                // aborted the open. That is exactly backwards on the store this
                // matters most for: one already wedged by an older build, where
                // failing the open denies the recovery path a chance to run.
                // Perf tuning must never be the reason a store cannot be opened.
                _ = sqlite3_exec(
                    handle,
                    "INSERT INTO events_fts(events_fts, rank) VALUES('automerge', 4)",
                    nil, nil, nil
                )
                _ = sqlite3_exec(
                    handle,
                    "INSERT INTO events_fts(events_fts, rank) VALUES('crisismerge', 16)",
                    nil, nil, nil
                )
            }
        }

        // Apply versioned schema migrations on top of the baseline tables above.
        // v1 marks "baseline schema present"; later versions add columns for
        // enrichment fields (file/process hashes, session context, etc).
        //
        // Migration failures are load-bearing. In particular, callers need
        // the typed SQLite codes to distinguish explicit corruption from
        // BUSY/LOCKED/PERM/READONLY/IOERR without parsing a message. Swallowing
        // one here would let daemon recovery make the wrong evidence decision.
        if writerInitializationAllowed {
            // Full SQLite quick_check is an explicit maintenance operation.
            // Startup validates journal evidence and schema separately; no
            // deferred quick_check task is scheduled by the daemon.
            try SchemaMigrator.run(
                on: handle,
                // Existing stores retire v7's old indexes through the measured
                // transition path. Its optional category index is unnecessary
                // for v8's journal queries; do not rebuild legacy rows at boot.
                // Preserve the admitted version/header step. Fresh empty
                // stores retain the original inexpensive bootstrap index.
                migrations: Self.schemaMigrations.map { migration in
                    existingEventSubstrate && migration.version == 7
                        ? Migration(
                            version: migration.version,
                            name: migration.name,
                            sql: []
                        )
                        : migration
                },
                skipQuickCheck: true,
                beforeStorageWork: { work in
                    try admitSchemaWork(work)
                }
            )
            var stateProbe: OpaquePointer?
            let stateProbeRC = sqlite3_prepare_v2(
                handle,
                "SELECT 1 FROM event_storage_state WHERE singleton = 1 LIMIT 1",
                -1,
                &stateProbe,
                nil
            )
            guard stateProbeRC == SQLITE_OK, let stateProbe else {
                throw EventStoreError.prepareFailed(
                    "event storage state singleton probe failed"
                )
            }
            let stateExists = sqlite3_step(stateProbe) == SQLITE_ROW
            sqlite3_finalize(stateProbe)
            if !stateExists {
                try admitSchemaWork(SchemaStorageWork(
                    boundedMetadataStatementCount: 1,
                    rebuildStatementCount: 0
                ))
                try Self.exec(
                    handle,
                    "INSERT INTO event_storage_state (singleton, mutation_generation, updated_at) VALUES (1, 0, 0)"
                )
            }
            try Self.validateRollbackProtection(on: handle)
        }

        // Prepare insert statement.
        // v1.7.2 schema v2: 3 new indexed MCP attribution columns
        // (mcp_server_name, mcp_server_category, ai_tool_session_id).
        // Pulled from `event.enrichments` at insert time. Nullable —
        // events without MCP attribution leave them nil.
        // v1.9 PR-5 hotfix (audit B1): added five agent_* columns for
        // the v4 schema migration. Pre-fix the migration added the
        // columns but the INSERT never bound them, so every event
        // wrote NULL into the new fields and the partial index was
        // permanently empty. TraceCorrelator.flatten() writes these
        // keys into `event.enrichments`; we project them into columns
        // here so SQL-side queries (`WHERE agent_trace_id = ?`,
        // `WHERE agent_tool = 'claude_code'`) actually work.
        // v1.12.6 Wave 2A: 16 new columns promoted from raw_json (params
        // 30..=45). Order kept stable so re-prepares across schema bumps
        // are append-only. NULL/0 for fields that aren't present on a
        // given event category (e.g. tcc_decision is only set for TCC
        // events; ai_tool only when a TraceCorrelator binding exists).
        // Event ids identify immutable evidence. A duplicate is an idempotent
        // no-op, not a rewrite: this avoids both evidence mutation and a hidden
        // old-value FTS delete/new-value insert whose storage work cannot be
        // derived from the incoming event. Direct SQL UPDATEs remain covered by
        // `events_au`, which keeps the external-content FTS index coherent.
        let insertSQL = """
            INSERT OR IGNORE INTO events (
                id, timestamp, event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json,
                mcp_server_name, mcp_server_category, ai_tool_session_id,
                agent_trace_id, agent_span_id, agent_tool,
                machine_agent_confidence, agent_evidence_json,
                user_id, user_name, group_id, working_directory,
                responsible_pid, architecture, is_platform_binary,
                is_notarized, process_sha256, parent_name, parent_executable,
                parent_signer_type, ai_tool, ai_tool_child,
                session_launch_source, tcc_decision,
                journal_block_id, journal_ordinal, projection_reason,
                projection_estimated_bytes, projection_rank,
                projection_bucket
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,?40,?41,?42,?43,?44,?45,?46,?47,?48,?49,?50,?51)
            """
        var insertStmt: OpaquePointer?
        let prepareRC = !writerInitializationAllowed
            ? SQLITE_OK
            : sqlite3_prepare_v2(handle, insertSQL, -1, &insertStmt, nil)
        if prepareRC != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(handle))
            let failure = SQLiteFailureDetails(resultCode: prepareRC, db: handle)
            throw EventStoreError.sqliteFailure(
                context: "prepare insert",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }

        let pageSize = try Self.readPositivePragma(
            handle,
            name: "page_size"
        )
        guard pageSize <= SQLitePersistentStoreAdmission.maximumSQLitePageBytes else {
            throw EventStoreError.databaseOpenFailed(
                "unsupported SQLite page_size \(pageSize)"
            )
        }

        returnHandleToCaller = true
        return (
            handle,
            isReadOnly,
            insertStmt,
            admission,
            pageSize,
            checkpointController
        )
    }

    private static func readPositivePragma(
        _ db: OpaquePointer,
        name: String
    ) throws -> Int64 {
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            throw EventStoreError.databaseOpenFailed(
                "could not read PRAGMA \(name)"
            )
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw EventStoreError.databaseOpenFailed(
                "PRAGMA \(name) returned no row"
            )
        }
        let value = sqlite3_column_int64(stmt, 0)
        guard value > 0 else {
            throw EventStoreError.databaseOpenFailed(
                "invalid PRAGMA \(name)=\(value)"
            )
        }
        return value
    }

    /// Execute a SQL statement on a raw handle (used during init before actor is live).
    /// Execute SQL on a raw handle and surface the error to os.log when it
    /// fails. PRAGMAs used to be silently ignored; a failed `journal_mode =
    /// WAL` (corrupt DB, disk-full, read-only filesystem) would leave the
    /// store in a quieter fallback mode with no visible signal. `.public`
    /// interpolation keeps the diagnostic useful under `sudo log show`
    /// (values here are SQL strings and SQLite return codes, never user
    /// secrets).
    private static func exec(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .error("sqlite3_exec failed (rc=\(rc, privacy: .public)): \(sql, privacy: .public) — \(msg, privacy: .public)")
            throw EventStoreError.sqliteFailure(
                context: sql,
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }

    private static func schemaObject(
        on db: OpaquePointer,
        named name: String
    ) throws -> (type: String, sql: String)? {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "SELECT type, COALESCE(sql, '') FROM sqlite_master WHERE name = ?1 LIMIT 1",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw EventStoreError.prepareFailed(
                "schema object probe failed for \(name)"
            )
        }
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_text(
            statement,
            1,
            name,
            -1,
            unsafeBitCast(
                OpaquePointer(bitPattern: -1)!,
                to: sqlite3_destructor_type.self
            )
        )
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW,
              let type = sqlite3_column_text(statement, 0),
              let sql = sqlite3_column_text(statement, 1) else {
            throw EventStoreError.stepFailed(
                "schema object probe failed for \(name)"
            )
        }
        return (String(cString: type), String(cString: sql))
    }

    private static func canonicalSchemaSQL(_ sql: String) -> String {
        sql.lowercased()
            .split(whereSeparator: { $0.isWhitespace })
            .joined(separator: " ")
            .replacingOccurrences(of: "if not exists ", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: ";"))
    }

    /// Read the crash-resumable journal finalization marker without changing
    /// the database. A pre-v8 or partial-v8 store legitimately has no table or
    /// singleton yet and must take the ordinary transition path.
    private static func journalSchemaIsFinalized(
        on db: OpaquePointer
    ) throws -> Bool {
        guard let object = try schemaObject(
            on: db,
            named: "event_journal_migration"
        ) else { return false }
        guard object.type == "table" else {
            throw EventStoreError.decodingFailed(
                "event_journal_migration is not a table"
            )
        }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(
            db,
            "SELECT schema_finalized FROM event_journal_migration WHERE singleton = 1",
            -1,
            &statement,
            nil
        ) == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw EventStoreError.prepareFailed(
                "event journal finalization admission probe failed"
            )
        }
        defer { sqlite3_finalize(statement) }
        let first = sqlite3_step(statement)
        if first == SQLITE_DONE { return false }
        guard first == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "event journal finalization admission probe failed"
            )
        }
        let value = sqlite3_column_int(statement, 0)
        guard value == 0 || value == 1 else {
            throw EventStoreError.decodingFailed(
                "event journal finalization marker is invalid"
            )
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "event journal finalization admission marker is duplicated"
            )
        }
        return value == 1
    }

    /// A finalization marker authorizes bypassing transition-only checkpoint
    /// and scratch gates only when its immutable schema claims are still true.
    /// This is deliberately read-only; full FTS/content validation remains at
    /// the bounded pre-producer recovery boundary.
    private static func validateFinalizedJournalSchemaInventory(
        on db: OpaquePointer
    ) throws {
        for name in supersededEventIndexes {
            guard try schemaObject(on: db, named: name) == nil else {
                throw EventStoreError.storageNotReady(
                    "superseded event index \(name) remains after finalized transcode"
                )
            }
        }
        for (name, expectedType) in finalizedJournalSchemaObjects {
            guard let object = try schemaObject(on: db, named: name),
                  object.type == expectedType else {
                throw EventStoreError.storageNotReady(
                    "final event journal schema is missing \(expectedType) \(name)"
                )
            }
        }
        // Exact event pages/filtering and retention summaries use the journal;
        // sparse search uses FTS plus rowid or timestamp/text predicates. None
        // requires v7's category/severity index. Preserve existing copies,
        // but never make its absence prevent a valid v8 store from starting.
        if let optionalIndex = try schemaObject(
            on: db, named: "idx_events_cat_sev_ts"
        ), optionalIndex.type != "index" {
            throw EventStoreError.storageNotReady(
                "optional event category index has an unexpected schema type"
            )
        }
        try validateRollbackProtection(on: db)
    }

    private static func missingRollbackGuards(
        on db: OpaquePointer,
        existingTablesOnly: Bool = false
    ) throws -> [RollbackGuardDefinition] {
        var missing: [RollbackGuardDefinition] = []
        for definition in rollbackGuardDefinitions {
            if existingTablesOnly {
                guard let table = try schemaObject(
                    on: db,
                    named: definition.table
                ), table.type == "table" else {
                    continue
                }
            }
            guard let stored = try schemaObject(
                on: db,
                named: definition.name
            ) else {
                missing.append(definition)
                continue
            }
            guard stored.type == "trigger",
                  canonicalSchemaSQL(stored.sql)
                    == canonicalSchemaSQL(definition.sql) else {
                throw EventStoreError.decodingFailed(
                    "rc.13 rollback guard \(definition.name) is not the expected trigger"
                )
            }
        }
        return missing
    }

    private static func validateRollbackProtection(
        on db: OpaquePointer,
        requireAllGuards: Bool = true
    ) throws {
        if let legacyAlerts = try schemaObject(on: db, named: "alerts"),
           legacyAlerts.type == "table" {
            throw EventStoreError.storageNotReady(
                "legacy events.db alerts table must be relocated before the rc.13 rollback barrier"
            )
        }
        guard let barrier = try schemaObject(
            on: db,
            named: "idx_events_timestamp"
        ), barrier.type == "view",
              canonicalSchemaSQL(barrier.sql) == canonicalSchemaSQL(
                rollbackBarrierViewSQL
              ) else {
            throw EventStoreError.decodingFailed(
                "idx_events_timestamp is not the rc.13 rollback barrier"
            )
        }
        guard try missingRollbackGuards(
            on: db,
            existingTablesOnly: !requireAllGuards
        ).isEmpty else {
            throw EventStoreError.decodingFailed(
                "one or more rc.13 rollback DML guards are missing"
            )
        }
    }

    /// Creates an `EventStore` backed by a SQLite database at the default location.
    ///
    /// The database is stored at `~/Library/Application Support/MacCrab/events.db`.
    /// The directory is created if it does not already exist.
    ///
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
    public init(
        directory: String = "/Library/Application Support/MacCrab",
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil,
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
    ) throws {
        let maccrabDir = URL(fileURLWithPath: directory)

        // Skip dir-create + chmod when forceReadOnly — dashboard is not the
        // owner of these paths and shouldn't mutate them.
        if !forceReadOnly {
            try FileManager.default.createDirectory(
                at: maccrabDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o755],
                ofItemAtPath: maccrabDir.path
            )
        }

        let databasePath = maccrabDir.appendingPathComponent("events.db").path
        self.databasePath = databasePath
        self.liveMemoryBudget = liveMemoryBudget
        let effectiveStoragePolicy = forceReadOnly
            ? nil
            : (storagePolicy ?? Self.defaultStoragePolicy(for: databasePath))
        self.storagePolicy = effectiveStoragePolicy

        // v1.21.5 (audit sec-storage-crypto): umask 0o027 ⇒ new SQLite
        // WAL/SHM files are created 0o640 (owner rw, group read-only).
        // The evidence DBs are root-owned; the console-user dashboard/CLI
        // READ them (group-read) but must NOT write them directly. The
        // default macOS account is in the admin group (gid 80), so the
        // old group-WRITE bit (0o660) let any non-root admin process open
        // events.db read-write and DELETE the rows recording its own
        // activity (anti-forensics) with no sudo / escalation. All
        // legitimate mutations now route through the privileged inbox IPC
        // (the daemon applies them as root); 0o640 keeps group-read for
        // display while closing the direct-write tamper path.
        // (Skip umask + chmod entirely when forceReadOnly — see Wave 9A.)
        if forceReadOnly {
            let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
                at: databasePath,
                forceReadOnly: true,
                storagePolicy: nil,
                liveMemoryBudget: liveMemoryBudget
            )
            self.db = handle
            self.isReadOnly = ro
            self.insertStmt = stmt
            self.storageAdmission = admission
            self.sqlitePageSizeBytes = pageSize
            self.checkpointController = controller
        } else {
            let oldUmask = umask(0o027)
            defer { umask(oldUmask) }
            let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
                at: databasePath,
                forceReadOnly: false,
                storagePolicy: effectiveStoragePolicy,
                liveMemoryBudget: liveMemoryBudget
            )
            self.db = handle
            self.isReadOnly = ro
            self.insertStmt = stmt
            self.storageAdmission = admission
            self.sqlitePageSizeBytes = pageSize
            self.checkpointController = controller
            // Re-clamp existing files (incl. any created 0o660 by an older
            // build) to 0o640: owner rw, group read-only, no other.
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
        }
    }

    /// Creates an `EventStore` at a custom path (useful for testing).
    ///
    /// - Parameter path: Full file system path for the SQLite database.
    /// - Throws: `EventStoreError` if the database cannot be opened or initialized.
    public init(
        path: String,
        forceReadOnly: Bool = false,
        storagePolicy: SQLitePersistentStorePolicy? = nil,
        liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared
    ) throws {
        self.databasePath = path
        self.liveMemoryBudget = liveMemoryBudget
        let effectiveStoragePolicy = forceReadOnly
            ? nil
            : (storagePolicy ?? Self.defaultStoragePolicy(for: path))
        self.storagePolicy = effectiveStoragePolicy
        let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
            at: path,
            forceReadOnly: forceReadOnly,
            storagePolicy: effectiveStoragePolicy,
            liveMemoryBudget: liveMemoryBudget
        )
        self.db = handle
        self.isReadOnly = ro
        self.insertStmt = stmt
        self.storageAdmission = admission
        self.sqlitePageSizeBytes = pageSize
        self.checkpointController = controller
    }

    deinit {
        if let insertStmt { sqlite3_finalize(insertStmt) }
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
    }

    // MARK: - Insert

    /// Persists a single event to the store.
    ///
    /// The event is serialised to JSON for the `raw_json` column, and
    /// commonly-queried fields are extracted into their own columns.
    ///
    /// - Parameter event: The event to store.
    /// - Throws: `EventStoreError` on serialisation or database failure.
    /// Install (or replace) the pre-insert filter. Called by daemon bootstrap
    /// after the support dir is resolved + DaemonConfig parsed. Tests can call
    /// this to dial a specific filter into a temp store.
    public func setInsertFilter(_ filter: EventInsertFilter?) {
        self.insertFilter = filter
    }

    /// Run an explicitly requested SQLite `PRAGMA quick_check` on this handle.
    /// This diagnostic is not scheduled automatically: it occupies the store
    /// actor while running. Startup performs the journal/schema validation
    /// required before producers start. Findings here are logged; callers
    /// needing a throwing diagnostic can use SchemaMigrator.quickCheck.
    public func runQuickCheck() {
        guard let db = self.db else { return }
        do {
            try SchemaMigrator.quickCheck(on: db) { msg in
                Logger(subsystem: "com.maccrab.storage", category: "event-store")
                    .info("quick_check: \(msg, privacy: .public)")
            }
        } catch {
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .warning("Requested quick_check failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Snapshot the filter's drop counter. Wired into the daemon's heartbeat
    /// so the dashboard can surface "X events dropped at insert filter today"
    /// — operators tuning their filter list need to see the impact.
    public func insertFilterCounters() -> (dropped: Int, passed: Int)? {
        return insertFilter?.counters.snapshot()
    }

    /// Durable distinct-UUID count of events that exceeded the shared
    /// canonical ingress envelope. Retry and restart cannot clear or inflate
    /// this qualification poison; projection-only truncation is excluded.
    public func payloadTruncatedTotal() -> Int {
        guard (try? hasJournalSchema()) == true,
              let statement = try? prepare(
                "SELECT payload_poison_total FROM event_storage_state WHERE singleton = 1"
              ) else { return 0 }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(statement, 0))
    }

    /// Fail-closed status source for qualification/heartbeat snapshots. The
    /// legacy nonthrowing accessor remains only for source compatibility while
    /// status callers migrate; it must not be used to assert journal health.
    public func payloadPoisonTotalSnapshot() throws -> Int {
        guard try hasJournalSchema() else {
            throw EventStoreError.storageNotReady(
                "canonical journal poison state is unavailable"
            )
        }
        let statement = try prepare(
            "SELECT payload_poison_total FROM event_storage_state WHERE singleton = 1"
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.decodingFailed(
                "canonical journal poison counter is unavailable"
            )
        }
        let value = sqlite3_column_int64(statement, 0)
        guard value >= 0, sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "canonical journal poison counter is corrupt"
            )
        }
        return Int(value)
    }

    internal func setTerminalDeltaOwnershipGrowthHookForTesting(
        _ hook: (@Sendable () -> Void)?
    ) {
        terminalDeltaOwnershipGrowthHookForTesting = hook
    }

    internal func setJournalExpiryPostCommitHookForTesting(
        _ hook: (@Sendable () -> Void)?
    ) {
        journalExpiryPostCommitHookForTesting = hook
    }

    internal func setJournalExpiryCheckpointHookForTesting(
        _ hook: (@Sendable () -> Void)?
    ) {
        journalExpiryCheckpointHookForTesting = hook
    }

    public func insert(event: Event) throws {
        let lane = EventPipelineLane.finalLane(for: event)
        _ = try insert(events: [event], lane: lane)
    }

    /// Bytes of the events budget that only the PRIORITY lane may consume.
    ///
    /// Storage admission used to be lane-blind: at the footprint threshold it
    /// refused whatever arrived next, so a process exec and a routine chmod were
    /// treated identically. That is the wrong policy for a detection engine, and
    /// it disagreed with the rest of the product — `EventPipelineLane` already
    /// splits events into priority/file streams, and eviction already protects
    /// process rows first (`processEventsFloorMinutes`, v1.21.4). Three
    /// subsystems knew file events were the cheap ones; the gate that decides
    /// what actually gets recorded did not.
    ///
    /// Measured consequence on an installed rc.7 host: ~890 events/minute
    /// refused with `footprint_limit` while 1,400/s of temp-file churn filled
    /// the store — process and network telemetry lost to make room for `chmod`.
    ///
    /// It is also an evasion primitive. Flooding cheap file events pushes the
    /// footprint over the threshold, after which the attacker's OWN process and
    /// network events stop being recorded. The product ships a self-defence
    /// monitor for telemetry-drop evasion; admission was manufacturing exactly
    /// that condition under ordinary load.
    ///
    /// The reserve makes the file lane yield first. Priority events remain
    /// admissible down to the absolute cap because their volume is bounded and
    /// small — on a host doing 1,400 file events/sec the priority lane is a
    /// rounding error beside it.
    public static func priorityLaneReserveBytes(
        maxFootprintBytes: Int64
    ) -> Int64 {
        // 10% of the budget, floored at 16 MiB and capped at 64 MiB. The floor
        // matters more than the fraction: 15 minutes of priority-lane events is
        // a few MiB, so even the floor makes the retention guarantee satisfiable
        // for the lane that carries the evidence. The ceiling keeps the reserve
        // from ever becoming the dominant consumer of the budget it protects.
        return max(16 * 1_048_576, min(64 * 1_048_576, maxFootprintBytes / 10))
    }

    private struct PreparedPersistedEvent {
        /// Complete canonical journal representation (privacy-sanitized and
        /// bounded only at the formally derived source-poison ceiling).
        let event: Event
        let canonicalJSON: Data
        /// Independently bounded compatibility/search representation.
        let projectionEvent: Event
        let projectionJSON: Data
        let jsonString: String
        let indexedCommandLine: String
        let recordDigest: Data
        /// Versioned digest of the raw immutable source fields before the
        /// canonical at-rest privacy transform. This remains append-local so
        /// later terminal revisions can prove source identity without either
        /// retaining secrets or trying to reconstruct them from sanitized
        /// journal JSON.
        let sourceIdentitySHA256: Data
        /// Non-nil only for a source value rejected at the shared ingress
        /// boundary. The compact replacement remains journaled under the same
        /// UUID while this content-bound poison identity is durably conserved.
        let overflow: EventJournalOverflowEvidence?
    }

    private struct ProjectionReference {
        let blockID: Int64
        let ordinal: Int
        let reason: ProjectionReason
        let estimatedBytes: Int
        let rank: Int32
        let bucket: Int64
    }

    private enum JournalProjectionMode: Equatable {
        case normal
        case migrationSplit
    }

    /// Build the exact privacy-sanitized representation shared by the
    /// lossless journal and the sparse projection. Keeping this before either
    /// write prevents the two tiers from disagreeing about secret redaction or
    /// payload truncation.
    private func preparePersistedEvent(
        _ event: Event
    ) throws -> PreparedPersistedEvent {
        do {
            return try preparePersistedEvent(
                EventJournalAdmissionValidator.prepare(event)
            )
        } catch let error as EventStoreError {
            throw error
        } catch {
            throw EventStoreError.encodingFailed(error.localizedDescription)
        }
    }

    /// Validate and consume the once-prepared ingress value without repeating
    /// the recursive credential sanitization or canonical JSON encoding on the
    /// storage actor. Public construction is intentionally revalidated: a
    /// caller cannot pair arbitrary bytes/digests with another Event value.
    private func preparePersistedEvent(
        _ ingress: EventJournalIngressPreparation
    ) throws -> PreparedPersistedEvent {
        do {
            let canonical = ingress.canonicalJSON
            guard !canonical.isEmpty,
                  canonical.count <= EventJournalCodec.maximumRecordBytes,
                  Data(SHA256.hash(data: canonical))
                    == ingress.canonicalSHA256,
                  let decoded = try? decoder.decode(
                    Event.self,
                    from: canonical
                  ),
                  decoded == ingress.event else {
                throw EventStoreError.encodingFailed(
                    "Prepared canonical Event identity/digest is invalid"
                )
            }
            let storedEvent = ingress.event
            guard ingress.sourceIdentitySHA256.count == SHA256.byteCount else {
                throw EventStoreError.encodingFailed(
                    "Prepared raw source identity has an invalid digest length"
                )
            }
            if let overflow = ingress.overflow {
                guard overflow.originalEventID == storedEvent.id,
                      overflow.originalBytes >= 0,
                      overflow.originalSHA256.count == SHA256.byteCount,
                      overflow.sourceIdentitySHA256
                        == ingress.sourceIdentitySHA256,
                      storedEvent.eventAction == "journal_overflow" else {
                    throw EventStoreError.encodingFailed(
                        "Prepared overflow Event evidence is invalid"
                    )
                }
            }
            let projectionEvent: Event
            if canonical.count <= Self.maxRawJsonBytes {
                projectionEvent = storedEvent
            } else {
                projectionEvent = try truncatePayload(
                    sanitizedEvent: storedEvent,
                    originalBytes: canonical.count,
                    originalSHA256: SHA256.hash(data: canonical)
                        .map { String(format: "%02x", $0) }
                        .joined(),
                    maximumBytes: Self.maxRawJsonBytes
                ).event
            }
            let projectionJSON = try journalEncoder.encode(projectionEvent)
            guard projectionJSON.count <= Self.maxRawJsonBytes,
                  let string = String(
                    data: projectionJSON,
                    encoding: .utf8
                  ) else {
                throw EventStoreError.encodingFailed(
                    "Projection Event JSON exceeds its compatibility ceiling"
                )
            }
            let indexed = Self.boundIndexedText(
                projectionEvent.process.commandLine,
                maxBytes: Self.maxIndexedCommandLineBytes
            )
            return PreparedPersistedEvent(
                event: storedEvent,
                canonicalJSON: canonical,
                projectionEvent: projectionEvent,
                projectionJSON: projectionJSON,
                jsonString: string,
                indexedCommandLine: indexed,
                recordDigest: ingress.canonicalSHA256,
                sourceIdentitySHA256: ingress.sourceIdentitySHA256,
                overflow: ingress.overflow
            )
        } catch let error as EventStoreError {
            throw error
        } catch {
            throw EventStoreError.encodingFailed(error.localizedDescription)
        }
    }

    /// Prepare the complete persisted representation before asking the caller
    /// to admit the write. Batch insertion uses the callback to close the
    /// current transaction before adding a row that would exceed its reserve.
    private func insert(
        event: Event,
        applyInsertFilter: Bool,
        projection: ProjectionReference? = nil,
        prepared suppliedPreparation: PreparedPersistedEvent? = nil,
        beforeWrite: (Int64) throws -> Void
    ) throws -> Bool {
        // v1.8.0 Layer 1: drop noise events at insert. Cheaper than letting
        // them hit SQLite + FTS5 + indexes. Self-monitoring (daemon watches
        // its own log/DB) was 17% of volume on field-measured hardware.
        if applyInsertFilter,
           let filter = insertFilter,
           filter.shouldDrop(event: event) {
            return false
        }
        let prepared: PreparedPersistedEvent
        if let suppliedPreparation {
            guard suppliedPreparation.event == event,
                  suppliedPreparation.overflow == nil else {
                throw EventStoreError.encodingFailed(
                    "Sparse insertion preparation does not match exact event"
                )
            }
            prepared = suppliedPreparation
        } else {
            prepared = try preparePersistedEvent(event)
        }
        let event = prepared.projectionEvent
        // Sparse projection rows retain canonical JSON as a downgrade-safe
        // compatibility copy. The copy is bounded to at most four rows/sec;
        // the complete corpus lives only in the compressed journal.
        let jsonString = prepared.jsonString
        let indexedCommandLine = prepared.indexedCommandLine
        let mutationBytes = Self.estimatedEventMutationBytes(
            event: event,
            indexedCommandLine: indexedCommandLine,
            rawJSON: jsonString,
            pageSizeBytes: sqlitePageSizeBytes
        )
        try beforeWrite(mutationBytes)

        // Storage admission can synchronously recover a sticky pressure latch
        // by calling reopenAfterStorageRecovery(). That path finalizes the old
        // cached statement and replaces the SQLite handle. Acquire the statement
        // only after admission so no local pointer can outlive that reopen.
        guard let stmt = insertStmt else {
            // admitStorageWrite performs one bounded, full-estimate secondary
            // recovery if a reopen races back into shed-only mode. Reaching this
            // guard therefore means no authoritative writer could be restored.
            throw EventStoreError.prepareFailed(
                "Insert statement not prepared after storage admission"
            )
        }
        sqlite3_reset(stmt)
        sqlite3_clear_bindings(stmt)

        // 1: id (UUID -> String)
        bindText(stmt, index: 1, value: event.id.uuidString)
        // 2: timestamp (Unix epoch seconds)
        sqlite3_bind_double(stmt, 2, event.timestamp.timeIntervalSince1970)
        // 3: event_category
        bindText(stmt, index: 3, value: event.eventCategory.rawValue)
        // 4: event_type
        bindText(stmt, index: 4, value: event.eventType.rawValue)
        // 5: event_action
        bindText(stmt, index: 5, value: event.eventAction)
        // 6: severity
        bindText(stmt, index: 6, value: event.severity.rawValue)
        // 7: process_pid
        sqlite3_bind_int(stmt, 7, event.process.pid)
        // 8: process_name
        bindText(stmt, index: 8, value: event.process.name)
        // 9: process_path (executable)
        bindText(stmt, index: 9, value: event.process.executable)
        // 10: process_commandline (sanitized, length-bounded). Bounded
        // independently of raw_json because this column feeds the events_fts
        // index directly — an oversized argv would otherwise blow up the FTS
        // index unbounded. See maxIndexedCommandLineBytes.
        bindText(stmt, index: 10, value: indexedCommandLine)
        // 11: process_ppid
        sqlite3_bind_int(stmt, 11, event.process.ppid)
        // 12: process_signer
        bindTextOrNull(stmt, index: 12, value: event.process.codeSignature?.signerType.rawValue)
        // 13: process_team_id
        bindTextOrNull(stmt, index: 13, value: event.process.codeSignature?.teamId)
        // 14: process_signing_id
        bindTextOrNull(stmt, index: 14, value: event.process.codeSignature?.signingId)
        // 15: file_path
        bindTextOrNull(stmt, index: 15, value: event.file?.path)
        // 16: file_action
        bindTextOrNull(stmt, index: 16, value: event.file?.action.rawValue)
        // 17: network_dest_ip
        bindTextOrNull(stmt, index: 17, value: event.network?.destinationIp)
        // 18: network_dest_port
        if let port = event.network?.destinationPort {
            sqlite3_bind_int(stmt, 18, Int32(port))
        } else {
            sqlite3_bind_null(stmt, 18)
        }
        // 19: tcc_service
        bindTextOrNull(stmt, index: 19, value: event.tcc?.service)
        // 20: tcc_client
        bindTextOrNull(stmt, index: 20, value: event.tcc?.client)
        // 21: raw_json (sanitized)
        bindText(stmt, index: 21, value: jsonString)
        // v1.7.2 schema v2: indexed MCP attribution columns.
        // 22: mcp_server_name
        bindTextOrNull(stmt, index: 22, value: event.enrichments["mcp_server_name"])
        // 23: mcp_server_category
        bindTextOrNull(stmt, index: 23, value: event.enrichments["mcp_server_category"])
        // 24: ai_tool_session_id
        bindTextOrNull(stmt, index: 24, value: event.enrichments["ai_tool_session_id"])
        // v1.9 schema v4: agent trace correlation columns. Keys live in
        // `event.enrichments` written by `TraceCorrelator.flatten()`;
        // we project them into indexed columns so SQL-side queries
        // (`WHERE agent_trace_id = ?`, `agent_tool = ?`,
        // `machine_agent_confidence = ?`) and the partial index
        // `idx_events_trace` actually populate.
        // 25: agent_trace_id
        bindTextOrNull(stmt, index: 25, value: event.enrichments[TraceCorrelator.EnrichmentKey.traceId])
        // 26: agent_span_id
        bindTextOrNull(stmt, index: 26, value: event.enrichments[TraceCorrelator.EnrichmentKey.spanId])
        // 27: agent_tool
        bindTextOrNull(stmt, index: 27, value: event.enrichments[TraceCorrelator.EnrichmentKey.agentTool])
        // 28: machine_agent_confidence
        bindTextOrNull(stmt, index: 28, value: event.enrichments[TraceCorrelator.EnrichmentKey.confidence])
        // 29: agent_evidence_json
        bindTextOrNull(stmt, index: 29, value: event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson])
        // v1.12.6 Wave 2A schema v6: promoted process / signature /
        // session / ai-tool fields. Empty Strings are bound as NULL so
        // `IS NULL` filters work in SQL; "" would otherwise non-match
        // for `field IS NOT NULL`. Bool fields use SQLite 0/1 INTEGER.
        // 30: user_id (UInt32 -> Int64 to avoid Int32 overflow)
        sqlite3_bind_int64(stmt, 30, Int64(event.process.userId))
        // 31: user_name -- empty -> NULL (often empty in capture stream)
        bindTextOrNull(stmt, index: 31, value: event.process.userName.isEmpty ? nil : event.process.userName)
        // 32: group_id
        sqlite3_bind_int64(stmt, 32, Int64(event.process.groupId))
        // 33: working_directory -- empty -> NULL
        bindTextOrNull(stmt, index: 33, value: event.process.workingDirectory.isEmpty ? nil : event.process.workingDirectory)
        // 34: responsible_pid (Int32, never negative in practice but
        // bind raw value — historical events have rpid==pid placeholder)
        sqlite3_bind_int(stmt, 34, event.process.rpid)
        // 35: architecture (Optional<String>) -- nil already maps to NULL
        bindTextOrNull(stmt, index: 35, value: event.process.architecture)
        // 36: is_platform_binary -- 0/1 not "true"/"false"
        sqlite3_bind_int(stmt, 36, event.process.isPlatformBinary ? 1 : 0)
        // 37: is_notarized -- only when codeSignature is present.
        // NULL means "unknown" (no signature info), 0 means "explicitly
        // not notarized", 1 means "notarized". Sigma rules predicate
        // on the 3-state via the NotarizationStatus resolver alias.
        if let sig = event.process.codeSignature {
            sqlite3_bind_int(stmt, 37, sig.isNotarized ? 1 : 0)
        } else {
            sqlite3_bind_null(stmt, 37)
        }
        // 38: process_sha256 -- only when ProcessHasher attached hashes
        bindTextOrNull(stmt, index: 38, value: event.process.hashes?.sha256)
        // 39: parent_name -- first ancestor or NULL when ancestors empty
        bindTextOrNull(stmt, index: 39, value: event.process.ancestors.first?.name)
        // 40: parent_executable -- ditto
        bindTextOrNull(stmt, index: 40, value: event.process.ancestors.first?.executable)
        // 41: parent_signer_type -- set by EventEnricher when parent
        // process signature lookup succeeds; nil otherwise.
        bindTextOrNull(stmt, index: 41, value: event.enrichments["ParentSignerType"])
        // 42: ai_tool -- reads either canonical key. AIProcessTracker
        // (EventLoop.swift:89,97) writes "ai_tool"; TraceCorrelator
        // (the legacy EnrichmentKey.agentTool constant) writes
        // "agent_tool". Either should populate the indexed column.
        // v1.12.6 RC2 fix: pre-RC1 only read EnrichmentKey.agentTool
        // so the column was 100% NULL in production despite
        // "claude_code"/"cursor"/etc. being live in raw_json under
        // the "ai_tool" key. Rules can match either Sigma alias
        // against this column (AITool, AiTool both resolve here).
        let aiTool = event.enrichments["ai_tool"]
            ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        bindTextOrNull(stmt, index: 42, value: aiTool)
        // 43: ai_tool_child -- 1 when MCPAttributor / AgentLineage
        // marks this process as a descendant of an AI tool; otherwise
        // NULL (not "0", so historical rows still register as unknown).
        if let aiChild = event.enrichments["ai_tool_child"] {
            sqlite3_bind_int(stmt, 43, aiChild == "true" ? 1 : 0)
        } else {
            sqlite3_bind_null(stmt, 43)
        }
        // 44: session_launch_source -- LaunchSource raw value ("ssh",
        // "terminal", "launchd", ...) from SessionEnricher; nil when
        // the enricher hasn't classified the parent chain yet. The
        // "telemetry_gap" sentinel (LaunchSource.telemetryGap) is the
        // honest-degradation value written when attribution was UNRESOLVED
        // because a kernel telemetry gap was active for the event's window
        // (EventEnricher.telemetryGapSession) — distinct from a silent NULL.
        bindTextOrNull(stmt, index: 44, value: event.process.session?.launchSource?.rawValue)
        // 45: tcc_decision -- "granted" / "denied". TCCInfo.allowed
        // (Bool) flattened to a string so the Sigma rule can compare
        // against rule literals without engine-side Bool plumbing.
        if let allowed = event.tcc?.allowed {
            bindText(stmt, index: 45, value: allowed ? "granted" : "denied")
        } else {
            sqlite3_bind_null(stmt, 45)
        }
        if let projection {
            sqlite3_bind_int64(stmt, 46, projection.blockID)
            sqlite3_bind_int(stmt, 47, Int32(projection.ordinal))
            sqlite3_bind_int(stmt, 48, projection.reason.rawValue)
            sqlite3_bind_int64(
                stmt, 49, Int64(projection.estimatedBytes)
            )
            sqlite3_bind_int(stmt, 50, projection.rank)
            sqlite3_bind_int64(stmt, 51, projection.bucket)
        } else {
            sqlite3_bind_null(stmt, 46)
            sqlite3_bind_null(stmt, 47)
            sqlite3_bind_int(stmt, 48, ProjectionReason.pending.rawValue)
            sqlite3_bind_int(stmt, 49, 0)
            sqlite3_bind_int(stmt, 50, 100)
            sqlite3_bind_null(stmt, 51)
        }

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            // v1.12.0 RC28 audit fix (Resil-B1): surface SQLITE_FULL
            // distinctly so EventLoop can stop trying to insert (no
            // point hammering a full disk) instead of treating it as
            // a transient step failure. The vendored Unix VFS reports
            // ENOSPC writes as primary SQLITE_FULL; other VFS paths may
            // retain ENOSPC/EDQUOT in sqlite3_system_errno().
            if failure.primaryResultCode == SQLITE_FULL
                || failure.systemErrno == ENOSPC
                || failure.systemErrno == EDQUOT {
                throw EventStoreError.diskFull(msg, failure: failure)
            }
            // #13: transient lock contention (past the 5s busy_timeout) — the
            // batched writer retries rather than dropping the batch.
            if rc == SQLITE_BUSY || rc == SQLITE_LOCKED {
                throw EventStoreError.busy(msg, failure: failure)
            }
            // C-04: a mid-run corruption code triggers a bounded, rate-limited
            // close→quarantine→reopen so ingestion recovers instead of failing
            // forever. We still throw this event's failure (the row is lost);
            // the *next* insert lands in the freshly-reopened DB. (When reached
            // from the batch `insert(events:lane:)`, the enclosing transaction's
            // ROLLBACK runs on the reopened handle as a harmless no-op.)
            if failure.isExplicitCorruption {
                attemptCorruptionSelfHeal(failure: failure, reason: msg)
            }
            throw EventStoreError.sqliteFailure(
                context: "insert step",
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
        if sqlite3_changes(db) > 0 {
            maintenanceRowMutationHighWaterBytes = max(
                maintenanceRowMutationHighWaterBytes ?? 0,
                mutationBytes
            )
        }
        return true
    }

    /// Derive the transaction estimate from exactly what the insert binds.
    /// `raw_json` is capped at 64 KiB and the independently indexed command
    /// line at 16 KiB, but every other projected string is counted at its real
    /// UTF-8 length so an adversarial path/enrichment can only make admission
    /// stricter. Table bytes and every secondary-index key are counted once;
    /// FTS input is counted four times for token/posting expansion. The shared
    /// estimator doubles that durable representation for WAL/page-image writes
    /// and charges up to 20 random leaf pages per row at the authoritative DB
    /// page size (events table + PK + 13 live indexes + three FTS5 backing
    /// b-trees, with two pages of margin). Interior tree/header slack is charged once per transaction by
    /// `eventTransactionEstimate`, so batching does not pay it once per event.
    static func estimatedEventMutationBytes(
        event: Event,
        indexedCommandLine: String,
        rawJSON: String,
        pageSizeBytes: Int64
    ) -> Int64 {
        func bytes(_ value: String?) -> Int64 {
            guard let value else { return 0 }
            return Int64(value.utf8.count)
        }
        func add(_ total: inout Int64, _ value: Int64) {
            total = SQLitePersistentStoreAdmission.saturatingAdd(total, value)
        }
        func addStrings(_ total: inout Int64, _ values: [String?]) {
            for value in values { add(&total, bytes(value)) }
        }

        let aiTool = event.enrichments["ai_tool"]
            ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        let tccDecision = event.tcc.map { $0.allowed ? "granted" : "denied" }

        // Row payload: every text column bound by insert(event:). Numeric/null
        // columns receive a fixed-width allowance below.
        var logical: Int64 = 45 * 16
        addStrings(&logical, [
            event.id.uuidString,
            event.eventCategory.rawValue,
            event.eventType.rawValue,
            event.eventAction,
            event.severity.rawValue,
            event.process.name,
            event.process.executable,
            indexedCommandLine,
            event.process.codeSignature?.signerType.rawValue,
            event.process.codeSignature?.teamId,
            event.process.codeSignature?.signingId,
            event.file?.path,
            event.file?.action.rawValue,
            event.network?.destinationIp,
            event.tcc?.service,
            event.tcc?.client,
            rawJSON,
            event.enrichments["mcp_server_name"],
            event.enrichments["mcp_server_category"],
            event.enrichments["ai_tool_session_id"],
            event.enrichments[TraceCorrelator.EnrichmentKey.traceId],
            event.enrichments[TraceCorrelator.EnrichmentKey.spanId],
            event.enrichments[TraceCorrelator.EnrichmentKey.agentTool],
            event.enrichments[TraceCorrelator.EnrichmentKey.confidence],
            event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson],
            event.process.userName.isEmpty ? nil : event.process.userName,
            event.process.workingDirectory.isEmpty ? nil : event.process.workingDirectory,
            event.process.architecture,
            event.process.hashes?.sha256,
            event.process.ancestors.first?.name,
            event.process.ancestors.first?.executable,
            event.enrichments["ParentSignerType"],
            aiTool,
            event.process.session?.launchSource?.rawValue,
            tccDecision,
        ])

        // Secondary indexes. Duplicates are intentional: they are separate
        // durable b-tree keys. Fixed numeric timestamp/rowid portions receive
        // 16 bytes per listed key.
        let indexedStrings: [String?] = [
            event.id.uuidString,                         // PRIMARY KEY
            event.eventCategory.rawValue,               // category + composites
            event.eventCategory.rawValue,
            event.eventCategory.rawValue,
            event.eventCategory.rawValue,
            event.severity.rawValue,                    // severity + composites
            event.severity.rawValue,
            event.severity.rawValue,
            event.process.executable,                   // process/timestamp
            event.enrichments["mcp_server_name"],
            event.enrichments[TraceCorrelator.EnrichmentKey.traceId],
            event.enrichments["ai_tool_session_id"],
            event.process.userName.isEmpty ? nil : String(event.process.userId),
            aiTool,
            event.process.ancestors.first?.executable,
        ]
        addStrings(&logical, indexedStrings)
        add(&logical, Int64(indexedStrings.count) * 16)

        // FTS5 can materialize a token dictionary plus postings/doclist data.
        // Count four copies here; the shared WAL multiplier below makes this
        // an eightfold allowance for the source text.
        var ftsBytes: Int64 = 0
        addStrings(&ftsBytes, [
            event.process.name,
            event.process.executable,
            indexedCommandLine,
            event.file?.path,
            event.network?.destinationIp,
            event.tcc?.service,
            event.tcc?.client,
        ])
        add(
            &logical,
            SQLitePersistentStoreAdmission.saturatingMultiply(ftsBytes, by: 4)
        )

        return SQLitePersistentStoreAdmission.conservativeEncodedRowMutationBytes(
            logicalRepresentationBytes: logical,
            pageSizeBytes: pageSizeBytes,
            maximumLeafPageTouches: 20
        )
    }

    // MARK: - Payload truncation (v1.12.6)

    /// Result of the payload truncation pipeline.
    private struct TruncatedPayload {
        let event: Event
        let string: String
    }

    /// Apply structured truncation to an oversized event payload so the
    /// SQLite write fits inside `maxRawJsonBytes`. Returns a re-encoded
    /// JSON string plus the mutated `Event` so callers can observe the
    /// truncation markers (used in tests).
    ///
    /// Pipeline (cheapest → most aggressive):
    ///   1. Replace each `process.args` entry over `argTruncationThreshold`
    ///      bytes with `"<truncated:N bytes>"`. Drops the dominant 1MB
    ///      base64-arg case to a marker.
    ///   2. If still oversized, also collapse `process.commandLine` to a
    ///      marker (recovers events whose mass lives in the joined string
    ///      rather than per-arg).
    ///   3. As a last-resort fail-open, replace oversized `enrichments`
    ///      values with markers and RE-ENCODE (largest-first, stop as soon
    ///      as it fits). The result is always valid, decodable JSON — never
    ///      a byte-sliced string — so `queryEvents()` can still surface the
    ///      row instead of silently dropping it on a decode error.
    ///
    /// Always sets `payload.truncated = "true"` and
    /// `payload.original_bytes = "<N>"` on the resulting event so the FTS
    /// index, dashboard, and analytics consumers see the cap was hit.
    private func truncatePayload(
        sanitizedEvent: Event,
        originalBytes: Int,
        originalSHA256: String,
        maximumBytes: Int
    ) throws -> TruncatedPayload {
        let log = Logger(subsystem: "com.maccrab.storage", category: "event-store")
        var mutated = sanitizedEvent
        mutated.enrichments["payload.truncated"] = "true"
        mutated.enrichments["payload.original_bytes"] = String(originalBytes)
        mutated.enrichments["payload.original_sha256"] = originalSHA256

        // Pass 1: per-arg truncation.
        let originalArgs = sanitizedEvent.process.args
        let truncatedArgs: [String] = originalArgs.map { arg in
            let argBytes = arg.utf8.count
            if argBytes > Self.argTruncationThreshold {
                return "<truncated:\(argBytes) bytes>"
            }
            return arg
        }

        let argsChanged = zip(originalArgs, truncatedArgs).contains { $0 != $1 }
        if argsChanged {
            mutated = withProcess(
                event: mutated,
                rebuiltProcess: rebuildProcess(
                    sanitizedEvent.process,
                    commandLine: sanitizedEvent.process.commandLine,
                    args: truncatedArgs,
                    envVars: sanitizedEvent.process.envVars
                )
            )
        }

        if let encoded = try? journalEncoder.encode(mutated),
           encoded.count <= maximumBytes,
           let s = String(data: encoded, encoding: .utf8) {
            return TruncatedPayload(event: mutated, string: s)
        }

        // Pass 2: also collapse the joined commandLine.
        let originalCmd = sanitizedEvent.process.commandLine
        let cmdBytes = originalCmd.utf8.count
        let collapsedCmd = "<truncated:\(cmdBytes) bytes>"
        mutated = withProcess(
            event: mutated,
            rebuiltProcess: rebuildProcess(
                sanitizedEvent.process,
                commandLine: collapsedCmd,
                args: truncatedArgs,
                envVars: sanitizedEvent.process.envVars
            )
        )

        if let encoded = try? journalEncoder.encode(mutated),
           encoded.count <= maximumBytes,
           let s = String(data: encoded, encoding: .utf8) {
            return TruncatedPayload(event: mutated, string: s)
        }

        // Pass 3 (fail-open): structured enrichment truncation + re-encode.
        //
        // The earlier implementation byte-SLICED the encoded JSON string and
        // appended a tail marker. That produced SYNTACTICALLY INVALID JSON:
        // `queryEvents()` decodes raw_json into an `Event` and `catch { continue }`s
        // on failure, so every sliced row — and its truncation signal — was
        // silently dropped on READ, becoming permanently invisible to the
        // dashboard/analytics (a live audit found such rows in events.db).
        //
        // After Pass 1+2 collapsed `args` and `commandLine`, the residual mass
        // lives in oversized ENRICHMENT values (captured file content, agent
        // evidence, env blocks). Replace those with markers, cheapest-first
        // (largest value first, stop as soon as it fits), and re-encode:
        // `JSONEncoder` always emits valid JSON, so the row stays decodable and
        // the `payload.truncated` / `payload.original_bytes` markers survive.
        var stripped = mutated
        let bigEnrichmentKeys = stripped.enrichments
            .filter { $0.value.utf8.count > Self.argTruncationThreshold }
            .sorted {
                let left = $0.value.utf8.count
                let right = $1.value.utf8.count
                return left == right ? $0.key < $1.key : left > right
            }
            .map(\.key)
        for key in bigEnrichmentKeys {
            let n = stripped.enrichments[key]?.utf8.count ?? 0
            stripped.enrichments[key] = "<truncated:\(n) bytes>"
            if let encoded = try? journalEncoder.encode(stripped),
               encoded.count <= maximumBytes,
               let s = String(data: encoded, encoding: .utf8) {
                log.warning("Payload truncation fell through to enrichment-strip path for event \(sanitizedEvent.id.uuidString, privacy: .public) (\(originalBytes) bytes)")
                return TruncatedPayload(event: stripped, string: s)
            }
        }

        // Residual mass may live in any other Event domain: thousands of
        // individually-small args, signature chains/entitlements, ancestors,
        // env keys, paths, network/TCC strings, or rule-match arrays. Apply a
        // deterministic JSON-structure bound and decode it back into Event at
        // each pass. This preserves required Codable shape and makes the cap a
        // mathematical postcondition instead of a best effort.
        let passes: [(stringBytes: Int, arrayCount: Int, mapCount: Int)] = [
            (2_048, 64, 128),
            (512, 24, 64),
            (192, 8, 24),
            (64, 2, 8),
        ]
        for pass in passes {
            if let candidate = try? structurallyBoundEvent(
                stripped,
                maximumStringBytes: pass.stringBytes,
                maximumArrayCount: pass.arrayCount,
                maximumDynamicMapCount: pass.mapCount
            ),
               let encoded = try? journalEncoder.encode(candidate),
               encoded.count <= maximumBytes,
               let string = String(data: encoded, encoding: .utf8) {
                log.warning("Payload truncation used all-field bound for event \(sanitizedEvent.id.uuidString, privacy: .public) (\(originalBytes) bytes -> \(encoded.count))")
                return TruncatedPayload(event: candidate, string: string)
            }
        }

        // Fixed-shape last pass. It preserves immutable identity, numeric
        // process/session/audit identity, category/action/severity, payload
        // kind, and bounded rule attribution while eliminating every
        // unbounded collection. With the current Event schema this is under
        // 16 KiB, leaving wide margin below the 64-KiB journal ceiling.
        func clip(_ value: String, bytes: Int = 64) -> String {
            Self.boundIndexedText(value, maxBytes: bytes)
        }
        let source = stripped.process
        let minimalProcess = ProcessInfo(
            pid: source.pid,
            ppid: source.ppid,
            rpid: source.rpid,
            name: clip(source.name),
            executable: clip(source.executable, bytes: 256),
            commandLine: clip(source.commandLine, bytes: 256),
            args: source.args.prefix(2).map { clip($0, bytes: 128) },
            workingDirectory: clip(source.workingDirectory, bytes: 128),
            userId: source.userId,
            userName: clip(source.userName),
            groupId: source.groupId,
            startTime: source.startTime,
            exitCode: source.exitCode,
            codeSignature: source.codeSignature.map { signature in
                CodeSignatureInfo(
                    signerType: signature.signerType,
                    teamId: signature.teamId.map { clip($0) },
                    signingId: signature.signingId.map { clip($0) },
                    authorities: signature.authorities.prefix(2).map { clip($0) },
                    flags: signature.flags,
                    isNotarized: signature.isNotarized,
                    issuerChain: signature.issuerChain.map {
                        $0.prefix(2).map { clip($0) }
                    },
                    certHashes: signature.certHashes.map {
                        $0.prefix(2).map { clip($0) }
                    },
                    isAdhocSigned: signature.isAdhocSigned,
                    entitlements: signature.entitlements.map {
                        $0.prefix(2).map { clip($0) }
                    }
                )
            },
            ancestors: source.ancestors.prefix(2).map {
                ProcessAncestor(
                    pid: $0.pid,
                    executable: clip($0.executable, bytes: 128),
                    name: clip($0.name)
                )
            },
            architecture: source.architecture.map { clip($0) },
            isPlatformBinary: source.isPlatformBinary,
            hashes: source.hashes.map {
                ProcessHashes(
                    sha256: $0.sha256.map { clip($0) },
                    cdhash: $0.cdhash.map { clip($0) },
                    md5: $0.md5.map { clip($0) }
                )
            },
            session: source.session.map {
                SessionInfo(
                    sessionId: $0.sessionId,
                    tty: $0.tty.map { clip($0) },
                    loginUser: $0.loginUser.map { clip($0) },
                    sshRemoteIP: $0.sshRemoteIP.map { clip($0) },
                    launchSource: $0.launchSource
                )
            },
            envVars: nil,
            auditIdentity: source.auditIdentity
        )
        let minimalFile = stripped.file.map {
            FileInfo(
                path: clip($0.path, bytes: 256),
                name: clip($0.name),
                directory: clip($0.directory, bytes: 128),
                extension_: $0.extension_.map { clip($0) },
                size: $0.size,
                action: $0.action,
                sourcePath: $0.sourcePath.map { clip($0, bytes: 256) }
            )
        }
        let minimalNetwork = stripped.network.map {
            NetworkInfo(
                sourceIp: clip($0.sourceIp),
                sourcePort: $0.sourcePort,
                destinationIp: clip($0.destinationIp),
                destinationPort: $0.destinationPort,
                destinationHostname: $0.destinationHostname.map { clip($0) },
                direction: $0.direction,
                transport: clip($0.transport)
            )
        }
        let minimalTCC = stripped.tcc.map {
            TCCInfo(
                service: clip($0.service),
                client: clip($0.client),
                clientPath: clip($0.clientPath, bytes: 256),
                allowed: $0.allowed,
                authReason: clip($0.authReason)
            )
        }
        var minimalEnrichments: [String: String] = [:]
        for key in [
            "payload.truncated",
            "payload.original_bytes",
            "payload.original_sha256",
            "ai_tool_session_id",
            TraceCorrelator.EnrichmentKey.traceId,
            TraceCorrelator.EnrichmentKey.spanId,
            TraceCorrelator.EnrichmentKey.agentTool,
        ] {
            if let value = stripped.enrichments[key] {
                minimalEnrichments[key] = clip(value, bytes: 128)
            }
        }
        let minimal = Event(
            id: stripped.id,
            timestamp: stripped.timestamp,
            eventCategory: stripped.eventCategory,
            eventType: stripped.eventType,
            eventAction: clip(stripped.eventAction),
            process: minimalProcess,
            file: minimalFile,
            network: minimalNetwork,
            tcc: minimalTCC,
            enrichments: minimalEnrichments,
            severity: stripped.severity,
            ruleMatches: stripped.ruleMatches.prefix(8).map {
                RuleMatch(
                    ruleId: clip($0.ruleId),
                    ruleName: clip($0.ruleName, bytes: 128),
                    severity: $0.severity,
                    description: clip($0.description, bytes: 256),
                    mitreTechniques: $0.mitreTechniques.prefix(8).map { clip($0) },
                    tags: $0.tags.prefix(8).map { clip($0) },
                    suppressible: $0.suppressible
                )
            }
        )
        let minimalData = try journalEncoder.encode(minimal)
        guard minimalData.count <= maximumBytes,
              let minimalString = String(data: minimalData, encoding: .utf8) else {
            throw EventStoreError.encodingFailed(
                "fixed-shape bounded Event exceeds maxRawJsonBytes"
            )
        }
        return TruncatedPayload(event: minimal, string: minimalString)
    }

    private func structurallyBoundEvent(
        _ event: Event,
        maximumStringBytes: Int,
        maximumArrayCount: Int,
        maximumDynamicMapCount: Int
    ) throws -> Event {
        let data = try journalEncoder.encode(event)
        let object = try JSONSerialization.jsonObject(with: data)
        let dynamicMaps = Set(["enrichments", "envVars"])
        let markerKeys = Set([
            "payload.truncated",
            "payload.original_bytes",
            "payload.original_sha256",
        ])

        func bounded(_ value: Any, key: String?) -> Any {
            if let string = value as? String {
                return Self.boundIndexedText(
                    string,
                    maxBytes: maximumStringBytes
                )
            }
            if let array = value as? [Any] {
                return array.prefix(maximumArrayCount).map {
                    bounded($0, key: nil)
                }
            }
            if let dictionary = value as? [String: Any] {
                var keys = dictionary.keys.sorted()
                if let key, dynamicMaps.contains(key) {
                    let protected = keys.filter { markerKeys.contains($0) }
                    let ordinary = keys.filter {
                        !markerKeys.contains($0) && $0.utf8.count <= 256
                    }
                    keys = Array(
                        (protected + ordinary).prefix(maximumDynamicMapCount)
                    )
                }
                var output: [String: Any] = [:]
                output.reserveCapacity(keys.count)
                for childKey in keys {
                    if let child = dictionary[childKey] {
                        output[childKey] = bounded(child, key: childKey)
                    }
                }
                return output
            }
            return value
        }

        let boundedObject = bounded(object, key: nil)
        let boundedData = try JSONSerialization.data(
            withJSONObject: boundedObject,
            options: [.sortedKeys]
        )
        return try decoder.decode(Event.self, from: boundedData)
    }

    /// Rebuild a `ProcessInfo` with new `commandLine` and `args` fields,
    /// preserving every other field. Used by the truncation pipeline so
    /// downstream enrichments (codeSignature, ancestors, hashes, etc.)
    /// survive the per-arg rewrite.
    private func rebuildProcess(
        _ source: ProcessInfo,
        commandLine: String,
        args: [String],
        envVars: [String: String]?
    ) -> ProcessInfo {
        return ProcessInfo(
            pid: source.pid,
            ppid: source.ppid,
            rpid: source.rpid,
            name: source.name,
            executable: source.executable,
            commandLine: commandLine,
            args: args,
            workingDirectory: source.workingDirectory,
            userId: source.userId,
            userName: source.userName,
            groupId: source.groupId,
            startTime: source.startTime,
            exitCode: source.exitCode,
            codeSignature: source.codeSignature,
            ancestors: source.ancestors,
            architecture: source.architecture,
            isPlatformBinary: source.isPlatformBinary,
            hashes: source.hashes,
            session: source.session,
            envVars: envVars,
            auditIdentity: source.auditIdentity
        )
    }

    /// Rebuild an `Event` swapping in a different `ProcessInfo`. Preserves
    /// id/timestamp/category/type/action and copies enrichments + severity
    /// + ruleMatches through.
    private func withProcess(event: Event, rebuiltProcess: ProcessInfo) -> Event {
        return Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: rebuiltProcess,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: event.severity,
            ruleMatches: event.ruleMatches
        )
    }

    private struct JournalCategoryMetadata {
        var count = 0
        var minimum: TimeInterval?
        var maximum: TimeInterval?

        mutating func include(_ timestamp: TimeInterval) {
            count += 1
            minimum = minimum.map { min($0, timestamp) } ?? timestamp
            maximum = maximum.map { max($0, timestamp) } ?? timestamp
        }
    }

    private struct JournalBlockMetadata {
        let minimum: TimeInterval
        let maximum: TimeInterval
        let retainedUntil: TimeInterval
        let admissionBucket: Int64
        let byCategory: [EventCategory: JournalCategoryMetadata]
    }

    private struct VerifiedJournalSummary {
        let blockID: Int64
        let eventCount: Int
        let metadata: JournalBlockMetadata
    }

    private struct AuthenticatedCategoryMetadata: Codable {
        let category: String
        let count: Int
        let minimum: TimeInterval?
        let maximum: TimeInterval?
    }

    private struct AuthenticatedJournalMetadata: Codable {
        let version: Int
        let minimum: TimeInterval
        let maximum: TimeInterval
        let retainedUntil: TimeInterval
        let admissionBucket: Int64
        let eventCount: Int
        let rawBytes: Int
        let codec: Int
        let categories: [AuthenticatedCategoryMetadata]
    }

    private static func journalMetadataDigest(
        metadata: JournalBlockMetadata,
        eventCount: Int,
        roster: Data,
        sourceIdentityRoster: Data,
        rawBytes: Int,
        codec: Int,
        payloadDigest: Data
    ) throws -> Data {
        let value = AuthenticatedJournalMetadata(
            version: 2,
            minimum: metadata.minimum,
            maximum: metadata.maximum,
            retainedUntil: metadata.retainedUntil,
            admissionBucket: metadata.admissionBucket,
            eventCount: eventCount,
            rawBytes: rawBytes,
            codec: codec,
            categories: EventCategory.allCases.map { category in
                let stats = metadata.byCategory[category]
                    ?? JournalCategoryMetadata()
                return AuthenticatedCategoryMetadata(
                    category: category.rawValue,
                    count: stats.count,
                    minimum: stats.minimum,
                    maximum: stats.maximum
                )
            }
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(value)
        var hasher = SHA256()
        hasher.update(data: Data("MacCrab.EventJournal.Metadata.v2\u{0}".utf8))
        hasher.update(data: encoded)
        hasher.update(data: roster)
        hasher.update(data: sourceIdentityRoster)
        hasher.update(data: payloadDigest)
        return Data(hasher.finalize())
    }

    private static func uuidData(_ id: UUID) -> Data {
        var bytes = id.uuid
        return withUnsafeBytes(of: &bytes) { Data($0) }
    }

    private static func projectionDispositionData(
        _ values: [JournalProjectionDisposition]
    ) -> Data {
        var data = Data(repeating: 0, count: (values.count * 3 + 7) / 8)
        for (ordinal, value) in values.enumerated() {
            let bitOffset = ordinal * 3
            for bit in 0..<3 where (value.rawValue & (1 << bit)) != 0 {
                let absolute = bitOffset + bit
                data[absolute >> 3] |= UInt8(1 << (absolute & 7))
            }
        }
        return data
    }

    private static func projectionDispositions(
        from data: Data,
        eventCount: Int
    ) throws -> [JournalProjectionDisposition] {
        let expectedBytes = (eventCount * 3 + 7) / 8
        guard eventCount > 0, data.count == expectedBytes else {
            throw EventStoreError.decodingFailed(
                "journal projection disposition length is invalid"
            )
        }
        if let last = data.last, eventCount * 3 % 8 != 0 {
            let used = eventCount * 3 % 8
            let tailMask = UInt8.max << UInt8(used)
            guard last & tailMask == 0 else {
                throw EventStoreError.decodingFailed(
                    "journal projection disposition tail bits are nonzero"
                )
            }
        }
        var values: [JournalProjectionDisposition] = []
        values.reserveCapacity(eventCount)
        for ordinal in 0..<eventCount {
            let bitOffset = ordinal * 3
            var raw: UInt8 = 0
            for bit in 0..<3 {
                let absolute = bitOffset + bit
                if data[absolute >> 3] & UInt8(1 << (absolute & 7)) != 0 {
                    raw |= UInt8(1 << bit)
                }
            }
            guard let value = JournalProjectionDisposition(rawValue: raw) else {
                throw EventStoreError.decodingFailed(
                    "journal projection disposition state is invalid"
                )
            }
            values.append(value)
        }
        return values
    }

    private static func uuid(
        from bytes: UnsafeRawBufferPointer,
        offset: Int
    ) throws -> UUID {
        guard offset >= 0, offset <= bytes.count - 16 else {
            throw EventStoreError.decodingFailed(
                "journal UUID roster contains a non-16-byte identifier"
            )
        }
        return UUID(uuid: (
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
            bytes[offset + 8], bytes[offset + 9], bytes[offset + 10], bytes[offset + 11],
            bytes[offset + 12], bytes[offset + 13], bytes[offset + 14], bytes[offset + 15]
        ))
    }

    private func hasJournalSchema() throws -> Bool {
        let statement = try prepare(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_journal_blocks' LIMIT 1"
        )
        defer { sqlite3_finalize(statement) }
        let rc = sqlite3_step(statement)
        if rc == SQLITE_ROW { return true }
        if rc == SQLITE_DONE { return false }
        throw EventStoreError.stepFailed("event journal schema lookup failed")
    }

    private func validateProjectionIntegrity(
        blockID: Int64,
        admissionBucket: Int64,
        eventCount: Int,
        roster: Data,
        dispositionData: Data,
        exactEvents: [Event],
        poisonByOrdinal: [Int: [EventJournalPoisonRecord]]
    ) throws {
        guard exactEvents.count == eventCount else {
            throw EventStoreError.decodingFailed(
                "journal block \(blockID) exact/projection cardinality differs"
            )
        }
        let dispositions = try Self.projectionDispositions(
            from: dispositionData,
            eventCount: eventCount
        )
        var materialized = 0
        var quota = 0
        var replaced = 0
        var physical = 0
        var external = 0
        var migration = 0
        for disposition in dispositions {
            switch disposition {
            case .materialized: materialized += 1
            case .quota: quota += 1
            case .replaced: replaced += 1
            case .physical: physical += 1
            case .externalDeletion: external += 1
            case .migrationSplit: migration += 1
            }
        }

        let coverage = try prepare(
            """
            SELECT bucket_start, considered_count, materialized_count,
                   materialized_bytes, omitted_quota_count,
                   omitted_replaced_count, omitted_physical_count,
                   omitted_external_count, omitted_migration_count,
                   pending_count, replacement_total
            FROM event_projection_block_coverage WHERE block_id = ?1
            """
        )
        sqlite3_bind_int64(coverage, 1, blockID)
        guard sqlite3_step(coverage) == SQLITE_ROW else {
            sqlite3_finalize(coverage)
            throw EventStoreError.decodingFailed(
                "journal block \(blockID) is missing projection coverage"
            )
        }
        let storedBucket = sqlite3_column_int64(coverage, 0)
        let storedConsidered = Int(sqlite3_column_int64(coverage, 1))
        let storedMaterialized = Int(sqlite3_column_int64(coverage, 2))
        let storedMaterializedBytes = sqlite3_column_int64(coverage, 3)
        let storedQuota = Int(sqlite3_column_int64(coverage, 4))
        let storedReplaced = Int(sqlite3_column_int64(coverage, 5))
        let storedPhysical = Int(sqlite3_column_int64(coverage, 6))
        let storedExternal = Int(sqlite3_column_int64(coverage, 7))
        let storedMigration = Int(sqlite3_column_int64(coverage, 8))
        let storedPending = Int(sqlite3_column_int64(coverage, 9))
        let storedReplacements = Int(sqlite3_column_int64(coverage, 10))
        guard sqlite3_step(coverage) == SQLITE_DONE else {
            sqlite3_finalize(coverage)
            throw EventStoreError.decodingFailed(
                "journal block \(blockID) has duplicate projection coverage"
            )
        }
        sqlite3_finalize(coverage)
        guard storedBucket == admissionBucket,
              storedConsidered == eventCount,
              storedMaterialized == materialized,
              storedQuota == quota,
              storedReplaced == replaced,
              storedPhysical == physical,
              storedExternal == external,
              storedMigration == migration,
              storedPending == 0,
              storedReplacements == replaced else {
            throw EventStoreError.decodingFailed(
                "journal block \(blockID) projection coverage does not match its disposition vector"
            )
        }

        let typedColumns = Self.legacyTypedEventColumns.joined(separator: ", ")
        let projection = try prepare(
            "SELECT rowid, \(typedColumns), journal_ordinal, projection_estimated_bytes, projection_rank, projection_bucket, projection_reason FROM events WHERE journal_block_id = ?1 ORDER BY journal_ordinal ASC"
        )
        defer { sqlite3_finalize(projection) }
        sqlite3_bind_int64(projection, 1, blockID)
        var seenOrdinals = Set<Int>()
        var materializedBytes: Int64 = 0
        while true {
            let rc = sqlite3_step(projection)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.decodingFailed(
                    "journal block \(blockID) has an invalid projection row"
                )
            }
            let row = try readLegacyJournalRow(projection)
            let metadataOffset = Int32(
                Self.legacyTypedEventColumns.count + 1
            )
            let ordinal = Int(sqlite3_column_int64(
                projection, metadataOffset
            ))
            let bytes = sqlite3_column_int64(
                projection, metadataOffset + 1
            )
            let rank = sqlite3_column_int(
                projection, metadataOffset + 2
            )
            let bucket = sqlite3_column_int64(
                projection, metadataOffset + 3
            )
            let reason = sqlite3_column_int(
                projection, metadataOffset + 4
            )
            guard ordinal >= 0, ordinal < eventCount,
                  bytes >= 0,
                  row.identityStorageValid,
                  seenOrdinals.insert(ordinal).inserted,
                  dispositions[ordinal] == .materialized,
                  poisonByOrdinal[ordinal] == nil else {
                throw EventStoreError.decodingFailed(
                    "journal block \(blockID) projection row/disposition mismatch"
                )
            }
            let rosterID = try roster.withUnsafeBytes { rosterBytes in
                try Self.uuid(from: rosterBytes, offset: ordinal * 16)
            }
            guard row.idBytes == Data(rosterID.uuidString.utf8) else {
                throw EventStoreError.decodingFailed(
                    "journal block \(blockID) projection UUID/ordinal mismatch"
                )
            }
            let expected = try preparePersistedEvent(exactEvents[ordinal])
            let expectedValues = expectedLegacyTypedValues(
                for: expected.projectionEvent,
                preservingRaw: .text(expected.projectionJSON)
            )
            guard row.typedValues == expectedValues,
                  bytes == Int64(Self.estimatedProjectionBytes(expected)),
                  rank == Self.projectionRank(for: exactEvents[ordinal]),
                  bucket == admissionBucket,
                  reason == Self.projectionReason(
                    for: exactEvents[ordinal]
                  ).rawValue else {
                throw EventStoreError.decodingFailed(
                    "journal block \(blockID) projection content does not equal its terminal-preferred canonical Event"
                )
            }
            materializedBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                materializedBytes,
                bytes
            )
        }
        guard seenOrdinals.count == materialized,
              materializedBytes == storedMaterializedBytes else {
            throw EventStoreError.decodingFailed(
                "journal block \(blockID) materialized projection accounting mismatch"
            )
        }
    }

    private func validateGlobalProjectionCoverage() throws {
        let mismatch = try prepare(
            """
            WITH block_totals AS (
                SELECT bucket_start,
                       SUM(considered_count) AS considered_count,
                       SUM(materialized_count) AS materialized_count,
                       SUM(materialized_bytes) AS materialized_bytes,
                       SUM(omitted_quota_count) AS omitted_quota_count,
                       SUM(omitted_replaced_count) AS omitted_replaced_count,
                       SUM(omitted_physical_count) AS omitted_physical_count,
                       SUM(omitted_external_count) AS omitted_external_count,
                       SUM(omitted_migration_count) AS omitted_migration_count,
                       SUM(pending_count) AS pending_count,
                       SUM(replacement_total) AS replacement_total
                FROM event_projection_block_coverage GROUP BY bucket_start
            )
            SELECT 1
            FROM event_projection_coverage AS g
            LEFT JOIN block_totals AS b USING(bucket_start)
            WHERE b.bucket_start IS NULL
               OR g.considered_count != b.considered_count
               OR g.materialized_count != b.materialized_count
               OR g.materialized_bytes != b.materialized_bytes
               OR g.omitted_quota_count != b.omitted_quota_count
               OR g.omitted_replaced_count != b.omitted_replaced_count
               OR g.omitted_physical_count != b.omitted_physical_count
               OR g.omitted_external_count != b.omitted_external_count
               OR g.omitted_migration_count != b.omitted_migration_count
               OR g.pending_count != b.pending_count
               OR g.replacement_total != b.replacement_total
            UNION ALL
            SELECT 1 FROM block_totals AS b
            LEFT JOIN event_projection_coverage AS g USING(bucket_start)
            WHERE g.bucket_start IS NULL
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(mismatch) }
        let rc = sqlite3_step(mismatch)
        guard rc == SQLITE_DONE else {
            if rc == SQLITE_ROW {
                throw EventStoreError.decodingFailed(
                    "global projection coverage does not equal retained block contributions"
                )
            }
            throw EventStoreError.stepFailed(
                "global projection coverage validation failed"
            )
        }
    }

    /// FTS5 external-content integrity is stronger than comparing row counts:
    /// with iArg=1 the vendored implementation reconciles every content-table
    /// row and token against the index. A missing posting among otherwise
    /// healthy results must never let `search` return a plausible partial set.
    /// Run this only at the bounded pre-producer finalization boundary.
    private func validateFTSExternalContentIntegrity() throws {
        // Vendored FTS5's rank=1 integrity command tokenizes and reconciles
        // external content without changing any shadow table. Serialize it
        // against a cross-process writer, but do not apply a fictitious growth
        // admission that could make a healthy near-cap store fail every reopen.
        guard let db else {
            throw EventStoreError.stepFailed(
                "FTS integrity validation has no database handle"
            )
        }
        guard sqlite3_get_autocommit(db) != 0 else {
            throw EventStoreError.stepFailed(
                "FTS integrity validation entered inside a transaction"
            )
        }
        try Self.exec(db, "BEGIN IMMEDIATE TRANSACTION")
        do {
            let statement = try prepare(
                "INSERT INTO events_fts(events_fts, rank) VALUES('integrity-check', 1)"
            )
            let rc = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard rc == SQLITE_DONE else {
                throw EventStoreError.decodingFailed(
                    "event projection FTS external-content integrity check failed"
                )
            }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    /// Rebuild the exact UUID locator from append-local block rosters. A bad
    /// roster, duplicate UUID, or count mismatch is corruption, never a reason
    /// to silently omit evidence. The ceiling bounds hostile/corrupt startup
    /// allocation while covering a sustained 1,274/s fifteen-minute epoch.
    // MARK: - Journal-index refresh cost (v1.21.6-rc.45)
    //
    // Measured on an installed host: with the dashboard window open, its 5s
    // poll cost MORE than five seconds of CPU, so the app never left this path.
    // All 33 microstackshots in the OS-generated cpu_resource.diag rooted at
    // `exactEventsSnapshot`, descending into JSONDecoder -> Event.init(from:).
    // One `fs_usage` sample caught 52,188 preads in 3s, touching 9,663 distinct
    // pages at a 5.4x re-read factor to serve a request for the newest 200 rows.
    //
    // The cause was that the cheap append-only refresh in `rebuildJournalIndex`
    // required `minimumBlockID == journalIndexedMinimumBlockID`, so ANY journal
    // expiry forced a full rebuild — and expiry is continuous under a 15-minute
    // retention floor. `compactJournalIndex(below:)` now evicts the expired
    // entries and the append scan continues.
    //
    // This telemetry stays because the cost was previously invisible — no
    // counter, no log, nothing — and because the rebuild-to-append RATIO is the
    // signature of the defect recurring. A rebuild that takes seconds must say
    // so, and it must report which path it took rather than assert a cause.

    /// Full rebuilds are expected occasionally; one that takes longer than this
    /// is a performance fault worth naming.
    static let journalIndexSlowRefreshNanoseconds: UInt64 = 250_000_000
    private var journalIndexRefreshesTotal: UInt64 = 0
    private var journalIndexSlowRefreshesTotal: UInt64 = 0
    /// Full rebuilds vs cheap append refreshes. This ratio IS the defect
    /// signature: before rc.45 a reader on an expiring journal took the full
    /// rebuild essentially every time, and nothing measured it.
    private var journalIndexFullRebuildsTotal: UInt64 = 0
    private var journalIndexAppendRefreshesTotal: UInt64 = 0
    private var journalIndexLastRefreshNanoseconds: UInt64 = 0
    private var journalIndexLastSlowLogUptimeNanoseconds: UInt64 = 0
    private var journalIndexStageNanoseconds: [String: UInt64] = [:]
    private var journalIndexStagesComplete = false

    /// Refresh cost, for the heartbeat and for tests.
    public func journalIndexRefreshDiagnostics() -> (
        refreshes: UInt64, slowRefreshes: UInt64, lastNanoseconds: UInt64,
        fullRebuilds: UInt64, appendRefreshes: UInt64,
        stagesNanoseconds: [String: UInt64], stagesComplete: Bool
    ) {
        (
            journalIndexRefreshesTotal,
            journalIndexSlowRefreshesTotal,
            journalIndexLastRefreshNanoseconds,
            journalIndexFullRebuildsTotal,
            journalIndexAppendRefreshesTotal,
            journalIndexStageNanoseconds,
            journalIndexStagesComplete
        )
    }

    private func recordJournalIndexStage(_ stage: String, started: UInt64) {
        let elapsed = DispatchTime.now().uptimeNanoseconds &- started
        let sum = journalIndexStageNanoseconds[stage, default: 0].addingReportingOverflow(elapsed)
        journalIndexStageNanoseconds[stage] = sum.overflow ? .max : sum.partialValue
    }

    private func ensureJournalIndex() throws {
        try checkReadOnlyRetirement()
        // rc.43: any throw out of the rebuild INVALIDATES the in-memory index.
        // The chunked scan populates journalBaseLocations/journalDeltaLocations
        // incrementally, so a mid-rebuild failure (a torn concurrent-append
        // scan, an integrity throw) can leave them partially filled with
        // journalIndexLoaded still false. Left as-is the next call would
        // append-refresh onto that partial state and trip the duplicate-UUID
        // guard forever. Forcing journalIndexLoaded=false and clearing the
        // partial locators guarantees the next attempt is a clean full rebuild.
        let refreshStartedAt = DispatchTime.now().uptimeNanoseconds
        defer { recordJournalIndexRefresh(startedAt: refreshStartedAt) }
        do {
            try rebuildJournalIndex()
        } catch {
            journalIndexLoaded = false
            journalIndexTopologyGeneration = nil
            journalIndexedBlockCount = 0
            journalIndexedMinimumBlockID = nil
            journalIndexedMaximumBlockID = nil
            journalBaseLocations.removeAll(keepingCapacity: false)
            journalDeltaLocations.removeAll()
            journalIndexedLocationCount = 0
            throw error
        }
    }

    /// rc.43 test seam: when set, the next `rebuildJournalIndex` throws AFTER
    /// it has begun populating the in-memory locators, simulating a torn scan
    /// (e.g. a concurrent-append count mismatch). The retry must then perform a
    /// clean full rebuild rather than tripping the duplicate-UUID guard.
    var journalRebuildFailAfterPartialForTesting = false

    private func recordJournalIndexRefresh(startedAt: UInt64) {
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = now >= startedAt ? now &- startedAt : 0
        journalIndexRefreshesTotal &+= 1
        journalIndexLastRefreshNanoseconds = elapsed
        guard elapsed >= Self.journalIndexSlowRefreshNanoseconds else { return }
        journalIndexSlowRefreshesTotal &+= 1
        // Rate-limit to once per 30s: under the pathological case this fires on
        // every read, and a log line per read would itself become the problem.
        let sinceLastLog = now >= journalIndexLastSlowLogUptimeNanoseconds
            ? now &- journalIndexLastSlowLogUptimeNanoseconds
            : 0
        guard journalIndexLastSlowLogUptimeNanoseconds == 0
                || sinceLastLog >= 30_000_000_000 else { return }
        journalIndexLastSlowLogUptimeNanoseconds = now
        Logger(subsystem: "com.maccrab.storage", category: "event-store")
            .notice(
                "event journal index refresh took \(elapsed / 1_000_000, privacy: .public) ms (\(self.journalIndexSlowRefreshesTotal, privacy: .public) slow of \(self.journalIndexRefreshesTotal, privacy: .public) refreshes; \(self.journalIndexFullRebuildsTotal, privacy: .public) full rebuilds, \(self.journalIndexAppendRefreshesTotal, privacy: .public) append refreshes). A reader polling faster than this cannot keep up. One slow refresh at startup is the initial build; rebuilds climbing WITH append refreshes flat means expiry is again forcing full rebuilds."
            )
    }

    /// Evict every indexed entry below `minimum`, so a journal expiry no longer
    /// forces a full index rebuild.
    ///
    /// v1.21.6-rc.45. The append-only refresh used to require
    /// `minimumBlockID == journalIndexedMinimumBlockID`, so ANY expiry sent the
    /// reader down the full-rebuild path — and under a 15-minute retention floor
    /// expiry is continuous. Measured on an installed host: the dashboard's 5s
    /// poll cost more than five seconds of CPU, 52,188 preads in 3 s, 9,663
    /// distinct pages at a 5.4x re-read factor, to serve a request for the
    /// newest 200 rows. Every one of the OS-captured microstackshots rooted in
    /// this rebuild.
    ///
    /// The writer already had this compaction (in `expireJournalBlocks`, keyed
    /// on the tombstones it created); a read-only handle could not reach it,
    /// because it learns about expiry only as a raised `journal_min_block_id`.
    /// This is the same eviction keyed on that threshold instead.
    ///
    /// `journalBaseLocations` is sorted by UUID, not by block id, so expired
    /// entries are scattered rather than a contiguous prefix — hence a filter
    /// rather than a range drop. `removeAll(where:)` preserves relative order,
    /// so the UUID sort survives and the binary search stays valid.
    ///
    /// Returns false when the caller must fall back to a full rebuild.
    private func compactJournalIndex(below minimum: Int64) -> Bool {
        // An overflowed index only knows its surplus through a bloom filter,
        // which cannot un-insert. Evicting under it would leave the filter
        // claiming ids the index no longer holds, so refuse and rebuild.
        guard !journalIndexOverflowed else { return false }

        journalBaseLocations.removeAll { $0.location.blockID < minimum }
        journalDeltaLocations.removeBlocks(below: minimum)
        verifiedJournalSummaries.removeAll { $0.blockID < minimum }
        journalExpiredBlockTombstones.removeAll { $0 < minimum }

        // Recompute every derived value from the surviving set, exactly as the
        // writer-side compaction does — never by subtracting an assumed delta.
        journalIndexedLocationCount = journalBaseLocations.count
            + journalDeltaLocations.count
        journalVerifiedBlocks = verifiedJournalSummaries.count
        journalIndexedBlockCount = Int64(verifiedJournalSummaries.count)
        journalIndexedMinimumBlockID = verifiedJournalSummaries.first?.blockID
        journalIndexedMaximumBlockID = verifiedJournalSummaries.last?.blockID

        // These cache positions index into the array we just rewrote.
        journalExpirySummaryCursor = 0
        journalExpirySummaryCutoff = nil
        return true
    }

    private func rebuildJournalIndex() throws {
        guard try hasJournalSchema() else {
            journalBaseLocations.removeAll(keepingCapacity: false)
            journalDeltaLocations.removeAll()
            journalIndexedLocationCount = 0
            journalOverflowBloom = JournalBloom()
            journalOverflowFirstBlockID = nil
            journalIndexOverflowed = false
            journalExpiredBlockTombstones.removeAll(keepingCapacity: false)
            journalExpirySummaryCursor = 0
            journalExpirySummaryCutoff = nil
            journalVerifiedBlocks = 0
            journalVerifiedTerminalRevisions = 0
            journalIntegrityFailures = 0
            verifiedJournalSummaries.removeAll(keepingCapacity: false)
            journalIndexLoaded = true
            journalIndexTopologyGeneration = nil
            journalIndexedBlockCount = 0
            journalIndexedMinimumBlockID = nil
            journalIndexedMaximumBlockID = nil
            return
        }
        let topology = try prepare(
            """
            SELECT journal_topology_generation, journal_block_count,
                   journal_min_block_id, journal_max_block_id
            FROM event_storage_state WHERE singleton = 1
            """
        )
        guard sqlite3_step(topology) == SQLITE_ROW else {
            sqlite3_finalize(topology)
            throw EventStoreError.decodingFailed(
                "event journal topology state is unavailable"
            )
        }
        let topologyGeneration = sqlite3_column_int64(topology, 0)
        let blockCount = sqlite3_column_int64(topology, 1)
        let minimumBlockID = sqlite3_column_type(topology, 2) == SQLITE_NULL
            ? nil : sqlite3_column_int64(topology, 2)
        let maximumBlockID = sqlite3_column_type(topology, 3) == SQLITE_NULL
            ? nil : sqlite3_column_int64(topology, 3)
        guard topologyGeneration >= 0, blockCount >= 0,
              (blockCount == 0
                && minimumBlockID == nil && maximumBlockID == nil)
                || (blockCount > 0
                    && (minimumBlockID ?? 0) > 0
                    && (maximumBlockID ?? 0) >= (minimumBlockID ?? 1)),
              sqlite3_step(topology) == SQLITE_DONE else {
            sqlite3_finalize(topology)
            throw EventStoreError.decodingFailed(
                "event journal topology state is corrupt"
            )
        }
        sqlite3_finalize(topology)
        if journalIndexLoaded,
           journalIndexTopologyGeneration == topologyGeneration {
            return
        }
        // v1.21.6-rc.45: tolerate expiry.
        //
        // This used to require `minimumBlockID == journalIndexedMinimumBlockID`
        // AND judge appendability by the NET `blockCount`. Both fail the moment
        // the journal expires anything: the net count can be flat while the tail
        // grew, and the minimum advances on every expiry. Under a 15-minute
        // retention floor that meant a full rebuild on essentially every read.
        //
        // Now an advanced minimum is handled by evicting the expired entries
        // (`compactJournalIndex(below:)`) and continuing with the append scan.
        // Appendability is judged by the tail advancing, which is the property
        // the scan actually depends on — `scanLowerBound` is
        // `journalIndexedMaximumBlockID`. The reconciliation below still holds
        // because the compaction recomputes `journalIndexedBlockCount` from the
        // surviving blocks, so `blockCount - journalIndexedBlockCount` is
        // exactly the number of appended blocks the scan will see.
        var appendOnlyRefresh = journalIndexLoaded
            && journalIndexedBlockCount > 0
            && !journalIndexOverflowed
            && (minimumBlockID ?? 0) >= (journalIndexedMinimumBlockID ?? 0)
            && (maximumBlockID ?? 0) > (journalIndexedMaximumBlockID ?? 0)
        if appendOnlyRefresh,
           let minimumBlockID,
           minimumBlockID > (journalIndexedMinimumBlockID ?? 0) {
            // Expiry happened alongside the appends. Evict, then continue; if
            // the index cannot be compacted safely, fall back to a full rebuild.
            if !compactJournalIndex(below: minimumBlockID) {
                appendOnlyRefresh = false
            } else if journalIndexedBlockCount == 0 {
                // Everything previously indexed expired — there is no surviving
                // base to append onto, so rebuild rather than scan from a
                // lower bound that no longer exists.
                appendOnlyRefresh = false
            }
        }
        if !appendOnlyRefresh {
            journalBaseLocations.removeAll(keepingCapacity: false)
            journalDeltaLocations.removeAll()
            journalIndexedLocationCount = 0
            journalOverflowBloom = JournalBloom()
            journalOverflowFirstBlockID = nil
            journalIndexOverflowed = false
            journalExpiredBlockTombstones.removeAll(keepingCapacity: false)
            journalExpirySummaryCursor = 0
            journalExpirySummaryCutoff = nil
            journalVerifiedBlocks = 0
            journalVerifiedTerminalRevisions = 0
            journalIntegrityFailures = 0
            verifiedJournalSummaries.removeAll(keepingCapacity: false)
        }
        if appendOnlyRefresh {
            journalIndexAppendRefreshesTotal &+= 1
        } else {
            journalIndexFullRebuildsTotal &+= 1
        }
        let maximumIndexEvents = Self.journalInMemoryLocationLimit
        journalIndexStageNanoseconds = [:]
        journalIndexStagesComplete = false
        if !appendOnlyRefresh {
            let countStatement = try prepare(
                "SELECT COALESCE(SUM(event_count), 0) FROM event_journal_blocks"
            )
            guard sqlite3_step(countStatement) == SQLITE_ROW else {
                sqlite3_finalize(countStatement)
                throw EventStoreError.stepFailed(
                    "event journal retained-count scan failed"
                )
            }
            let retainedCount = sqlite3_column_int64(countStatement, 0)
            sqlite3_finalize(countStatement)
            journalBaseLocations.reserveCapacity(
                min(maximumIndexEvents, max(0, Int(retainedCount)))
            )
        }
        let scanLowerBound = appendOnlyRefresh
            ? journalIndexedMaximumBlockID : nil
        // rc.41: CHUNKED scan, verification outside any open statement.
        //
        // This loop used to run `loadJournalBlock` / `loadExactJournalBlock`
        // (nested SELECTs + full payload decode + SHA256) per row WHILE STEPPING
        // one scan statement over every retained block. In autocommit an
        // implicit read transaction lasts for the statement's whole lifetime,
        // so the WAL read-mark was held for the entire multi-minute
        // verification even with no BEGIN in sight — the same pin the explicit
        // dashboard transaction had, in a different coat. The scan now steps a
        // bounded batch of row-local data, FINALIZES the statement (releasing
        // the read-mark), and only then verifies that batch; between batches
        // the writer can checkpoint. A writer landing a topology change across
        // batches is caught by the scanned-count guard below and by the
        // caller's in-transaction generation recheck, which retries.
        struct ScannedJournalRow {
            let blockID: Int64
            let storedSummary: JournalBlockMetadata
            let count: Int
            let admissionBucket: Int64
            let roster: Data
            let dispositionData: Data
        }
        var scannedBlocks: Int64 = 0
        var scanCursor: Int64? = scanLowerBound
        scanLoop: while true {
            var batch: [ScannedJournalRow] = []
            batch.reserveCapacity(Self.journalScanBatchBlocks)
            do {
                let stageStarted = DispatchTime.now().uptimeNanoseconds
                defer { recordJournalIndexStage("metadata_scan", started: stageStarted) }
                let statement = try prepare(
                    """
                    SELECT block_id, min_timestamp, max_timestamp, retained_until,
                           admission_bucket, event_count,
                           process_count, process_min_timestamp, process_max_timestamp,
                           file_count, file_min_timestamp, file_max_timestamp,
                           network_count, network_min_timestamp, network_max_timestamp,
                           authentication_count, authentication_min_timestamp, authentication_max_timestamp,
                           tcc_count, tcc_min_timestamp, tcc_max_timestamp,
                           registry_count, registry_min_timestamp, registry_max_timestamp,
                           event_ids, source_identity_sha256s,
                           projection_dispositions,
                           projection_dispositions_sha256,
                           raw_bytes, codec, sha256, metadata_sha256
                    FROM event_journal_blocks
                    WHERE (?1 IS NULL OR block_id > ?1)
                      AND (?3 IS NULL OR block_id <= ?3)
                    ORDER BY block_id ASC
                    LIMIT ?2
                    """
                )
                defer { sqlite3_finalize(statement) }
                if let scanCursor {
                    sqlite3_bind_int64(statement, 1, scanCursor)
                } else {
                    sqlite3_bind_null(statement, 1)
                }
                sqlite3_bind_int64(statement, 2, Int64(Self.journalScanBatchBlocks))
                // rc.43: cap the chunked scan at the block-id the topology read
                // reported. Without snapshot isolation between batches a writer
                // that APPENDS mid-scan would otherwise be pulled in, making the
                // final scanned-count disagree with the topology, aborting the
                // pass with the append-only index only PARTIALLY populated — and
                // the next retry re-inserts the same entries and trips the
                // duplicate-UUID guard ("event journal contains a duplicate UUID
                // roster entry"). Bounding the scan to blocks that existed at
                // topology-read time makes concurrent appends invisible to this
                // pass; the very next read observes the new generation and
                // append-refreshes them.
                if let maximumBlockID {
                    sqlite3_bind_int64(statement, 3, maximumBlockID)
                } else {
                    sqlite3_bind_null(statement, 3)
                }
                while true {
                    let rc = sqlite3_step(statement)
                    if rc == SQLITE_DONE { break }
                    guard rc == SQLITE_ROW else {
                        throw EventStoreError.stepFailed(
                            "event journal UUID roster scan failed"
                        )
                    }
                    let blockID = sqlite3_column_int64(statement, 0)
                    scannedBlocks += 1
                    guard blockID > 0,
                          blockID <= Self.maximumPackedJournalBlockID else {
                        throw EventStoreError.decodingFailed(
                            "event journal block id is outside the packed locator range"
                        )
                    }
                    let minimum = sqlite3_column_double(statement, 1)
                    let maximum = sqlite3_column_double(statement, 2)
                    let retainedUntil = sqlite3_column_double(statement, 3)
                    let admissionBucket = sqlite3_column_int64(statement, 4)
                    let count = Int(sqlite3_column_int(statement, 5))
                    var categoryMetadata: [EventCategory: JournalCategoryMetadata] = [:]
                    var categoryColumn: Int32 = 6
                    var categoryTotal = 0
                    for category in EventCategory.allCases {
                        let categoryCount = Int(
                            sqlite3_column_int(statement, categoryColumn)
                        )
                        let minimumType = sqlite3_column_type(
                            statement, categoryColumn + 1
                        )
                        let maximumType = sqlite3_column_type(
                            statement, categoryColumn + 2
                        )
                        let categoryMinimum = minimumType == SQLITE_NULL
                            ? nil : sqlite3_column_double(statement, categoryColumn + 1)
                        let categoryMaximum = maximumType == SQLITE_NULL
                            ? nil : sqlite3_column_double(statement, categoryColumn + 2)
                        guard categoryCount >= 0,
                              (categoryCount == 0)
                                == (categoryMinimum == nil && categoryMaximum == nil),
                              categoryMinimum?.isFinite ?? true,
                              categoryMaximum?.isFinite ?? true,
                              categoryMinimum.map { low in
                                  categoryMaximum.map { low <= $0 } ?? false
                              } ?? true else {
                            throw EventStoreError.decodingFailed(
                                "event journal block \(blockID) has invalid category metadata"
                            )
                        }
                        categoryTotal += categoryCount
                        categoryMetadata[category] = JournalCategoryMetadata(
                            count: categoryCount,
                            minimum: categoryMinimum,
                            maximum: categoryMaximum
                        )
                        categoryColumn += 3
                    }
                    let byteCount = Int(sqlite3_column_bytes(statement, 24))
                    let sourceIdentityByteCount = Int(
                        sqlite3_column_bytes(statement, 25)
                    )
                    let dispositionByteCount = Int(
                        sqlite3_column_bytes(statement, 26)
                    )
                    let dispositionDigestCount = Int(
                        sqlite3_column_bytes(statement, 27)
                    )
                    let rawBytes = Int(sqlite3_column_int64(statement, 28))
                    let codec = Int(sqlite3_column_int(statement, 29))
                    let payloadDigestCount = Int(sqlite3_column_bytes(statement, 30))
                    let metadataDigestCount = Int(sqlite3_column_bytes(statement, 31))
                    guard count > 0,
                          count <= EventJournalCodec.maximumEventsPerBlock,
                          categoryTotal == count,
                          minimum.isFinite, maximum.isFinite, minimum <= maximum,
                          retainedUntil.isFinite,
                          retainedUntil >= Double(admissionBucket) + Self.journalRetentionSeconds,
                          retainedUntil < Double(admissionBucket) + Self.journalRetentionSeconds + 1,
                          byteCount == count * 16,
                          sourceIdentityByteCount == count * SHA256.byteCount,
                          dispositionByteCount == (count * 3 + 7) / 8,
                          dispositionDigestCount == SHA256.byteCount,
                          rawBytes > 0,
                          rawBytes <= EventJournalCodec.maximumUncompressedBytes,
                          codec == EventJournalCodec.rawCodec
                            || codec == EventJournalCodec.lzfseCodec,
                          payloadDigestCount == 32,
                          metadataDigestCount == 32,
                          let pointer = sqlite3_column_blob(statement, 24),
                          let sourceIdentityPointer = sqlite3_column_blob(statement, 25),
                          let dispositionPointer = sqlite3_column_blob(statement, 26),
                          let dispositionDigestPointer = sqlite3_column_blob(statement, 27),
                          let payloadDigestPointer = sqlite3_column_blob(statement, 30),
                          let metadataDigestPointer = sqlite3_column_blob(statement, 31) else {
                        throw EventStoreError.decodingFailed(
                            "event journal block \(blockID) has an invalid UUID roster"
                        )
                    }
                    let roster = Data(bytes: pointer, count: byteCount)
                    let sourceIdentityRoster = Data(
                        bytes: sourceIdentityPointer,
                        count: sourceIdentityByteCount
                    )
                    let dispositionData = Data(
                        bytes: dispositionPointer,
                        count: dispositionByteCount
                    )
                    let dispositionDigest = Data(
                        bytes: dispositionDigestPointer,
                        count: dispositionDigestCount
                    )
                    guard Data(SHA256.hash(data: dispositionData))
                            == dispositionDigest else {
                        throw EventStoreError.decodingFailed(
                            "event journal block \(blockID) disposition checksum mismatch"
                        )
                    }
                    let storedMetadataDigest = Data(
                        bytes: metadataDigestPointer,
                        count: metadataDigestCount
                    )
                    let calculatedMetadataDigest = try Self.journalMetadataDigest(
                        metadata: JournalBlockMetadata(
                            minimum: minimum,
                            maximum: maximum,
                            retainedUntil: retainedUntil,
                            admissionBucket: admissionBucket,
                            byCategory: categoryMetadata
                        ),
                        eventCount: count,
                        roster: roster,
                        sourceIdentityRoster: sourceIdentityRoster,
                        rawBytes: rawBytes,
                        codec: codec,
                        payloadDigest: Data(
                            bytes: payloadDigestPointer,
                            count: payloadDigestCount
                        )
                    )
                    guard calculatedMetadataDigest == storedMetadataDigest else {
                        journalIntegrityFailures += 1
                        throw EventStoreError.decodingFailed(
                            "event journal block \(blockID) metadata checksum mismatch"
                        )
                    }
                    batch.append(ScannedJournalRow(
                        blockID: blockID,
                        storedSummary: JournalBlockMetadata(
                            minimum: minimum,
                            maximum: maximum,
                            retainedUntil: retainedUntil,
                            admissionBucket: admissionBucket,
                            byCategory: categoryMetadata
                        ),
                        count: count,
                        admissionBucket: admissionBucket,
                        roster: roster,
                        dispositionData: dispositionData
                    ))
                }
            }
            guard let lastRow = batch.last else { break scanLoop }
            scanCursor = lastRow.blockID
            if journalRebuildFailAfterPartialForTesting {
                journalRebuildFailAfterPartialForTesting = false
                throw EventStoreError.decodingFailed(
                    "test-injected torn journal scan after partial population"
                )
            }
            journalIndexRebuildHookForTesting?(
                db.map { sqlite3_get_autocommit($0) == 0 } ?? false
            )
            // Phase 2: heavy verification and index population with NO scan
            // statement open — every nested load below is its own short-lived
            // implicit transaction, so the writer can checkpoint between them.
            for row in batch {
                let blockID = row.blockID
                let decodedBlock: OwnedJournalBlock
                do {
                    let stageStarted = DispatchTime.now().uptimeNanoseconds
                    defer { recordJournalIndexStage("base_authentication", started: stageStarted) }
                    decodedBlock = try loadJournalBlock(blockID: blockID)
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    journalIntegrityFailures += 1
                    throw error
                }
                guard try Self.journalSummaryMatchesPayload(
                    stored: row.storedSummary,
                    decoded: decodedBlock.events
                ) else {
                    journalIntegrityFailures += 1
                    throw EventStoreError.decodingFailed(
                        "event journal block \(blockID) summary does not match its payload"
                    )
                }
                do {
                    let stageStarted = DispatchTime.now().uptimeNanoseconds
                    // The exact loader validates poison against this same
                    // authenticated base before applying any overlays. Count
                    // that work here once, together with exact/projection
                    // validation, instead of repeating the poison-ledger pass.
                    defer { recordJournalIndexStage("poison_overlays_and_projection", started: stageStarted) }
                    let exact = try loadExactJournalBlock(
                        blockID: blockID,
                        authenticatedBase: decodedBlock
                    )
                    try validateProjectionIntegrity(
                        blockID: blockID,
                        admissionBucket: row.admissionBucket,
                        eventCount: row.count,
                        roster: row.roster,
                        dispositionData: row.dispositionData,
                        exactEvents: exact.events,
                        poisonByOrdinal: exact.poisonByOrdinal
                    )
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    journalIntegrityFailures += 1
                    throw error
                }
                journalVerifiedBlocks += 1
                verifiedJournalSummaries.append(
                    VerifiedJournalSummary(
                        blockID: blockID,
                        eventCount: row.count,
                        metadata: row.storedSummary
                    )
                )
                let populationStarted = DispatchTime.now().uptimeNanoseconds
                try row.roster.withUnsafeBytes { bytes in
                    for ordinal in 0..<row.count {
                        let id = try Self.uuid(
                            from: bytes,
                            offset: ordinal * 16
                        )
                        let location = JournalLocation(
                            blockID: blockID,
                            ordinal: ordinal
                        )
                        if journalIndexedLocationCount < maximumIndexEvents {
                            let entry = PackedJournalEntry(id: id, location: location)
                            if appendOnlyRefresh {
                                guard indexedJournalLocation(for: id) == nil else {
                                    throw EventStoreError.decodingFailed(
                                        "event journal contains a duplicate UUID roster entry"
                                    )
                                }
                                journalDeltaLocations.insert(entry)
                            } else {
                                journalBaseLocations.append(entry)
                            }
                            journalIndexedLocationCount += 1
                        } else {
                            journalIndexOverflowed = true
                            journalOverflowBloom.insert(id)
                            journalOverflowFirstBlockID = min(
                                journalOverflowFirstBlockID ?? blockID,
                                blockID
                            )
                        }
                    }
                }
                recordJournalIndexStage("packed_index_population", started: populationStarted)
            }
            if batch.count < Self.journalScanBatchBlocks { break scanLoop }
        }
        let expectedScannedBlocks = appendOnlyRefresh
            ? blockCount - journalIndexedBlockCount : blockCount
        guard scannedBlocks == expectedScannedBlocks else {
            throw EventStoreError.decodingFailed(
                "event journal topology state does not match retained blocks"
            )
        }
        if !appendOnlyRefresh {
            let stageStarted = DispatchTime.now().uptimeNanoseconds
            defer { recordJournalIndexStage("packed_index_sort", started: stageStarted) }
            journalBaseLocations.sort { $0.precedes($1) }
        }
        if !appendOnlyRefresh, journalBaseLocations.count > 1 {
            for index in 1..<journalBaseLocations.count {
                guard !journalBaseLocations[index - 1].sameID(
                    as: journalBaseLocations[index]
                ) else {
                    throw EventStoreError.decodingFailed(
                        "event journal contains a duplicate UUID roster entry"
                    )
                }
            }
        }
        if !appendOnlyRefresh {
            do {
                let stageStarted = DispatchTime.now().uptimeNanoseconds
                defer { recordJournalIndexStage("global_terminal_integrity", started: stageStarted) }
                try validateTerminalRevisionIntegrity()
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                journalIntegrityFailures += 1
                throw error
            }
            do {
                let stageStarted = DispatchTime.now().uptimeNanoseconds
                defer { recordJournalIndexStage("global_projection_and_fts", started: stageStarted) }
                try validateGlobalProjectionCoverage()
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                journalIntegrityFailures += 1
                throw error
            }
        }
        journalIndexLoaded = true
        journalIndexTopologyGeneration = topologyGeneration
        journalIndexedBlockCount = blockCount
        journalIndexedMinimumBlockID = minimumBlockID
        journalIndexedMaximumBlockID = maximumBlockID
        journalIndexStagesComplete = true
    }

    private func indexedJournalLocation(
        for id: UUID
    ) -> JournalLocation? {
        let key = PackedJournalEntry(key: id)
        if let location = journalDeltaLocations.location(for: key) {
            return isJournalBlockTombstoned(location.blockID)
                ? nil : location
        }
        var lower = 0
        var upper = journalBaseLocations.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            let candidate = journalBaseLocations[middle]
            if candidate.sameID(as: key) {
                return isJournalBlockTombstoned(
                    candidate.location.blockID
                ) ? nil : candidate.location
            }
            if candidate.precedes(key) {
                lower = middle + 1
            } else {
                upper = middle
            }
        }
        return nil
    }

    private func isJournalBlockTombstoned(_ blockID: Int64) -> Bool {
        var lower = 0
        var upper = journalExpiredBlockTombstones.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            if journalExpiredBlockTombstones[middle] < blockID {
                lower = middle + 1
            } else {
                upper = middle
            }
        }
        return lower < journalExpiredBlockTombstones.count
            && journalExpiredBlockTombstones[lower] == blockID
    }

    private func addJournalBlockTombstone(_ blockID: Int64) {
        if let last = journalExpiredBlockTombstones.last, last < blockID {
            journalExpiredBlockTombstones.append(blockID)
            return
        }
        var lower = 0
        var upper = journalExpiredBlockTombstones.count
        while lower < upper {
            let middle = lower + (upper - lower) / 2
            if journalExpiredBlockTombstones[middle] < blockID {
                lower = middle + 1
            } else {
                upper = middle
            }
        }
        guard lower == journalExpiredBlockTombstones.count
                || journalExpiredBlockTombstones[lower] != blockID else {
            return
        }
        journalExpiredBlockTombstones.insert(blockID, at: lower)
    }

    /// Current fixed-width locator allocation, including the 4-MiB overflow
    /// Bloom. This is an exact capacity charge, not a Dictionary-size estimate.
    public func journalLocatorAllocatedBytes() -> Int64 {
        Int64(
            journalBaseLocations.capacity
                * MemoryLayout<PackedJournalEntry>.stride
                + journalDeltaLocations.allocatedBytes
                + journalOverflowBloom.allocatedBytes
                + journalExpiredBlockTombstones.capacity
                    * MemoryLayout<Int64>.stride
        )
    }

    /// Monotonic diagnostic used by production-shaped query qualification.
    /// A newest-one query must decode only the newest intersecting block(s),
    /// never the complete retained journal.
    public func journalExactQueryBlockDecodeCount() -> UInt64 {
        journalExactQueryBlockDecodes
    }

    /// Resolve ordinary IDs with bounded hash/binary lookups. Only stores that exceed
    /// the declared 1,274/s retention+sweep qualification envelope enter the
    /// overflow path; its Bloom gates a scan restricted to overflow blocks.
    /// Neither a legitimate retry nor a false positive walks the full retained
    /// 1.5M-ID corpus during normal operation.
    private func existingJournalLocations(
        for ids: Set<UUID>
    ) throws -> [UUID: JournalLocation] {
        var found: [UUID: JournalLocation] = [:]
        found.reserveCapacity(ids.count)
        for id in ids {
            if let location = indexedJournalLocation(for: id) {
                found[id] = location
            }
        }
        let unresolved = ids.subtracting(found.keys)
        let overflowPossible = Set(unresolved.filter {
            journalOverflowBloom.mightContain($0)
        })
        if journalIndexOverflowed, !overflowPossible.isEmpty,
           let firstBlockID = journalOverflowFirstBlockID {
            journalOverflowFallbackScans &+= 1
            let statement = try prepare(
                "SELECT block_id, event_count, event_ids FROM event_journal_blocks WHERE block_id >= ?1 ORDER BY block_id"
            )
            defer { sqlite3_finalize(statement) }
            sqlite3_bind_int64(statement, 1, firstBlockID)
            var remaining = overflowPossible
            while !remaining.isEmpty, sqlite3_step(statement) == SQLITE_ROW {
                let blockID = sqlite3_column_int64(statement, 0)
                let count = Int(sqlite3_column_int(statement, 1))
                let byteCount = Int(sqlite3_column_bytes(statement, 2))
                guard byteCount == count * 16,
                      let pointer = sqlite3_column_blob(statement, 2) else {
                    throw EventStoreError.decodingFailed(
                        "event journal overflow roster is invalid"
                    )
                }
                let bytes = UnsafeRawBufferPointer(
                    start: pointer,
                    count: byteCount
                )
                for ordinal in 0..<count {
                    let id = try Self.uuid(
                        from: bytes,
                        offset: ordinal * 16
                    )
                    guard remaining.contains(id) else { continue }
                    if found[id] != nil {
                        throw EventStoreError.decodingFailed(
                            "event journal contains duplicate UUID \(id.uuidString)"
                        )
                    }
                    found[id] = JournalLocation(
                        blockID: blockID,
                        ordinal: ordinal
                    )
                    remaining.remove(id)
                }
            }
        }
        return found
    }

    private func acquireEventStoreWorkspace(
        context: String
    ) throws -> EventPipelineMemoryLease {
        guard let lease = liveMemoryBudget.tryAcquire(
            bytes: EventJournalCodec.maximumWorkspaceBytes,
            owner: .eventStoreWorkspace
        ) else {
            throw EventStoreError.memoryLeaseUnavailable(
                "\(context) is waiting for bounded event-store workspace"
            )
        }
        return lease
    }

    private func openJournalPayloadBlob(
        table: String,
        rowID: Int64,
        writable: Bool,
        expectedBytes: Int,
        context: String
    ) throws -> OpaquePointer {
        guard let db else {
            throw EventStoreError.databaseOpenFailed("database is not open")
        }
        var blob: OpaquePointer?
        let rc = table.withCString { tableName in
            "payload".withCString { columnName in
                sqlite3_blob_open(
                    db,
                    "main",
                    tableName,
                    columnName,
                    rowID,
                    writable ? 1 : 0,
                    &blob
                )
            }
        }
        guard rc == SQLITE_OK, let blob,
              Int(sqlite3_blob_bytes(blob)) == expectedBytes else {
            if let blob { sqlite3_blob_close(blob) }
            throw EventStoreError.stepFailed(
                "\(context) incremental payload open failed"
            )
        }
        return blob
    }

    private func writeRawJournalPayload(
        _ payload: PreparedEventJournalPayload,
        table: String,
        rowID: Int64,
        context: String
    ) throws {
        guard case .rawFragments = payload else { return }
        let blob = try openJournalPayloadBlob(
            table: table,
            rowID: rowID,
            writable: true,
            expectedBytes: payload.storedBytes,
            context: context
        )
        defer { sqlite3_blob_close(blob) }
        var offset = 0
        try payload.forEachFragment { fragment in
            guard !fragment.isEmpty else { return }
            let rc = fragment.withUnsafeBytes { source -> Int32 in
                guard let base = source.baseAddress else {
                    return SQLITE_MISUSE
                }
                return sqlite3_blob_write(
                    blob,
                    base,
                    Int32(fragment.count),
                    Int32(offset)
                )
            }
            guard rc == SQLITE_OK else {
                throw EventStoreError.stepFailed(
                    "\(context) incremental payload write failed"
                )
            }
            offset += fragment.count
        }
        guard offset == payload.storedBytes else {
            throw EventStoreError.stepFailed(
                "\(context) incremental payload length mismatch"
            )
        }
    }

    private func loadJournalBlock(blockID: Int64) throws -> OwnedJournalBlock {
        let statement = try prepare(
            "SELECT codec, raw_bytes, sha256, length(payload), event_count, event_ids, source_identity_sha256s FROM event_journal_blocks WHERE block_id = ?1 LIMIT 1"
        )
        sqlite3_bind_int64(statement, 1, blockID)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            sqlite3_finalize(statement)
            throw EventStoreError.decodingFailed(
                "event journal locator references missing block \(blockID)"
            )
        }
        let codec = Int(sqlite3_column_int(statement, 0))
        let rawBytes = Int(sqlite3_column_int64(statement, 1))
        let digestCount = Int(sqlite3_column_bytes(statement, 2))
        let payloadCount = Int(sqlite3_column_int64(statement, 3))
        let eventCount = Int(sqlite3_column_int(statement, 4))
        let rosterCount = Int(sqlite3_column_bytes(statement, 5))
        let sourceIdentityRosterCount = Int(
            sqlite3_column_bytes(statement, 6)
        )
        guard digestCount == 32,
              payloadCount > 0,
              rosterCount == eventCount * 16,
              sourceIdentityRosterCount == eventCount * SHA256.byteCount,
              let digestPointer = sqlite3_column_blob(statement, 2),
              let rosterPointer = sqlite3_column_blob(statement, 5),
              sqlite3_column_blob(statement, 6) != nil else {
            sqlite3_finalize(statement)
            throw EventStoreError.decodingFailed(
                "event journal block \(blockID) has invalid persisted metadata"
            )
        }
        let digest = Data(bytes: digestPointer, count: digestCount)
        let roster = Data(bytes: rosterPointer, count: rosterCount)
        sqlite3_finalize(statement)

        let workspace = try acquireEventStoreWorkspace(
            context: "event journal block decode"
        )
        let blob = try openJournalPayloadBlob(
            table: "event_journal_blocks",
            rowID: blockID,
            writable: false,
            expectedBytes: payloadCount,
            context: "event journal block \(blockID)"
        )
        defer { sqlite3_blob_close(blob) }
        var records: [OwnedDecodedJournalRecord<Event>] = []
        records.reserveCapacity(eventCount)
        do {
            _ = try EventJournalCodec.decodeRecordsStreaming(
                codec: codec,
                rawBytes: rawBytes,
                expectedDigest: digest,
                payloadBytes: payloadCount,
                expectedRecordCount: eventCount,
                workspaceLease: workspace,
                reader: { offset, destination in
                    guard let base = destination.baseAddress else { return 0 }
                    let rc = sqlite3_blob_read(
                        blob,
                        base,
                        Int32(destination.count),
                        Int32(offset)
                    )
                    guard rc == SQLITE_OK else {
                        throw EventStoreError.stepFailed(
                            "event journal block \(blockID) incremental read failed"
                        )
                    }
                    return destination.count
                },
                recordLeaseProvider: { _, _ in
                    self.liveMemoryBudget.tryAcquire(
                        bytes: EventJournalAdmissionValidator
                            .maximumPreparationWorkspaceBytes,
                        owner: .journalPrepared
                    )
                },
                as: Event.self,
                decoder: decoder,
                consume: { owned in
                    let estimate = try EventJournalAdmissionValidator
                        .preflight(owned.value).sourceRetainedByteEstimate
                    guard estimate > 0,
                          estimate <= owned.ownershipLease.bytes,
                          owned.ownershipLease.resize(to: estimate) else {
                        throw EventJournalCodecError.invalidWorkspace
                    }
                    records.append(owned)
                }
            )
        } catch EventJournalCodecError.recordWorkspaceUnavailable {
            throw EventStoreError.memoryLeaseUnavailable(
                "event journal block \(blockID) decode is waiting for bounded record ownership"
            )
        } catch {
            throw EventStoreError.decodingFailed(
                "event journal block \(blockID): \(error.localizedDescription)"
            )
        }
        let block = OwnedJournalBlock(records: records)
        try roster.withUnsafeBytes { bytes in
            for (ordinal, event) in block.enumerated() {
                let rosterID = try Self.uuid(
                    from: bytes,
                    offset: ordinal * 16
                )
                guard rosterID == event.id else {
                    throw EventStoreError.decodingFailed(
                        "event journal block \(blockID) UUID roster mismatch at ordinal \(ordinal)"
                    )
                }
            }
        }
        journalBaseBlockDecodesForTesting &+= 1
        return block
    }

    private func validateDuplicate(
        _ prepared: PreparedPersistedEvent,
        at location: JournalLocation,
        in block: OwnedJournalBlock
    ) throws {
        guard location.ordinal >= 0, location.ordinal < block.count else {
            throw EventStoreError.decodingFailed(
                "event journal UUID locator ordinal is out of range"
            )
        }
        let existing = block[location.ordinal]
        let existingCanonical = try journalEncoder.encode(existing)
        guard existing.id == prepared.event.id,
              existingCanonical == prepared.canonicalJSON,
              try canonicalBaseSourceIdentityDigest(
                base: existing,
                at: location
              ) == prepared.sourceIdentitySHA256 else {
            throw EventStoreError.immutableEventConflict(
                eventID: prepared.event.id
            )
        }
    }

    private struct PreparedTerminalRevision {
        let location: JournalLocation
        let eventID: UUID
        let event: Event
        let baseDigest: Data
        let terminalDigest: Data
        let sourceIdentitySHA256: Data
        let canonicalBytes: Int
        let block: PreparedEventJournalBlock
        let projection: PreparedPersistedEvent
    }

    /// One authenticated block whose decoded Event graphs remain charged to
    /// the process-shared J budget for exactly as long as callers retain them.
    private struct OwnedJournalBlock: RandomAccessCollection {
        typealias Index = Int
        typealias Element = Event

        let records: [OwnedDecodedJournalRecord<Event>]

        var startIndex: Int { records.startIndex }
        var endIndex: Int { records.endIndex }
        subscript(position: Int) -> Event { records[position].value }

        var events: [Event] { records.map(\.value) }
        var ownershipLeases: [EventPipelineMemoryLease] {
            records.map(\.ownershipLease)
        }
    }

    private struct OwnedJournalRecordAtLocation {
        let record: OwnedDecodedJournalRecord<Event>
        let framedSHA256: Data
        let sourceIdentitySHA256: Data
    }

    /// Authenticate the complete framed block while decoding only one ordinal.
    /// Terminal settlement therefore owns one base J lease regardless of the
    /// block's other 127 records.
    private func loadJournalRecord(
        at location: JournalLocation,
        workspaceLease: EventPipelineMemoryLease
    ) throws -> OwnedJournalRecordAtLocation {
        guard workspaceLease.owner == .eventStoreWorkspace,
              workspaceLease.bytes >= EventJournalCodec.maximumWorkspaceBytes
        else {
            throw EventStoreError.memoryLeaseUnavailable(
                "targeted journal decode has no adopted EventStore workspace"
            )
        }
        let statement = try prepare(
            "SELECT codec, raw_bytes, sha256, length(payload), event_count, event_ids, source_identity_sha256s FROM event_journal_blocks WHERE block_id = ?1 LIMIT 1"
        )
        sqlite3_bind_int64(statement, 1, location.blockID)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            sqlite3_finalize(statement)
            throw EventStoreError.decodingFailed(
                "event journal locator references missing block \(location.blockID)"
            )
        }
        let codec = Int(sqlite3_column_int(statement, 0))
        let rawBytes = Int(sqlite3_column_int64(statement, 1))
        let digestCount = Int(sqlite3_column_bytes(statement, 2))
        let payloadCount = Int(sqlite3_column_int64(statement, 3))
        let eventCount = Int(sqlite3_column_int(statement, 4))
        let rosterCount = Int(sqlite3_column_bytes(statement, 5))
        let sourceRosterCount = Int(sqlite3_column_bytes(statement, 6))
        guard location.ordinal >= 0,
              location.ordinal < eventCount,
              digestCount == SHA256.byteCount,
              payloadCount > 0,
              rosterCount == eventCount * 16,
              sourceRosterCount == eventCount * SHA256.byteCount,
              let digestPointer = sqlite3_column_blob(statement, 2),
              let rosterPointer = sqlite3_column_blob(statement, 5),
              let sourcePointer = sqlite3_column_blob(statement, 6) else {
            sqlite3_finalize(statement)
            throw EventStoreError.decodingFailed(
                "targeted journal block metadata is invalid"
            )
        }
        let framedSHA256 = Data(bytes: digestPointer, count: digestCount)
        let roster = Data(bytes: rosterPointer, count: rosterCount)
        let sourceIdentitySHA256 = Data(
            bytes: sourcePointer.advanced(
                by: location.ordinal * SHA256.byteCount
            ),
            count: SHA256.byteCount
        )
        sqlite3_finalize(statement)

        let blob = try openJournalPayloadBlob(
            table: "event_journal_blocks",
            rowID: location.blockID,
            writable: false,
            expectedBytes: payloadCount,
            context: "targeted event journal block \(location.blockID)"
        )
        defer { sqlite3_blob_close(blob) }
        var selected: OwnedDecodedJournalRecord<Event>?
        do {
            _ = try EventJournalCodec.decodeRecordsStreaming(
                codec: codec,
                rawBytes: rawBytes,
                expectedDigest: framedSHA256,
                payloadBytes: payloadCount,
                expectedRecordCount: eventCount,
                workspaceLease: workspaceLease,
                reader: { offset, destination in
                    guard let base = destination.baseAddress else { return 0 }
                    let rc = sqlite3_blob_read(
                        blob,
                        base,
                        Int32(destination.count),
                        Int32(offset)
                    )
                    guard rc == SQLITE_OK else {
                        throw EventStoreError.stepFailed(
                            "targeted journal payload read failed"
                        )
                    }
                    return destination.count
                },
                shouldDecodeRecord: { $0 == location.ordinal },
                recordLeaseProvider: { ordinal, _ in
                    guard ordinal == location.ordinal else { return nil }
                    return self.liveMemoryBudget.tryAcquire(
                        bytes: EventJournalAdmissionValidator
                            .maximumPreparationWorkspaceBytes,
                        owner: .journalPrepared
                    )
                },
                as: Event.self,
                decoder: decoder,
                consume: { owned in
                    let retained = try EventJournalAdmissionValidator
                        .preflight(owned.value).sourceRetainedByteEstimate
                    guard retained > 0,
                          retained <= owned.ownershipLease.bytes,
                          owned.ownershipLease.resize(to: retained),
                          selected == nil else {
                        throw EventJournalCodecError.invalidWorkspace
                    }
                    selected = owned
                }
            )
        } catch EventJournalCodecError.recordWorkspaceUnavailable {
            throw EventStoreError.memoryLeaseUnavailable(
                "targeted event journal block \(location.blockID) decode is waiting for bounded record ownership"
            )
        } catch {
            throw EventStoreError.decodingFailed(
                "targeted event journal block \(location.blockID): \(error.localizedDescription)"
            )
        }
        guard let selected else {
            throw EventStoreError.decodingFailed(
                "targeted journal ordinal was not decoded"
            )
        }
        let rosterID = try roster.withUnsafeBytes {
            try Self.uuid(from: $0, offset: location.ordinal * 16)
        }
        guard selected.value.id == rosterID else {
            throw EventStoreError.decodingFailed(
                "targeted journal UUID roster mismatch"
            )
        }
        return OwnedJournalRecordAtLocation(
            record: selected,
            framedSHA256: framedSHA256,
            sourceIdentitySHA256: sourceIdentitySHA256
        )
    }

    /// Revalidate the immutable block/ordinal proof after BEGIN IMMEDIATE
    /// without decoding the payload a second time.
    private func validateJournalRecordLocationUnderWriterLock(
        _ location: JournalLocation,
        eventID: UUID,
        framedSHA256: Data,
        sourceIdentitySHA256: Data
    ) throws -> Int {
        let statement = try prepare(
            "SELECT event_count, sha256, substr(event_ids, ?2, 16), substr(source_identity_sha256s, ?3, 32) FROM event_journal_blocks WHERE block_id = ?1 LIMIT 1"
        )
        sqlite3_bind_int64(statement, 1, location.blockID)
        sqlite3_bind_int(statement, 2, Int32(location.ordinal * 16 + 1))
        sqlite3_bind_int(
            statement,
            3,
            Int32(location.ordinal * SHA256.byteCount + 1)
        )
        guard sqlite3_step(statement) == SQLITE_ROW else {
            sqlite3_finalize(statement)
            throw EventStoreError.terminalRevisionRequiresIdentityRefresh
        }
        func blob(_ column: Int32) -> Data? {
            let count = Int(sqlite3_column_bytes(statement, column))
            guard count >= 0 else { return nil }
            if count == 0 {
                return sqlite3_column_type(statement, column) == SQLITE_NULL
                    ? nil : Data()
            }
            guard let pointer = sqlite3_column_blob(statement, column) else {
                return nil
            }
            return Data(bytes: pointer, count: count)
        }
        let eventCount = Int(sqlite3_column_int(statement, 0))
        let digest = blob(1)
        let rosterID = blob(2)
        let sourceIdentity = blob(3)
        sqlite3_finalize(statement)
        guard location.ordinal >= 0,
              location.ordinal < eventCount,
              digest == framedSHA256,
              rosterID == Self.uuidData(eventID),
              sourceIdentity == sourceIdentitySHA256 else {
            throw EventStoreError.terminalRevisionRequiresIdentityRefresh
        }
        return eventCount
    }

    private struct LoadedTerminalRevision {
        let event: Event
        let baseDigest: Data
        let terminalDigest: Data
        let ownershipLease: EventPipelineMemoryLease
    }

    private func normalizedTerminalEvent(_ event: Event) -> Event {
        Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: event.process,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: event.severity,
            ruleMatches: ReviewedRuleMatches.normalized(event.ruleMatches)
        )
    }

    /// A terminal overlay may finalize enrichment-derived detail, but it may
    /// not invalidate the authenticated block summaries used to prune exact
    /// time/category reads or rewrite source identity. Heavy enrichment is
    /// allowed to fill userName, code signature, hashes, environment,
    /// enrichments, severity and reviewed matches; every capture-time field is
    /// immutable.
    private func terminalRevisionPreservesSourceIdentity(
        base: Event,
        terminal: Event
    ) -> Bool {
        let left = base.process
        let right = terminal.process
        return base.id == terminal.id
            && base.timestamp == terminal.timestamp
            && base.eventCategory == terminal.eventCategory
            && base.eventType == terminal.eventType
            && base.eventAction == terminal.eventAction
            && base.file == terminal.file
            && base.network == terminal.network
            && base.tcc == terminal.tcc
            && terminal.severity >= base.severity
            && left.pid == right.pid
            && left.ppid == right.ppid
            && left.rpid == right.rpid
            && left.name == right.name
            && left.executable == right.executable
            && left.commandLine == right.commandLine
            && left.args == right.args
            && left.workingDirectory == right.workingDirectory
            && left.userId == right.userId
            && left.groupId == right.groupId
            && left.startTime == right.startTime
            && left.exitCode == right.exitCode
            && left.ancestors == right.ancestors
            && left.architecture == right.architecture
            && left.isPlatformBinary == right.isPlatformBinary
            && left.session == right.session
            && left.auditIdentity == right.auditIdentity
    }

    private func loadTerminalRevision(
        at location: JournalLocation,
        base: Event
    ) throws -> LoadedTerminalRevision? {
        let statement = try prepare(
            """
            SELECT rowid, event_id, base_sha256, terminal_sha256,
                   framed_sha256, raw_bytes, codec, length(payload)
            FROM event_journal_terminal_revisions
            WHERE block_id = ?1 AND ordinal = ?2
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, location.blockID)
        sqlite3_bind_int(statement, 2, Int32(location.ordinal))
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE {
            return nil
        }
        guard rc == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "terminal journal revision lookup failed"
            )
        }
        func blob(_ column: Int32, expected: Int? = nil) throws -> Data {
            let count = Int(sqlite3_column_bytes(statement, column))
            if let expected, count != expected {
                throw EventStoreError.decodingFailed(
                    "terminal journal revision has invalid digest/identity length"
                )
            }
            guard count > 0,
                  let pointer = sqlite3_column_blob(statement, column) else {
                throw EventStoreError.decodingFailed(
                    "terminal journal revision blob is unavailable"
                )
            }
            return Data(bytes: pointer, count: count)
        }
        let rowID = sqlite3_column_int64(statement, 0)
        let eventIDData = try blob(1, expected: 16)
        let baseDigest = try blob(2, expected: 32)
        let terminalDigest = try blob(3, expected: 32)
        let framedDigest = try blob(4, expected: 32)
        let rawBytes = Int(sqlite3_column_int64(statement, 5))
        let codec = Int(sqlite3_column_int(statement, 6))
        let payloadBytes = Int(sqlite3_column_int64(statement, 7))

        let workspace = try acquireEventStoreWorkspace(
            context: "terminal journal revision decode"
        )
        let payloadBlob = try openJournalPayloadBlob(
            table: "event_journal_terminal_revisions",
            rowID: rowID,
            writable: false,
            expectedBytes: payloadBytes,
            context: "terminal revision"
        )
        defer { sqlite3_blob_close(payloadBlob) }
        var ownedDelta: OwnedDecodedJournalRecord<EventTerminalDelta>?
        do {
            _ = try EventJournalCodec.decodeRecordsStreaming(
                codec: codec,
                rawBytes: rawBytes,
                expectedDigest: framedDigest,
                payloadBytes: payloadBytes,
                expectedRecordCount: 1,
                workspaceLease: workspace,
                reader: { offset, destination in
                    guard let base = destination.baseAddress else { return 0 }
                    let rc = sqlite3_blob_read(
                        payloadBlob,
                        base,
                        Int32(destination.count),
                        Int32(offset)
                    )
                    guard rc == SQLITE_OK else {
                        throw EventStoreError.stepFailed(
                            "terminal revision incremental read failed"
                        )
                    }
                    return destination.count
                },
                recordLeaseProvider: { _, _ in
                    self.liveMemoryBudget.tryAcquire(
                        bytes: EventJournalAdmissionValidator
                            .maximumPreparationWorkspaceBytes,
                        owner: .journalPrepared
                    )
                },
                as: EventTerminalDelta.self,
                decoder: decoder,
                consume: { record in ownedDelta = record }
            )
        } catch EventJournalCodecError.recordWorkspaceUnavailable {
            throw EventStoreError.memoryLeaseUnavailable(
                "terminal journal revision decode is waiting for bounded record ownership"
            )
        }
        guard let ownedDelta,
              !ownedDelta.value.isEmpty,
              let event = try? ownedDelta.value.applying(to: base),
              ownedDelta.value.eventID == base.id,
              Self.uuidData(event.id) == eventIDData,
              Data(SHA256.hash(data: try journalEncoder.encode(event)))
                == terminalDigest else {
            throw EventStoreError.decodingFailed(
                "terminal journal revision canonical identity is invalid"
            )
        }
        let retainedBytes = try EventJournalAdmissionValidator
            .preflight(event).sourceRetainedByteEstimate
        guard retainedBytes > 0,
              retainedBytes <= ownedDelta.ownershipLease.bytes,
              ownedDelta.ownershipLease.resize(to: retainedBytes) else {
            throw EventStoreError.decodingFailed(
                "terminal journal revision ownership charge is invalid"
            )
        }
        return LoadedTerminalRevision(
            event: event,
            baseDigest: baseDigest,
            terminalDigest: terminalDigest,
            ownershipLease: ownedDelta.ownershipLease
        )
    }

    private func canonicalBaseSourceIdentityDigest(
        base: Event,
        at location: JournalLocation
    ) throws -> Data {
        _ = base
        let statement = try prepare(
            """
            SELECT event_count, source_identity_sha256s
            FROM event_journal_blocks
            WHERE block_id = ?1
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, location.blockID)
        let rc = sqlite3_step(statement)
        guard rc == SQLITE_ROW,
              location.ordinal >= 0,
              location.ordinal < Int(sqlite3_column_int(statement, 0)),
              Int(sqlite3_column_bytes(statement, 1))
                == Int(sqlite3_column_int(statement, 0)) * SHA256.byteCount,
              let bytes = sqlite3_column_blob(statement, 1) else {
            throw EventStoreError.decodingFailed(
                "journal raw source-identity roster is invalid"
            )
        }
        let digest = Data(
            bytes: bytes.advanced(
                by: location.ordinal * SHA256.byteCount
            ),
            count: SHA256.byteCount
        )
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "journal raw source-identity roster is duplicated"
            )
        }
        return digest
    }

    private func persistedBasePoison(
        at location: JournalLocation,
        base: Event
    ) throws -> EventJournalOverflowEvidence? {
        let statement = try prepare(
            """
            SELECT event_id, replacement_sha256, original_sha256,
                   source_identity_sha256, original_bytes, digest_kind
            FROM event_journal_payload_poison
            WHERE block_id = ?1 AND ordinal = ?2 AND poison_kind = 'base'
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, location.blockID)
        sqlite3_bind_int(statement, 2, Int32(location.ordinal))
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW,
              Int(sqlite3_column_bytes(statement, 0)) == 16,
              Int(sqlite3_column_bytes(statement, 1)) == SHA256.byteCount,
              Int(sqlite3_column_bytes(statement, 2)) == SHA256.byteCount,
              Int(sqlite3_column_bytes(statement, 3)) == SHA256.byteCount,
              let eventIDBytes = sqlite3_column_blob(statement, 0),
              let replacementBytes = sqlite3_column_blob(statement, 1),
              let originalBytes = sqlite3_column_blob(statement, 2),
              let identityBytes = sqlite3_column_blob(statement, 3),
              let digestKindBytes = sqlite3_column_text(statement, 5),
              let digestKind = EventJournalOverflowEvidence.DigestKind(
                rawValue: String(cString: digestKindBytes)
              ) else {
            throw EventStoreError.decodingFailed(
                "base journal poison marker/ledger mismatch"
            )
        }
        // SQLite column pointers are valid only until the next step/reset.
        // Copy the complete ledger identity before asserting PK uniqueness.
        let eventID = Data(bytes: eventIDBytes, count: 16)
        let replacementDigest = Data(
            bytes: replacementBytes,
            count: SHA256.byteCount
        )
        let originalDigest = Data(
            bytes: originalBytes,
            count: SHA256.byteCount
        )
        let sourceIdentityDigest = Data(
            bytes: identityBytes,
            count: SHA256.byteCount
        )
        let originalByteCount = Int(sqlite3_column_int64(statement, 4))
        guard eventID == Self.uuidData(base.id),
              replacementDigest
                == Data(SHA256.hash(data: try journalEncoder.encode(base))),
              sourceIdentityDigest == (try canonicalBaseSourceIdentityDigest(
                base: base,
                at: location
              )),
              base.eventAction == "journal_overflow",
              base.enrichments["journal.overflow"] == "true",
              base.enrichments["journal.original_sha256"]
                == originalDigest.map { String(format: "%02x", $0) }.joined(),
              base.enrichments["journal.original_bytes"]
                == String(originalByteCount),
              base.enrichments["journal.original_digest_kind"]
                == digestKind.rawValue,
              sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "base journal poison marker/ledger mismatch"
            )
        }
        return EventJournalOverflowEvidence(
            originalEventID: base.id,
            originalBytes: originalByteCount,
            originalSHA256: originalDigest,
            digestKind: digestKind,
            sourceIdentitySHA256: sourceIdentityDigest
        )
    }

    /// Terminal poison is sticky for the lifetime of its canonical base. Once
    /// any final revision was rejected, a later smaller retry cannot make that
    /// missing revision exact. Bind the durable poison to the immutable source
    /// identity and return the original rejected-content identity verbatim.
    private func persistedTerminalPoison(
        at location: JournalLocation,
        base: Event
    ) throws -> EventJournalOverflowEvidence? {
        try persistedMutablePoison(
            kind: .terminal,
            at: location,
            base: base
        )
    }

    private func persistedTerminalPoisonMetadata(
        at location: JournalLocation,
        eventID: UUID,
        sourceIdentitySHA256: Data
    ) throws -> EventJournalOverflowEvidence? {
        let statement = try prepare(
            "SELECT event_id, original_sha256, source_identity_sha256, original_bytes, digest_kind FROM event_journal_payload_poison WHERE block_id = ?1 AND ordinal = ?2 AND poison_kind = 'terminal'"
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, location.blockID)
        sqlite3_bind_int(statement, 2, Int32(location.ordinal))
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW,
              Int(sqlite3_column_bytes(statement, 0)) == 16,
              Int(sqlite3_column_bytes(statement, 1)) == SHA256.byteCount,
              Int(sqlite3_column_bytes(statement, 2)) == SHA256.byteCount,
              let eventIDBytes = sqlite3_column_blob(statement, 0),
              let digestBytes = sqlite3_column_blob(statement, 1),
              let sourceBytes = sqlite3_column_blob(statement, 2),
              let digestKindText = sqlite3_column_text(statement, 4),
              let digestKind = EventJournalOverflowEvidence.DigestKind(
                rawValue: String(cString: digestKindText)
              ) else {
            throw EventStoreError.decodingFailed(
                "terminal poison metadata is malformed"
            )
        }
        let storedEventID = Data(bytes: eventIDBytes, count: 16)
        let originalDigest = Data(
            bytes: digestBytes,
            count: SHA256.byteCount
        )
        let storedSource = Data(
            bytes: sourceBytes,
            count: SHA256.byteCount
        )
        let originalBytes = Int(sqlite3_column_int64(statement, 3))
        guard sqlite3_step(statement) == SQLITE_DONE,
              storedEventID == Self.uuidData(eventID),
              storedSource == sourceIdentitySHA256,
              originalBytes >= 0 else {
            throw EventStoreError.decodingFailed(
                "terminal poison metadata is not source-bound"
            )
        }
        return EventJournalOverflowEvidence(
            originalEventID: eventID,
            originalBytes: originalBytes,
            originalSHA256: originalDigest,
            digestKind: digestKind,
            sourceIdentitySHA256: storedSource
        )
    }

    private func persistedPromotionPoison(
        at location: JournalLocation,
        base: Event
    ) throws -> EventJournalOverflowEvidence? {
        try persistedMutablePoison(
            kind: .promotion,
            at: location,
            base: base
        )
    }

    private func persistedMutablePoison(
        kind: EventJournalPoisonRecord.Kind,
        at location: JournalLocation,
        base: Event
    ) throws -> EventJournalOverflowEvidence? {
        guard kind == .terminal || kind == .promotion else {
            throw EventStoreError.decodingFailed(
                "mutable journal poison lookup requested an invalid kind"
            )
        }
        let statement = try prepare(
            """
            SELECT event_id, original_sha256, source_identity_sha256,
                   original_bytes, digest_kind
            FROM event_journal_payload_poison
            WHERE block_id = ?1 AND ordinal = ?2
              AND poison_kind = ?3
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, location.blockID)
        sqlite3_bind_int(statement, 2, Int32(location.ordinal))
        bindText(statement, index: 3, value: kind.rawValue)
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW,
              Int(sqlite3_column_bytes(statement, 0)) == 16,
              Int(sqlite3_column_bytes(statement, 1)) == SHA256.byteCount,
              Int(sqlite3_column_bytes(statement, 2)) == SHA256.byteCount,
              let eventIDBytes = sqlite3_column_blob(statement, 0),
              let originalDigestBytes = sqlite3_column_blob(statement, 1),
              let sourceIdentityBytes = sqlite3_column_blob(statement, 2),
              let digestKindBytes = sqlite3_column_text(statement, 4),
              let digestKind = EventJournalOverflowEvidence.DigestKind(
                rawValue: String(cString: digestKindBytes)
              ) else {
            throw EventStoreError.decodingFailed(
                "\(kind.rawValue) journal poison ledger is malformed"
            )
        }
        let eventID = Data(bytes: eventIDBytes, count: 16)
        let originalDigest = Data(
            bytes: originalDigestBytes,
            count: SHA256.byteCount
        )
        let sourceIdentity = Data(
            bytes: sourceIdentityBytes,
            count: SHA256.byteCount
        )
        let originalByteCount = Int(sqlite3_column_int64(statement, 3))
        guard eventID == Self.uuidData(base.id),
              originalByteCount >= 0,
              sourceIdentity == (try canonicalBaseSourceIdentityDigest(
                base: base,
                at: location
              )),
              sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "\(kind.rawValue) journal poison is not source-bound to its base"
            )
        }
        return EventJournalOverflowEvidence(
            originalEventID: base.id,
            originalBytes: originalByteCount,
            originalSHA256: originalDigest,
            digestKind: digestKind,
            sourceIdentitySHA256: sourceIdentity
        )
    }

    /// Prove a retained block's compact overflow markers and poison ledger are
    /// a bijection. Base poison must be represented by the authenticated Event
    /// at the same ordinal; terminal poison must remain source-bound and may
    /// not coexist with an allegedly exact terminal revision.
    private func validatePoisonIntegrity(
        blockID: Int64,
        baseEvents: [Event]
    ) throws {
        struct Row {
            let ordinal: Int
            let kind: EventJournalPoisonRecord.Kind
            let eventID: Data
            let sourceIdentity: Data
            let hasTerminalRevision: Bool
        }
        var rows: [Row] = []
        try withPreparedStatement(
            """
            SELECT p.ordinal, p.poison_kind, p.event_id,
                   p.source_identity_sha256,
                   CASE WHEN t.block_id IS NULL THEN 0 ELSE 1 END
            FROM event_journal_payload_poison p
            LEFT JOIN event_journal_terminal_revisions t
              ON t.block_id = p.block_id AND t.ordinal = p.ordinal
            WHERE p.block_id = ?1
            ORDER BY p.ordinal, p.poison_kind
            """
        ) { statement in
            sqlite3_bind_int64(statement, 1, blockID)
            while true {
                let rc = sqlite3_step(statement)
                if rc == SQLITE_DONE { break }
                guard rc == SQLITE_ROW,
                      Int(sqlite3_column_bytes(statement, 2)) == 16,
                      Int(sqlite3_column_bytes(statement, 3)) == SHA256.byteCount,
                      let kindBytes = sqlite3_column_text(statement, 1),
                      let kind = EventJournalPoisonRecord.Kind(
                        rawValue: String(cString: kindBytes)
                      ),
                      let eventIDBytes = sqlite3_column_blob(statement, 2),
                      let sourceIdentityBytes = sqlite3_column_blob(statement, 3) else {
                    throw EventStoreError.decodingFailed(
                        "journal poison ledger row is malformed"
                    )
                }
                rows.append(Row(
                    ordinal: Int(sqlite3_column_int(statement, 0)),
                    kind: kind,
                    eventID: Data(bytes: eventIDBytes, count: 16),
                    sourceIdentity: Data(
                        bytes: sourceIdentityBytes,
                        count: SHA256.byteCount
                    ),
                    hasTerminalRevision: sqlite3_column_int(statement, 4) != 0
                ))
            }
        }

        var basePoisonOrdinals = Set<Int>()
        for row in rows {
            guard row.ordinal >= 0, row.ordinal < baseEvents.count,
                  row.eventID == Self.uuidData(baseEvents[row.ordinal].id) else {
                throw EventStoreError.decodingFailed(
                    "journal poison ledger references the wrong base ordinal"
                )
            }
            let location = JournalLocation(
                blockID: blockID,
                ordinal: row.ordinal
            )
            switch row.kind {
            case .base:
                guard basePoisonOrdinals.insert(row.ordinal).inserted,
                      try persistedBasePoison(
                        at: location,
                        base: baseEvents[row.ordinal]
                      ) != nil else {
                    throw EventStoreError.decodingFailed(
                        "journal base poison marker/ledger is not bijective"
                    )
                }
            case .terminal:
                guard !row.hasTerminalRevision,
                      row.sourceIdentity
                        == (try canonicalBaseSourceIdentityDigest(
                            base: baseEvents[row.ordinal],
                            at: location
                        )) else {
                    throw EventStoreError.decodingFailed(
                        "terminal poison is not uniquely source-bound to its base"
                    )
                }
            case .promotion:
                // A later reviewed union can fail after an earlier bounded
                // promotion was durable. Preserve that exact prefix and bind
                // the sticky gap to the same immutable source; coexistence is
                // therefore intentional (unlike terminal poison+revision).
                guard row.sourceIdentity
                        == (try canonicalBaseSourceIdentityDigest(
                            base: baseEvents[row.ordinal],
                            at: location
                        )) else {
                    throw EventStoreError.decodingFailed(
                        "promotion poison is not uniquely source-bound to its base"
                    )
                }
            }
        }
        let markerOrdinals = Set(baseEvents.indices.filter { ordinal in
            let event = baseEvents[ordinal]
            return event.eventAction == "journal_overflow"
                && event.enrichments["journal.overflow"] == "true"
        })
        guard markerOrdinals == basePoisonOrdinals else {
            throw EventStoreError.decodingFailed(
                "journal overflow marker/poison ledger conservation failed"
            )
        }
    }

    private func validateTerminalRevisionIntegrity() throws {
        journalVerifiedTerminalRevisions = 0
        let statement = try prepare(
            "SELECT block_id, ordinal FROM event_journal_terminal_revisions ORDER BY block_id, ordinal"
        )
        defer { sqlite3_finalize(statement) }
        var cachedBlockID: Int64?
        var cachedBlock = OwnedJournalBlock(records: [])
        while true {
            try checkReadOnlyRetirement()
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "terminal revision integrity scan failed"
                )
            }
            let location = JournalLocation(
                blockID: sqlite3_column_int64(statement, 0),
                ordinal: Int(sqlite3_column_int(statement, 1))
            )
            if cachedBlockID != location.blockID {
                cachedBlock = try loadJournalBlock(
                    blockID: location.blockID
                )
                cachedBlockID = location.blockID
            }
            guard location.ordinal >= 0,
                  location.ordinal < cachedBlock.count else {
                throw EventStoreError.decodingFailed(
                    "terminal revision references a missing base ordinal"
                )
            }
            let base = cachedBlock[location.ordinal]
            guard let revision = try loadTerminalRevision(
                at: location,
                base: base
            ) else {
                throw EventStoreError.decodingFailed(
                    "terminal revision references a missing base ordinal"
                )
            }
            let baseJSON = try journalEncoder.encode(base)
            let terminalJSON = try journalEncoder.encode(revision.event)
            guard revision.baseDigest == Data(SHA256.hash(data: baseJSON)),
                  revision.terminalDigest
                    == Data(SHA256.hash(data: terminalJSON)),
                  terminalJSON != baseJSON,
                  terminalRevisionPreservesSourceIdentity(
                    base: base,
                    terminal: revision.event
                  ) else {
                throw EventStoreError.decodingFailed(
                    "terminal revision is not checksum/source bound to its base"
                )
            }
            journalVerifiedTerminalRevisions += 1
        }
    }

    private func event(
        _ event: Event,
        replacingRuleMatches matches: [RuleMatch]
    ) -> Event {
        Event(
            id: event.id,
            timestamp: event.timestamp,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            eventAction: event.eventAction,
            process: event.process,
            file: event.file,
            network: event.network,
            tcc: event.tcc,
            enrichments: event.enrichments,
            severity: max(
                event.severity,
                matches.map(\.severity).max() ?? event.severity
            ),
            ruleMatches: ReviewedRuleMatches.normalized(matches)
        )
    }

    private func reviewedPromotionMatches(
        at location: JournalLocation,
        eventID: UUID
    ) throws -> [RuleMatch] {
        let statement = try prepare(
            """
            SELECT event_id, matches_sha256, matches_json
            FROM event_journal_projection_promotions
            WHERE block_id = ?1 AND ordinal = ?2
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, location.blockID)
        sqlite3_bind_int(statement, 2, Int32(location.ordinal))
        var result: [RuleMatch] = []
        while true {
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW,
                  Int(sqlite3_column_bytes(statement, 0)) == 16,
                  Int(sqlite3_column_bytes(statement, 1)) == SHA256.byteCount,
                  let idBytes = sqlite3_column_blob(statement, 0),
                  let digestBytes = sqlite3_column_blob(statement, 1),
                  let jsonBytes = sqlite3_column_blob(statement, 2) else {
                throw EventStoreError.decodingFailed(
                    "projection promotion row is malformed"
                )
            }
            let jsonCount = Int(sqlite3_column_bytes(statement, 2))
            guard jsonCount > 0,
                  jsonCount <= EventJournalCodec.maximumRecordBytes,
                  Data(bytes: idBytes, count: 16) == Self.uuidData(eventID) else {
                throw EventStoreError.decodingFailed(
                    "projection promotion identity is invalid"
                )
            }
            let json = Data(bytes: jsonBytes, count: jsonCount)
            let digest = Data(bytes: digestBytes, count: SHA256.byteCount)
            guard Data(SHA256.hash(data: json)) == digest,
                  let matches = try? decoder.decode(
                    [RuleMatch].self,
                    from: json
                  ),
                  matches == ReviewedRuleMatches.normalized(matches) else {
                throw EventStoreError.decodingFailed(
                    "projection promotion canonical payload is invalid"
                )
            }
            result = ReviewedRuleMatches.merged(result, matches)
        }
        return result
    }

    /// Decode one exact retained Event, atomically preferring its terminal
    /// revision and then unioning append-only reviewed promotion evidence.
    private struct OwnedExactJournalEvent {
        let event: Event
        let ownershipLeases: [EventPipelineMemoryLease]
    }

    private func loadExactJournalEvent(
        at location: JournalLocation
    ) throws -> OwnedExactJournalEvent {
        let block = try loadJournalBlock(blockID: location.blockID)
        guard location.ordinal >= 0, location.ordinal < block.count else {
            throw EventStoreError.decodingFailed(
                "journal exact-event ordinal is out of range"
            )
        }
        let base = block[location.ordinal]
        let terminal = try loadTerminalRevision(
            at: location,
            base: base
        )
        let latest = terminal?.event ?? base
        var ownershipLeases = [block.records[location.ordinal].ownershipLease]
        if let terminal { ownershipLeases.append(terminal.ownershipLease) }
        let reviewed = try reviewedPromotionMatches(
            at: location,
            eventID: base.id
        )
        guard !reviewed.isEmpty else {
            return OwnedExactJournalEvent(
                event: latest,
                ownershipLeases: ownershipLeases
            )
        }
        return OwnedExactJournalEvent(
            event: event(
                latest,
                replacingRuleMatches: ReviewedRuleMatches.merged(
                    latest.ruleMatches,
                    reviewed
                )
            ),
            ownershipLeases: ownershipLeases
        )
    }

    private struct ExactJournalBlock {
        var events: [Event]
        var ownershipLeasesByOrdinal: [[EventPipelineMemoryLease]]
        var poisonByOrdinal: [Int: [EventJournalPoisonRecord]]
        var inheritedLossOrdinals: Set<Int>
    }

    private struct JournalOverlayUsage {
        let terminalCount: Int
        let terminalRawBytes: Int
        let terminalPayloadBytes: Int
        let promotionCount: Int
        let promotionBytes: Int
        let inheritedLossCount: Int
        let inheritedLossBytes: Int

        var retainedLogicalBytes: Int {
            let overlays = promotionBytes.addingReportingOverflow(
                inheritedLossBytes
            )
            guard !overlays.overflow else { return Int.max }
            let total = terminalRawBytes.addingReportingOverflow(
                overlays.partialValue
            )
            return total.overflow ? Int.max : total.partialValue
        }

        var cascadePayloadBytes: Int {
            let overlays = promotionBytes.addingReportingOverflow(
                inheritedLossBytes
            )
            guard !overlays.overflow else { return Int.max }
            let total = terminalPayloadBytes.addingReportingOverflow(
                overlays.partialValue
            )
            return total.overflow ? Int.max : total.partialValue
        }
    }

    /// Read the complete per-block overlay charge in one row. Terminal raw
    /// bytes (not only compressed bytes) bound the decoded Event graph; the
    /// payload sum separately bounds the FK-cascade/WAL mutation.
    private func journalOverlayUsage(
        blockID: Int64,
        eventCount: Int
    ) throws -> JournalOverlayUsage {
        let statement = try prepare(
            """
            SELECT
              (SELECT COUNT(*) FROM event_journal_terminal_revisions WHERE block_id = ?1),
              (SELECT COALESCE(SUM(raw_bytes), 0) FROM event_journal_terminal_revisions WHERE block_id = ?1),
              (SELECT COALESCE(SUM(length(payload)), 0) FROM event_journal_terminal_revisions WHERE block_id = ?1),
              (SELECT COUNT(*) FROM event_journal_projection_promotions WHERE block_id = ?1),
              (SELECT COALESCE(SUM(length(matches_json)), 0) FROM event_journal_projection_promotions WHERE block_id = ?1),
              (SELECT COUNT(*) FROM event_journal_inherited_loss WHERE block_id = ?1),
              (SELECT COALESCE(SUM(length(recovered_fields_json) + length(unavailable_fields_json) + 256), 0) FROM event_journal_inherited_loss WHERE block_id = ?1)
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, blockID)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "journal overlay accounting is unavailable"
            )
        }
        let usage = JournalOverlayUsage(
            terminalCount: Int(sqlite3_column_int64(statement, 0)),
            terminalRawBytes: Int(sqlite3_column_int64(statement, 1)),
            terminalPayloadBytes: Int(sqlite3_column_int64(statement, 2)),
            promotionCount: Int(sqlite3_column_int64(statement, 3)),
            promotionBytes: Int(sqlite3_column_int64(statement, 4)),
            inheritedLossCount: Int(sqlite3_column_int64(statement, 5)),
            inheritedLossBytes: Int(sqlite3_column_int64(statement, 6))
        )
        guard sqlite3_step(statement) == SQLITE_DONE,
              usage.terminalCount >= 0,
              usage.terminalCount <= eventCount,
              usage.promotionCount >= 0,
              usage.promotionCount <= eventCount,
              usage.inheritedLossCount >= 0,
              usage.inheritedLossCount <= eventCount,
              usage.terminalRawBytes >= 0,
              usage.terminalPayloadBytes >= 0,
              usage.promotionBytes >= 0,
              usage.inheritedLossBytes >= 0,
              usage.retainedLogicalBytes
                <= Self.journalOverlayPayloadLimitBytes else {
            throw EventStoreError.decodingFailed(
                "journal block \(blockID) exceeds its overlay bound"
            )
        }
        return usage
    }

    /// One-block exact decode. Overlay and poison queries are proportional to
    /// the low-cardinality rows in this block, never one SQL lookup per Event.
    private func loadExactJournalBlock(
        blockID: Int64
    ) throws -> ExactJournalBlock {
        let baseBlock = try loadJournalBlock(blockID: blockID)
        return try loadExactJournalBlock(
            blockID: blockID,
            authenticatedBase: baseBlock
        )
    }

    /// Reuse a base authenticated for this block in the same synchronous actor
    /// turn. Startup already retains these owned records for summary checking;
    /// decoding them again would repeat I/O and charge a second Event graph.
    /// All overlay and poison validation still runs, and the returned exact
    /// block retains the original base leases alongside its overlay leases.
    private func loadExactJournalBlock(
        blockID: Int64,
        authenticatedBase baseBlock: OwnedJournalBlock
    ) throws -> ExactJournalBlock {
        var events = baseBlock.events
        let baseEvents = events
        var ownershipLeasesByOrdinal = baseBlock.records.map {
            [$0.ownershipLease]
        }
        _ = try journalOverlayUsage(
            blockID: blockID,
            eventCount: events.count
        )
        try validatePoisonIntegrity(
            blockID: blockID,
            baseEvents: baseEvents
        )

        let terminals = try prepare(
            "SELECT ordinal FROM event_journal_terminal_revisions WHERE block_id = ?1 ORDER BY ordinal"
        )
        defer { sqlite3_finalize(terminals) }
        sqlite3_bind_int64(terminals, 1, blockID)
        var terminalRC = sqlite3_step(terminals)
        while terminalRC == SQLITE_ROW {
            let ordinal = Int(sqlite3_column_int(terminals, 0))
            let location = JournalLocation(blockID: blockID, ordinal: ordinal)
            guard ordinal >= 0, ordinal < events.count else {
                throw EventStoreError.decodingFailed(
                    "terminal revision block scan has an invalid ordinal"
                )
            }
            guard let revision = try loadTerminalRevision(
                at: location,
                base: baseEvents[ordinal]
            ) else {
                throw EventStoreError.decodingFailed(
                    "terminal revision block scan has an invalid ordinal"
                )
            }
            let baseJSON = try journalEncoder.encode(baseEvents[ordinal])
            let terminalJSON = try journalEncoder.encode(revision.event)
            guard revision.baseDigest == Data(SHA256.hash(data: baseJSON)),
                  revision.terminalDigest
                    == Data(SHA256.hash(data: terminalJSON)),
                  terminalJSON != baseJSON,
                  terminalRevisionPreservesSourceIdentity(
                    base: baseEvents[ordinal],
                    terminal: revision.event
                  ) else {
                throw EventStoreError.decodingFailed(
                    "terminal revision block scan is not source-bound"
                )
            }
            events[ordinal] = revision.event
            ownershipLeasesByOrdinal[ordinal].append(
                revision.ownershipLease
            )
            terminalRC = sqlite3_step(terminals)
        }
        guard terminalRC == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "terminal revision block scan failed"
            )
        }

        var promoted: [Int: [RuleMatch]] = [:]
        let promotions = try prepare(
            """
            SELECT ordinal, event_id, matches_sha256, matches_json
            FROM event_journal_projection_promotions
            WHERE block_id = ?1 ORDER BY ordinal
            """
        )
        defer { sqlite3_finalize(promotions) }
        sqlite3_bind_int64(promotions, 1, blockID)
        var promotionRC = sqlite3_step(promotions)
        while promotionRC == SQLITE_ROW {
            let ordinal = Int(sqlite3_column_int(promotions, 0))
            let idCount = Int(sqlite3_column_bytes(promotions, 1))
            let digestCount = Int(sqlite3_column_bytes(promotions, 2))
            let jsonCount = Int(sqlite3_column_bytes(promotions, 3))
            guard ordinal >= 0, ordinal < events.count,
                  idCount == 16, digestCount == SHA256.byteCount,
                  jsonCount > 0,
                  jsonCount <= EventJournalCodec.maximumRecordBytes,
                  let idBytes = sqlite3_column_blob(promotions, 1),
                  let digestBytes = sqlite3_column_blob(promotions, 2),
                  let jsonBytes = sqlite3_column_blob(promotions, 3),
                  Data(bytes: idBytes, count: 16)
                    == Self.uuidData(events[ordinal].id) else {
                throw EventStoreError.decodingFailed(
                    "projection promotion block scan is malformed"
                )
            }
            let json = Data(bytes: jsonBytes, count: jsonCount)
            let digest = Data(bytes: digestBytes, count: digestCount)
            guard Data(SHA256.hash(data: json)) == digest,
                  let matches = try? decoder.decode(
                    [RuleMatch].self,
                    from: json
                  ),
                  matches == ReviewedRuleMatches.normalized(matches) else {
                throw EventStoreError.decodingFailed(
                    "projection promotion block checksum/canonical mismatch"
                )
            }
            promoted[ordinal] = ReviewedRuleMatches.merged(
                promoted[ordinal] ?? [],
                matches
            )
            promotionRC = sqlite3_step(promotions)
        }
        guard promotionRC == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "projection promotion block scan failed"
            )
        }
        for (ordinal, matches) in promoted {
            events[ordinal] = event(
                events[ordinal],
                replacingRuleMatches: ReviewedRuleMatches.merged(
                    events[ordinal].ruleMatches,
                    matches
                )
            )
        }

        var poisonByOrdinal: [Int: [EventJournalPoisonRecord]] = [:]
        let poison = try prepare(
            """
            SELECT ordinal, event_id, poison_kind, original_bytes,
                   original_sha256, digest_kind
            FROM event_journal_payload_poison
            WHERE block_id = ?1 ORDER BY ordinal, poison_kind
            """
        )
        defer { sqlite3_finalize(poison) }
        sqlite3_bind_int64(poison, 1, blockID)
        var poisonRC = sqlite3_step(poison)
        while poisonRC == SQLITE_ROW {
            let ordinal = Int(sqlite3_column_int(poison, 0))
            let idCount = Int(sqlite3_column_bytes(poison, 1))
            let digestCount = Int(sqlite3_column_bytes(poison, 4))
            guard ordinal >= 0, ordinal < events.count,
                  idCount == 16, digestCount == SHA256.byteCount,
                  let idBytes = sqlite3_column_blob(poison, 1),
                  let kindBytes = sqlite3_column_text(poison, 2),
                  let digestBytes = sqlite3_column_blob(poison, 4),
                  let digestKindBytes = sqlite3_column_text(poison, 5),
                  Data(bytes: idBytes, count: 16)
                    == Self.uuidData(events[ordinal].id),
                  let kind = EventJournalPoisonRecord.Kind(
                    rawValue: String(cString: kindBytes)
                  ),
                  let digestKind = EventJournalOverflowEvidence.DigestKind(
                    rawValue: String(cString: digestKindBytes)
                  ) else {
                throw EventStoreError.decodingFailed(
                    "journal poison block scan is malformed"
                )
            }
            poisonByOrdinal[ordinal, default: []].append(
                EventJournalPoisonRecord(
                    eventID: events[ordinal].id,
                    kind: kind,
                    originalBytes: Int(sqlite3_column_int64(poison, 3)),
                    originalSHA256: Data(
                        bytes: digestBytes,
                        count: digestCount
                    ),
                    digestKind: digestKind
                )
            )
            poisonRC = sqlite3_step(poison)
        }
        guard poisonRC == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "journal poison block scan failed"
            )
        }

        var inheritedLossOrdinals = Set<Int>()
        let inheritedLoss = try prepare(
            """
            SELECT ordinal, event_id, loss_kind, original_bytes,
                   original_sha256, recovered_fields_json,
                   unavailable_fields_json, ledger_sha256
            FROM event_journal_inherited_loss
            WHERE block_id = ?1 ORDER BY ordinal
            """
        )
        defer { sqlite3_finalize(inheritedLoss) }
        sqlite3_bind_int64(inheritedLoss, 1, blockID)
        var inheritedLossRC = sqlite3_step(inheritedLoss)
        while inheritedLossRC == SQLITE_ROW {
            let ordinal = Int(sqlite3_column_int(inheritedLoss, 0))
            func blob(_ column: Int32) throws -> Data {
                let count = Int(sqlite3_column_bytes(inheritedLoss, column))
                guard count >= 0,
                      count == 0
                        || sqlite3_column_blob(inheritedLoss, column) != nil
                else {
                    throw EventStoreError.decodingFailed(
                        "legacy inherited-loss bytes are unavailable"
                    )
                }
                return count == 0 ? Data() : Data(
                    bytes: sqlite3_column_blob(inheritedLoss, column)!,
                    count: count
                )
            }
            let eventID = try blob(1)
            guard ordinal >= 0, ordinal < baseEvents.count,
                  inheritedLossOrdinals.insert(ordinal).inserted,
                  eventID == Self.uuidData(baseEvents[ordinal].id),
                  let kindPointer = sqlite3_column_text(inheritedLoss, 2)
            else {
                throw EventStoreError.decodingFailed(
                    "legacy inherited-loss ledger has an invalid identity"
                )
            }
            let kind = String(cString: kindPointer)
            guard kind == "structured_truncation"
                    || kind == "sanitizer_rebuild" else {
                throw EventStoreError.decodingFailed(
                    "legacy inherited-loss ledger has an invalid kind"
                )
            }
            let originalBytes: Int?
            if sqlite3_column_type(inheritedLoss, 3) == SQLITE_NULL {
                originalBytes = nil
            } else {
                let value = sqlite3_column_int64(inheritedLoss, 3)
                guard value > 0, value <= Int64(Int.max) else {
                    throw EventStoreError.decodingFailed(
                        "legacy inherited-loss byte count is invalid"
                    )
                }
                originalBytes = Int(value)
            }
            let originalSHA: Data?
            if sqlite3_column_type(inheritedLoss, 4) == SQLITE_NULL {
                originalSHA = nil
            } else {
                let value = try blob(4)
                guard value.count == SHA256.byteCount else {
                    throw EventStoreError.decodingFailed(
                        "legacy inherited-loss source digest is invalid"
                    )
                }
                originalSHA = value
            }
            let recovered = try blob(5)
            let unavailable = try blob(6)
            let ledgerDigest = try blob(7)
            guard recovered.count >= 2, recovered.count <= 8_192,
                  unavailable.count >= 2, unavailable.count <= 8_192,
                  ledgerDigest.count == SHA256.byteCount,
                  let recoveredFields = try? decoder.decode(
                    [String].self,
                    from: recovered
                  ),
                  let unavailableFields = try? decoder.decode(
                    [String].self,
                    from: unavailable
                  ),
                  recoveredFields == Array(Set(recoveredFields)).sorted(),
                  unavailableFields
                    == Array(Set(unavailableFields)).sorted() else {
                throw EventStoreError.decodingFailed(
                    "legacy inherited-loss field ledger is malformed"
                )
            }
            var hasher = SHA256()
            hasher.update(data: Data(
                "MacCrab.LegacyInheritedLoss.v1\u{0}".utf8
            ))
            hasher.update(data: eventID)
            hasher.update(data: Data(kind.utf8))
            var encodedBytes = UInt64(originalBytes ?? Int.max).bigEndian
            withUnsafeBytes(of: &encodedBytes) {
                hasher.update(data: Data($0))
            }
            hasher.update(
                data: originalSHA
                    ?? Data(repeating: 0, count: SHA256.byteCount)
            )
            hasher.update(data: recovered)
            hasher.update(data: unavailable)
            guard Data(hasher.finalize()) == ledgerDigest,
                  kind != "structured_truncation"
                    || baseEvents[ordinal]
                        .enrichments["payload.truncated"] == "true"
            else {
                throw EventStoreError.decodingFailed(
                    "legacy inherited-loss ledger checksum/source binding failed"
                )
            }
            inheritedLossRC = sqlite3_step(inheritedLoss)
        }
        guard inheritedLossRC == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "legacy inherited-loss block scan failed"
            )
        }
        return ExactJournalBlock(
            events: events,
            ownershipLeasesByOrdinal: ownershipLeasesByOrdinal,
            poisonByOrdinal: poisonByOrdinal,
            inheritedLossOrdinals: inheritedLossOrdinals
        )
    }

    private func terminalRevisionTransactionEstimate(
        payloadBytes: Int,
        eventCount: Int,
        canaryProjectionRefreshCount: Int = 0
    ) -> Int64 {
        guard eventCount > 0 else { return 0 }
        let projectionLogical = Int64(eventCount)
            .multipliedReportingOverflow(
                by: Int64(Self.maxRawJsonBytes + 1_024)
            )
        let logical = SQLitePersistentStoreAdmission.saturatingAdd(
            Int64(max(0, payloadBytes)),
            projectionLogical.overflow
                ? Int64.max : projectionLogical.partialValue
        )
        let mutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 2 * eventCount + 2
            )
        let ordinary = SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: mutation,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 8
        )
        guard canaryProjectionRefreshCount > 0 else { return ordinary }
        // A growing canary may replace at most the other three sparse rows
        // in its admission bucket. Charge their FTS/content deletion, bounded
        // disposition roster rewrite and coverage ledgers before any DML.
        // Poison-only settlement keeps the default zero count and its existing
        // protected headroom; this allowance belongs to actual row refreshes.
        let victimMutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes:
                    Int64(Self.projectionBytesPerBucket + 4_096),
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 20
            )
        let perVictim = eventTransactionEstimate(rowMutationBytes: victimMutation)
        let victims = SQLitePersistentStoreAdmission.saturatingMultiply(
            Int64(canaryProjectionRefreshCount),
            by: Int64(Self.projectionRowsPerBucket - 1)
        )
        return SQLitePersistentStoreAdmission.saturatingAdd(
            ordinary,
            SQLitePersistentStoreAdmission.saturatingMultiply(perVictim, by: victims)
        )
    }

    private struct JournalExpiryAggregateKey: Hashable {
        let day: String
        let category: String
        let signer: String
        let processPath: String
    }

    /// Poison rows already present in `exact` are charged by the expiry
    /// estimator itself. Reserve only still-unsettled terminal and reviewed-
    /// promotion gaps. Passing the full block cardinality after a poison had
    /// landed double-counted the row and could make a block appear unexpirable
    /// within one SQLite page of the fixed reserve.
    private func remainingMutablePoisonSlots(
        exact: ExactJournalBlock,
        terminalRevisionCount: Int
    ) -> Int {
        let terminalUnavailable = Set<Int>(exact.poisonByOrdinal.compactMap {
            entry in
            let (ordinal, records) = entry
            return records.contains(where: {
                $0.kind == .base || $0.kind == .terminal
            }) ? ordinal : nil
        })
        let promotionUnavailable = Set<Int>(exact.poisonByOrdinal.compactMap {
            entry in
            let (ordinal, records) = entry
            return records.isEmpty ? nil : ordinal
        })
        let terminalSlots = max(
            0,
            exact.events.count - terminalRevisionCount
                - terminalUnavailable.count
        )
        let promotionSlots = max(
            0,
            exact.events.count - promotionUnavailable.count
        )
        let total = terminalSlots.addingReportingOverflow(promotionSlots)
        return total.overflow ? Int.max : total.partialValue
    }

    /// Every growth mutation that can precede terminal settlement leaves this
    /// small, fixed family/free-space envelope intact. It is sufficient to
    /// record one compact terminal poison for a maximum-size (128-record)
    /// block, so a later capacity decision can degrade to durable gaps instead
    /// of returning a permanent uncommitted remainder.
    private var terminalPoisonSettlementHeadroomBytes: Int64 {
        terminalRevisionTransactionEstimate(
            payloadBytes: EventJournalCodec.maximumEventsPerBlock * 512,
            eventCount: EventJournalCodec.maximumEventsPerBlock
        )
    }

    /// Recompute the transaction that would retire this block *now*. Every
    /// terminal/promotion mutation runs this prospective check while holding
    /// BEGIN IMMEDIATE, so a large base can accept only the overlay headroom
    /// that still leaves base+cascade+rollup+projection below 32 MiB.
    private func journalExpiryTransactionEstimate(
        blockID: Int64,
        exact: ExactJournalBlock,
        overlayCascadePayloadBytes: Int,
        additionalPoisonCount: Int = 0
    ) throws -> Int64 {
        guard additionalPoisonCount >= 0 else { return Int64.max }
        let block = try prepare(
            "SELECT length(payload) FROM event_journal_blocks WHERE block_id = ?1"
        )
        sqlite3_bind_int64(block, 1, blockID)
        guard sqlite3_step(block) == SQLITE_ROW else {
            sqlite3_finalize(block)
            throw EventStoreError.decodingFailed(
                "journal expiry estimate references a missing block"
            )
        }
        let basePayloadBytes = Int(sqlite3_column_int64(block, 0))
        sqlite3_finalize(block)

        let coverage = try prepare(
            "SELECT materialized_count, materialized_bytes FROM event_projection_block_coverage WHERE block_id = ?1"
        )
        sqlite3_bind_int64(coverage, 1, blockID)
        guard sqlite3_step(coverage) == SQLITE_ROW else {
            sqlite3_finalize(coverage)
            throw EventStoreError.decodingFailed(
                "journal expiry estimate is missing block coverage"
            )
        }
        let materialized = Int(sqlite3_column_int64(coverage, 0))
        let materializedBytes = sqlite3_column_int64(coverage, 1)
        sqlite3_finalize(coverage)

        var keys = Set<JournalExpiryAggregateKey>()
        var gapKeys = Set<String>()
        for (ordinal, event) in exact.events.enumerated() {
            let path = Self.boundIndexedText(
                event.process.executable,
                maxBytes: 2_048
            )
            let day = Self.isoDay(event.timestamp)
            let category = event.eventCategory.rawValue
            keys.insert(JournalExpiryAggregateKey(
                day: day,
                category: category,
                signer: event.process.codeSignature?.signerType.rawValue ?? "",
                processPath: path
            ))
            if exact.poisonByOrdinal[ordinal] != nil {
                gapKeys.insert("\(day)\u{1f}\(category)\u{1f}canonical_poison")
            } else {
                if exact.inheritedLossOrdinals.contains(ordinal) {
                    gapKeys.insert(
                        "\(day)\u{1f}\(category)\u{1f}inherited_legacy_loss"
                    )
                }
                if path != event.process.executable {
                    gapKeys.insert(
                        "\(day)\u{1f}\(category)\u{1f}aggregate_key_compacted"
                    )
                }
            }
        }
        var aggregateLogical: Int64 = 0
        for key in keys {
            aggregateLogical = SQLitePersistentStoreAdmission.saturatingAdd(
                aggregateLogical,
                Int64(
                    256 + key.day.utf8.count + key.category.utf8.count
                        + key.signer.utf8.count + key.processPath.utf8.count
                )
            )
        }
        for key in gapKeys {
            aggregateLogical = SQLitePersistentStoreAdmission.saturatingAdd(
                aggregateLogical,
                Int64(192 + key.utf8.count)
            )
        }
        let aggregateMutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: aggregateLogical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: max(
                    4,
                    (keys.count + gapKeys.count) * 2
                )
            )
        let projectionMutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: max(
                    materializedBytes,
                    // A block belongs to one admission bucket and can own at
                    // most four sparse rows. Reserve their full bounded JSON
                    // shape so a later reviewed rewrite cannot invalidate the
                    // block's already-proved expiry envelope.
                    Int64(
                        Self.projectionRowsPerBucket * Self.maxRawJsonBytes
                    )
                ),
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: max(8, materialized * 8 + 8)
            )
        let cascade = basePayloadBytes.addingReportingOverflow(
            overlayCascadePayloadBytes
        )
        guard !cascade.overflow else { return Int64.max }
        var poisonCount = additionalPoisonCount
        for records in exact.poisonByOrdinal.values {
            let next = poisonCount.addingReportingOverflow(records.count)
            guard !next.overflow else { return Int64.max }
            poisonCount = next.partialValue
        }
        return journalBlockTransactionEstimate(
            payloadBytes: cascade.partialValue,
            eventCount: exact.events.count,
            legacyRowMutationBytes: SQLitePersistentStoreAdmission
                .saturatingAdd(aggregateMutation, projectionMutation),
            poisonCount: poisonCount
        )
    }

    /// Payload-independent upper bound used by the one-record terminal path.
    /// It reserves one distinct bounded aggregate key and every possible
    /// canonical/inherited/compaction gap per ordinal, plus all three poison
    /// kinds. Base formation proves this same bound before COMMIT, so a later
    /// sparse delta can be admitted from SQL metadata without retaining and
    /// decoding the other 127 Event graphs.
    private func journalExpiryWorstCaseTransactionEstimate(
        blockID: Int64,
        eventCount: Int,
        overlayCascadePayloadBytes: Int
    ) throws -> Int64 {
        guard eventCount > 0,
              eventCount <= EventJournalCodec.maximumEventsPerBlock,
              overlayCascadePayloadBytes >= 0 else {
            return Int64.max
        }
        let block = try prepare(
            "SELECT length(payload) FROM event_journal_blocks WHERE block_id = ?1"
        )
        sqlite3_bind_int64(block, 1, blockID)
        guard sqlite3_step(block) == SQLITE_ROW else {
            sqlite3_finalize(block)
            throw EventStoreError.decodingFailed(
                "worst-case expiry estimate references a missing block"
            )
        }
        let basePayloadBytes = Int(sqlite3_column_int64(block, 0))
        sqlite3_finalize(block)

        let coverage = try prepare(
            "SELECT materialized_count, materialized_bytes FROM event_projection_block_coverage WHERE block_id = ?1"
        )
        sqlite3_bind_int64(coverage, 1, blockID)
        guard sqlite3_step(coverage) == SQLITE_ROW else {
            sqlite3_finalize(coverage)
            throw EventStoreError.decodingFailed(
                "worst-case expiry estimate is missing block coverage"
            )
        }
        let materialized = Int(sqlite3_column_int64(coverage, 0))
        let materializedBytes = sqlite3_column_int64(coverage, 1)
        sqlite3_finalize(coverage)

        // 2 KiB bounded process path plus day/category/signer/row/index slack,
        // and three distinct gap reasons for every ordinal.
        let aggregateLogical = SQLitePersistentStoreAdmission
            .saturatingMultiply(Int64(eventCount), by: 4_096)
        let aggregateMutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: aggregateLogical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: max(8, eventCount * 8)
            )
        let projectionMutation = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: max(
                    materializedBytes,
                    Int64(
                        Self.projectionRowsPerBucket * Self.maxRawJsonBytes
                    )
                ),
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: max(8, materialized * 8 + 8)
            )
        let cascade = basePayloadBytes.addingReportingOverflow(
            overlayCascadePayloadBytes
        )
        let poisonCount = eventCount.multipliedReportingOverflow(by: 3)
        guard !cascade.overflow, !poisonCount.overflow else {
            return Int64.max
        }
        return journalBlockTransactionEstimate(
            payloadBytes: cascade.partialValue,
            eventCount: eventCount,
            legacyRowMutationBytes: SQLitePersistentStoreAdmission
                .saturatingAdd(aggregateMutation, projectionMutation),
            poisonCount: poisonCount.partialValue
        )
    }

    private static func journalBlockMetadata(
        _ events: [Event],
        now: TimeInterval,
        admissionBucketOverride: Int64? = nil
    ) throws -> JournalBlockMetadata {
        guard let first = events.first else {
            throw EventJournalCodecError.emptyBlock
        }
        let firstTimestamp = first.timestamp.timeIntervalSince1970
        guard firstTimestamp.isFinite else {
            throw EventStoreError.encodingFailed("Event timestamp is non-finite")
        }
        var minimum = firstTimestamp
        var maximum = firstTimestamp
        var categories: [EventCategory: JournalCategoryMetadata] = [:]
        for event in events {
            let timestamp = event.timestamp.timeIntervalSince1970
            guard timestamp.isFinite else {
                throw EventStoreError.encodingFailed(
                    "Event timestamp is non-finite"
                )
            }
            minimum = min(minimum, timestamp)
            maximum = max(maximum, timestamp)
            categories[event.eventCategory, default: JournalCategoryMetadata()]
                .include(timestamp)
        }
        let admissionBucket = admissionBucketOverride ?? Int64(floor(now))
        return JournalBlockMetadata(
            minimum: minimum,
            maximum: maximum,
            // Retention is measured from durable admission, not attacker-
            // controlled/event-source wall time. Out-of-order or future-dated
            // events therefore receive the complete floor without pinning a
            // block forever.
            retainedUntil: admissionBucketOverride == nil
                ? now + journalRetentionSeconds
                : Double(admissionBucket) + journalRetentionSeconds,
            admissionBucket: admissionBucket,
            byCategory: categories
        )
    }

    private static func journalSummaryMatchesPayload(
        stored: JournalBlockMetadata,
        decoded events: [Event]
    ) throws -> Bool {
        guard !events.isEmpty else { return false }
        let derived = try journalBlockMetadata(
            events,
            now: stored.retainedUntil - journalRetentionSeconds
        )
        guard derived.minimum == stored.minimum,
              derived.maximum == stored.maximum,
              derived.admissionBucket == stored.admissionBucket else {
            return false
        }
        for category in EventCategory.allCases {
            let left = stored.byCategory[category] ?? JournalCategoryMetadata()
            let right = derived.byCategory[category] ?? JournalCategoryMetadata()
            guard left.count == right.count,
                  left.minimum == right.minimum,
                  left.maximum == right.maximum else {
                return false
            }
        }
        return true
    }

    /// Called only after BEGIN IMMEDIATE. The in-memory UUID locator was built
    /// before waiting for the cross-process writer lock, so its topology token
    /// must still equal the durable singleton before a new roster is inserted.
    /// SQLite then keeps every competing writer out until COMMIT.
    private func requireCurrentJournalIdentityUnderWriterLock() throws {
        guard let expected = journalIndexTopologyGeneration else {
            throw EventStoreError.journalBlockRequiresIdentityRefresh
        }
        let statement = try prepare(
            """
            SELECT journal_topology_generation
            FROM event_storage_state WHERE singleton = 1
            """
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.decodingFailed(
                "event journal topology token is unavailable under writer lock"
            )
        }
        let current = sqlite3_column_int64(statement, 0)
        guard current >= 0, sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "event journal topology token is corrupt under writer lock"
            )
        }
        guard current == expected else {
            throw EventStoreError.journalBlockRequiresIdentityRefresh
        }
    }

    /// Admission is first evaluated before waiting for SQLite's cross-process
    /// writer lock. Re-measure after BEGIN IMMEDIATE and before the first page
    /// mutation so another writer's just-committed WAL cannot make that earlier
    /// headroom decision stale.
    private func requireCurrentFamilyCapacityUnderWriterLock(
        estimatedBytes: Int64,
        postCommitHeadroomBytes: Int64 = 0,
        lane: EventPipelineLane? = nil,
        maintenance: Bool = false
    ) throws {
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        let protectedHeadroom = terminalSettlementProtectionActive
            ? max(
                postCommitHeadroomBytes,
                terminalPoisonSettlementHeadroomBytes
            )
            : postCommitHeadroomBytes
        guard estimatedBytes >= 0, estimatedBytes <= reserve else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: estimatedBytes,
                    reserveBytes: reserve
                )
        }
        guard protectedHeadroom >= 0, protectedHeadroom <= reserve else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: protectedHeadroom,
                    reserveBytes: reserve
                )
        }
        if var admission = storageAdmission {
            defer { storageAdmission = admission }
            try admission.admitSerializedWrite(
                estimatedTransactionBytes: estimatedBytes,
                postCommitHeadroomBytes: protectedHeadroom,
                maintenance: maintenance,
                on: db
            )
            if !maintenance {
                try enforceFileLaneReserve(
                    admission,
                    estimatedTransactionBytes:
                        SQLitePersistentStoreAdmission.saturatingAdd(
                            estimatedBytes,
                            protectedHeadroom
                        ),
                    lane: lane ?? .priority
                )
            }
        } else {
            let policy = storagePolicy
                ?? Self.defaultStoragePolicy(for: databasePath)
            let family = try SQLitePersistentStoreAdmission.measureFamily(
                databasePath
            )
            guard SQLitePersistentStoreAdmission.saturatingAdd(
                family,
                SQLitePersistentStoreAdmission.saturatingAdd(
                    estimatedBytes,
                    protectedHeadroom
                )
            ) <= policy.maxFootprintBytes else {
                throw EventStoreError.storageNotReady(
                    "cross-process writer consumed the measured event-store transaction headroom"
                )
            }
            let free = try SQLitePersistentStoreAdmission.measureFreeSpace(
                policy.storageVolumePath
            )
            let floor = maintenance ? 0 : policy.freeSpaceFloorBytes
            guard SQLitePersistentStoreAdmission.saturatingAdd(
                floor,
                SQLitePersistentStoreAdmission.saturatingAdd(
                    estimatedBytes,
                    protectedHeadroom
                )
            ) <= free else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    reserveBytes: estimatedBytes,
                    requiredFreeBytes:
                        SQLitePersistentStoreAdmission.saturatingAdd(
                            floor,
                            SQLitePersistentStoreAdmission.saturatingAdd(
                            estimatedBytes,
                            protectedHeadroom
                            )
                        )
                )
            }
        }
    }

    /// Serialize every rc.13 journal-family writer before its authoritative
    /// capacity decision. Calling `execute("BEGIN ...")` would run admission
    /// before SQLite waits for the cross-process writer lock, leaving a TOCTOU
    /// window in which another connection can consume the measured headroom.
    /// This helper acquires the lock without DML, then re-probes the complete
    /// family/free-space estimate while that lock is held. A refusal rolls the
    /// empty transaction back, so no page mutation can precede admission.
    private func beginSerializedWrite(
        estimatedBytes: Int64,
        postCommitHeadroomBytes: Int64 = 0,
        lane: EventPipelineLane? = nil,
        maintenance: Bool = false
    ) throws {
        guard let db else {
            throw EventStoreError.stepFailed(
                "serialized event-store write has no database handle"
            )
        }
        guard sqlite3_get_autocommit(db) != 0 else {
            throw EventStoreError.stepFailed(
                "serialized event-store write attempted inside a transaction"
            )
        }
        let protectedHeadroom = terminalSettlementProtectionActive
            ? max(
                postCommitHeadroomBytes,
                terminalPoisonSettlementHeadroomBytes
            )
            : postCommitHeadroomBytes
        try Self.exec(db, "BEGIN IMMEDIATE TRANSACTION")
        do {
            try requireCurrentFamilyCapacityUnderWriterLock(
                estimatedBytes: estimatedBytes,
                postCommitHeadroomBytes: protectedHeadroom,
                lane: lane,
                maintenance: maintenance
            )
        } catch {
            try? Self.exec(db, "ROLLBACK")
            throw error
        }
    }

    /// Execute one bounded mutation behind the same cross-process writer-lock
    /// and authoritative capacity gate used by the journal. Runtime
    /// maintenance is included: a logical DELETE or FTS merge may still append
    /// full page images to a reader-pinned WAL, so autocommit is not a safe
    /// substitute for serialized admission.
    private func withSerializedWrite<Result>(
        estimatedBytes: Int64,
        postCommitHeadroomBytes: Int64 = 0,
        lane: EventPipelineLane? = nil,
        maintenance: Bool = false,
        _ body: () throws -> Result
    ) throws -> Result {
        try beginSerializedWrite(
            estimatedBytes: estimatedBytes,
            postCommitHeadroomBytes: postCommitHeadroomBytes,
            lane: lane,
            maintenance: maintenance
        )
        do {
            let result = try body()
            try execute("COMMIT")
            return result
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    private func insertJournalBlock(
        _ preparedEvents: [PreparedPersistedEvent],
        lane: EventPipelineLane,
        admissionBucketOverride: Int64? = nil,
        projectionMode: JournalProjectionMode = .normal,
        legacyRowIDs: [Int64] = [],
        legacySourceDigests: [Data] = [],
        legacyInheritedLosses: [LegacyInheritedLoss?] = [],
        legacyRowMutationBytes: Int64 = 0,
        migrationProgress: (migrated: Int, lastRowID: Int64)? = nil
    ) throws -> Int64 {
        guard legacyInheritedLosses.isEmpty
                || legacyInheritedLosses.count == preparedEvents.count else {
            throw EventStoreError.encodingFailed(
                "legacy inherited-loss ordinals do not match journal records"
            )
        }
        guard legacyRowIDs.count == legacySourceDigests.count else {
            throw EventStoreError.encodingFailed(
                "legacy source identities do not match migration row ids"
            )
        }
        let records = preparedEvents.map(\.canonicalJSON)
        let codecWorkspace = try acquireEventStoreWorkspace(
            context: "event journal block encode"
        )
        let block = try EventJournalCodec.prepare(
            jsonRecords: records,
            workspaceLease: codecWorkspace
        )
        let events = preparedEvents.map(\.event)
        var roster = Data()
        roster.reserveCapacity(events.count * 16)
        for event in events { roster.append(Self.uuidData(event.id)) }
        var sourceIdentityRoster = Data()
        sourceIdentityRoster.reserveCapacity(
            preparedEvents.count * SHA256.byteCount
        )
        for prepared in preparedEvents {
            guard prepared.sourceIdentitySHA256.count == SHA256.byteCount else {
                throw EventStoreError.encodingFailed(
                    "journal raw source identity has an invalid digest length"
                )
            }
            sourceIdentityRoster.append(prepared.sourceIdentitySHA256)
        }
        let initialDisposition: JournalProjectionDisposition =
            projectionMode == .migrationSplit ? .migrationSplit : .quota
        let initialDispositions = Self.projectionDispositionData(
            [JournalProjectionDisposition](
                repeating: initialDisposition,
                count: events.count
            )
        )
        let initialDispositionDigest = Data(
            SHA256.hash(data: initialDispositions)
        )
        let inheritedLossCount = legacyInheritedLosses.compactMap { $0 }.count
        let inheritedLossMutation = inheritedLossCount == 0 ? 0
            : SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: Int64(
                        inheritedLossCount * 20 * 1_024
                    ),
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumLeafPageTouches: inheritedLossCount * 2
                )
        let estimate = journalBlockTransactionEstimate(
            payloadBytes: block.payload.storedBytes,
            eventCount: events.count,
            legacyRowMutationBytes:
                SQLitePersistentStoreAdmission.saturatingAdd(
                    legacyRowMutationBytes,
                    inheritedLossMutation
                ),
            poisonCount: preparedEvents.reduce(into: 0) { count, prepared in
                if prepared.overflow != nil { count += 1 }
            }
        )
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        guard estimate <= reserve else {
            throw EventStoreError.stepFailed(
                "journal block transaction estimate \(estimate) exceeds reserve \(reserve)"
            )
        }
        // Split migration appends deliberately leave the legacy row in place
        // until a second bounded transaction. They still require the recovery
        // hard-cap check and do not need future producer settlement headroom.
        let maintenance = projectionMode == .migrationSplit
            || !legacyRowIDs.isEmpty || inheritedLossCount > 0
        if maintenance {
            try admitJournalRecoveryTransaction(
                estimatedBytes: estimate
            )
        }
        try beginSerializedWrite(
            estimatedBytes: estimate,
            // Fresh producer bases keep the complete serialized transaction
            // reserve available after COMMIT. Terminal delta or sticky-poison
            // settlement may then consume that headroom even when the family
            // sits at its steady-state boundary. Migration rows are already
            // terminal and run before producers, so they do not reserve it.
            postCommitHeadroomBytes: maintenance ? 0 : reserve,
            lane: lane,
            maintenance: maintenance
        )
        do {
            try requireCurrentJournalIdentityUnderWriterLock()
            for (rowID, digest) in zip(
                legacyRowIDs,
                legacySourceDigests
            ) {
                guard try legacyTypedRowDigest(rowID: rowID) == digest else {
                    throw EventStoreError.storageNotReady(
                        "legacy migration source moved before its writer lock; retry recovery"
                    )
                }
            }
            // Retention begins at the serialized admission boundary. Waiting
            // behind another process can never consume part of the durable
            // fifteen-minute floor or assign a normal block to an old bucket.
            let now = Date().timeIntervalSince1970
            let metadata = try Self.journalBlockMetadata(
                events,
                now: now,
                admissionBucketOverride: admissionBucketOverride
            )
            let metadataDigest = try Self.journalMetadataDigest(
                metadata: metadata,
                eventCount: events.count,
                roster: roster,
                sourceIdentityRoster: sourceIdentityRoster,
                rawBytes: block.rawBytes,
                codec: block.codec,
                payloadDigest: block.digest
            )
            let sql = """
                INSERT INTO event_journal_blocks (
                    min_timestamp, max_timestamp, retained_until,
                    admission_bucket, event_count,
                    process_count, process_min_timestamp, process_max_timestamp,
                    file_count, file_min_timestamp, file_max_timestamp,
                    network_count, network_min_timestamp, network_max_timestamp,
                    authentication_count, authentication_min_timestamp, authentication_max_timestamp,
                    tcc_count, tcc_min_timestamp, tcc_max_timestamp,
                    registry_count, registry_min_timestamp, registry_max_timestamp,
                    event_ids, source_identity_sha256s,
                    projection_dispositions,
                    projection_dispositions_sha256,
                    raw_bytes, codec, sha256, metadata_sha256, payload
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32)
                """
            let statement = try prepare(sql)
            defer { sqlite3_finalize(statement) }
            sqlite3_bind_double(statement, 1, metadata.minimum)
            sqlite3_bind_double(statement, 2, metadata.maximum)
            sqlite3_bind_double(statement, 3, metadata.retainedUntil)
            sqlite3_bind_int64(statement, 4, metadata.admissionBucket)
            sqlite3_bind_int(statement, 5, Int32(events.count))
            var bindIndex: Int32 = 6
            for category in EventCategory.allCases {
                let value = metadata.byCategory[category]
                    ?? JournalCategoryMetadata()
                sqlite3_bind_int(statement, bindIndex, Int32(value.count))
                bindIndex += 1
                if let minimum = value.minimum {
                    sqlite3_bind_double(statement, bindIndex, minimum)
                } else {
                    sqlite3_bind_null(statement, bindIndex)
                }
                bindIndex += 1
                if let maximum = value.maximum {
                    sqlite3_bind_double(statement, bindIndex, maximum)
                } else {
                    sqlite3_bind_null(statement, bindIndex)
                }
                bindIndex += 1
            }
            bindBlob(statement, index: 24, value: roster)
            bindBlob(statement, index: 25, value: sourceIdentityRoster)
            bindBlob(statement, index: 26, value: initialDispositions)
            bindBlob(statement, index: 27, value: initialDispositionDigest)
            sqlite3_bind_int64(statement, 28, Int64(block.rawBytes))
            sqlite3_bind_int(statement, 29, Int32(block.codec))
            bindBlob(statement, index: 30, value: block.digest)
            bindBlob(statement, index: 31, value: metadataDigest)
            switch block.payload {
            case .compressed(let payload):
                bindBlob(statement, index: 32, value: payload)
            case .rawFragments:
                guard sqlite3_bind_zeroblob64(
                    statement,
                    32,
                    sqlite3_uint64(block.payload.storedBytes)
                ) == SQLITE_OK else {
                    throw EventStoreError.stepFailed(
                        "event journal raw zeroblob bind failed"
                    )
                }
            }
            guard sqlite3_step(statement) == SQLITE_DONE else {
                throw EventStoreError.stepFailed(
                    "event journal block insert failed: \(String(cString: sqlite3_errmsg(db)))"
                )
            }
            let blockID = sqlite3_last_insert_rowid(db)
            guard blockID > 0,
                  blockID <= Self.maximumPackedJournalBlockID else {
                throw EventStoreError.stepFailed(
                    "event journal block id exceeds the packed locator range"
                )
            }
            try writeRawJournalPayload(
                block.payload,
                table: "event_journal_blocks",
                rowID: blockID,
                context: "event journal block \(blockID)"
            )
            for (ordinal, prepared) in preparedEvents.enumerated() {
                if let overflow = prepared.overflow {
                    try persistCanonicalOverflowPoison(
                        overflow,
                        replacementDigest: prepared.recordDigest,
                        kind: "base",
                        location: JournalLocation(
                            blockID: blockID,
                            ordinal: ordinal
                        ),
                        now: now
                    )
                }
            }
            if !legacyInheritedLosses.isEmpty {
                let lossInsert = try prepare(
                    """
                    INSERT INTO event_journal_inherited_loss (
                        block_id, ordinal, event_id, loss_kind,
                        original_bytes, original_sha256,
                        recovered_fields_json, unavailable_fields_json,
                        ledger_sha256, created_at
                    ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                    """
                )
                defer { sqlite3_finalize(lossInsert) }
                for (ordinal, loss) in legacyInheritedLosses.enumerated() {
                    guard let loss else { continue }
                    let recovered = try journalEncoder.encode(
                        loss.recoveredFields
                    )
                    let unavailable = try journalEncoder.encode(
                        loss.unavailableFields
                    )
                    guard recovered.count <= 8_192,
                          unavailable.count <= 8_192 else {
                        throw EventStoreError.encodingFailed(
                            "legacy inherited-loss field ledger exceeds bound"
                        )
                    }
                    let eventID = Self.uuidData(events[ordinal].id)
                    var hasher = SHA256()
                    hasher.update(data: Data(
                        "MacCrab.LegacyInheritedLoss.v1\u{0}".utf8
                    ))
                    hasher.update(data: eventID)
                    hasher.update(data: Data(loss.kind.utf8))
                    var originalBytes = UInt64(
                        loss.originalBytes ?? Int.max
                    ).bigEndian
                    withUnsafeBytes(of: &originalBytes) {
                        hasher.update(data: Data($0))
                    }
                    hasher.update(
                        data: loss.originalSHA256
                            ?? Data(repeating: 0, count: SHA256.byteCount)
                    )
                    hasher.update(data: recovered)
                    hasher.update(data: unavailable)

                    sqlite3_reset(lossInsert)
                    sqlite3_clear_bindings(lossInsert)
                    sqlite3_bind_int64(lossInsert, 1, blockID)
                    sqlite3_bind_int(lossInsert, 2, Int32(ordinal))
                    bindBlob(lossInsert, index: 3, value: eventID)
                    bindText(lossInsert, index: 4, value: loss.kind)
                    if let bytes = loss.originalBytes {
                        sqlite3_bind_int64(lossInsert, 5, Int64(bytes))
                    } else {
                        sqlite3_bind_null(lossInsert, 5)
                    }
                    if let digest = loss.originalSHA256 {
                        bindBlob(lossInsert, index: 6, value: digest)
                    } else {
                        sqlite3_bind_null(lossInsert, 6)
                    }
                    bindBlob(lossInsert, index: 7, value: recovered)
                    bindBlob(lossInsert, index: 8, value: unavailable)
                    bindBlob(
                        lossInsert,
                        index: 9,
                        value: Data(hasher.finalize())
                    )
                    sqlite3_bind_double(lossInsert, 10, now)
                    guard sqlite3_step(lossInsert) == SQLITE_DONE else {
                        throw EventStoreError.stepFailed(
                            "legacy inherited-loss ledger insert failed"
                        )
                    }
                }
            }
            if !legacyRowIDs.isEmpty {
                let rowList = legacyRowIDs.map(String.init).joined(separator: ",")
                try execute(
                    "DELETE FROM events_fts WHERE rowid IN (\(rowList))"
                )
                try execute(
                    "DELETE FROM events WHERE rowid IN (\(rowList))"
                )
                guard sqlite3_changes(db) == Int32(legacyRowIDs.count) else {
                    throw EventStoreError.stepFailed(
                        "legacy journal migration deleted an unexpected row count"
                    )
                }
            }
            let blockCoverage = try prepare(
                "INSERT INTO event_projection_block_coverage (block_id, bucket_start) VALUES (?1, ?2)"
            )
            sqlite3_bind_int64(blockCoverage, 1, blockID)
            sqlite3_bind_int64(
                blockCoverage, 2, metadata.admissionBucket
            )
            let coverageRC = sqlite3_step(blockCoverage)
            sqlite3_finalize(blockCoverage)
            guard coverageRC == SQLITE_DONE else {
                throw EventStoreError.stepFailed(
                    "event projection block coverage insert failed"
                )
            }
            switch projectionMode {
            case .normal:
                try finalizeProjectionForBlock(
                    preparedEvents,
                    blockID: blockID,
                    admissionBucket: metadata.admissionBucket
                )
            case .migrationSplit:
                // The still-present legacy row owns this UUID until the next
                // bounded transaction. Trying to insert a sparse row here
                // would collide and deadlock recovery. Record the transition-
                // specific omission durably and visibly instead; exact journal
                // evidence is already complete, and the subsequent source
                // deletion is UUID/digest-idempotent after a crash.
                var delta = ProjectionCoverageDelta()
                delta.considered = preparedEvents.count
                delta.omittedMigration = preparedEvents.count
                try persistProjectionCoverage(
                    bucket: metadata.admissionBucket,
                    blockID: blockID,
                    newBlock: delta,
                    displacedByBlock: [:],
                    now: now
                )
            }
            // The caller's prepared J ownership and this block's S payload
            // are still live until COMMIT. Re-decoding the just-written block
            // here would duplicate both graphs and require a second S lease.
            // Build the prospective exact view from the authenticated inputs
            // already used for this INSERT instead.
            var prospectivePoison: [Int: [EventJournalPoisonRecord]] = [:]
            for (ordinal, prepared) in preparedEvents.enumerated() {
                if let overflow = prepared.overflow {
                    prospectivePoison[ordinal] = [EventJournalPoisonRecord(
                        eventID: prepared.event.id,
                        kind: .base,
                        originalBytes: overflow.originalBytes,
                        originalSHA256: overflow.originalSHA256,
                        digestKind: overflow.digestKind
                    )]
                }
            }
            let prospectiveExact = ExactJournalBlock(
                events: events,
                ownershipLeasesByOrdinal: Array(
                    repeating: [],
                    count: events.count
                ),
                poisonByOrdinal: prospectivePoison,
                inheritedLossOrdinals: Set(
                    legacyInheritedLosses.enumerated().compactMap {
                        $0.element == nil ? nil : $0.offset
                    }
                )
            )
            let prospectiveUsage = try journalOverlayUsage(
                blockID: blockID,
                eventCount: prospectiveExact.events.count
            )
            guard try journalExpiryTransactionEstimate(
                blockID: blockID,
                exact: prospectiveExact,
                overlayCascadePayloadBytes:
                    prospectiveUsage.cascadePayloadBytes,
                // Every non-poison base may later need one sticky terminal gap
                // and one sticky reviewed-promotion gap. Reserve both bounded
                // expiry rows at formation so capacity pressure always settles
                // durably instead of becoming an unretryable volatile error.
                additionalPoisonCount: remainingMutablePoisonSlots(
                    exact: prospectiveExact,
                    terminalRevisionCount: prospectiveUsage.terminalCount
                )
            ) <= reserve,
                  try journalExpiryWorstCaseTransactionEstimate(
                    blockID: blockID,
                    eventCount: prospectiveExact.events.count,
                    overlayCascadePayloadBytes:
                        prospectiveUsage.cascadePayloadBytes
                  ) <= reserve else {
                throw EventStoreError.journalBlockRequiresSplit(
                    eventCount: preparedEvents.count
                )
            }
            if let migrationProgress {
                let progress = try prepare(
                    """
                    UPDATE event_journal_migration SET
                        last_legacy_rowid = MAX(last_legacy_rowid, ?1),
                        migrated_events = migrated_events + ?2,
                        remaining_events = remaining_events - ?2,
                        updated_at = ?3
                    WHERE singleton = 1
                    """
                )
                sqlite3_bind_int64(progress, 1, migrationProgress.lastRowID)
                sqlite3_bind_int64(progress, 2, Int64(migrationProgress.migrated))
                sqlite3_bind_double(progress, 3, now)
                let progressRC = sqlite3_step(progress)
                sqlite3_finalize(progress)
                guard progressRC == SQLITE_DONE,
                      sqlite3_changes(db) == 1 else {
                    throw EventStoreError.stepFailed(
                        "legacy journal migration progress update failed"
                    )
                }
            }
            try advanceStorageMutationGeneration(now: now)
            try execute("COMMIT")
            for (ordinal, event) in events.enumerated() {
                let location = JournalLocation(
                    blockID: blockID,
                    ordinal: ordinal
                )
                if journalIndexedLocationCount
                    < Self.journalInMemoryLocationLimit {
                    journalDeltaLocations.insert(
                        PackedJournalEntry(id: event.id, location: location)
                    )
                    journalIndexedLocationCount += 1
                } else {
                    journalIndexOverflowed = true
                    journalOverflowBloom.insert(event.id)
                    journalOverflowFirstBlockID = min(
                        journalOverflowFirstBlockID ?? blockID,
                        blockID
                    )
                }
            }
            verifiedJournalSummaries.append(
                VerifiedJournalSummary(
                    blockID: blockID,
                    eventCount: events.count,
                    metadata: metadata
                )
            )
            if let topologyGeneration = journalIndexTopologyGeneration {
                journalIndexTopologyGeneration = topologyGeneration + 1
                journalIndexedBlockCount += 1
                journalIndexedMinimumBlockID = min(
                    journalIndexedMinimumBlockID ?? blockID,
                    blockID
                )
                journalIndexedMaximumBlockID = max(
                    journalIndexedMaximumBlockID ?? blockID,
                    blockID
                )
            }
            journalVerifiedBlocks += 1
            committedBatchInsertTransactions &+= 1
            return blockID
        } catch let error as EventStoreError {
            try? execute("ROLLBACK")
            if case .journalBlockRequiresSplit = error {
                // No COMMIT was attempted: the cache remains authoritative and
                // the caller can safely reform a smaller prefix immediately.
                throw error
            }
            // COMMIT errors can have an uncertain durable outcome. Force the
            // next operation to reconstruct truth from append-local rosters.
            journalIndexLoaded = false
            journalIndexTopologyGeneration = nil
            journalIndexedBlockCount = 0
            journalIndexedMinimumBlockID = nil
            journalIndexedMaximumBlockID = nil
            journalBaseLocations.removeAll(keepingCapacity: false)
            journalDeltaLocations.removeAll()
            journalIndexedLocationCount = 0
            journalOverflowBloom = JournalBloom()
            journalOverflowFirstBlockID = nil
            journalIndexOverflowed = false
            journalExpiredBlockTombstones.removeAll(keepingCapacity: false)
            journalExpirySummaryCursor = 0
            journalExpirySummaryCutoff = nil
            verifiedJournalSummaries.removeAll(keepingCapacity: false)
            journalVerifiedBlocks = 0
            throw error
        } catch {
            try? execute("ROLLBACK")
            // COMMIT errors can have an uncertain durable outcome. Force the
            // next operation to reconstruct truth from append-local rosters.
            journalIndexLoaded = false
            journalIndexTopologyGeneration = nil
            journalIndexedBlockCount = 0
            journalIndexedMinimumBlockID = nil
            journalIndexedMaximumBlockID = nil
            journalBaseLocations.removeAll(keepingCapacity: false)
            journalDeltaLocations.removeAll()
            journalIndexedLocationCount = 0
            journalOverflowBloom = JournalBloom()
            journalOverflowFirstBlockID = nil
            journalIndexOverflowed = false
            journalExpiredBlockTombstones.removeAll(keepingCapacity: false)
            journalExpirySummaryCursor = 0
            journalExpirySummaryCutoff = nil
            verifiedJournalSummaries.removeAll(keepingCapacity: false)
            journalVerifiedBlocks = 0
            throw error
        }
    }

    /// Complete worst-case transaction charge for one append-local journal
    /// block. `payloadBytes` may be the actual compressed payload at execution
    /// or the larger raw framed size while choosing a chunk. The latter keeps
    /// chunk formation page-size-aware without repeatedly compressing every
    /// candidate prefix. Legacy migration additionally deletes the old wide
    /// row plus its indexes and FTS postings in this same transaction, so that
    /// already-WAL-amplified mutation charge is included rather than hidden
    /// behind maintenance admission.
    private func journalBlockTransactionEstimate(
        payloadBytes: Int,
        eventCount: Int,
        legacyRowMutationBytes: Int64 = 0,
        poisonCount: Int = 0
    ) -> Int64 {
        guard payloadBytes >= 0, eventCount >= 0, poisonCount >= 0,
              legacyRowMutationBytes >= 0 else { return Int64.max }
        let rosterAndMetadata = SQLitePersistentStoreAdmission.saturatingAdd(
            Int64(eventCount * (16 + 48)),
            4_096
        )
        let journalLogicalBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            Int64(payloadBytes),
            rosterAndMetadata
        )
        // At most four independently 64-KiB-bounded projection rows can win an
        // admission bucket. One MiB conservatively covers their typed table,
        // retained indexes, full-detail FTS and aggregate coverage mutations.
        let logicalBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            journalLogicalBytes,
            1 * 1_024 * 1_024
        )
        var journalDurableAndWAL = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logicalBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 16
            )
        if poisonCount > 0 {
            let poisonLogical = SQLitePersistentStoreAdmission
                .saturatingMultiply(Int64(poisonCount), by: 256)
            journalDurableAndWAL = SQLitePersistentStoreAdmission
                .saturatingAdd(
                    journalDurableAndWAL,
                    SQLitePersistentStoreAdmission
                        .conservativeEncodedRowMutationBytes(
                            logicalRepresentationBytes: poisonLogical,
                            pageSizeBytes: sqlitePageSizeBytes,
                            maximumLeafPageTouches: poisonCount * 2
                        )
                )
        }
        return eventTransactionEstimate(
            rowMutationBytes: SQLitePersistentStoreAdmission.saturatingAdd(
                journalDurableAndWAL,
                legacyRowMutationBytes
            )
        )
    }

    /// Persist the canonical-ceiling poison identity in the same transaction
    /// as its compact journal replacement. Distinct UUIDs are counted exactly
    /// once across retry/restart; a reused UUID with different rejected source
    /// content fails loudly instead of being hidden behind the replacement.
    private func persistCanonicalOverflowPoison(
        _ overflow: EventJournalOverflowEvidence,
        replacementDigest: Data,
        kind: String,
        location: JournalLocation,
        now: TimeInterval
    ) throws {
        let insert = try prepare(
            """
            INSERT OR IGNORE INTO event_journal_payload_poison (
                block_id, ordinal, event_id, poison_kind,
                replacement_sha256, original_sha256,
                source_identity_sha256, original_bytes, digest_kind,
                first_seen, last_seen,
                attempt_count
            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10,1)
            """
        )
        sqlite3_bind_int64(insert, 1, location.blockID)
        sqlite3_bind_int(insert, 2, Int32(location.ordinal))
        bindBlob(insert, index: 3, value: Self.uuidData(overflow.originalEventID))
        bindText(insert, index: 4, value: kind)
        bindBlob(insert, index: 5, value: replacementDigest)
        bindBlob(insert, index: 6, value: overflow.originalSHA256)
        bindBlob(insert, index: 7, value: overflow.sourceIdentitySHA256)
        sqlite3_bind_int64(insert, 8, Int64(overflow.originalBytes))
        bindText(insert, index: 9, value: overflow.digestKind.rawValue)
        sqlite3_bind_double(insert, 10, now)
        let rc = sqlite3_step(insert)
        let inserted = sqlite3_changes(db) == 1
        sqlite3_finalize(insert)
        guard rc == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "canonical overflow poison insert failed"
            )
        }
        if inserted {
            try executeExpectingSingleChange(
                "UPDATE event_storage_state SET payload_poison_total = payload_poison_total + 1 WHERE singleton = 1",
                context: "canonical overflow poison total update"
            )
            return
        }

        let verify = try prepare(
            """
            SELECT replacement_sha256, original_sha256,
                   source_identity_sha256, original_bytes, digest_kind
            FROM event_journal_payload_poison
            WHERE block_id = ?1 AND ordinal = ?2 AND poison_kind = ?3
            """
        )
        defer { sqlite3_finalize(verify) }
        sqlite3_bind_int64(verify, 1, location.blockID)
        sqlite3_bind_int(verify, 2, Int32(location.ordinal))
        bindText(verify, index: 3, value: kind)
        guard sqlite3_step(verify) == SQLITE_ROW,
              Int(sqlite3_column_bytes(verify, 0)) == SHA256.byteCount,
              Int(sqlite3_column_bytes(verify, 1)) == SHA256.byteCount,
              Int(sqlite3_column_bytes(verify, 2)) == SHA256.byteCount,
              let replacement = sqlite3_column_blob(verify, 0),
              let original = sqlite3_column_blob(verify, 1),
              let identity = sqlite3_column_blob(verify, 2),
              Data(bytes: replacement, count: SHA256.byteCount)
                == replacementDigest,
              Data(bytes: original, count: SHA256.byteCount)
                == overflow.originalSHA256,
              Data(bytes: identity, count: SHA256.byteCount)
                == overflow.sourceIdentitySHA256,
              sqlite3_column_int64(verify, 3)
                == Int64(overflow.originalBytes),
              let persistedDigestKind = sqlite3_column_text(verify, 4),
              String(cString: persistedDigestKind)
                == overflow.digestKind.rawValue else {
            throw EventStoreError.immutableEventConflict(
                eventID: overflow.originalEventID
            )
        }
    }

    private static func projectionRank(for event: Event) -> Int32 {
        if NoiseFilter.isCoverageCanaryProbe(event: event) { return 0 }
        if !event.ruleMatches.isEmpty { return 1 }
        if event.severity >= .high { return 2 }
        if event.eventCategory != .file { return 3 }
        if let action = event.file?.action,
           action == .create || action == .rename
            || action == .delete || action == .link {
            return 4
        }
        return 5
    }

    private static func projectionReason(
        for event: Event
    ) -> ProjectionReason {
        if NoiseFilter.isCoverageCanaryProbe(event: event) {
            return .coverageCanary
        }
        if !event.ruleMatches.isEmpty { return .reviewedRuleMatch }
        return .selected
    }

    /// Logical-byte quota charged before a row may enter the sparse tier.
    /// This deliberately counts every typed/indexed string plus four copies of
    /// FTS input and the downgrade-safe JSON. A pathological event is still in
    /// the complete journal but cannot punch through the projection budget.
    private static func estimatedProjectionBytes(
        _ prepared: PreparedPersistedEvent
    ) -> Int {
        let event = prepared.projectionEvent
        func bytes(_ value: String?) -> Int { value?.utf8.count ?? 0 }
        var total = 1_024 + prepared.projectionJSON.count
        let aiTool = event.enrichments["ai_tool"]
            ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        let typed: [String?] = [
            event.id.uuidString,
            event.eventCategory.rawValue,
            event.eventType.rawValue,
            event.eventAction,
            event.severity.rawValue,
            event.process.name,
            event.process.executable,
            prepared.indexedCommandLine,
            event.process.codeSignature?.signerType.rawValue,
            event.process.codeSignature?.teamId,
            event.process.codeSignature?.signingId,
            event.file?.path,
            event.file?.action.rawValue,
            event.network?.destinationIp,
            event.tcc?.service,
            event.tcc?.client,
            event.enrichments["mcp_server_name"],
            event.enrichments["mcp_server_category"],
            event.enrichments["ai_tool_session_id"],
            event.enrichments[TraceCorrelator.EnrichmentKey.traceId],
            event.enrichments[TraceCorrelator.EnrichmentKey.spanId],
            event.enrichments[TraceCorrelator.EnrichmentKey.agentTool],
            event.enrichments[TraceCorrelator.EnrichmentKey.confidence],
            event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson],
            event.process.userName,
            event.process.workingDirectory,
            event.process.architecture,
            event.process.hashes?.sha256,
            event.process.ancestors.first?.name,
            event.process.ancestors.first?.executable,
            event.enrichments["ParentSignerType"],
            aiTool,
            event.process.session?.launchSource?.rawValue,
        ]
        for value in typed {
            let addition = total.addingReportingOverflow(bytes(value))
            if addition.overflow { return Int.max }
            total = addition.partialValue
        }
        let fts: [String?] = [
            event.process.name,
            event.process.executable,
            prepared.indexedCommandLine,
            event.file?.path,
            event.network?.destinationIp,
            event.tcc?.service,
            event.tcc?.client,
        ]
        for value in fts {
            let count = bytes(value)
            if count > (Int.max - total) / 4 { return Int.max }
            total += count * 4
        }
        return total
    }

    private func beginProjectionCoverage(
        bucket: Int64,
        blockID: Int64,
        now: TimeInterval
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO event_projection_coverage (
                bucket_start, considered_count, pending_count, updated_at
            ) VALUES (?1, 1, 1, ?2)
            ON CONFLICT(bucket_start) DO UPDATE SET
                considered_count = considered_count + 1,
                pending_count = pending_count + 1,
                updated_at = excluded.updated_at
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, bucket)
        sqlite3_bind_double(statement, 2, now)
        guard sqlite3_step(statement) == SQLITE_DONE,
              sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed(
                "projection coverage admission failed"
            )
        }
        try executeExpectingSingleChange(
            """
            UPDATE event_projection_block_coverage SET
                considered_count = considered_count + 1,
                pending_count = pending_count + 1
            WHERE block_id = \(blockID)
            """
        )
    }

    private func advanceStorageMutationGeneration(
        now: TimeInterval = Date().timeIntervalSince1970
    ) throws {
        let statement = try prepare(
            """
            UPDATE event_storage_state SET
                mutation_generation = mutation_generation + 1,
                updated_at = ?1
            WHERE singleton = 1
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, now)
        guard sqlite3_step(statement) == SQLITE_DONE,
              sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed(
                "event storage mutation generation update failed"
            )
        }
    }

    private func currentStorageMutationGeneration() throws -> UInt64 {
        // A genuine pre-v8 read-only substrate has no generation row and is
        // explicitly generation zero. Once the journal schema exists, a
        // missing/corrupt singleton is integrity failure, never a zero-valued
        // fallback that could make a mixed snapshot look race-bound.
        guard try hasJournalSchema() else { return 0 }
        let statement = try prepare(
            "SELECT mutation_generation FROM event_storage_state WHERE singleton = 1"
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "event storage mutation generation is unavailable"
            )
        }
        let generation = sqlite3_column_int64(statement, 0)
        guard generation >= 0, sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "event storage mutation generation is corrupt"
            )
        }
        return UInt64(generation)
    }

    private func executeExpectingSingleChange(
        _ sql: String,
        context: String = "projection coverage update"
    ) throws {
        try execute(sql)
        guard sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed(
                "\(context) affected \(sqlite3_changes(db)) rows instead of 1"
            )
        }
    }

    private func projectionCoverageUsage(
        bucket: Int64
    ) throws -> (rows: Int, bytes: Int) {
        let statement = try prepare(
            "SELECT materialized_count, materialized_bytes FROM event_projection_coverage WHERE bucket_start = ?1"
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, bucket)
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return (0, 0) }
        guard rc == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "projection coverage bucket is missing"
            )
        }
        return (
            Int(sqlite3_column_int64(statement, 0)),
            Int(sqlite3_column_int64(statement, 1))
        )
    }

    private func finishProjectionCoverage(
        bucket: Int64,
        blockID: Int64,
        materializedBytes: Int? = nil,
        omittedReason: ProjectionReason? = nil,
        replacement: Bool = false,
        now: TimeInterval
    ) throws {
        let sql: String
        if let materializedBytes {
            sql = """
                UPDATE event_projection_coverage SET
                    pending_count = pending_count - 1,
                    materialized_count = materialized_count + 1,
                    materialized_bytes = materialized_bytes + \(materializedBytes),
                    updated_at = \(now)
                WHERE bucket_start = \(bucket)
                """
        } else {
            let column: String
            switch omittedReason {
            case .rankReplacement: column = "omitted_replaced_count"
            case .physicalBudget: column = "omitted_physical_count"
            default: column = "omitted_quota_count"
            }
            sql = """
                UPDATE event_projection_coverage SET
                    pending_count = pending_count - 1,
                    \(column) = \(column) + 1,
                    replacement_total = replacement_total + \(replacement ? 1 : 0),
                    updated_at = \(now)
                WHERE bucket_start = \(bucket)
                """
        }
        try executeExpectingSingleChange(sql)
        let blockSQL: String
        if let materializedBytes {
            blockSQL = """
                UPDATE event_projection_block_coverage SET
                    pending_count = pending_count - 1,
                    materialized_count = materialized_count + 1,
                    materialized_bytes = materialized_bytes + \(materializedBytes)
                WHERE block_id = \(blockID)
                """
        } else {
            let column: String
            switch omittedReason {
            case .rankReplacement: column = "omitted_replaced_count"
            case .physicalBudget: column = "omitted_physical_count"
            default: column = "omitted_quota_count"
            }
            blockSQL = """
                UPDATE event_projection_block_coverage SET
                    pending_count = pending_count - 1,
                    \(column) = \(column) + 1,
                    replacement_total = replacement_total + \(replacement ? 1 : 0)
                WHERE block_id = \(blockID)
                """
        }
        try executeExpectingSingleChange(blockSQL)
    }

    private struct WorstProjectionRow {
        let rowID: Int64
        let id: String
        let rank: Int32
        let bytes: Int
        let blockID: Int64
        let ordinal: Int
    }

    private func worstProjection(in bucket: Int64) throws -> WorstProjectionRow? {
        let statement = try prepare(
            """
            SELECT rowid, id, projection_rank, projection_estimated_bytes,
                   journal_block_id, journal_ordinal
            FROM events
            WHERE journal_block_id IS NOT NULL
              AND projection_bucket = ?1
            ORDER BY projection_rank DESC, id DESC
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, bucket)
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW,
              let idPointer = sqlite3_column_text(statement, 1) else {
            throw EventStoreError.stepFailed(
                "projection replacement selection failed"
            )
        }
        return WorstProjectionRow(
            rowID: sqlite3_column_int64(statement, 0),
            id: String(cString: idPointer),
            rank: sqlite3_column_int(statement, 2),
            bytes: Int(sqlite3_column_int64(statement, 3)),
            blockID: sqlite3_column_int64(statement, 4),
            ordinal: Int(sqlite3_column_int(statement, 5))
        )
    }

    private func evictProjection(
        _ victim: WorstProjectionRow
    ) throws {
        let deleteFTS = try prepare(
            "DELETE FROM events_fts WHERE rowid = ?1"
        )
        sqlite3_bind_int64(deleteFTS, 1, victim.rowID)
        let ftsRC = sqlite3_step(deleteFTS)
        sqlite3_finalize(deleteFTS)
        guard ftsRC == SQLITE_DONE,
              sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed("projection FTS eviction failed")
        }
        let deleteRow = try prepare("DELETE FROM events WHERE rowid = ?1")
        sqlite3_bind_int64(deleteRow, 1, victim.rowID)
        let rowRC = sqlite3_step(deleteRow)
        sqlite3_finalize(deleteRow)
        guard rowRC == SQLITE_DONE,
              sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed("projection row eviction failed")
        }
    }

    /// Plan a complete rank-respecting replacement without mutating any row.
    /// The existing projection contract admits at most four rows per bucket,
    /// so a refresh can examine/replace at most the other three. A partial
    /// plan must never discard neighbors and then omit the canary anyway.
    private func canaryProjectionReplacementPlan(
        bucket: Int64,
        row: WorstProjectionRow,
        incomingRank: Int32,
        prospectiveBytes: Int
    ) throws -> [WorstProjectionRow]? {
        let statement = try prepare(
            """
            SELECT rowid, id, projection_rank, projection_estimated_bytes,
                   journal_block_id, journal_ordinal
            FROM events
            WHERE journal_block_id IS NOT NULL
              AND projection_bucket = ?1 AND rowid != ?2
            ORDER BY projection_rank DESC, id DESC LIMIT ?3
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, bucket)
        sqlite3_bind_int64(statement, 2, row.rowID)
        sqlite3_bind_int(statement, 3, Int32(Self.projectionRowsPerBucket - 1))
        var remainingBytes = prospectiveBytes
        var victims: [WorstProjectionRow] = []
        while remainingBytes > Self.projectionBytesPerBucket {
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { return nil }
            guard rc == SQLITE_ROW,
                  let idText = sqlite3_column_text(statement, 1) else {
                throw EventStoreError.stepFailed("canary projection replacement lookup failed")
            }
            let victim = WorstProjectionRow(
                rowID: sqlite3_column_int64(statement, 0),
                id: String(cString: idText),
                rank: sqlite3_column_int(statement, 2),
                bytes: Int(sqlite3_column_int64(statement, 3)),
                blockID: sqlite3_column_int64(statement, 4),
                ordinal: Int(sqlite3_column_int(statement, 5))
            )
            guard incomingRank < victim.rank
                    || (incomingRank == victim.rank && row.id < victim.id)
            else { return nil }
            guard victim.bytes > 0, victim.bytes <= remainingBytes else {
                throw EventStoreError.decodingFailed("canary projection replacement bytes are invalid")
            }
            remainingBytes -= victim.bytes
            victims.append(victim)
        }
        return victims
    }

    /// Remove one stale sparse representation while preserving the exact
    /// append-local disposition/coverage conservation. Used when a reviewed
    /// value cannot itself fit the bounded promotion overlay: leaving the old
    /// row materialized would let FTS/UI claim evidence that is no longer the
    /// terminal-preferred value.
    @discardableResult
    private func dematerializeProjectionIfPresent(
        blockID: Int64,
        ordinal: Int,
        replacement: JournalProjectionDisposition,
        context: String
    ) throws -> Bool {
        guard replacement == .quota || replacement == .physical
                || replacement == .replaced else {
            throw EventStoreError.stepFailed(
                "\(context) has an invalid omission transition"
            )
        }
        let statement = try prepare(
            """
            SELECT rowid, id, projection_rank,
                   projection_estimated_bytes, projection_bucket
            FROM events
            WHERE journal_block_id = ?1 AND journal_ordinal = ?2
            LIMIT 1
            """
        )
        sqlite3_bind_int64(statement, 1, blockID)
        sqlite3_bind_int(statement, 2, Int32(ordinal))
        let rc = sqlite3_step(statement)
        if rc == SQLITE_DONE {
            sqlite3_finalize(statement)
            return false
        }
        guard rc == SQLITE_ROW,
              let idText = sqlite3_column_text(statement, 1) else {
            sqlite3_finalize(statement)
            throw EventStoreError.stepFailed(
                "\(context) sparse-row lookup failed"
            )
        }
        let row = WorstProjectionRow(
            rowID: sqlite3_column_int64(statement, 0),
            id: String(cString: idText),
            rank: sqlite3_column_int(statement, 2),
            bytes: Int(sqlite3_column_int64(statement, 3)),
            blockID: blockID,
            ordinal: ordinal
        )
        let bucket = sqlite3_column_int64(statement, 4)
        sqlite3_finalize(statement)
        try evictProjection(row)
        try replacePersistedProjectionDisposition(
            blockID: blockID,
            ordinal: ordinal,
            expected: .materialized,
            replacement: replacement
        )
        let column: String
        switch replacement {
        case .quota: column = "omitted_quota_count"
        case .replaced: column = "omitted_replaced_count"
        default: column = "omitted_physical_count"
        }
        let replacementCount = replacement == .replaced ? 1 : 0
        try executeExpectingSingleChange(
            "UPDATE event_projection_block_coverage SET materialized_count = materialized_count - 1, materialized_bytes = materialized_bytes - \(row.bytes), \(column) = \(column) + 1, replacement_total = replacement_total + \(replacementCount) WHERE block_id = \(blockID)",
            context: "\(context) block omission"
        )
        try executeExpectingSingleChange(
            "UPDATE event_projection_coverage SET materialized_count = materialized_count - 1, materialized_bytes = materialized_bytes - \(row.bytes), \(column) = \(column) + 1, replacement_total = replacement_total + \(replacementCount), updated_at = \(Date().timeIntervalSince1970) WHERE bucket_start = \(bucket)",
            context: "\(context) global omission"
        )
        return true
    }

    /// Rebuild an existing sparse row from the terminal/promotion-preferred
    /// canonical Event. If the replacement no longer fits either sparse quota,
    /// remove the stale row and flip its authenticated disposition instead.
    /// Call only while holding BEGIN IMMEDIATE.
    private func reconcileExistingProjectionUnderWriterLock(
        event exactEvent: Event,
        location: JournalLocation,
        context: String,
        prepared suppliedPreparation: PreparedPersistedEvent? = nil
    ) throws -> Bool {
        let projection = try prepare(
            """
            SELECT rowid, id, projection_rank,
                   projection_estimated_bytes, projection_bucket,
                   projection_reason, CAST(raw_json AS BLOB)
            FROM events
            WHERE journal_block_id = ?1 AND journal_ordinal = ?2
            LIMIT 1
            """
        )
        sqlite3_bind_int64(projection, 1, location.blockID)
        sqlite3_bind_int(projection, 2, Int32(location.ordinal))
        let rc = sqlite3_step(projection)
        if rc == SQLITE_DONE {
            sqlite3_finalize(projection)
            return false
        }
        guard rc == SQLITE_ROW,
              let idText = sqlite3_column_text(projection, 1) else {
            sqlite3_finalize(projection)
            throw EventStoreError.stepFailed(
                "\(context) sparse-row lookup failed"
            )
        }
        let row = WorstProjectionRow(
            rowID: sqlite3_column_int64(projection, 0),
            id: String(cString: idText),
            rank: sqlite3_column_int(projection, 2),
            bytes: Int(sqlite3_column_int64(projection, 3)),
            blockID: location.blockID,
            ordinal: location.ordinal
        )
        let bucket = sqlite3_column_int64(projection, 4)
        let existingReason = sqlite3_column_int(projection, 5)
        let existingRawCount = Int(sqlite3_column_bytes(projection, 6))
        let existingRaw: Data?
        if existingRawCount == 0 {
            existingRaw = sqlite3_column_type(projection, 6) == SQLITE_NULL
                ? nil : Data()
        } else if let pointer = sqlite3_column_blob(projection, 6) {
            existingRaw = Data(bytes: pointer, count: existingRawCount)
        } else {
            existingRaw = nil
        }
        sqlite3_finalize(projection)

        let prepared: PreparedPersistedEvent
        if let suppliedPreparation {
            guard suppliedPreparation.event == exactEvent,
                  suppliedPreparation.overflow == nil else {
                throw EventStoreError.encodingFailed(
                    "\(context) projection preparation does not match exact event"
                )
            }
            prepared = suppliedPreparation
        } else {
            let ingress = try EventJournalAdmissionValidator.prepare(exactEvent)
            guard ingress.overflow == nil else {
                _ = try dematerializeProjectionIfPresent(
                    blockID: location.blockID,
                    ordinal: location.ordinal,
                    replacement: .physical,
                    context: context
                )
                return false
            }
            prepared = try preparePersistedEvent(ingress)
        }
        let newBytes = Self.estimatedProjectionBytes(prepared)
        let reason = Self.projectionReason(for: exactEvent)
        let rank = Self.projectionRank(for: exactEvent)
        if row.bytes == newBytes,
           row.rank == rank,
           existingReason == reason.rawValue,
           existingRaw == prepared.projectionJSON {
            // True idempotence: do not churn FTS/content pages, coverage, or
            // the conservative physical-ownership gauge when the sparse row
            // already equals the canonical terminal-preferred projection.
            return true
        }
        guard newBytes <= Self.projectionBytesPerBucket else {
            _ = try dematerializeProjectionIfPresent(
                blockID: location.blockID,
                ordinal: location.ordinal,
                replacement: .quota,
                context: context
            )
            return false
        }
        let usage = try projectionCoverageUsage(bucket: bucket)
        var prospectiveBucketBytes = usage.bytes - row.bytes + newBytes
        var replacementVictims: [WorstProjectionRow] = []
        if prospectiveBucketBytes > Self.projectionBytesPerBucket,
           reason == .coverageCanary,
           let plan = try canaryProjectionReplacementPlan(
               bucket: bucket,
               row: row,
               incomingRank: rank,
               prospectiveBytes: prospectiveBucketBytes
           ) {
            replacementVictims = plan
            prospectiveBucketBytes -= plan.reduce(0) { $0 + $1.bytes }
        }
        let growth = max(0, newBytes - row.bytes)
        // Deleting an FTS row can allocate delete postings before a later
        // merge reclaims them. Do not subtract retired victims from physical
        // ownership; conservatively charge their bounded mutations as well.
        let replacementPhysicalCharge = replacementVictims.reduce(Int64(0)) {
            SQLitePersistentStoreAdmission.saturatingAdd(
                $0, projectionPhysicalCharge(estimatedBytes: $1.bytes)
            )
        }
        try refreshProjectionPhysicalUpperBoundIfNeeded()
        let physicalLimit = reason == .coverageCanary
            ? Self.projectionPhysicalLimitBytes
            : Self.projectionPhysicalLimitBytes
                - Self.projectionCanaryReserveBytes
        // Replacing a row without logical growth cannot consume another fixed
        // 16-page insertion allowance. Charging it on every idempotent
        // terminal/promotion reconciliation inflated the cached upper bound and
        // eventually evicted an unchanged row. Before *any* physical omission,
        // replace the conservative cache with an authoritative DBSTAT sample.
        var projectedUpper = projectionOwnedUpperBoundBytes ?? Int64.max
        if growth > 0 {
            projectedUpper = SQLitePersistentStoreAdmission.saturatingAdd(
                projectedUpper,
                projectionPhysicalCharge(estimatedBytes: growth)
            )
        }
        projectedUpper = SQLitePersistentStoreAdmission.saturatingAdd(
            projectedUpper, replacementPhysicalCharge
        )
        if projectedUpper > physicalLimit {
            try refreshProjectionPhysicalUpperBoundIfNeeded(force: true)
            projectedUpper = projectionOwnedUpperBoundBytes ?? Int64.max
            if growth > 0 {
                projectedUpper = SQLitePersistentStoreAdmission.saturatingAdd(
                    projectedUpper,
                    projectionPhysicalCharge(estimatedBytes: growth)
                )
            }
            projectedUpper = SQLitePersistentStoreAdmission.saturatingAdd(
                projectedUpper, replacementPhysicalCharge
            )
        }
        guard prospectiveBucketBytes <= Self.projectionBytesPerBucket,
              projectedUpper <= physicalLimit else {
            _ = try dematerializeProjectionIfPresent(
                blockID: location.blockID,
                ordinal: location.ordinal,
                replacement: prospectiveBucketBytes
                    > Self.projectionBytesPerBucket ? .quota : .physical,
                context: context
            )
            return false
        }

        for victim in replacementVictims {
            guard try dematerializeProjectionIfPresent(
                blockID: victim.blockID,
                ordinal: victim.ordinal,
                replacement: .replaced,
                context: "canary terminal projection replacement"
            ) else {
                throw EventStoreError.stepFailed("planned canary projection victim disappeared")
            }
        }

        try evictProjection(row)
        let inserted = try insert(
            event: exactEvent,
            applyInsertFilter: false,
            projection: ProjectionReference(
                blockID: location.blockID,
                ordinal: location.ordinal,
                reason: reason,
                estimatedBytes: newBytes,
                rank: rank,
                bucket: bucket
            ),
            prepared: prepared
        ) { _ in }
        guard inserted else {
            throw EventStoreError.stepFailed(
                "\(context) sparse-row rewrite was not inserted"
            )
        }
        let byteDelta = newBytes - row.bytes
        try executeExpectingSingleChange(
            "UPDATE event_projection_block_coverage SET materialized_bytes = materialized_bytes + \(byteDelta) WHERE block_id = \(location.blockID)",
            context: "\(context) block-byte update"
        )
        try executeExpectingSingleChange(
            "UPDATE event_projection_coverage SET materialized_bytes = materialized_bytes + \(byteDelta), updated_at = \(Date().timeIntervalSince1970) WHERE bucket_start = \(bucket)",
            context: "\(context) global-byte update"
        )
        projectionOwnedUpperBoundBytes = projectedUpper
        return true
    }

    private func replacePersistedProjectionDisposition(
        blockID: Int64,
        ordinal: Int,
        expected: JournalProjectionDisposition,
        replacement: JournalProjectionDisposition
    ) throws {
        let read = try prepare(
            "SELECT event_count, projection_dispositions, projection_dispositions_sha256 FROM event_journal_blocks WHERE block_id = ?1"
        )
        sqlite3_bind_int64(read, 1, blockID)
        guard sqlite3_step(read) == SQLITE_ROW else {
            sqlite3_finalize(read)
            throw EventStoreError.decodingFailed(
                "projection victim references a missing journal block"
            )
        }
        let count = Int(sqlite3_column_int(read, 0))
        let byteCount = Int(sqlite3_column_bytes(read, 1))
        let digestCount = Int(sqlite3_column_bytes(read, 2))
        guard let bytes = sqlite3_column_blob(read, 1),
              let digestBytes = sqlite3_column_blob(read, 2),
              digestCount == SHA256.byteCount else {
            sqlite3_finalize(read)
            throw EventStoreError.decodingFailed(
                "projection victim disposition bytes are unavailable"
            )
        }
        let data = Data(bytes: bytes, count: byteCount)
        let storedDigest = Data(bytes: digestBytes, count: digestCount)
        sqlite3_finalize(read)
        guard Data(SHA256.hash(data: data)) == storedDigest else {
            throw EventStoreError.decodingFailed(
                "projection victim disposition checksum mismatch"
            )
        }
        var dispositions = try Self.projectionDispositions(
            from: data,
            eventCount: count
        )
        guard ordinal >= 0, ordinal < dispositions.count,
              dispositions[ordinal] == expected else {
            throw EventStoreError.decodingFailed(
                "projection victim disposition is not materialized"
            )
        }
        dispositions[ordinal] = replacement
        let updated = Self.projectionDispositionData(dispositions)
        let statement = try prepare(
            "UPDATE event_journal_blocks SET projection_dispositions = ?1, projection_dispositions_sha256 = ?2 WHERE block_id = ?3"
        )
        bindBlob(statement, index: 1, value: updated)
        bindBlob(
            statement,
            index: 2,
            value: Data(SHA256.hash(data: updated))
        )
        sqlite3_bind_int64(statement, 3, blockID)
        let rc = sqlite3_step(statement)
        sqlite3_finalize(statement)
        guard rc == SQLITE_DONE, sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed(
                "projection victim disposition update failed"
            )
        }
    }

    /// Exact live allocation owned by the interactive projection: the content
    /// table, every index whose tbl_name is events, and all full-detail FTS5
    /// shadow tables/indexes. Freelist pages are not projection-owned and are
    /// charged separately by the whole-family admission boundary.
    private func projectionPhysicalBytes() throws -> Int64 {
        projectionDBStatProbeCount &+= 1
        let statement = try prepare(
            """
            SELECT COALESCE(SUM(pgsize), 0)
            FROM dbstat
            WHERE name = 'events'
               OR name LIKE 'events_fts%'
               OR name IN (
                    SELECT name FROM sqlite_master
                    WHERE type = 'index' AND tbl_name = 'events'
               )
            """
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "projection DBSTAT ownership query failed"
            )
        }
        return max(0, sqlite3_column_int64(statement, 0))
    }

    private func projectionPhysicalCharge(
        estimatedBytes: Int
    ) -> Int64 {
        let logical = Int64(max(0, estimatedBytes))
        let roundedLogical = ((logical + sqlitePageSizeBytes - 1)
            / sqlitePageSizeBytes) * sqlitePageSizeBytes
        // Content table + PK + timestamp + cat/severity/time + the full-detail
        // FTS shadow family. This is deliberately a strict new-page allowance;
        // most inserts reuse existing leaves, so periodic exact DBSTAT resets
        // recover the conservatism without risking an overrun.
        return SQLitePersistentStoreAdmission.saturatingAdd(
            roundedLogical,
            SQLitePersistentStoreAdmission.saturatingMultiply(
                sqlitePageSizeBytes,
                by: 16
            )
        )
    }

    private func refreshProjectionPhysicalUpperBoundIfNeeded(
        force: Bool = false
    ) throws {
        if force || projectionOwnedUpperBoundBytes == nil
            || projectionBlocksSincePhysicalMeasure
                >= Self.projectionPhysicalRemeasureBlockInterval {
            projectionOwnedUpperBoundBytes = try projectionPhysicalBytes()
            projectionBlocksSincePhysicalMeasure = 0
        }
    }

    private struct ProjectionCoverageDelta {
        var considered = 0
        var materialized = 0
        var materializedBytes = 0
        var omittedQuota = 0
        var omittedReplaced = 0
        var omittedPhysical = 0
        var omittedExternal = 0
        var omittedMigration = 0
        var replacements = 0
    }

    private func persistProjectionCoverage(
        bucket: Int64,
        blockID: Int64,
        newBlock: ProjectionCoverageDelta,
        displacedByBlock: [Int64: ProjectionCoverageDelta],
        now: TimeInterval
    ) throws {
        let displacedCount = displacedByBlock.values.reduce(0) {
            $0 + $1.omittedReplaced
        }
        let displacedBytes = displacedByBlock.values.reduce(0) {
            $0 + $1.materializedBytes
        }
        let globalMaterialized = newBlock.materialized - displacedCount
        let globalBytes = newBlock.materializedBytes - displacedBytes
        let globalReplaced = newBlock.omittedReplaced + displacedCount
        let globalReplacements = newBlock.replacements + displacedCount
        // Apply signed replacement deltas only to an existing aggregate row.
        // SQLite validates the VALUES row before ON CONFLICT runs, so binding
        // a negative materialized-byte delta into an UPSERT candidate violates
        // the table CHECK even when the resulting aggregate remains positive.
        let statement = try prepare(
            """
            UPDATE event_projection_coverage SET
                considered_count = considered_count + ?2,
                materialized_count = materialized_count + ?3,
                materialized_bytes = materialized_bytes + ?4,
                omitted_quota_count = omitted_quota_count + ?5,
                omitted_replaced_count = omitted_replaced_count + ?6,
                omitted_physical_count = omitted_physical_count + ?7,
                omitted_external_count = omitted_external_count + ?8,
                omitted_migration_count = omitted_migration_count + ?9,
                replacement_total = replacement_total + ?10,
                updated_at = ?11
            WHERE bucket_start = ?1
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, bucket)
        sqlite3_bind_int64(statement, 2, Int64(newBlock.considered))
        sqlite3_bind_int64(statement, 3, Int64(globalMaterialized))
        sqlite3_bind_int64(statement, 4, Int64(globalBytes))
        sqlite3_bind_int64(statement, 5, Int64(newBlock.omittedQuota))
        sqlite3_bind_int64(statement, 6, Int64(globalReplaced))
        sqlite3_bind_int64(statement, 7, Int64(newBlock.omittedPhysical))
        sqlite3_bind_int64(statement, 8, Int64(newBlock.omittedExternal))
        sqlite3_bind_int64(statement, 9, Int64(newBlock.omittedMigration))
        sqlite3_bind_int64(statement, 10, Int64(globalReplacements))
        sqlite3_bind_double(statement, 11, now)
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "aggregate projection coverage update failed"
            )
        }
        let updatedRows = sqlite3_changes(db)
        guard updatedRows == 0 || updatedRows == 1 else {
            throw EventStoreError.stepFailed(
                "aggregate projection coverage update changed an unexpected row count"
            )
        }
        if updatedRows == 0 {
            guard globalMaterialized >= 0,
                  globalBytes >= 0,
                  globalReplaced >= 0,
                  globalReplacements >= 0 else {
                throw EventStoreError.stepFailed(
                    "aggregate projection coverage insert has negative absolute values"
                )
            }
            let insert = try prepare(
                """
                INSERT INTO event_projection_coverage (
                    bucket_start, considered_count, materialized_count,
                    materialized_bytes, omitted_quota_count,
                    omitted_replaced_count, omitted_physical_count,
                    omitted_external_count, omitted_migration_count,
                    pending_count, replacement_total, updated_at
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11)
                """
            )
            defer { sqlite3_finalize(insert) }
            sqlite3_bind_int64(insert, 1, bucket)
            sqlite3_bind_int64(insert, 2, Int64(newBlock.considered))
            sqlite3_bind_int64(insert, 3, Int64(globalMaterialized))
            sqlite3_bind_int64(insert, 4, Int64(globalBytes))
            sqlite3_bind_int64(insert, 5, Int64(newBlock.omittedQuota))
            sqlite3_bind_int64(insert, 6, Int64(globalReplaced))
            sqlite3_bind_int64(insert, 7, Int64(newBlock.omittedPhysical))
            sqlite3_bind_int64(insert, 8, Int64(newBlock.omittedExternal))
            sqlite3_bind_int64(insert, 9, Int64(newBlock.omittedMigration))
            sqlite3_bind_int64(insert, 10, Int64(globalReplacements))
            sqlite3_bind_double(insert, 11, now)
            guard sqlite3_step(insert) == SQLITE_DONE,
                  sqlite3_changes(db) == 1 else {
                throw EventStoreError.stepFailed(
                    "aggregate projection coverage insert failed"
                )
            }
        }

        try executeExpectingSingleChange(
            """
            UPDATE event_projection_block_coverage SET
                considered_count = \(newBlock.considered),
                materialized_count = \(newBlock.materialized),
                materialized_bytes = \(newBlock.materializedBytes),
                omitted_quota_count = \(newBlock.omittedQuota),
                omitted_replaced_count = \(newBlock.omittedReplaced),
                omitted_physical_count = \(newBlock.omittedPhysical),
                omitted_external_count = \(newBlock.omittedExternal),
                omitted_migration_count = \(newBlock.omittedMigration),
                pending_count = 0,
                replacement_total = \(newBlock.replacements)
            WHERE block_id = \(blockID)
            """,
            context: "new block projection coverage update"
        )
        for (victimBlockID, delta) in displacedByBlock {
            try executeExpectingSingleChange(
                """
                UPDATE event_projection_block_coverage SET
                    materialized_count = materialized_count - \(delta.omittedReplaced),
                    materialized_bytes = materialized_bytes - \(delta.materializedBytes),
                    omitted_replaced_count = omitted_replaced_count + \(delta.omittedReplaced),
                    replacement_total = replacement_total + \(delta.omittedReplaced)
                WHERE block_id = \(victimBlockID)
                """,
                context: "displaced block projection coverage update"
            )
        }
    }

    private func finalizeProjectionForBlock(
        _ preparedEvents: [PreparedPersistedEvent],
        blockID: Int64,
        admissionBucket: Int64
    ) throws {
        let now = Date().timeIntervalSince1970
        try refreshProjectionPhysicalUpperBoundIfNeeded()
        var usage = try projectionCoverageUsage(bucket: admissionBucket)
        var delta = ProjectionCoverageDelta()
        var displacedByBlock: [Int64: ProjectionCoverageDelta] = [:]
        var dispositions = [JournalProjectionDisposition](
            repeating: .quota,
            count: preparedEvents.count
        )
        var forcedPhysicalMeasureThisBlock = false
        for (ordinal, prepared) in preparedEvents.enumerated() {
            let event = prepared.event
            let bucket = admissionBucket
            delta.considered += 1
            // `journal_overflow` is a compact, typed evidence-gap marker, not
            // an exact Event. Never expose it as an ordinary sparse/search row.
            // Exact APIs surface the bound poison ledger; coverage records the
            // deliberate physical omission.
            guard prepared.overflow == nil else {
                delta.omittedPhysical += 1
                dispositions[ordinal] = .physical
                continue
            }
            let rank = Self.projectionRank(for: event)
            let reason = Self.projectionReason(for: event)
            let bytes = Self.estimatedProjectionBytes(prepared)
            let isCoverageCanary = reason == .coverageCanary
            guard bytes <= Self.projectionBytesPerBucket else {
                delta.omittedQuota += 1
                dispositions[ordinal] = .quota
                continue
            }

            while usage.rows >= Self.projectionRowsPerBucket
                    || usage.bytes > Self.projectionBytesPerBucket - bytes {
                guard let victim = try worstProjection(in: bucket) else { break }
                let incomingID = event.id.uuidString
                let outranksVictim = rank < victim.rank
                    || (rank == victim.rank && incomingID < victim.id)
                guard outranksVictim else { break }
                try evictProjection(victim)
                usage.rows -= 1
                usage.bytes -= victim.bytes
                if victim.blockID == blockID {
                    delta.materialized -= 1
                    delta.materializedBytes -= victim.bytes
                    delta.omittedReplaced += 1
                    delta.replacements += 1
                    dispositions[victim.ordinal] = .replaced
                } else {
                    try replacePersistedProjectionDisposition(
                        blockID: victim.blockID,
                        ordinal: victim.ordinal,
                        expected: .materialized,
                        replacement: .replaced
                    )
                    var victimDelta = displacedByBlock[victim.blockID]
                        ?? ProjectionCoverageDelta()
                    victimDelta.omittedReplaced += 1
                    victimDelta.materializedBytes += victim.bytes
                    displacedByBlock[victim.blockID] = victimDelta
                }
            }
            guard usage.rows < Self.projectionRowsPerBucket,
                  usage.bytes <= Self.projectionBytesPerBucket - bytes else {
                delta.omittedQuota += 1
                dispositions[ordinal] = .quota
                continue
            }

            let physicalCharge = projectionPhysicalCharge(
                estimatedBytes: bytes
            )
            let softLimit = isCoverageCanary
                ? Self.projectionPhysicalLimitBytes
                : Self.projectionPhysicalLimitBytes
                    - Self.projectionCanaryReserveBytes
            var projectedUpper = SQLitePersistentStoreAdmission.saturatingAdd(
                projectionOwnedUpperBoundBytes ?? Int64.max,
                physicalCharge
            )
            if projectedUpper > softLimit,
               !forcedPhysicalMeasureThisBlock {
                // Only the near-limit path pays for DBSTAT. Ordinary operation
                // scans allocation at startup and every 64 journal blocks. A
                // block that still cannot fit after this exact probe classifies
                // every remaining candidate from the conservative cached bound;
                // it never rescans the projection once per omitted Event.
                try refreshProjectionPhysicalUpperBoundIfNeeded(force: true)
                forcedPhysicalMeasureThisBlock = true
                projectedUpper = SQLitePersistentStoreAdmission.saturatingAdd(
                    projectionOwnedUpperBoundBytes ?? Int64.max,
                    physicalCharge
                )
            }
            guard projectedUpper <= softLimit else {
                delta.omittedPhysical += 1
                dispositions[ordinal] = .physical
                continue
            }

            let inserted = try insert(
                event: event,
                applyInsertFilter: false,
                projection: ProjectionReference(
                    blockID: blockID,
                    ordinal: ordinal,
                    reason: reason,
                    estimatedBytes: bytes,
                    rank: rank,
                    bucket: bucket
                )
            ) { _ in }
            guard inserted, sqlite3_changes(db) > 0 else {
                throw EventStoreError.stepFailed(
                    "sparse projection UUID collision for \(event.id.uuidString)"
                )
            }
            projectionOwnedUpperBoundBytes = projectedUpper
            usage.rows += 1
            usage.bytes += bytes
            delta.materialized += 1
            delta.materializedBytes += bytes
            dispositions[ordinal] = .materialized
        }
        let dispositionData = Self.projectionDispositionData(dispositions)
        let dispositionUpdate = try prepare(
            "UPDATE event_journal_blocks SET projection_dispositions = ?1, projection_dispositions_sha256 = ?2 WHERE block_id = ?3"
        )
        bindBlob(dispositionUpdate, index: 1, value: dispositionData)
        bindBlob(
            dispositionUpdate,
            index: 2,
            value: Data(SHA256.hash(data: dispositionData))
        )
        sqlite3_bind_int64(dispositionUpdate, 3, blockID)
        let dispositionRC = sqlite3_step(dispositionUpdate)
        sqlite3_finalize(dispositionUpdate)
        guard dispositionRC == SQLITE_DONE,
              sqlite3_changes(db) == 1 else {
            throw EventStoreError.stepFailed(
                "new block projection disposition update failed"
            )
        }
        try persistProjectionCoverage(
            bucket: admissionBucket,
            blockID: blockID,
            newBlock: delta,
            displacedByBlock: displacedByBlock,
            now: now
        )
        projectionBlocksSincePhysicalMeasure += 1
    }

    /// Persists a batch in reserve-bounded transactions. A very large caller
    /// array (the daemon buffer is independently capped at 20K) can no longer
    /// grow one WAL transaction without limit. Each chunk commits before the
    /// next fresh disk probe; immutable event-id duplicate no-ops make retry
    /// after a later chunk failure idempotent, though the whole input array is intentionally no
    /// longer one atomic unit. On failure, `EventBatchInsertFailure` carries
    /// the exact committed count and filter-passing suffix.
    ///
    /// - Parameters:
    ///   - events: The events to store. Every event must classify to `lane`.
    ///   - lane: The homogeneous pipeline lane that owns this batch. This is
    ///     carried from the detection stream rather than defaulted at storage
    ///     admission, so file-firehose transactions cannot consume the
    ///     priority-only footprint reserve.
    /// - Throws: `EventBatchInsertFailure` on serialisation/database failure.
    @discardableResult
    public func insert(
        events: [Event],
        lane: EventPipelineLane
    ) throws -> EventBatchInsertResult {
        let prepared: [EventJournalIngressPreparation]
        do {
            prepared = try events.map(EventJournalAdmissionValidator.prepare)
        } catch {
            throw EventBatchInsertFailure(
                progress: EventBatchInsertResult(
                    inputCount: events.count,
                    persistedCount: 0,
                    filteredCount: 0,
                    committedTransactionCount: 0,
                    inputDispositions: events.map {
                        .uncommitted(eventID: $0.id)
                    }
                ),
                uncommittedEvents: events,
                underlyingError: error
            )
        }
        return try insertPreparedBatch(
            preparedEvents: prepared,
            lane: lane,
            applyInsertFilter: true
        )
    }

    /// Hot-path overload for the synchronous ingress boundary. Sanitization,
    /// structural validation, canonical encoding and SHA-256 have already run
    /// exactly once; EventStore revalidates the handle but does not repeat the
    /// recursive work.
    @discardableResult
    public func insert(
        preparedEvents: [EventJournalIngressPreparation],
        lane: EventPipelineLane
    ) throws -> EventBatchInsertResult {
        try insertPreparedBatch(
            preparedEvents: preparedEvents,
            lane: lane,
            applyInsertFilter: true
        )
    }

    private func insertPreparedBatch(
        preparedEvents: [EventJournalIngressPreparation],
        lane: EventPipelineLane,
        applyInsertFilter: Bool,
        identityRefreshAttempt: Int = 0,
        committedTransactionOffset: Int = 0
    ) throws -> EventBatchInsertResult {
        let events = preparedEvents.map(\.event)
        let startingGeneration = activeDatabaseGeneration
        guard events.allSatisfy({
            EventPipelineLane.finalLane(for: $0) == lane
        }) else {
            throw EventBatchInsertFailure(
                progress: EventBatchInsertResult(
                    inputCount: events.count,
                    persistedCount: 0,
                    filteredCount: 0,
                    committedTransactionCount: 0,
                    inputDispositions: events.map {
                        .uncommitted(eventID: $0.id)
                    }
                ),
                uncommittedEvents: events,
                underlyingError: EventStoreError.stepFailed(
                    "Event batch mixes pipeline lanes or is mislabeled as \(lane.key)"
                )
            )
        }

        var candidates: [EventJournalIngressPreparation] = []
        candidates.reserveCapacity(events.count)
        var candidateOriginalIndices: [Int] = []
        candidateOriginalIndices.reserveCapacity(events.count)
        var inputDispositions = events.map {
            EventJournalInsertDisposition.uncommitted(eventID: $0.id)
        }
        var filteredCount = 0

        var committedRows = 0
        var committedTransactions = committedTransactionOffset
        do {
            try ensureJournalIndex()
            // Durable identity dominates today's filter configuration. Resolve
            // and canonical-validate every existing UUID before consulting the
            // mutable routine-noise filter; otherwise a changed filter could
            // relabel durable evidence as filtered or hide UUID reuse.
            let existingByID = try existingJournalLocations(
                for: Set(preparedEvents.map { $0.event.id })
            )
            var canonicalDigestSeenInCall: [UUID: Data] = [:]
            var duplicatesByBlock: [Int64: [(index: Int, location: JournalLocation)]] = [:]
            for (index, event) in events.enumerated() {
                if let location = existingByID[event.id] {
                    duplicatesByBlock[location.blockID, default: []]
                        .append((index, location))
                }
            }
            // One decoded block at a time: even a 20K uncertain-commit retry
            // cannot retain every old payload graph concurrently.
            for blockID in duplicatesByBlock.keys.sorted() {
                let block = try loadJournalBlock(blockID: blockID)
                for duplicate in duplicatesByBlock[blockID] ?? [] {
                    let prepared = try preparePersistedEvent(
                        preparedEvents[duplicate.index]
                    )
                    try validateDuplicate(
                        prepared,
                        at: duplicate.location,
                        in: block
                    )
                    let base = block[duplicate.location.ordinal]
                    // Poison is durable store truth, not a property of this
                    // caller's preparation. Re-submitting the compact marker
                    // itself must remain poisoned rather than becoming an
                    // apparently exact durable Event.
                    if let poison = try persistedBasePoison(
                        at: duplicate.location,
                        base: base
                    ) {
                        inputDispositions[duplicate.index] = .poisoned(poison)
                    } else {
                        guard prepared.overflow == nil else {
                            throw EventStoreError.decodingFailed(
                                "canonical overflow marker is missing its durable poison ledger"
                            )
                        }
                        inputDispositions[duplicate.index] = .durable(
                            eventID: prepared.event.id
                        )
                    }
                    canonicalDigestSeenInCall[prepared.event.id]
                        = prepared.recordDigest
                }
            }
            for (inputIndex, ingress) in preparedEvents.enumerated() {
                let event = ingress.event
                if existingByID[event.id] != nil { continue }
                if applyInsertFilter,
                   ingress.overflow == nil,
                   let filter = insertFilter,
                   filter.shouldDrop(event: event) {
                    filteredCount += 1
                    inputDispositions[inputIndex] = .filtered(
                        eventID: event.id
                    )
                } else {
                    candidates.append(ingress)
                    candidateOriginalIndices.append(inputIndex)
                }
            }
            let reserve = storageAdmission?.transactionReserveBytes
                ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
            var formationLimit = EventJournalCodec.maximumEventsPerBlock
            formationLoop: while committedRows < candidates.count {
                var sourceCount = 0
                var framedBytes = 12
                var preparedUnique: [PreparedPersistedEvent] = []
                // Prefix formation is speculative until COMMIT. A stricter
                // future-expiry check may roll it back and request a split;
                // never let those uncommitted UUIDs leak into the durable
                // in-call dedupe map.
                var formationDigests = canonicalDigestSeenInCall
                while committedRows + sourceCount < candidates.count,
                      sourceCount < formationLimit {
                    let candidate = candidates[committedRows + sourceCount]
                    let prepared = try preparePersistedEvent(candidate)
                    let nextBytes = framedBytes + 4
                        + prepared.canonicalJSON.count
                    let nextCount = preparedUnique.count + 1
                    let nextEstimate = journalBlockTransactionEstimate(
                        // Raw framing is never smaller than the payload that
                        // EventJournalCodec will actually persist.
                        payloadBytes: nextBytes,
                        eventCount: nextCount,
                        poisonCount: preparedUnique.reduce(into: 0) {
                            count, item in
                            if item.overflow != nil { count += 1 }
                        } + (prepared.overflow == nil ? 0 : 1)
                    )
                    if !preparedUnique.isEmpty, nextEstimate > reserve {
                        break
                    }
                    guard nextEstimate <= reserve else {
                        throw SQLitePersistentStoreAdmissionError
                            .transactionEstimateExceedsReserve(
                                estimatedBytes: nextEstimate,
                                reserveBytes: reserve
                            )
                    }
                    framedBytes = nextBytes
                    sourceCount += 1

                    if let prior = formationDigests[prepared.event.id] {
                        guard prior == prepared.recordDigest else {
                            throw EventStoreError.immutableEventConflict(
                                eventID: prepared.event.id
                            )
                        }
                        continue
                    }
                    formationDigests[prepared.event.id]
                        = prepared.recordDigest
                    preparedUnique.append(prepared)
                }
                guard sourceCount > 0 else {
                    throw EventStoreError.encodingFailed(
                        "could not form a bounded event journal block"
                    )
                }
                if !preparedUnique.isEmpty {
                    do {
                        _ = try insertJournalBlock(
                            preparedUnique,
                            lane: lane
                        )
                    } catch EventStoreError.journalBlockRequiresSplit(
                        let eventCount
                    ) {
                        guard eventCount > 1, sourceCount > 1 else {
                            throw SQLitePersistentStoreAdmissionError
                                .transactionEstimateExceedsReserve(
                                    estimatedBytes:
                                        SQLitePersistentStoreAdmission
                                            .saturatingAdd(reserve, 1),
                                    reserveBytes: reserve
                                )
                        }
                        formationLimit = max(1, sourceCount / 2)
                        continue formationLoop
                    } catch EventStoreError
                        .journalBlockRequiresIdentityRefresh {
                        guard identityRefreshAttempt < 8 else {
                            throw EventStoreError.storageNotReady(
                                "event journal identity changed repeatedly while serializing a cross-process append"
                            )
                        }
                        // No part of this prefix committed. Re-run the complete
                        // input against a freshly authenticated locator; any
                        // earlier chunks from this call resolve as idempotent
                        // durable duplicates and preserve ordered outcomes.
                        return try insertPreparedBatch(
                            preparedEvents: preparedEvents,
                            lane: lane,
                            applyInsertFilter: applyInsertFilter,
                            identityRefreshAttempt:
                                identityRefreshAttempt + 1,
                            committedTransactionOffset:
                                committedTransactions
                        )
                    }
                    committedTransactions += 1
                }
                canonicalDigestSeenInCall = formationDigests
                for candidateIndex in committedRows..<(committedRows + sourceCount) {
                    let inputIndex = candidateOriginalIndices[candidateIndex]
                    let candidate = candidates[candidateIndex]
                    inputDispositions[inputIndex] = candidate.overflow.map {
                        .poisoned($0)
                    } ?? .durable(eventID: candidate.event.id)
                }
                committedRows += sourceCount
                formationLimit = EventJournalCodec.maximumEventsPerBlock
            }
            let durableCount = inputDispositions.reduce(into: 0) {
                count, disposition in
                if case .durable = disposition { count += 1 }
            }
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: durableCount,
                filteredCount: filteredCount,
                committedTransactionCount: committedTransactions,
                inputDispositions: inputDispositions
            )
        } catch {
            let databaseWasReplaced = activeDatabaseGeneration
                != startingGeneration
            if databaseWasReplaced {
                for inputIndex in inputDispositions.indices {
                    switch inputDispositions[inputIndex] {
                    case .durable(let eventID):
                        inputDispositions[inputIndex] = .uncommitted(
                            eventID: eventID
                        )
                    case .poisoned(let evidence):
                        inputDispositions[inputIndex] = .uncommitted(
                            eventID: evidence.originalEventID
                        )
                    case .filtered, .uncommitted:
                        break
                    }
                }
            }
            let durableRows = inputDispositions.reduce(into: 0) { count, disposition in
                if case .durable = disposition { count += 1 }
            }
            let durableTransactions = databaseWasReplaced
                ? 0 : committedTransactions
            throw EventBatchInsertFailure(
                progress: EventBatchInsertResult(
                    inputCount: events.count,
                    persistedCount: durableRows,
                    filteredCount: filteredCount,
                    committedTransactionCount: durableTransactions,
                    inputDispositions: inputDispositions
                ),
                uncommittedEvents: zip(
                    events,
                    inputDispositions
                ).compactMap { event, disposition in
                    if case .uncommitted = disposition {
                        return event
                    }
                    return nil
                },
                underlyingError: error,
                activeDatabaseWasReplaced: databaseWasReplaced,
                replacementReadyForRetry: databaseWasReplaced
                    && db != nil && insertStmt != nil && !isReadOnly
            )
        }
    }

    /// Idempotently prove one Event's canonical base is durable. Ordinary
    /// callers retain the configured insert-filter outcome; a later reviewed
    /// detection/alert may explicitly bypass only that filter so a previously
    /// routine event cannot remain absent after it becomes security-relevant.
    public func ensureJournaled(
        _ event: Event,
        lane: EventPipelineLane,
        reason: EventJournalEnsureReason = .ordinary
    ) throws -> EventJournalEnsureOutcome {
        let prepared: EventJournalIngressPreparation
        do {
            prepared = try EventJournalAdmissionValidator.prepare(event)
        } catch {
            throw EventStoreError.encodingFailed(error.localizedDescription)
        }
        return try ensureJournaled(
            prepared,
            lane: lane,
            reason: reason
        )
    }

    public func ensureJournaled(
        _ prepared: EventJournalIngressPreparation,
        lane: EventPipelineLane,
        reason: EventJournalEnsureReason = .ordinary
    ) throws -> EventJournalEnsureOutcome {
        let result = try insertPreparedBatch(
            preparedEvents: [prepared],
            lane: lane,
            applyInsertFilter: reason == .ordinary
        )
        guard result.inputDispositions.count == 1 else {
            throw EventStoreError.stepFailed(
                "single-event journal ensure returned an incomplete identity disposition"
            )
        }
        switch result.inputDispositions[0] {
        case .durable(let eventID):
            return .durable(eventID: eventID)
        case .poisoned(let evidence):
            return .poisoned(evidence)
        case .filtered(let eventID):
            return .filtered(eventID: eventID)
        case .uncommitted(let eventID):
            throw EventStoreError.stepFailed(
                "single-event journal ensure left \(eventID.uuidString) uncommitted without throwing"
            )
        }
    }

    /// Verify a compact base receipt without retaining or re-sanitizing the
    /// source Event graph. The comparison is against the immutable base record
    /// (terminal detail is a separate append-only revision) and the result is
    /// bound to the same SQLite snapshot generation.
    public func verifyJournaled(
        eventID: UUID,
        canonicalSHA256: Data
    ) throws -> EventJournalVerification {
        guard canonicalSHA256.count == SHA256.byteCount else {
            throw EventStoreError.encodingFailed(
                "journal receipt digest must be 32 bytes"
            )
        }
        return try withVerifiedExactReadSnapshot { generation in
            guard let location = try existingJournalLocations(
                for: Set([eventID])
            )[eventID] else {
                return EventJournalVerification(
                    disposition: .missing(eventID: eventID),
                    storageMutationGeneration: generation
                )
            }
            let block = try loadJournalBlock(blockID: location.blockID)
            guard location.ordinal >= 0, location.ordinal < block.count,
                  block[location.ordinal].id == eventID else {
                throw EventStoreError.decodingFailed(
                    "journal receipt locator identity is invalid"
                )
            }
            let base = block[location.ordinal]
            let digest = Data(
                SHA256.hash(data: try journalEncoder.encode(base))
            )
            guard digest == canonicalSHA256 else {
                return EventJournalVerification(
                    disposition: .conflict(eventID: eventID),
                    storageMutationGeneration: generation
                )
            }
            if let poison = try persistedBasePoison(
                at: location,
                base: base
            ) {
                return EventJournalVerification(
                    disposition: .poisoned(poison),
                    storageMutationGeneration: generation
                )
            }
            return EventJournalVerification(
                disposition: .durable(eventID: eventID),
                storageMutationGeneration: generation
            )
        }
    }

    /// Append reviewed match evidence by UUID and, when the Event already owns
    /// a sparse row, rewrite that row from the exact terminal-preferred Event.
    /// Calls union rather than replace their match sets, so completion order
    /// and retry boundaries converge on identical canonical state.
    @discardableResult
    public func promoteProjection(
        eventID: UUID,
        reviewedMatches: [RuleMatch]
    ) throws -> ProjectionPromotionOutcome {
        try promoteProjection(
            eventID: eventID,
            reviewedMatches: reviewedMatches,
            identityRefreshAttempt: 0
        )
    }

    private func promoteProjection(
        eventID: UUID,
        reviewedMatches: [RuleMatch],
        identityRefreshAttempt: Int
    ) throws -> ProjectionPromotionOutcome {
        let requested = ReviewedRuleMatches.normalized(reviewedMatches)
        try ensureJournalIndex()
        guard let location = try existingJournalLocations(
            for: Set([eventID])
        )[eventID] else {
            throw EventStoreError.terminalRevisionRequiresBase(eventID: eventID)
        }
        let baseBlock = try loadJournalBlock(blockID: location.blockID)
        guard location.ordinal >= 0, location.ordinal < baseBlock.count else {
            throw EventStoreError.decodingFailed(
                "reviewed projection base ordinal is invalid"
            )
        }
        let base = baseBlock[location.ordinal]
        let ownedCurrent = try loadExactJournalEvent(at: location)
        let current = ownedCurrent.event
        if let poison = try persistedBasePoison(at: location, base: base)
            ?? persistedTerminalPoison(at: location, base: base)
            ?? persistedPromotionPoison(at: location, base: base) {
            return ProjectionPromotionOutcome(
                eventID: eventID,
                insertedMatchCount: 0,
                totalReviewedMatchCount: current.ruleMatches.count,
                projectionMaterialized: false,
                evidenceGap: poison,
                storageMutationGeneration:
                    try currentStorageMutationGeneration()
            )
        }
        let prior = ReviewedRuleMatches.normalized(current.ruleMatches)
        let merged = ReviewedRuleMatches.merged(prior, requested)
        let priorSet = Set(prior)
        let added = merged.filter { !priorSet.contains($0) }

        let needsPromotionWrite = !added.isEmpty

        let promotedSource = event(current, replacingRuleMatches: merged)
        let promotedIngress = try EventJournalAdmissionValidator.prepare(
            promotedSource
        )
        let sourceIdentity = try canonicalBaseSourceIdentityDigest(
            base: base,
            at: location
        )
        let promotionGap: EventJournalOverflowEvidence = {
            if let overflow = promotedIngress.overflow {
                return EventJournalOverflowEvidence(
                    originalEventID: eventID,
                    originalBytes: overflow.originalBytes,
                    originalSHA256: overflow.originalSHA256,
                    digestKind: overflow.digestKind,
                    sourceIdentitySHA256: sourceIdentity
                )
            }
            return EventJournalOverflowEvidence(
                originalEventID: eventID,
                originalBytes: promotedIngress.canonicalJSON.count,
                originalSHA256: promotedIngress.canonicalSHA256,
                digestKind: .canonicalJSON,
                sourceIdentitySHA256: sourceIdentity
            )
        }()
        let promotedEvent = promotedIngress.event
        let canonicalMerged = ReviewedRuleMatches.normalized(
            promotedEvent.ruleMatches
        )
        let canonicalAdded = canonicalMerged.filter {
            !priorSet.contains($0)
        }

        // Persist one canonical monotonic union per ordinal. An append-only row
        // per review call would make retry/completion history unbounded and
        // eventually make exact decode/expiry exceed the fixed reserve.
        let matchJSON = try journalEncoder.encode(canonicalMerged)
        let matchDigest = Data(SHA256.hash(data: matchJSON))
        let estimate = terminalRevisionTransactionEstimate(
            payloadBytes: 512 + Self.maxRawJsonBytes,
            eventCount: 1
        )
        try beginSerializedWrite(
            estimatedBytes: estimate,
            postCommitHeadroomBytes:
                terminalPoisonSettlementHeadroomBytes,
            lane: .priority
        )
        var isMaterialized = false
        do {
            let lockedBaseBlock = try loadJournalBlock(
                blockID: location.blockID
            )
            guard location.ordinal >= 0,
                  location.ordinal < lockedBaseBlock.count else {
                throw EventStoreError.decodingFailed(
                    "reviewed projection base moved under writer lock"
                )
            }
            let lockedBase = lockedBaseBlock[location.ordinal]
            guard try canonicalBaseSourceIdentityDigest(
                base: lockedBase,
                at: location
            ) == sourceIdentity else {
                throw EventStoreError.projectionPromotionRequiresIdentityRefresh
            }
            if try persistedPromotionPoison(
                at: location,
                base: lockedBase
            ) != nil {
                throw EventStoreError.projectionPromotionRequiresIdentityRefresh
            }
            let usage = try journalOverlayUsage(
                blockID: location.blockID,
                eventCount: lockedBaseBlock.count
            )
            let priorPromotionSizeStatement = try prepare(
                "SELECT COALESCE(length(matches_json), 0) FROM event_journal_projection_promotions WHERE block_id = ?1 AND ordinal = ?2"
            )
            sqlite3_bind_int64(
                priorPromotionSizeStatement, 1, location.blockID
            )
            sqlite3_bind_int(
                priorPromotionSizeStatement, 2, Int32(location.ordinal)
            )
            let priorPromotionSize: Int
            let priorPromotionRC = sqlite3_step(
                priorPromotionSizeStatement
            )
            if priorPromotionRC == SQLITE_ROW {
                priorPromotionSize = Int(
                    sqlite3_column_int64(priorPromotionSizeStatement, 0)
                )
            } else if priorPromotionRC == SQLITE_DONE {
                priorPromotionSize = 0
            } else {
                sqlite3_finalize(priorPromotionSizeStatement)
                throw EventStoreError.stepFailed(
                    "reviewed projection prior-size lookup failed"
                )
            }
            sqlite3_finalize(priorPromotionSizeStatement)

            func settlePromotionGap()
                throws -> ProjectionPromotionOutcome {
                // An attempted larger promotion admission can latch pressure;
                // prove the compact fallback again while the same writer lock
                // is held, then make the gap and stale-row removal atomic.
                try requireCurrentFamilyCapacityUnderWriterLock(
                    estimatedBytes: estimate,
                    postCommitHeadroomBytes:
                        terminalPoisonSettlementHeadroomBytes,
                    lane: .priority
                )
                try persistCanonicalOverflowPoison(
                    promotionGap,
                    replacementDigest: promotionGap.originalSHA256,
                    kind: EventJournalPoisonRecord.Kind.promotion.rawValue,
                    location: location,
                    now: Date().timeIntervalSince1970
                )
                _ = try dematerializeProjectionIfPresent(
                    blockID: location.blockID,
                    ordinal: location.ordinal,
                    replacement: .physical,
                    context: "reviewed projection gap"
                )
                isMaterialized = false
                let gapExact = try loadExactJournalBlock(
                    blockID: location.blockID
                )
                let gapUsage = try journalOverlayUsage(
                    blockID: location.blockID,
                    eventCount: gapExact.events.count
                )
                guard try journalExpiryTransactionEstimate(
                    blockID: location.blockID,
                    exact: gapExact,
                    overlayCascadePayloadBytes:
                        gapUsage.cascadePayloadBytes,
                    additionalPoisonCount: remainingMutablePoisonSlots(
                        exact: gapExact,
                        terminalRevisionCount: gapUsage.terminalCount
                    )
                ) <= storageTransactionReserveBytes else {
                    throw EventStoreError.storageNotReady(
                        "reserved reviewed-promotion gap would make its base block unexpirable"
                    )
                }
                try execute("COMMIT")
                return ProjectionPromotionOutcome(
                    eventID: eventID,
                    insertedMatchCount: 0,
                    totalReviewedMatchCount: prior.count,
                    projectionMaterialized: false,
                    evidenceGap: promotionGap,
                    storageMutationGeneration:
                        try currentStorageMutationGeneration()
                )
            }
            let withoutPrior = usage.retainedLogicalBytes
                .subtractingReportingOverflow(priorPromotionSize)
            let prospective = withoutPrior.partialValue
                .addingReportingOverflow(matchJSON.count)
            var prospectiveExact = try loadExactJournalBlock(
                blockID: location.blockID
            )
            guard location.ordinal >= 0,
                  location.ordinal < prospectiveExact.events.count,
                  prospectiveExact.events[location.ordinal] == current else {
                throw EventStoreError
                    .projectionPromotionRequiresIdentityRefresh
            }
            if needsPromotionWrite {
                guard promotedIngress.overflow == nil,
                      matchJSON.count <= EventJournalCodec.maximumRecordBytes,
                      !withoutPrior.overflow, !prospective.overflow,
                      prospective.partialValue
                        <= Self.journalOverlayPayloadLimitBytes else {
                    return try settlePromotionGap()
                }
                prospectiveExact.events[location.ordinal] = promotedEvent
                let prospectiveCascade = usage.cascadePayloadBytes
                    .subtractingReportingOverflow(priorPromotionSize)
                let cascadeWithPromotion = prospectiveCascade.partialValue
                    .addingReportingOverflow(matchJSON.count)
                guard !prospectiveCascade.overflow,
                      !cascadeWithPromotion.overflow,
                      try journalExpiryTransactionEstimate(
                        blockID: location.blockID,
                        exact: prospectiveExact,
                        overlayCascadePayloadBytes:
                            cascadeWithPromotion.partialValue,
                        additionalPoisonCount: remainingMutablePoisonSlots(
                            exact: prospectiveExact,
                            terminalRevisionCount: usage.terminalCount
                        )
                      ) <= storageTransactionReserveBytes else {
                    return try settlePromotionGap()
                }
            }
            let durableEstimate = terminalRevisionTransactionEstimate(
                payloadBytes: (needsPromotionWrite ? matchJSON.count : 0)
                    + Self.maxRawJsonBytes,
                eventCount: 1,
                canaryProjectionRefreshCount:
                    NoiseFilter.isCoverageCanaryProbe(event: promotedEvent) ? 1 : 0
            )
            do {
                try requireCurrentFamilyCapacityUnderWriterLock(
                    estimatedBytes: durableEstimate,
                    postCommitHeadroomBytes:
                        terminalPoisonSettlementHeadroomBytes,
                    lane: .priority
                )
            } catch is SQLitePersistentStoreAdmissionError {
                return try settlePromotionGap()
            } catch EventStoreError.storageNotReady(_) {
                return try settlePromotionGap()
            }
            if needsPromotionWrite {
                let insertPromotion = try prepare(
                    """
                    INSERT INTO event_journal_projection_promotions (
                        block_id, ordinal, event_id, matches_sha256,
                        matches_json, created_at
                    ) VALUES (?1,?2,?3,?4,?5,?6)
                    ON CONFLICT(block_id, ordinal) DO UPDATE SET
                        event_id = excluded.event_id,
                        matches_sha256 = excluded.matches_sha256,
                        matches_json = excluded.matches_json,
                        created_at = excluded.created_at
                    """
                )
                sqlite3_bind_int64(insertPromotion, 1, location.blockID)
                sqlite3_bind_int(
                    insertPromotion, 2, Int32(location.ordinal)
                )
                bindBlob(
                    insertPromotion,
                    index: 3,
                    value: Self.uuidData(eventID)
                )
                bindBlob(insertPromotion, index: 4, value: matchDigest)
                bindBlob(insertPromotion, index: 5, value: matchJSON)
                sqlite3_bind_double(
                    insertPromotion, 6, Date().timeIntervalSince1970
                )
                let promotionRC = sqlite3_step(insertPromotion)
                sqlite3_finalize(insertPromotion)
                guard promotionRC == SQLITE_DONE,
                      sqlite3_changes(db) == 1 else {
                    throw EventStoreError.stepFailed(
                        "reviewed projection promotion insert failed"
                    )
                }
            }

            isMaterialized = try reconcileExistingProjectionUnderWriterLock(
                event: promotedEvent,
                location: location,
                context: "reviewed projection"
            )
            let finalizedExact = try loadExactJournalBlock(
                blockID: location.blockID
            )
            let finalizedUsage = try journalOverlayUsage(
                blockID: location.blockID,
                eventCount: finalizedExact.events.count
            )
            guard try journalExpiryTransactionEstimate(
                blockID: location.blockID,
                exact: finalizedExact,
                overlayCascadePayloadBytes:
                    finalizedUsage.cascadePayloadBytes,
                additionalPoisonCount: remainingMutablePoisonSlots(
                    exact: finalizedExact,
                    terminalRevisionCount: finalizedUsage.terminalCount
                )
            ) <= storageTransactionReserveBytes else {
                throw EventStoreError.storageNotReady(
                    "reviewed projection rewrite would make its canonical block unexpirable"
                )
            }
            try execute("COMMIT")
        } catch EventStoreError.projectionPromotionRequiresIdentityRefresh {
            try? execute("ROLLBACK")
            guard identityRefreshAttempt < 8 else {
                throw EventStoreError.storageNotReady(
                    "reviewed projection identity changed repeatedly while serializing a cross-process merge"
                )
            }
            return try promoteProjection(
                eventID: eventID,
                reviewedMatches: reviewedMatches,
                identityRefreshAttempt: identityRefreshAttempt + 1
            )
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
        return ProjectionPromotionOutcome(
            eventID: eventID,
            insertedMatchCount: canonicalAdded.count,
            totalReviewedMatchCount: canonicalMerged.count,
            projectionMaterialized: isMaterialized,
            storageMutationGeneration: try currentStorageMutationGeneration()
        )
    }

    private func terminalBatchResult(
        inputCount: Int,
        outcomes: [EventTerminalRevisionOutcome],
        committedTransactions: Int
    ) throws -> EventTerminalRevisionBatchResult {
        var durable = Set<UUID>()
        var inserted = Set<UUID>()
        var idempotent = Set<UUID>()
        for outcome in outcomes {
            switch outcome {
            case .unchangedBase(let eventID):
                durable.insert(eventID)
                idempotent.insert(eventID)
            case .inserted(let eventID):
                durable.insert(eventID)
                inserted.insert(eventID)
            case .alreadyDurable(let eventID):
                durable.insert(eventID)
                idempotent.insert(eventID)
            case .poisoned:
                break
            }
        }
        return EventTerminalRevisionBatchResult(
            inputCount: inputCount,
            outcomes: outcomes,
            durableEventIDs: durable,
            insertedEventIDs: inserted,
            idempotentEventIDs: idempotent,
            committedTransactionCount: committedTransactions,
            storageMutationGeneration: try currentStorageMutationGeneration()
        )
    }

    /// Production terminal seam. The caller compacts away its typed delta,
    /// transfers the preparation lease J -> S, and passes that exact lease.
    /// Storage authenticates the full block while decoding only the target
    /// ordinal, then drops ordinary event graphs before taking the writer lock.
    /// A recognized coverage canary may retain its small terminal projection
    /// under that same J lease through commit, so its FTS proof survives the
    /// production terminal update without retaining full graphs for all events.
    @discardableResult
    public func appendTerminalDeltas(
        preparedDeltas: [EventTerminalDeltaStoragePreparation],
        lane: EventPipelineLane,
        workspaceLease: EventPipelineMemoryLease
    ) throws -> EventTerminalDeltaBatchResult {
        guard preparedDeltas.count <= 1 else {
            throw EventStoreError.encodingFailed(
                "terminal delta settlement accepts one adopted workspace at a time"
            )
        }
        guard let prepared = preparedDeltas.first else {
            return EventTerminalDeltaBatchResult(
                inputCount: 0,
                outcomes: [],
                committedTransactionCount: 0,
                storageMutationGeneration:
                    try currentStorageMutationGeneration()
            )
        }
        guard workspaceLease.owner == .eventStoreWorkspace,
              workspaceLease.bytes >= EventJournalCodec.maximumWorkspaceBytes,
              prepared.compactRetainedByteEstimate > 0,
              prepared.compactRetainedByteEstimate
                <= EventJournalCodec.maximumWorkspaceBytes,
              prepared.baseCanonicalSHA256.count == SHA256.byteCount,
              prepared.sourceIdentitySHA256.count == SHA256.byteCount,
              prepared.canonicalDeltaSHA256.count == SHA256.byteCount else {
            throw EventStoreError.encodingFailed(
                "terminal delta adopted workspace or compact receipt is invalid"
            )
        }

        enum PlannedWrite {
            case unchanged(baseBytes: Int)
            case delta(
                block: PreparedEventJournalBlock,
                terminalDigest: Data,
                terminalBytes: Int
            )
            case poison(
                delta: EventTerminalDeltaOverflowEvidence,
                generic: EventJournalOverflowEvidence
            )
        }
        struct Plan {
            let location: JournalLocation
            let framedSHA256: Data
            let write: PlannedWrite
            var canaryProjection: PreparedPersistedEvent? = nil
            var canaryOwnership: EventPipelineMemoryLease? = nil
        }
        func poisonPlan(
            location: JournalLocation,
            framedSHA256: Data,
            bytes: Int,
            digest: Data,
            reason: EventTerminalDeltaOverflowEvidence.Reason,
            digestKind: EventJournalOverflowEvidence.DigestKind
        ) -> Plan {
            let delta = EventTerminalDeltaOverflowEvidence(
                eventID: prepared.eventID,
                baseCanonicalSHA256: prepared.baseCanonicalSHA256,
                sourceIdentitySHA256: prepared.sourceIdentitySHA256,
                originalBytes: bytes,
                originalSHA256: digest,
                reason: reason
            )
            return Plan(
                location: location,
                framedSHA256: framedSHA256,
                write: .poison(
                    delta: delta,
                    generic: EventJournalOverflowEvidence(
                        originalEventID: prepared.eventID,
                        originalBytes: bytes,
                        originalSHA256: digest,
                        digestKind: digestKind,
                        sourceIdentitySHA256:
                            prepared.sourceIdentitySHA256
                    )
                )
            )
        }

        try ensureJournalIndex()
        guard let location = try existingJournalLocations(
            for: Set([prepared.eventID])
        )[prepared.eventID] else {
            throw EventStoreError.terminalRevisionRequiresBase(
                eventID: prepared.eventID
            )
        }

        let plan: Plan = try {
            let owned = try loadJournalRecord(
                at: location,
                workspaceLease: workspaceLease
            )
            let base = owned.record.value
            let baseOwnershipBytes = owned.record.ownershipLease.bytes
            guard base.id == prepared.eventID,
                  owned.record.canonicalSHA256
                    == prepared.baseCanonicalSHA256,
                  owned.sourceIdentitySHA256
                    == prepared.sourceIdentitySHA256 else {
                throw EventStoreError.terminalRevisionConflict(
                    eventID: prepared.eventID
                )
            }
            if let overflow = prepared.overflow {
                guard prepared.canonicalDeltaJSON.isEmpty,
                      prepared.canonicalDeltaSHA256
                        == overflow.originalSHA256,
                      overflow.eventID == prepared.eventID,
                      overflow.baseCanonicalSHA256
                        == prepared.baseCanonicalSHA256,
                      overflow.sourceIdentitySHA256
                        == prepared.sourceIdentitySHA256 else {
                    throw EventStoreError.encodingFailed(
                        "terminal delta overflow preparation is malformed"
                    )
                }
                return poisonPlan(
                    location: location,
                    framedSHA256: owned.framedSHA256,
                    bytes: overflow.originalBytes,
                    digest: overflow.originalSHA256,
                    reason: overflow.reason,
                    digestKind: .structuralPreflight
                )
            }
            guard !prepared.canonicalDeltaJSON.isEmpty,
                  prepared.canonicalDeltaJSON.count
                    <= EventTerminalDeltaValidator
                        .maximumCanonicalDeltaBytes,
                  Data(SHA256.hash(data: prepared.canonicalDeltaJSON))
                    == prepared.canonicalDeltaSHA256 else {
                throw EventStoreError.encodingFailed(
                    "terminal delta compact preparation is not digest-bound"
                )
            }
            let combined = owned.record.ownershipLease.bytes
                .addingReportingOverflow(
                    prepared.deltaGraphRetainedByteEstimate
                )
            guard !combined.overflow,
                  combined.partialValue
                    <= EventJournalAdmissionValidator
                        .maximumPreparationWorkspaceBytes else {
                return poisonPlan(
                    location: location,
                    framedSHA256: owned.framedSHA256,
                    bytes: prepared.deltaGraphRetainedByteEstimate,
                    digest: prepared.canonicalDeltaSHA256,
                    reason: .storageCapacity,
                    digestKind: .structuralPreflight
                )
            }
            terminalDeltaOwnershipGrowthHookForTesting?()
            guard owned.record.ownershipLease.resize(
                to: combined.partialValue
            ) else {
                throw EventStoreError.memoryLeaseUnavailable(
                    "terminal delta for journal block \(location.blockID) is waiting for bounded base-and-delta ownership"
                )
            }
            var decodedDelta: EventTerminalDelta? = try decoder.decode(
                EventTerminalDelta.self,
                from: prepared.canonicalDeltaJSON
            )
            guard decodedDelta?.eventID == prepared.eventID else {
                throw EventStoreError.encodingFailed(
                    "terminal delta event identity is invalid"
                )
            }
            if decodedDelta?.isEmpty == true {
                return Plan(
                    location: location,
                    framedSHA256: owned.framedSHA256,
                    write: .unchanged(
                        baseBytes: owned.record.canonicalByteCount
                    )
                )
            }
            let terminal = try decodedDelta!.applying(to: base)
            decodedDelta = nil
            guard owned.record.ownershipLease.resize(
                to: EventJournalAdmissionValidator
                    .maximumPreparationWorkspaceBytes
            ) else {
                throw EventStoreError.memoryLeaseUnavailable(
                    "terminal delta for journal block \(location.blockID) is waiting for bounded terminal encoding ownership"
                )
            }
            let terminalJSON = try journalEncoder.encode(terminal)
            let terminalDigest = Data(SHA256.hash(data: terminalJSON))
            guard terminalJSON.count <= EventJournalCodec.maximumRecordBytes
            else {
                return poisonPlan(
                    location: location,
                    framedSHA256: owned.framedSHA256,
                    bytes: terminalJSON.count,
                    digest: terminalDigest,
                    reason: .storageCapacity,
                    digestKind: .canonicalJSON
                )
            }
            let encoded = try EventJournalCodec.prepare(
                jsonRecords: [prepared.canonicalDeltaJSON],
                workspaceLease: workspaceLease,
                workspaceRetainedInputBytes:
                    prepared.compactRetainedByteEstimate
            )
            var plan = Plan(
                location: location,
                framedSHA256: owned.framedSHA256,
                write: .delta(
                    block: encoded,
                    terminalDigest: terminalDigest,
                    terminalBytes: terminalJSON.count
                )
            )
            if NoiseFilter.isCoverageCanaryProbe(event: terminal),
               terminalJSON.count <= Self.maxRawJsonBytes {
                let preflight = try EventJournalAdmissionValidator.preflight(terminal)
                // No truncation is needed below maxRawJsonBytes. Account for
                // the still-live base, terminal/validation/encoding graphs,
                // canonical bytes, projection Data/String and indexed text
                // before constructing the additional projection buffers.
                let components = [
                    baseOwnershipBytes,
                    preflight.sourceRetainedByteEstimate,
                    preflight.sourceRetainedByteEstimate,
                    preflight.sourceRetainedByteEstimate,
                    terminalJSON.count,
                    Self.maxRawJsonBytes * 3,
                    Self.maxIndexedCommandLineBytes,
                    4_096,
                ]
                var retained = 0
                for component in components {
                    let sum = retained.addingReportingOverflow(component)
                    guard component >= 0, !sum.overflow else {
                        throw EventStoreError.memoryLeaseUnavailable(
                            "terminal canary projection ownership exceeds its bounded workspace"
                        )
                    }
                    retained = sum.partialValue
                }
                guard !preflight.structurallyOverflowed,
                      retained <= owned.record.ownershipLease.bytes else {
                    throw EventStoreError.memoryLeaseUnavailable(
                        "terminal canary projection ownership exceeds its bounded workspace"
                    )
                }
                plan.canaryProjection = try preparePersistedEvent(
                    EventJournalIngressPreparation(
                        event: terminal,
                        canonicalJSON: terminalJSON,
                        canonicalSHA256: terminalDigest,
                        sourceIdentitySHA256: prepared.sourceIdentitySHA256,
                        overflow: nil
                    )
                )
                plan.canaryOwnership = owned.record.ownershipLease
            }
            return plan
        }()
        // The exceptional canary graph and its existing J credit have one
        // lifetime on success, refusal, rollback and idempotent return.
        defer { withExtendedLifetime(plan) {} }

        let poisonEstimate = terminalRevisionTransactionEstimate(
            payloadBytes: 512,
            eventCount: 1
        )
        try beginSerializedWrite(
            estimatedBytes: poisonEstimate,
            postCommitHeadroomBytes: terminalPoisonSettlementHeadroomBytes,
            lane: lane
        )
        var committed = false
        var disposition: EventTerminalDeltaOutcome.Disposition
        var outputDigest: Data?
        var outputBytes = 0
        do {
            let eventCount = try validateJournalRecordLocationUnderWriterLock(
                plan.location,
                eventID: prepared.eventID,
                framedSHA256: plan.framedSHA256,
                sourceIdentitySHA256: prepared.sourceIdentitySHA256
            )
            if let existing = try persistedTerminalPoisonMetadata(
                at: plan.location,
                eventID: prepared.eventID,
                sourceIdentitySHA256: prepared.sourceIdentitySHA256
            ) {
                if case let .poison(delta, _) = plan.write {
                    guard existing.originalBytes == delta.originalBytes,
                          existing.originalSHA256
                            == delta.originalSHA256 else {
                        throw EventStoreError.terminalRevisionConflict(
                            eventID: prepared.eventID
                        )
                    }
                }
                try execute("ROLLBACK")
                let evidence = EventTerminalDeltaOverflowEvidence(
                    eventID: prepared.eventID,
                    baseCanonicalSHA256: prepared.baseCanonicalSHA256,
                    sourceIdentitySHA256: prepared.sourceIdentitySHA256,
                    originalBytes: existing.originalBytes,
                    originalSHA256: existing.originalSHA256,
                    reason: .storageCapacity
                )
                disposition = .poisoned(evidence)
            } else {
                let existingRevision = try prepare(
                    "SELECT event_id, base_sha256, terminal_sha256 FROM event_journal_terminal_revisions WHERE block_id = ?1 AND ordinal = ?2"
                )
                sqlite3_bind_int64(
                    existingRevision, 1, plan.location.blockID
                )
                sqlite3_bind_int(
                    existingRevision, 2, Int32(plan.location.ordinal)
                )
                let revisionRC = sqlite3_step(existingRevision)
                var existingBase: Data?
                var existingTerminal: Data?
                var existingID: Data?
                if revisionRC == SQLITE_ROW {
                    func copy(_ column: Int32) -> Data? {
                        let count = Int(sqlite3_column_bytes(
                            existingRevision, column
                        ))
                        guard count > 0,
                              let pointer = sqlite3_column_blob(
                                existingRevision, column
                              ) else { return nil }
                        return Data(bytes: pointer, count: count)
                    }
                    existingID = copy(0)
                    existingBase = copy(1)
                    existingTerminal = copy(2)
                }
                let revisionTail = sqlite3_step(existingRevision)
                sqlite3_finalize(existingRevision)
                guard revisionRC == SQLITE_DONE
                        || (revisionRC == SQLITE_ROW
                            && revisionTail == SQLITE_DONE) else {
                    throw EventStoreError.decodingFailed(
                        "terminal delta revision metadata is malformed"
                    )
                }
                if revisionRC == SQLITE_ROW {
                    guard existingID == Self.uuidData(prepared.eventID),
                          existingBase == prepared.baseCanonicalSHA256 else {
                        throw EventStoreError.terminalRevisionConflict(
                            eventID: prepared.eventID
                        )
                    }
                    guard case let .delta(
                        _, terminalDigest, terminalBytes
                    ) = plan.write,
                          existingTerminal == terminalDigest else {
                        throw EventStoreError.terminalRevisionConflict(
                            eventID: prepared.eventID
                        )
                    }
                    try execute("ROLLBACK")
                    disposition = .alreadyDurable
                    outputDigest = terminalDigest
                    outputBytes = terminalBytes
                } else {
                    switch plan.write {
                    case let .unchanged(baseBytes):
                        try execute("ROLLBACK")
                        disposition = .unchangedBase
                        outputDigest = prepared.baseCanonicalSHA256
                        outputBytes = baseBytes
                    case let .poison(delta, generic):
                        try persistCanonicalOverflowPoison(
                            generic,
                            replacementDigest: generic.originalSHA256,
                            kind: EventJournalPoisonRecord.Kind.terminal
                                .rawValue,
                            location: plan.location,
                            now: Date().timeIntervalSince1970
                        )
                        _ = try dematerializeProjectionIfPresent(
                            blockID: plan.location.blockID,
                            ordinal: plan.location.ordinal,
                            replacement: .physical,
                            context: "terminal delta poison"
                        )
                        let usage = try journalOverlayUsage(
                            blockID: plan.location.blockID,
                            eventCount: eventCount
                        )
                        guard try journalExpiryWorstCaseTransactionEstimate(
                            blockID: plan.location.blockID,
                            eventCount: eventCount,
                            overlayCascadePayloadBytes:
                                usage.cascadePayloadBytes
                        ) <= storageTransactionReserveBytes else {
                            throw EventStoreError.storageNotReady(
                                "terminal delta poison would make its block unexpirable"
                            )
                        }
                        try execute("COMMIT")
                        committed = true
                        disposition = .poisoned(delta)
                    case let .delta(
                        block, terminalDigest, terminalBytes
                    ):
                        let usage = try journalOverlayUsage(
                            blockID: plan.location.blockID,
                            eventCount: eventCount
                        )
                        let logical = usage.retainedLogicalBytes
                            .addingReportingOverflow(block.rawBytes)
                        let cascade = usage.cascadePayloadBytes
                            .addingReportingOverflow(
                                block.payload.storedBytes
                            )
                        var fits = !logical.overflow && !cascade.overflow
                            && logical.partialValue
                                <= Self.journalOverlayPayloadLimitBytes
                        if fits {
                            fits = try journalExpiryWorstCaseTransactionEstimate(
                                blockID: plan.location.blockID,
                                eventCount: eventCount,
                                overlayCascadePayloadBytes:
                                    cascade.partialValue
                            ) <= storageTransactionReserveBytes
                        }
                        let exactEstimate = terminalRevisionTransactionEstimate(
                            payloadBytes: block.payload.storedBytes,
                            eventCount: 1,
                            canaryProjectionRefreshCount:
                                plan.canaryProjection == nil ? 0 : 1
                        )
                        if fits {
                            do {
                                try requireCurrentFamilyCapacityUnderWriterLock(
                                    estimatedBytes: exactEstimate,
                                    postCommitHeadroomBytes:
                                        terminalPoisonSettlementHeadroomBytes,
                                    lane: lane
                                )
                            } catch is SQLitePersistentStoreAdmissionError {
                                fits = false
                            } catch EventStoreError.storageNotReady(_) {
                                fits = false
                            }
                        }
                        if !fits {
                            let delta = EventTerminalDeltaOverflowEvidence(
                                eventID: prepared.eventID,
                                baseCanonicalSHA256:
                                    prepared.baseCanonicalSHA256,
                                sourceIdentitySHA256:
                                    prepared.sourceIdentitySHA256,
                                originalBytes: terminalBytes,
                                originalSHA256: terminalDigest,
                                reason: .storageCapacity
                            )
                            let generic = EventJournalOverflowEvidence(
                                originalEventID: prepared.eventID,
                                originalBytes: terminalBytes,
                                originalSHA256: terminalDigest,
                                digestKind: .canonicalJSON,
                                sourceIdentitySHA256:
                                    prepared.sourceIdentitySHA256
                            )
                            try persistCanonicalOverflowPoison(
                                generic,
                                replacementDigest: terminalDigest,
                                kind: EventJournalPoisonRecord.Kind.terminal
                                    .rawValue,
                                location: plan.location,
                                now: Date().timeIntervalSince1970
                            )
                            _ = try dematerializeProjectionIfPresent(
                                blockID: plan.location.blockID,
                                ordinal: plan.location.ordinal,
                                replacement: .physical,
                                context: "terminal delta capacity poison"
                            )
                            try execute("COMMIT")
                            committed = true
                            disposition = .poisoned(delta)
                        } else {
                            let statement = try prepare(
                                "INSERT INTO event_journal_terminal_revisions (block_id, ordinal, event_id, base_sha256, terminal_sha256, framed_sha256, raw_bytes, codec, payload, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)"
                            )
                            sqlite3_bind_int64(
                                statement, 1, plan.location.blockID
                            )
                            sqlite3_bind_int(
                                statement, 2, Int32(plan.location.ordinal)
                            )
                            bindBlob(
                                statement, index: 3,
                                value: Self.uuidData(prepared.eventID)
                            )
                            bindBlob(
                                statement, index: 4,
                                value: prepared.baseCanonicalSHA256
                            )
                            bindBlob(
                                statement, index: 5,
                                value: terminalDigest
                            )
                            bindBlob(
                                statement, index: 6,
                                value: block.digest
                            )
                            sqlite3_bind_int64(
                                statement, 7, Int64(block.rawBytes)
                            )
                            sqlite3_bind_int(
                                statement, 8, Int32(block.codec)
                            )
                            switch block.payload {
                            case .compressed(let payload):
                                bindBlob(statement, index: 9, value: payload)
                            case .rawFragments:
                                guard sqlite3_bind_zeroblob64(
                                    statement,
                                    9,
                                    sqlite3_uint64(block.payload.storedBytes)
                                ) == SQLITE_OK else {
                                    sqlite3_finalize(statement)
                                    throw EventStoreError.stepFailed(
                                        "terminal delta zeroblob bind failed"
                                    )
                                }
                            }
                            sqlite3_bind_double(
                                statement,
                                10,
                                Date().timeIntervalSince1970
                            )
                            let rc = sqlite3_step(statement)
                            sqlite3_finalize(statement)
                            guard rc == SQLITE_DONE,
                                  sqlite3_changes(db) == 1 else {
                                throw EventStoreError.stepFailed(
                                    "terminal delta insert failed"
                                )
                            }
                            try writeRawJournalPayload(
                                block.payload,
                                table:
                                    "event_journal_terminal_revisions",
                                rowID: sqlite3_last_insert_rowid(db),
                                context: "terminal delta"
                            )
                            if let canary = plan.canaryProjection {
                                _ = try reconcileExistingProjectionUnderWriterLock(
                                    event: canary.event,
                                    location: plan.location,
                                    context: "terminal canary delta",
                                    prepared: canary
                                )
                            } else {
                                _ = try dematerializeProjectionIfPresent(
                                    blockID: plan.location.blockID,
                                    ordinal: plan.location.ordinal,
                                    replacement: .physical,
                                    context: "terminal delta"
                                )
                            }
                            try execute("COMMIT")
                            committed = true
                            disposition = .inserted
                            outputDigest = terminalDigest
                            outputBytes = terminalBytes
                        }
                    }
                }
            }
        } catch {
            if let db, sqlite3_get_autocommit(db) == 0 {
                try? execute("ROLLBACK")
            }
            throw error
        }

        let outcome = EventTerminalDeltaOutcome(
            eventID: prepared.eventID,
            disposition: disposition,
            canonicalDeltaSHA256: prepared.canonicalDeltaSHA256,
            terminalCanonicalSHA256: outputDigest,
            terminalCanonicalByteCount: outputBytes
        )
        return EventTerminalDeltaBatchResult(
            inputCount: 1,
            outcomes: [outcome],
            committedTransactionCount: committed ? 1 : 0,
            storageMutationGeneration: try currentStorageMutationGeneration()
        )
    }

    @discardableResult
    public func appendTerminalRevision(
        _ event: Event,
        lane: EventPipelineLane
    ) throws -> EventTerminalRevisionOutcome {
        let result = try appendTerminalRevisions([event], lane: lane)
        guard result.outcomes.count == 1 else {
            throw EventStoreError.stepFailed(
                "single terminal revision returned an incomplete outcome"
            )
        }
        return result.outcomes[0]
    }

    /// Append exactly one final canonical revision for each changed base Event.
    /// Unchanged high-rate traffic creates no row and no WAL. Rows are keyed by
    /// append-local base block/ordinal, checksum-bound to the immutable base,
    /// and cascade with that block at retention expiry.
    @discardableResult
    public func appendTerminalRevisions(
        _ events: [Event],
        lane: EventPipelineLane
    ) throws -> EventTerminalRevisionBatchResult {
        let prepared: [EventJournalIngressPreparation]
        do {
            prepared = try events.map(EventJournalAdmissionValidator.prepare)
        } catch {
            let generation = try currentStorageMutationGeneration()
            throw EventTerminalRevisionBatchFailure(
                progress: EventTerminalRevisionBatchResult(
                    inputCount: events.count,
                    outcomes: [],
                    durableEventIDs: [],
                    insertedEventIDs: [],
                    idempotentEventIDs: [],
                    committedTransactionCount: 0,
                    storageMutationGeneration: generation
                ),
                uncommittedEvents: events,
                underlyingError: error
            )
        }
        return try appendTerminalRevisions(
            preparedEvents: prepared,
            lane: lane
        )
    }

    @discardableResult
    public func appendTerminalRevisions(
        preparedEvents: [EventJournalIngressPreparation],
        lane: EventPipelineLane
    ) throws -> EventTerminalRevisionBatchResult {
        try appendPreparedTerminalRevisions(
            preparedEvents: preparedEvents,
            lane: lane,
            identityRefreshAttempt: 0,
            committedTransactionOffset: 0
        )
    }

    private func appendPreparedTerminalRevisions(
        preparedEvents: [EventJournalIngressPreparation],
        lane: EventPipelineLane,
        identityRefreshAttempt: Int,
        committedTransactionOffset: Int
    ) throws -> EventTerminalRevisionBatchResult {
        let events = preparedEvents.map(\.event)
        guard events.allSatisfy({
            EventPipelineLane.finalLane(for: $0) == lane
        }) else {
            let progress = try terminalBatchResult(
                inputCount: events.count,
                outcomes: [],
                committedTransactions: 0
            )
            throw EventTerminalRevisionBatchFailure(
                progress: progress,
                uncommittedEvents: events,
                underlyingError: EventStoreError.stepFailed(
                    "Terminal revision batch mixes pipeline lanes or is mislabeled as \(lane.key)"
                )
            )
        }
        guard !events.isEmpty else {
            return try terminalBatchResult(
                inputCount: 0,
                outcomes: [],
                committedTransactions: 0
            )
        }

        var outcomes: [EventTerminalRevisionOutcome] = []
        outcomes.reserveCapacity(events.count)
        var committedTransactions = committedTransactionOffset
        var inputOffset = 0
        do {
            try ensureJournalIndex()
            let locations = try existingJournalLocations(
                for: Set(events.map(\.id))
            )
            let reserve = storageAdmission?.transactionReserveBytes
                ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes

            while inputOffset < events.count {
                var scan = inputOffset
                var uniqueRecords: [PreparedTerminalRevision] = []
                var pendingOutcomes: [EventTerminalRevisionOutcome] = []
                var pendingLocations: [JournalLocation] = []
                var pendingByLocation: [JournalLocation: Data] = [:]
                var payloadBytes = 0
                var cachedBlockID: Int64?
                var cachedBlock = OwnedJournalBlock(records: [])

                while scan < events.count,
                      pendingOutcomes.count
                        < EventJournalCodec.maximumEventsPerBlock {
                    let supplied = events[scan]
                    guard let location = locations[supplied.id] else {
                        throw EventStoreError.terminalRevisionRequiresBase(
                            eventID: supplied.id
                        )
                    }
                    if cachedBlockID != location.blockID {
                        cachedBlock = try loadJournalBlock(
                            blockID: location.blockID
                        )
                        cachedBlockID = location.blockID
                    }
                    guard location.ordinal >= 0,
                          location.ordinal < cachedBlock.count else {
                        throw EventStoreError.decodingFailed(
                            "terminal revision base ordinal is out of range"
                        )
                    }
                    let base = cachedBlock[location.ordinal]
                    let terminal = try preparePersistedEvent(
                        preparedEvents[scan]
                    )
                    let baseSourceIdentity = try
                        canonicalBaseSourceIdentityDigest(
                            base: base,
                            at: location
                        )
                    guard terminal.sourceIdentitySHA256
                            == baseSourceIdentity else {
                        throw EventStoreError.terminalRevisionConflict(
                            eventID: supplied.id
                        )
                    }
                    let terminalDeltaJSON: Data?
                    if terminal.overflow == nil {
                        guard terminalRevisionPreservesSourceIdentity(
                            base: base,
                            terminal: terminal.event
                        ) else {
                            throw EventStoreError.terminalRevisionConflict(
                                eventID: supplied.id
                            )
                        }
                        let delta: EventTerminalDelta
                        do {
                            delta = try EventTerminalDelta(
                                base: base,
                                terminal: terminal.event
                            )
                        } catch {
                            throw EventStoreError.terminalRevisionConflict(
                                eventID: supplied.id
                            )
                        }
                        terminalDeltaJSON = try journalEncoder.encode(delta)
                    } else {
                        terminalDeltaJSON = nil
                    }
                    // An accepted canonical terminal can still be too large
                    // for the block's append-local overlay envelope (for
                    // example a 9-MiB late enrichment against the 8-MiB
                    // retained-overlay ceiling). Convert that reachable case
                    // into the same durable, sticky terminal-poison contract
                    // as a canonical-ingress overflow. Retrying must never
                    // spin on storageNotReady or let expiry erase an
                    // unrecorded final-value gap.
                    let overlayFramingBytes = (terminalDeltaJSON?.count ?? 0)
                        .addingReportingOverflow(16)
                    let capacityPoison: EventJournalOverflowEvidence? = {
                        guard terminal.overflow == nil else { return nil }
                        guard overlayFramingBytes.overflow
                                || overlayFramingBytes.partialValue
                                    > Self.journalOverlayPayloadLimitBytes
                        else { return nil }
                        return EventJournalOverflowEvidence(
                            originalEventID: terminal.event.id,
                            originalBytes: terminal.canonicalJSON.count,
                            originalSHA256: terminal.recordDigest,
                            digestKind: .canonicalJSON,
                            sourceIdentitySHA256:
                                terminal.sourceIdentitySHA256
                        )
                    }()
                    let terminalPoison = terminal.overflow ?? capacityPoison
                    if let stickyPoison = try persistedTerminalPoison(
                        at: location,
                        base: base
                    ) {
                        if let overflow = terminalPoison {
                            guard overflow == stickyPoison else {
                                throw EventStoreError.terminalRevisionConflict(
                                    eventID: supplied.id
                                )
                            }
                        } else {
                            guard terminalRevisionPreservesSourceIdentity(
                                base: base,
                                terminal: terminal.event
                            ) else {
                                throw EventStoreError.terminalRevisionConflict(
                                    eventID: supplied.id
                                )
                            }
                        }
                        guard pendingOutcomes.isEmpty else { break }
                        outcomes.append(.poisoned(stickyPoison))
                        inputOffset += 1
                        scan = inputOffset
                        continue
                    }
                    if let overflow = terminalPoison {
                        guard pendingOutcomes.isEmpty else { break }
                        guard try loadTerminalRevision(
                            at: location,
                            base: base
                        ) == nil,
                              overflow.sourceIdentitySHA256
                                == baseSourceIdentity else {
                            throw EventStoreError.terminalRevisionConflict(
                                eventID: supplied.id
                            )
                        }
                        let poisonEstimate = terminalRevisionTransactionEstimate(
                            payloadBytes: 512,
                            eventCount: 1
                        )
                        try beginSerializedWrite(
                            estimatedBytes: poisonEstimate,
                            postCommitHeadroomBytes:
                                terminalPoisonSettlementHeadroomBytes,
                            lane: .priority
                        )
                        do {
                            if let durablePoison = try persistedTerminalPoison(
                                at: location,
                                base: base
                            ) {
                                guard durablePoison == overflow else {
                                    throw EventStoreError
                                        .terminalRevisionConflict(
                                            eventID: supplied.id
                                        )
                                }
                                throw EventStoreError
                                    .terminalRevisionRequiresIdentityRefresh
                            }
                            guard try loadTerminalRevision(
                                at: location,
                                base: base
                            ) == nil
                            else {
                                throw EventStoreError.terminalRevisionConflict(
                                    eventID: supplied.id
                                )
                            }
                            try persistCanonicalOverflowPoison(
                                overflow,
                                replacementDigest: terminal.recordDigest,
                                kind: "terminal",
                                location: location,
                                now: Date().timeIntervalSince1970
                            )
                            _ = try dematerializeProjectionIfPresent(
                                blockID: location.blockID,
                                ordinal: location.ordinal,
                                replacement: .physical,
                                context: "terminal poison"
                            )
                            let prospectiveExact = try loadExactJournalBlock(
                                blockID: location.blockID
                            )
                            let usage = try journalOverlayUsage(
                                blockID: location.blockID,
                                eventCount: prospectiveExact.events.count
                            )
                            guard try journalExpiryTransactionEstimate(
                                blockID: location.blockID,
                                exact: prospectiveExact,
                                overlayCascadePayloadBytes:
                                    usage.cascadePayloadBytes,
                                additionalPoisonCount:
                                    remainingMutablePoisonSlots(
                                        exact: prospectiveExact,
                                        terminalRevisionCount:
                                            usage.terminalCount
                                    )
                            ) <= storageTransactionReserveBytes else {
                                throw EventStoreError.storageNotReady(
                                    "terminal poison would make its canonical block unexpirable"
                                )
                            }
                            try execute("COMMIT")
                        } catch EventStoreError
                            .terminalRevisionRequiresIdentityRefresh {
                            try? execute("ROLLBACK")
                            guard identityRefreshAttempt < 8 else {
                                throw EventStoreError.storageNotReady(
                                    "terminal poison identity changed repeatedly while serializing a cross-process retry"
                                )
                            }
                            return try appendPreparedTerminalRevisions(
                                preparedEvents: preparedEvents,
                                lane: lane,
                                identityRefreshAttempt:
                                    identityRefreshAttempt + 1,
                                committedTransactionOffset:
                                    committedTransactions
                            )
                        } catch {
                            try? execute("ROLLBACK")
                            throw error
                        }
                        committedTransactions += 1
                        outcomes.append(.poisoned(overflow))
                        inputOffset += 1
                        scan = inputOffset
                        continue
                    }
                    let baseJSON = try journalEncoder.encode(base)
                    let baseDigest = Data(SHA256.hash(data: baseJSON))
                    if terminal.canonicalJSON == baseJSON {
                        guard pendingOutcomes.isEmpty else { break }
                        outcomes.append(.unchangedBase(eventID: supplied.id))
                        inputOffset += 1
                        scan = inputOffset
                        continue
                    }
                    if let existing = try loadTerminalRevision(
                        at: location,
                        base: base
                    ) {
                        guard existing.baseDigest == baseDigest,
                              existing.terminalDigest
                                == terminal.recordDigest,
                              try journalEncoder.encode(existing.event)
                                == terminal.canonicalJSON else {
                            throw EventStoreError.terminalRevisionConflict(
                                eventID: supplied.id
                            )
                        }
                        guard pendingOutcomes.isEmpty else { break }
                        outcomes.append(.alreadyDurable(eventID: supplied.id))
                        inputOffset += 1
                        scan = inputOffset
                        continue
                    }
                    if let prior = pendingByLocation[location] {
                        guard prior == terminal.recordDigest else {
                            throw EventStoreError.terminalRevisionConflict(
                                eventID: supplied.id
                            )
                        }
                        pendingOutcomes.append(
                            .alreadyDurable(eventID: supplied.id)
                        )
                        pendingLocations.append(location)
                        scan += 1
                        continue
                    }
                    guard let terminalDeltaJSON else {
                        throw EventStoreError.terminalRevisionConflict(
                            eventID: supplied.id
                        )
                    }
                    // Each prepared payload owns the codec's complete S
                    // reservation until SQLite copies/blob-writes it. Form one
                    // unique terminal row per transaction; identical inputs
                    // may still coalesce onto that row below.
                    if !uniqueRecords.isEmpty { break }
                    let codecWorkspace = try acquireEventStoreWorkspace(
                        context: "terminal journal delta encode"
                    )
                    let encoded = try EventJournalCodec.prepare(
                        jsonRecords: [terminalDeltaJSON],
                        workspaceLease: codecWorkspace
                    )
                    let nextPayload = payloadBytes.addingReportingOverflow(
                        encoded.payload.storedBytes
                    )
                    let nextCount = uniqueRecords.count + 1
                    let estimate = nextPayload.overflow
                        ? Int64.max
                        : terminalRevisionTransactionEstimate(
                            payloadBytes: nextPayload.partialValue,
                            eventCount: nextCount,
                            canaryProjectionRefreshCount:
                                uniqueRecords.filter {
                                    NoiseFilter.isCoverageCanaryProbe(event: $0.event)
                                }.count
                                + (NoiseFilter.isCoverageCanaryProbe(event: terminal.event) ? 1 : 0)
                        )
                    if !uniqueRecords.isEmpty, estimate > reserve { break }
                    guard estimate <= reserve else {
                        throw SQLitePersistentStoreAdmissionError
                            .transactionEstimateExceedsReserve(
                                estimatedBytes: estimate,
                                reserveBytes: reserve
                            )
                    }
                    payloadBytes = nextPayload.partialValue
                    pendingByLocation[location] = terminal.recordDigest
                    uniqueRecords.append(
                        PreparedTerminalRevision(
                            location: location,
                            eventID: supplied.id,
                            event: terminal.event,
                            baseDigest: baseDigest,
                            terminalDigest: terminal.recordDigest,
                            sourceIdentitySHA256:
                                terminal.sourceIdentitySHA256,
                            canonicalBytes: terminal.canonicalJSON.count,
                            block: encoded,
                            projection: terminal
                        )
                    )
                    pendingOutcomes.append(.inserted(eventID: supplied.id))
                    pendingLocations.append(location)
                    scan += 1
                }

                if uniqueRecords.isEmpty {
                    // The loop can consume only zero-write outcomes in this
                    // shape; those update inputOffset immediately.
                    guard inputOffset < events.count else { continue }
                    if scan == inputOffset {
                        throw EventStoreError.stepFailed(
                            "could not form a bounded terminal revision transaction"
                        )
                    }
                    continue
                }

                // Acquire the cross-process writer lock with the compact
                // all-poison settlement envelope. The exact delta plan is
                // recomputed and admitted below while serialized. If another
                // writer consumed delta headroom, this transaction can still
                // durably settle every input as a content-bound gap.
                let poisonSettlementPayload = uniqueRecords.count
                    .multipliedReportingOverflow(by: 512)
                let poisonSettlementEstimate = terminalRevisionTransactionEstimate(
                    payloadBytes: poisonSettlementPayload.overflow
                        ? Int.max : poisonSettlementPayload.partialValue,
                    eventCount: uniqueRecords.count
                )
                try beginSerializedWrite(
                    estimatedBytes: poisonSettlementEstimate,
                    postCommitHeadroomBytes:
                        terminalPoisonSettlementHeadroomBytes,
                    lane: .priority
                )
                do {
                    var lockedBaseBlockID: Int64?
                    var lockedBaseBlock = OwnedJournalBlock(records: [])
                    for record in uniqueRecords {
                        if lockedBaseBlockID != record.location.blockID {
                            lockedBaseBlock = try loadJournalBlock(
                                blockID: record.location.blockID
                            )
                            lockedBaseBlockID = record.location.blockID
                        }
                        guard record.location.ordinal >= 0,
                              record.location.ordinal
                                < lockedBaseBlock.count else {
                            throw EventStoreError.decodingFailed(
                                "terminal revision base moved under writer lock"
                            )
                        }
                        let lockedBase = lockedBaseBlock[
                            record.location.ordinal
                        ]
                        guard record.sourceIdentitySHA256
                                == (try canonicalBaseSourceIdentityDigest(
                                    base: lockedBase,
                                    at: record.location
                                )) else {
                            throw EventStoreError
                                .terminalRevisionConflict(
                                    eventID: record.eventID
                                )
                        }
                        if try persistedTerminalPoison(
                            at: record.location,
                            base: lockedBase
                        ) != nil {
                            throw EventStoreError
                                .terminalRevisionRequiresIdentityRefresh
                        }
                        if let existing = try loadTerminalRevision(
                            at: record.location,
                            base: lockedBase
                        ) {
                            guard existing.baseDigest == record.baseDigest,
                                  existing.terminalDigest
                                    == record.terminalDigest
                            else {
                                throw EventStoreError
                                    .terminalRevisionConflict(
                                        eventID: record.eventID
                                    )
                            }
                            throw EventStoreError
                                .terminalRevisionRequiresIdentityRefresh
                        }
                    }
                    var capacityPoisonByLocation:
                        [JournalLocation: EventJournalOverflowEvidence] = [:]
                    func capacityPoison(
                        for record: PreparedTerminalRevision
                    ) -> EventJournalOverflowEvidence {
                        EventJournalOverflowEvidence(
                            originalEventID: record.eventID,
                            originalBytes: record.canonicalBytes,
                            originalSHA256: record.terminalDigest,
                            digestKind: .canonicalJSON,
                            sourceIdentitySHA256:
                                record.sourceIdentitySHA256
                        )
                    }
                    let affectedBlockIDs = Set(uniqueRecords.map {
                        $0.location.blockID
                    })
                    for blockID in affectedBlockIDs.sorted() {
                        let countStatement = try prepare(
                            "SELECT event_count FROM event_journal_blocks WHERE block_id = ?1"
                        )
                        sqlite3_bind_int64(countStatement, 1, blockID)
                        guard sqlite3_step(countStatement) == SQLITE_ROW else {
                            sqlite3_finalize(countStatement)
                            throw EventStoreError.decodingFailed(
                                "terminal journal base block disappeared before commit"
                            )
                        }
                        let eventCount = Int(
                            sqlite3_column_int(countStatement, 0)
                        )
                        sqlite3_finalize(countStatement)
                        let usage = try journalOverlayUsage(
                            blockID: blockID,
                            eventCount: eventCount
                        )
                        var workingLogical = usage.retainedLogicalBytes
                        var workingCascade = usage.cascadePayloadBytes
                        var workingTerminalCount = usage.terminalCount
                        var workingExact = try loadExactJournalBlock(
                            blockID: blockID
                        )
                        let blockRecords = uniqueRecords.filter {
                            $0.location.blockID == blockID
                        }
                        for record in blockRecords {
                            guard record.location.ordinal >= 0,
                                  record.location.ordinal
                                    < workingExact.events.count else {
                                throw EventStoreError.decodingFailed(
                                    "terminal journal prospective ordinal is invalid"
                                )
                            }
                            guard workingExact.poisonByOrdinal[
                                record.location.ordinal
                            ]?.contains(where: { $0.kind == .terminal })
                                != true else {
                                throw EventStoreError
                                    .terminalRevisionRequiresIdentityRefresh
                            }
                            let nextLogical = workingLogical
                                .addingReportingOverflow(record.block.rawBytes)
                            let nextCascade = workingCascade
                                .addingReportingOverflow(
                                    record.block.payload.storedBytes
                                )
                            var candidateExact = workingExact
                            candidateExact.events[record.location.ordinal] =
                                record.event
                            let expiryEstimate = try
                                journalExpiryTransactionEstimate(
                                    blockID: blockID,
                                    exact: candidateExact,
                                    overlayCascadePayloadBytes:
                                        nextCascade.partialValue,
                                    additionalPoisonCount:
                                        remainingMutablePoisonSlots(
                                            exact: candidateExact,
                                            terminalRevisionCount:
                                                workingTerminalCount + 1
                                        )
                                )
                            let candidateFits = !nextLogical.overflow
                                && !nextCascade.overflow
                                && nextLogical.partialValue
                                    <= Self.journalOverlayPayloadLimitBytes
                                && workingTerminalCount + 1 <= eventCount
                                && expiryEstimate <= reserve
                            if candidateFits {
                                workingLogical = nextLogical.partialValue
                                workingCascade = nextCascade.partialValue
                                workingTerminalCount += 1
                                workingExact = candidateExact
                                continue
                            }

                            // The final canonical value is valid but cannot be
                            // added without violating the retained-block/expiry
                            // envelope. Settle that exact ordinal as a durable,
                            // sticky, content-bound terminal gap in this same
                            // serialized transaction. It must never escape as
                            // a nonretryable storageNotReady remainder.
                            let overflow = capacityPoison(for: record)
                            capacityPoisonByLocation[record.location] = overflow
                            workingExact.poisonByOrdinal[
                                record.location.ordinal,
                                default: []
                            ].append(EventJournalPoisonRecord(
                                eventID: record.eventID,
                                kind: .terminal,
                                originalBytes: record.canonicalBytes,
                                originalSHA256: record.terminalDigest,
                                digestKind: .canonicalJSON
                            ))
                            guard try journalExpiryTransactionEstimate(
                                blockID: blockID,
                                exact: workingExact,
                                overlayCascadePayloadBytes: workingCascade,
                                additionalPoisonCount:
                                    remainingMutablePoisonSlots(
                                        exact: workingExact,
                                        terminalRevisionCount:
                                            workingTerminalCount
                                    )
                            ) <= reserve else {
                                throw EventStoreError.storageNotReady(
                                    "reserved terminal-poison settlement would make its base block unexpirable"
                                )
                            }
                        }
                    }

                    let plannedPayload = uniqueRecords.reduce(into: 0) {
                        total, record in
                        let bytes = capacityPoisonByLocation[record.location]
                            == nil ? record.block.payload.storedBytes : 512
                        let next = total.addingReportingOverflow(bytes)
                        total = next.overflow ? Int.max : next.partialValue
                    }
                    let plannedEstimate = terminalRevisionTransactionEstimate(
                        payloadBytes: plannedPayload,
                        eventCount: uniqueRecords.count,
                        canaryProjectionRefreshCount: uniqueRecords.filter {
                            capacityPoisonByLocation[$0.location] == nil
                                && NoiseFilter.isCoverageCanaryProbe(event: $0.event)
                        }.count
                    )
                    var exactPlanAdmitted = true
                    do {
                        try requireCurrentFamilyCapacityUnderWriterLock(
                            estimatedBytes: plannedEstimate,
                            postCommitHeadroomBytes:
                                terminalPoisonSettlementHeadroomBytes,
                            lane: .priority
                        )
                    } catch is SQLitePersistentStoreAdmissionError {
                        exactPlanAdmitted = false
                    } catch EventStoreError.storageNotReady(_) {
                        exactPlanAdmitted = false
                    }
                    if !exactPlanAdmitted {
                        // A cross-process writer may have consumed enough
                        // family/WAL headroom that the deltas no longer fit
                        // after this call's preflight. The initial serialized
                        // admission reserved compact poison settlement, so
                        // degrade the entire transaction without releasing the
                        // lock or returning a permanent writer remainder.
                        for record in uniqueRecords {
                            capacityPoisonByLocation[record.location] =
                                capacityPoison(for: record)
                        }
                        for blockID in affectedBlockIDs.sorted() {
                            var poisonExact = try loadExactJournalBlock(
                                blockID: blockID
                            )
                            let usage = try journalOverlayUsage(
                                blockID: blockID,
                                eventCount: poisonExact.events.count
                            )
                            for record in uniqueRecords where
                                record.location.blockID == blockID {
                                poisonExact.poisonByOrdinal[
                                    record.location.ordinal,
                                    default: []
                                ].append(EventJournalPoisonRecord(
                                    eventID: record.eventID,
                                    kind: .terminal,
                                    originalBytes: record.canonicalBytes,
                                    originalSHA256: record.terminalDigest,
                                    digestKind: .canonicalJSON
                                ))
                            }
                            guard try journalExpiryTransactionEstimate(
                                blockID: blockID,
                                exact: poisonExact,
                                overlayCascadePayloadBytes:
                                    usage.cascadePayloadBytes,
                                additionalPoisonCount:
                                    remainingMutablePoisonSlots(
                                        exact: poisonExact,
                                        terminalRevisionCount:
                                            usage.terminalCount
                                    )
                            ) <= reserve else {
                                throw EventStoreError.storageNotReady(
                                    "reserved all-poison settlement would make its base block unexpirable"
                                )
                            }
                        }
                        try requireCurrentFamilyCapacityUnderWriterLock(
                            estimatedBytes: poisonSettlementEstimate,
                            postCommitHeadroomBytes:
                                terminalPoisonSettlementHeadroomBytes,
                            lane: .priority
                        )
                    }
                    let now = Date().timeIntervalSince1970
                    for record in uniqueRecords {
                        if let overflow = capacityPoisonByLocation[
                            record.location
                        ] {
                            try persistCanonicalOverflowPoison(
                                overflow,
                                replacementDigest: record.terminalDigest,
                                kind: "terminal",
                                location: record.location,
                                now: now
                            )
                            _ = try dematerializeProjectionIfPresent(
                                blockID: record.location.blockID,
                                ordinal: record.location.ordinal,
                                replacement: .physical,
                                context: "terminal capacity poison"
                            )
                            for index in pendingOutcomes.indices where
                                pendingLocations[index] == record.location {
                                pendingOutcomes[index] = .poisoned(overflow)
                            }
                            continue
                        }
                        let statement = try prepare(
                            """
                            INSERT INTO event_journal_terminal_revisions (
                                block_id, ordinal, event_id, base_sha256,
                                terminal_sha256, framed_sha256, raw_bytes,
                                codec, payload, created_at
                            ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
                            """
                        )
                        sqlite3_bind_int64(
                            statement, 1, record.location.blockID
                        )
                        sqlite3_bind_int(
                            statement, 2, Int32(record.location.ordinal)
                        )
                        bindBlob(
                            statement, index: 3,
                            value: Self.uuidData(record.eventID)
                        )
                        bindBlob(
                            statement, index: 4,
                            value: record.baseDigest
                        )
                        bindBlob(
                            statement, index: 5,
                            value: record.terminalDigest
                        )
                        bindBlob(
                            statement, index: 6,
                            value: record.block.digest
                        )
                        sqlite3_bind_int64(
                            statement, 7, Int64(record.block.rawBytes)
                        )
                        sqlite3_bind_int(
                            statement, 8, Int32(record.block.codec)
                        )
                        switch record.block.payload {
                        case .compressed(let payload):
                            bindBlob(statement, index: 9, value: payload)
                        case .rawFragments:
                            guard sqlite3_bind_zeroblob64(
                                statement,
                                9,
                                sqlite3_uint64(
                                    record.block.payload.storedBytes
                                )
                            ) == SQLITE_OK else {
                                sqlite3_finalize(statement)
                                throw EventStoreError.stepFailed(
                                    "terminal raw zeroblob bind failed"
                                )
                            }
                        }
                        sqlite3_bind_double(statement, 10, now)
                        let rc = sqlite3_step(statement)
                        sqlite3_finalize(statement)
                        guard rc == SQLITE_DONE,
                              sqlite3_changes(db) == 1 else {
                            throw EventStoreError.stepFailed(
                                "terminal journal revision insert failed"
                            )
                        }
                        let terminalRowID = sqlite3_last_insert_rowid(db)
                        try writeRawJournalPayload(
                            record.block.payload,
                            table: "event_journal_terminal_revisions",
                            rowID: terminalRowID,
                            context: "terminal journal revision"
                        )
                        _ = try reconcileExistingProjectionUnderWriterLock(
                            event: record.event,
                            location: record.location,
                            context: "terminal revision",
                            prepared: record.projection
                        )
                    }
                    try execute("COMMIT")
                } catch EventStoreError
                    .terminalRevisionRequiresIdentityRefresh {
                    try? execute("ROLLBACK")
                    guard identityRefreshAttempt < 8 else {
                        throw EventStoreError.storageNotReady(
                            "terminal revision identity changed repeatedly while serializing a cross-process retry"
                        )
                    }
                    return try appendPreparedTerminalRevisions(
                        preparedEvents: preparedEvents,
                        lane: lane,
                        identityRefreshAttempt: identityRefreshAttempt + 1,
                        committedTransactionOffset: committedTransactions
                    )
                } catch {
                    try? execute("ROLLBACK")
                    throw error
                }
                committedTransactions += 1
                outcomes.append(contentsOf: pendingOutcomes)
                inputOffset = scan
            }
            return try terminalBatchResult(
                inputCount: events.count,
                outcomes: outcomes,
                committedTransactions: committedTransactions
            )
        } catch {
            let progress: EventTerminalRevisionBatchResult
            do {
                progress = try terminalBatchResult(
                    inputCount: events.count,
                    outcomes: outcomes,
                    committedTransactions: committedTransactions
                )
            } catch {
                throw EventTerminalRevisionBatchFailure(
                    progress: EventTerminalRevisionBatchResult(
                        inputCount: events.count,
                        outcomes: outcomes,
                        durableEventIDs: [],
                        insertedEventIDs: [],
                        idempotentEventIDs: [],
                        committedTransactionCount: committedTransactions,
                        storageMutationGeneration: 0
                    ),
                    uncommittedEvents: Array(events.dropFirst(inputOffset)),
                    underlyingError: error
                )
            }
            throw EventTerminalRevisionBatchFailure(
                progress: progress,
                uncommittedEvents: Array(events.dropFirst(inputOffset)),
                underlyingError: error
            )
        }
    }

    /// Pre-v8 row writer retained only as a migration/test compatibility
    /// helper. Production insertion enters through the block journal above.
    @discardableResult
    private func insertLegacyBatch(
        events: [Event],
        lane: EventPipelineLane
    ) throws -> EventBatchInsertResult {
        let startingGeneration = activeDatabaseGeneration
        guard events.allSatisfy({ EventPipelineLane.finalLane(for: $0) == lane }) else {
            throw EventBatchInsertFailure(
                progress: EventBatchInsertResult(
                    inputCount: events.count,
                    persistedCount: 0,
                    filteredCount: 0,
                    committedTransactionCount: 0,
                    inputDispositions: events.map {
                        .uncommitted(eventID: $0.id)
                    }
                ),
                uncommittedEvents: events,
                underlyingError: EventStoreError.stepFailed(
                    "Event batch mixes pipeline lanes or is mislabeled as \(lane.key)"
                )
            )
        }
        var candidates: [Event] = []
        candidates.reserveCapacity(events.count)
        var candidateOriginalIndices: [Int] = []
        candidateOriginalIndices.reserveCapacity(events.count)
        var inputDispositions = events.map {
            EventJournalInsertDisposition.uncommitted(eventID: $0.id)
        }
        var filteredCount = 0
        for (inputIndex, event) in events.enumerated() {
            if let filter = insertFilter, filter.shouldDrop(event: event) {
                filteredCount += 1
                inputDispositions[inputIndex] = .filtered(eventID: event.id)
            } else {
                candidates.append(event)
                candidateOriginalIndices.append(inputIndex)
            }
        }

        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        var transactionOpen = false
        var rowMutationEstimate: Int64 = 0
        var rowsInOpenTransaction = 0
        var committedRows = 0
        var committedTransactions = 0

        func commitOpenTransaction() throws {
            guard transactionOpen else { return }
            try execute("COMMIT")
            committedBatchInsertTransactions &+= 1
            committedTransactions += 1
            committedRows += rowsInOpenTransaction
            transactionOpen = false
            rowMutationEstimate = 0
            rowsInOpenTransaction = 0
        }

        do {
            for event in candidates {
                _ = try insert(
                    event: event,
                    applyInsertFilter: false
                ) { rowBytes in
                    let nextRows = SQLitePersistentStoreAdmission
                        .saturatingAdd(rowMutationEstimate, rowBytes)
                    let nextEstimate = eventTransactionEstimate(
                        rowMutationBytes: nextRows
                    )
                    if transactionOpen, nextEstimate > reserve {
                        try commitOpenTransaction()
                    }
                    if !transactionOpen {
                        let firstEstimate = eventTransactionEstimate(
                            rowMutationBytes: rowBytes
                        )
                        // The chunk can continue growing until `reserve` before
                        // its next admission boundary. Charge that complete
                        // upper bound now; admitting only `firstEstimate` lets
                        // later file rows consume the priority-only headroom
                        // without another probe. Preserve an oversized first
                        // row's real estimate so the shared gate still returns
                        // transactionEstimateExceedsReserve.
                        let admissionEstimate = max(firstEstimate, reserve)
                        try execute(
                            "BEGIN TRANSACTION",
                            estimatedTransactionBytes: admissionEstimate,
                            lane: lane
                        )
                        transactionOpen = true
                    }
                    rowMutationEstimate = SQLitePersistentStoreAdmission
                        .saturatingAdd(rowMutationEstimate, rowBytes)
                }
                rowsInOpenTransaction += 1
            }
            try commitOpenTransaction()
            for (candidateIndex, inputIndex) in candidateOriginalIndices.enumerated() {
                inputDispositions[inputIndex] = .durable(
                    eventID: candidates[candidateIndex].id
                )
            }
            return EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: committedRows,
                filteredCount: filteredCount,
                committedTransactionCount: committedTransactions,
                inputDispositions: inputDispositions
            )
        } catch {
            if transactionOpen { try? execute("ROLLBACK") }
            let databaseWasReplaced = activeDatabaseGeneration
                != startingGeneration
            for (candidateIndex, inputIndex) in candidateOriginalIndices.enumerated() {
                inputDispositions[inputIndex] = candidateIndex < committedRows
                    && !databaseWasReplaced
                    ? .durable(eventID: candidates[candidateIndex].id)
                    : .uncommitted(eventID: candidates[candidateIndex].id)
            }
            let durableRows = databaseWasReplaced ? 0 : committedRows
            let durableTransactions = databaseWasReplaced
                ? 0 : committedTransactions
            let progress = EventBatchInsertResult(
                inputCount: events.count,
                persistedCount: durableRows,
                filteredCount: filteredCount,
                committedTransactionCount: durableTransactions,
                inputDispositions: inputDispositions
            )
            throw EventBatchInsertFailure(
                progress: progress,
                uncommittedEvents: databaseWasReplaced
                    ? candidates
                    : Array(candidates.dropFirst(committedRows)),
                underlyingError: error,
                activeDatabaseWasReplaced: databaseWasReplaced,
                replacementReadyForRetry: databaseWasReplaced
                    && db != nil && insertStmt != nil && !isReadOnly
            )
        }
    }

    private func eventTransactionEstimate(
        rowMutationBytes: Int64
    ) -> Int64 {
        SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: rowMutationBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 48
        )
    }

    /// Deterministic regression surface for verifying that the reserve guard
    /// still batches ordinary events instead of degenerating to per-row commits.
    func batchInsertTransactionCount() -> UInt64 {
        committedBatchInsertTransactions
    }

    public struct EventJournalRecoverySnapshot: Sendable, Equatable {
        public let sourceEvents: Int
        public let migratedEvents: Int
        public let rolledExpiredEvents: Int
        public let corruptPreservedEvents: Int
        public let remainingEvents: Int
        public let complete: Bool
    }

    private enum LegacySQLiteValue: Equatable {
        case null
        case integer(Int64)
        case real(UInt64)
        case text(Data)
        case blob(Data)
    }

    /// Stable identity for one complete v7 source row, independent of its
    /// mutable SQLite rowid. The scan captures these exact values before any
    /// cross-process wait; migration/quarantine recompute them after BEGIN
    /// IMMEDIATE so a concurrent VACUUM can only force a safe retry, never
    /// redirect a rowid delete/marker onto unrelated evidence.
    private static func legacyTypedRowDigest(
        values: [LegacySQLiteValue]
    ) throws -> Data {
        guard values.count == legacyTypedEventColumns.count else {
            throw EventStoreError.decodingFailed(
                "legacy typed row digest column count is invalid"
            )
        }
        var hasher = SHA256()
        hasher.update(data: Data("MacCrab.LegacyTypedEventRow.v8\u{0}".utf8))
        func updateLength(_ value: Int) {
            var encoded = UInt64(max(0, value)).bigEndian
            withUnsafeBytes(of: &encoded) {
                hasher.update(data: Data($0))
            }
        }
        for (index, value) in values.enumerated() {
            let name = Data(legacyTypedEventColumns[index].utf8)
            updateLength(name.count)
            hasher.update(data: name)
            switch value {
            case .null:
                hasher.update(data: Data([UInt8(SQLITE_NULL)]))
                updateLength(0)
            case .integer(let integer):
                hasher.update(data: Data([UInt8(SQLITE_INTEGER)]))
                updateLength(MemoryLayout<UInt64>.size)
                var bits = UInt64(bitPattern: integer).bigEndian
                withUnsafeBytes(of: &bits) {
                    hasher.update(data: Data($0))
                }
            case .real(let bitPattern):
                hasher.update(data: Data([UInt8(SQLITE_FLOAT)]))
                updateLength(MemoryLayout<UInt64>.size)
                var bits = bitPattern.bigEndian
                withUnsafeBytes(of: &bits) {
                    hasher.update(data: Data($0))
                }
            case .text(let data):
                hasher.update(data: Data([UInt8(SQLITE_TEXT)]))
                updateLength(data.count)
                hasher.update(data: data)
            case .blob(let data):
                hasher.update(data: Data([UInt8(SQLITE_BLOB)]))
                updateLength(data.count)
                hasher.update(data: data)
            }
        }
        return Data(hasher.finalize())
    }

    /// Exact v7 typed projection order. `raw_json` is preserved and decoded
    /// separately; every other value must equal the projection deterministically
    /// derived from that pre-sanitization source Event before migration may
    /// delete the row.
    private static let legacyTypedEventColumns = [
        "id", "timestamp", "event_category", "event_type",
        "event_action", "severity", "process_pid", "process_name",
        "process_path", "process_commandline", "process_ppid",
        "process_signer", "process_team_id", "process_signing_id",
        "file_path", "file_action", "network_dest_ip",
        "network_dest_port", "tcc_service", "tcc_client", "raw_json",
        "mcp_server_name", "mcp_server_category", "ai_tool_session_id",
        "agent_trace_id", "agent_span_id", "agent_tool",
        "machine_agent_confidence", "agent_evidence_json", "user_id",
        "user_name", "group_id", "working_directory", "responsible_pid",
        "architecture", "is_platform_binary", "is_notarized",
        "process_sha256", "parent_name", "parent_executable",
        "parent_signer_type", "ai_tool", "ai_tool_child",
        "session_launch_source", "tcc_decision",
    ]

    private struct LegacyJournalRow {
        let rowID: Int64
        let idBytes: Data
        let timestamp: TimeInterval
        let categoryBytes: Data
        let rawJSON: Data
        let typedValues: [LegacySQLiteValue]
        /// v7 is not STRICT. Keep malformed storage-class rows representable so
        /// the per-row recovery loop can quarantine and retain them instead of
        /// letting one BLOB id / TEXT timestamp brick every future startup.
        let identityStorageValid: Bool
    }

    private struct LegacySourceIdentity {
        let rowID: Int64
        let typedRowDigest: Data
    }

    private func legacySQLiteValue(
        _ statement: OpaquePointer,
        column: Int32
    ) throws -> LegacySQLiteValue {
        switch sqlite3_column_type(statement, column) {
        case SQLITE_NULL:
            return .null
        case SQLITE_INTEGER:
            return .integer(sqlite3_column_int64(statement, column))
        case SQLITE_FLOAT:
            return .real(sqlite3_column_double(statement, column).bitPattern)
        case SQLITE_TEXT, SQLITE_BLOB:
            let count = Int(sqlite3_column_bytes(statement, column))
            let bytes: Data
            if count == 0 {
                bytes = Data()
            } else {
                guard let pointer = sqlite3_column_blob(statement, column) else {
                    throw EventStoreError.decodingFailed(
                        "legacy typed projection bytes are unavailable"
                    )
                }
                bytes = Data(bytes: pointer, count: count)
            }
            return sqlite3_column_type(statement, column) == SQLITE_TEXT
                ? .text(bytes) : .blob(bytes)
        default:
            throw EventStoreError.decodingFailed(
                "legacy typed projection has an unknown SQLite storage class"
            )
        }
    }

    private func readLegacyJournalRow(
        _ statement: OpaquePointer,
        rowIDColumn: Int32 = 0
    ) throws -> LegacyJournalRow {
        var values: [LegacySQLiteValue] = []
        values.reserveCapacity(Self.legacyTypedEventColumns.count)
        for offset in Self.legacyTypedEventColumns.indices {
            values.append(try legacySQLiteValue(
                statement,
                column: rowIDColumn + 1 + Int32(offset)
            ))
        }
        func columnBytes(_ offset: Int) throws -> Data {
            let column = rowIDColumn + 1 + Int32(offset)
            let count = Int(sqlite3_column_bytes(statement, column))
            if count == 0 { return Data() }
            guard let pointer = sqlite3_column_blob(statement, column) else {
                throw EventStoreError.decodingFailed(
                    "legacy typed diagnostic bytes are unavailable"
                )
            }
            return Data(bytes: pointer, count: count)
        }
        let idIsText: Bool
        let idBytes: Data
        if case .text(let bytes) = values[0] {
            idIsText = true
            idBytes = bytes
        } else {
            idIsText = false
            // sqlite3_column_blob applies the same value conversion as
            // CAST(id AS BLOB), which is the immutable quarantine join key.
            // This keeps non-TEXT ids protected by every retention path too.
            idBytes = try columnBytes(0)
        }
        let timestampIsReal: Bool
        let timestamp: TimeInterval
        if case .real(let bits) = values[1] {
            timestampIsReal = true
            timestamp = Double(bitPattern: bits)
        } else {
            timestampIsReal = false
            timestamp = 0
        }
        let categoryIsText: Bool
        let categoryBytes: Data
        if case .text(let bytes) = values[2] {
            categoryIsText = true
            categoryBytes = bytes
        } else {
            categoryIsText = false
            categoryBytes = try columnBytes(2)
        }
        let rawJSON: Data
        let rawStorageValid: Bool
        switch values[20] {
        case .text(let bytes), .blob(let bytes):
            rawJSON = bytes
            rawStorageValid = true
        default:
            rawJSON = try columnBytes(20)
            rawStorageValid = false
        }
        return LegacyJournalRow(
            rowID: sqlite3_column_int64(statement, rowIDColumn),
            idBytes: idBytes,
            timestamp: timestamp,
            categoryBytes: categoryBytes,
            rawJSON: rawJSON,
            typedValues: values,
            identityStorageValid: idIsText && timestampIsReal
                && categoryIsText && rawStorageValid
        )
    }

    private func expectedLegacyTypedValues(
        for event: Event,
        preservingRaw raw: LegacySQLiteValue
    ) -> [LegacySQLiteValue] {
        func text(_ value: String?) -> LegacySQLiteValue {
            value.map { .text(Data($0.utf8)) } ?? .null
        }
        func nonempty(_ value: String) -> LegacySQLiteValue {
            value.isEmpty ? .null : text(value)
        }
        let signature = event.process.codeSignature
        let aiTool = event.enrichments["ai_tool"]
            ?? event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]
        return [
            text(event.id.uuidString),
            .real(event.timestamp.timeIntervalSince1970.bitPattern),
            text(event.eventCategory.rawValue), text(event.eventType.rawValue),
            text(event.eventAction), text(event.severity.rawValue),
            .integer(Int64(event.process.pid)), text(event.process.name),
            text(event.process.executable),
            text(Self.boundIndexedText(
                event.process.commandLine,
                maxBytes: Self.maxIndexedCommandLineBytes
            )),
            .integer(Int64(event.process.ppid)),
            text(signature?.signerType.rawValue), text(signature?.teamId),
            text(signature?.signingId), text(event.file?.path),
            text(event.file?.action.rawValue),
            text(event.network?.destinationIp),
            event.network.map {
                .integer(Int64($0.destinationPort))
            } ?? .null,
            text(event.tcc?.service), text(event.tcc?.client), raw,
            text(event.enrichments["mcp_server_name"]),
            text(event.enrichments["mcp_server_category"]),
            text(event.enrichments["ai_tool_session_id"]),
            text(event.enrichments[TraceCorrelator.EnrichmentKey.traceId]),
            text(event.enrichments[TraceCorrelator.EnrichmentKey.spanId]),
            text(event.enrichments[TraceCorrelator.EnrichmentKey.agentTool]),
            text(event.enrichments[TraceCorrelator.EnrichmentKey.confidence]),
            text(event.enrichments[TraceCorrelator.EnrichmentKey.evidenceJson]),
            .integer(Int64(event.process.userId)),
            nonempty(event.process.userName),
            .integer(Int64(event.process.groupId)),
            nonempty(event.process.workingDirectory),
            .integer(Int64(event.process.rpid)), text(event.process.architecture),
            .integer(event.process.isPlatformBinary ? 1 : 0),
            signature.map { .integer($0.isNotarized ? 1 : 0) } ?? .null,
            text(event.process.hashes?.sha256),
            text(event.process.ancestors.first?.name),
            text(event.process.ancestors.first?.executable),
            text(event.enrichments["ParentSignerType"]), text(aiTool),
            event.enrichments["ai_tool_child"].map {
                .integer($0 == "true" ? 1 : 0)
            } ?? .null,
            text(event.process.session?.launchSource?.rawValue),
            event.tcc.map { text($0.allowed ? "granted" : "denied") }
                ?? .null,
        ]
    }

    private struct LegacyInheritedLoss {
        let kind: String
        let originalBytes: Int?
        let originalSHA256: Data?
        let recoveredFields: [String]
        let unavailableFields: [String]
    }

    private struct DecodedLegacyJournalRow {
        let event: Event
        let inheritedLoss: LegacyInheritedLoss?
    }

    private static func legacyUnavailableFieldPaths(
        event: Event,
        structuredTruncation: Bool,
        recoveredMismatchIndexes: [Int]
    ) -> [String] {
        var fields = Set<String>()
        if structuredTruncation {
            // rc.12's truncation rebuild preserved hashes/session/env but its
            // then-current ProcessInfo initializer omitted auditIdentity.
            // A prior command-sanitizer rebuild may already have dropped the
            // other newer ProcessInfo fields without leaving a separate bit,
            // so conservatively disclose those possible gaps too.
            fields.formUnion([
                "process.hashes.cdhash",
                "process.hashes.md5",
                "process.session.sessionId",
                "process.session.tty",
                "process.session.loginUser",
                "process.session.sshRemoteIP",
                "process.envVars",
                "process.auditIdentity",
            ])
            if event.process.args.contains(where: {
                $0.hasPrefix("<truncated:")
                    || $0.hasPrefix("…<truncated:")
            }) {
                fields.insert("process.args")
            }
            if event.process.commandLine.hasPrefix("<truncated:")
                || event.process.commandLine.hasPrefix("…<truncated:") {
                fields.insert("process.commandLine")
            }
            for (key, value) in event.enrichments where
                value.hasPrefix("<truncated:")
                    || value.hasPrefix("…<truncated:") {
                fields.insert("enrichments.\(key)")
            }
        }
        // A non-null typed SHA/launch source absent from raw proves rc.12 took
        // its command-sanitizer rebuild path. That constructor preserved every
        // ordinary Event field but defaulted these newer ProcessInfo additions.
        if recoveredMismatchIndexes.contains(37) {
            fields.formUnion([
                "process.hashes.cdhash",
                "process.hashes.md5",
            ])
        }
        if recoveredMismatchIndexes.contains(43) {
            fields.formUnion([
                "process.session.sessionId",
                "process.session.tty",
                "process.session.loginUser",
                "process.session.sshRemoteIP",
            ])
        }
        if recoveredMismatchIndexes.contains(37)
            || recoveredMismatchIndexes.contains(43) {
            fields.formUnion([
                "process.envVars",
                "process.auditIdentity",
            ])
        }
        return fields.sorted()
    }

    private func legacyText(
        _ row: LegacyJournalRow,
        _ index: Int
    ) throws -> String? {
        switch row.typedValues[index] {
        case .null:
            return nil
        case .text(let bytes):
            guard let value = String(data: bytes, encoding: .utf8) else {
                throw EventStoreError.decodingFailed(
                    "legacy typed text is not valid UTF-8"
                )
            }
            return value
        default:
            throw EventStoreError.decodingFailed(
                "legacy typed text has the wrong SQLite storage class"
            )
        }
    }

    private func legacyInteger(
        _ row: LegacyJournalRow,
        _ index: Int
    ) throws -> Int64? {
        switch row.typedValues[index] {
        case .null: return nil
        case .integer(let value): return value
        default:
            throw EventStoreError.decodingFailed(
                "legacy typed integer has the wrong SQLite storage class"
            )
        }
    }

    private func legacyTypedMismatchIndexes(
        expected: [LegacySQLiteValue],
        actual: [LegacySQLiteValue]
    ) -> [Int] {
        zip(expected.indices, zip(expected, actual)).compactMap {
            index, values in
            if index == 20 { return nil } // raw_json is compared separately.
            // Columns added in v2/v4/v6 were never backfilled. NULL means the
            // typed evidence was unavailable for that historical writer, so
            // retain the decoded raw value rather than manufacturing drift.
            if index >= 21, values.1 == .null { return nil }
            return values.0 == values.1 ? nil : index
        }
    }

    private static func legacyHexDigest(_ value: String?) -> Data? {
        guard let value, value.utf8.count == SHA256.byteCount * 2 else {
            return nil
        }
        var output = Data()
        output.reserveCapacity(SHA256.byteCount)
        var index = value.startIndex
        for _ in 0..<SHA256.byteCount {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                return nil
            }
            output.append(byte)
            index = next
        }
        return output
    }

    /// Overlay the exact rc.12 typed bind surface over its independently
    /// sanitized/truncated raw JSON. Non-null additive values are authoritative;
    /// additive NULL retains raw because older schema epochs were not backfilled.
    private func reconstructLegacyTypedEvent(
        _ source: Event,
        row: LegacyJournalRow,
        structuredTruncation: Bool
    ) throws -> Event {
        func requiredText(_ index: Int) throws -> String {
            guard let value = try legacyText(row, index) else {
                throw EventStoreError.decodingFailed(
                    "legacy required typed text is NULL"
                )
            }
            return value
        }
        func requiredInt32(_ index: Int) throws -> Int32 {
            guard let value = try legacyInteger(row, index),
                  let converted = Int32(exactly: value) else {
                throw EventStoreError.decodingFailed(
                    "legacy required Int32 is absent or out of range"
                )
            }
            return converted
        }
        func optionalUInt32(_ index: Int, fallback: UInt32) throws -> UInt32 {
            guard let value = try legacyInteger(row, index) else {
                return fallback
            }
            guard let converted = UInt32(exactly: value) else {
                throw EventStoreError.decodingFailed(
                    "legacy UInt32 is out of range"
                )
            }
            return converted
        }
        func optionalBool(_ index: Int, fallback: Bool) throws -> Bool {
            guard let value = try legacyInteger(row, index) else {
                return fallback
            }
            guard value == 0 || value == 1 else {
                throw EventStoreError.decodingFailed(
                    "legacy Bool is not encoded as 0/1"
                )
            }
            return value == 1
        }

        let rawProcess = source.process
        let typedCommandLine = try requiredText(9)
        let commandLine: String
        if !structuredTruncation,
           Self.boundIndexedText(
                rawProcess.commandLine,
                maxBytes: Self.maxIndexedCommandLineBytes
           ) == typedCommandLine {
            // The typed column is an index key, not a richer evidence field.
            commandLine = rawProcess.commandLine
        } else if rawProcess.commandLine.hasPrefix("<truncated:")
                    || rawProcess.commandLine.hasPrefix("…<truncated:") {
            commandLine = typedCommandLine
        } else {
            commandLine = rawProcess.commandLine.utf8.count
                >= typedCommandLine.utf8.count
                ? rawProcess.commandLine : typedCommandLine
        }

        let signerText = try legacyText(row, 11)
        let teamID = try legacyText(row, 12)
        let signingID = try legacyText(row, 13)
        let signature: CodeSignatureInfo?
        if let signerText {
            guard let signer = SignerType(rawValue: signerText) else {
                throw EventStoreError.decodingFailed(
                    "legacy signer type is invalid"
                )
            }
            let prior = rawProcess.codeSignature
            signature = CodeSignatureInfo(
                signerType: signer,
                teamId: teamID,
                signingId: signingID,
                authorities: prior?.authorities ?? [],
                flags: prior?.flags ?? 0,
                isNotarized: try optionalBool(
                    36,
                    fallback: prior?.isNotarized ?? false
                ),
                issuerChain: prior?.issuerChain,
                certHashes: prior?.certHashes,
                isAdhocSigned: prior?.isAdhocSigned,
                entitlements: prior?.entitlements
            )
        } else {
            guard teamID == nil, signingID == nil,
                  try legacyInteger(row, 36) == nil else {
                throw EventStoreError.decodingFailed(
                    "legacy signature columns are internally inconsistent"
                )
            }
            signature = nil
        }

        let sha256 = try legacyText(row, 37)
        let hashes: ProcessHashes?
        if let sha256 {
            hashes = ProcessHashes(
                sha256: sha256,
                cdhash: rawProcess.hashes?.cdhash,
                md5: rawProcess.hashes?.md5
            )
        } else {
            hashes = rawProcess.hashes
        }

        let parentName = try legacyText(row, 38)
        let parentExecutable = try legacyText(row, 39)
        var ancestors = rawProcess.ancestors
        if parentName != nil || parentExecutable != nil {
            guard let parentName, let parentExecutable else {
                throw EventStoreError.decodingFailed(
                    "legacy parent columns are internally inconsistent"
                )
            }
            let parent = ProcessAncestor(
                pid: ancestors.first?.pid ?? 0,
                executable: parentExecutable,
                name: parentName
            )
            if ancestors.isEmpty { ancestors = [parent] }
            else { ancestors[0] = parent }
        }

        let launchSourceText = try legacyText(row, 43)
        var session = rawProcess.session
        if let launchSourceText {
            guard let launchSource = LaunchSource(rawValue: launchSourceText)
            else {
                throw EventStoreError.decodingFailed(
                    "legacy session launch source is invalid"
                )
            }
            let prior = session
            session = SessionInfo(
                sessionId: prior?.sessionId,
                tty: prior?.tty,
                loginUser: prior?.loginUser,
                sshRemoteIP: prior?.sshRemoteIP,
                launchSource: launchSource
            )
        }

        let process = ProcessInfo(
            pid: try requiredInt32(6),
            ppid: try requiredInt32(10),
            rpid: try legacyInteger(row, 33).flatMap(Int32.init(exactly:))
                ?? rawProcess.rpid,
            name: try requiredText(7),
            executable: try requiredText(8),
            commandLine: commandLine,
            args: rawProcess.args,
            workingDirectory: try legacyText(row, 32)
                ?? rawProcess.workingDirectory,
            userId: try optionalUInt32(29, fallback: rawProcess.userId),
            userName: try legacyText(row, 30) ?? rawProcess.userName,
            groupId: try optionalUInt32(31, fallback: rawProcess.groupId),
            startTime: rawProcess.startTime,
            exitCode: rawProcess.exitCode,
            codeSignature: signature,
            ancestors: ancestors,
            architecture: try legacyText(row, 34) ?? rawProcess.architecture,
            isPlatformBinary: try optionalBool(
                35,
                fallback: rawProcess.isPlatformBinary
            ),
            hashes: hashes,
            session: session,
            envVars: rawProcess.envVars,
            auditIdentity: rawProcess.auditIdentity
        )

        let filePath = try legacyText(row, 14)
        let fileActionText = try legacyText(row, 15)
        let file: FileInfo?
        if filePath == nil, fileActionText == nil {
            file = nil
        } else {
            guard let filePath, let fileActionText,
                  let action = FileAction(rawValue: fileActionText) else {
                throw EventStoreError.decodingFailed(
                    "legacy file columns are internally inconsistent"
                )
            }
            if let prior = source.file {
                file = FileInfo(
                    path: filePath,
                    name: prior.name,
                    directory: prior.directory,
                    extension_: prior.extension_,
                    size: prior.size,
                    action: action,
                    sourcePath: prior.sourcePath
                )
            } else {
                file = FileInfo(path: filePath, action: action)
            }
        }

        let destinationIP = try legacyText(row, 16)
        let destinationPortValue = try legacyInteger(row, 17)
        let network: NetworkInfo?
        if destinationIP == nil, destinationPortValue == nil {
            network = nil
        } else {
            guard let destinationIP, let destinationPortValue,
                  let destinationPort = UInt16(exactly: destinationPortValue),
                  let prior = source.network else {
                throw EventStoreError.decodingFailed(
                    "legacy network typed evidence lacks its raw source context"
                )
            }
            network = NetworkInfo(
                sourceIp: prior.sourceIp,
                sourcePort: prior.sourcePort,
                destinationIp: destinationIP,
                destinationPort: destinationPort,
                destinationHostname: prior.destinationHostname,
                direction: prior.direction,
                transport: prior.transport
            )
        }

        let tccService = try legacyText(row, 18)
        let tccClient = try legacyText(row, 19)
        let tccDecision = try legacyText(row, 44)
        let tcc: TCCInfo?
        if tccService == nil, tccClient == nil, tccDecision == nil {
            tcc = nil
        } else {
            guard let tccService, let tccClient, let prior = source.tcc,
                  tccDecision == "granted" || tccDecision == "denied" else {
                throw EventStoreError.decodingFailed(
                    "legacy TCC typed evidence lacks its raw source context"
                )
            }
            tcc = TCCInfo(
                service: tccService,
                client: tccClient,
                clientPath: prior.clientPath,
                allowed: tccDecision == "granted",
                authReason: prior.authReason
            )
        }

        var enrichments = source.enrichments
        let enrichmentColumns: [(Int, String)] = [
            (21, "mcp_server_name"),
            (22, "mcp_server_category"),
            (23, "ai_tool_session_id"),
            (24, TraceCorrelator.EnrichmentKey.traceId),
            (25, TraceCorrelator.EnrichmentKey.spanId),
            (26, TraceCorrelator.EnrichmentKey.agentTool),
            (27, TraceCorrelator.EnrichmentKey.confidence),
            (28, TraceCorrelator.EnrichmentKey.evidenceJson),
            (40, "ParentSignerType"),
            (41, "ai_tool"),
        ]
        for (index, key) in enrichmentColumns {
            if let value = try legacyText(row, index) {
                enrichments[key] = value
            }
        }
        if let aiChild = try legacyInteger(row, 42) {
            guard aiChild == 0 || aiChild == 1 else {
                throw EventStoreError.decodingFailed(
                    "legacy ai_tool_child is not encoded as 0/1"
                )
            }
            enrichments["ai_tool_child"] = aiChild == 1 ? "true" : "false"
        }

        guard let eventType = EventType(rawValue: try requiredText(3)),
              let severity = Severity(rawValue: try requiredText(5)) else {
            throw EventStoreError.decodingFailed(
                "legacy event type/severity is invalid"
            )
        }
        return Event(
            id: source.id,
            timestamp: source.timestamp,
            eventCategory: source.eventCategory,
            eventType: eventType,
            eventAction: try requiredText(4),
            process: process,
            file: file,
            network: network,
            tcc: tcc,
            enrichments: enrichments,
            severity: severity,
            ruleMatches: source.ruleMatches
        )
    }

    private func tableHasColumn(_ table: String, _ column: String) throws -> Bool {
        guard table.unicodeScalars.allSatisfy({
            CharacterSet.alphanumerics
                .union(CharacterSet(charactersIn: "_"))
                .contains($0)
        }) else {
            throw EventStoreError.prepareFailed("unsafe table name")
        }
        let statement = try prepare("PRAGMA table_info(\(table))")
        defer { sqlite3_finalize(statement) }
        while sqlite3_step(statement) == SQLITE_ROW {
            if let pointer = sqlite3_column_text(statement, 1),
               String(cString: pointer) == column {
                return true
            }
        }
        return false
    }

    private func legacyJournalRowCount() throws -> Int {
        guard try tableHasColumn("events", "journal_block_id") else {
            let statement = try prepare("SELECT COUNT(*) FROM events")
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else {
                throw EventStoreError.stepFailed("legacy event count failed")
            }
            return Int(sqlite3_column_int64(statement, 0))
        }
        let statement = try prepare(
            """
            SELECT COUNT(*) FROM events AS e
            WHERE e.journal_block_id IS NULL
              AND e.journal_quarantine_marker IS NULL
            """
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed("legacy event count failed")
        }
        return Int(sqlite3_column_int64(statement, 0))
    }

    private func nextLegacyJournalRows(limit: Int) throws -> [LegacyJournalRow] {
        let columns = Self.legacyTypedEventColumns.map {
            "\"\($0)\""
        }.joined(separator: ", ")
        let statement = try prepare(
            """
            SELECT rowid, \(columns)
            FROM events
            WHERE journal_block_id IS NULL
              AND journal_quarantine_marker IS NULL
            ORDER BY rowid ASC
            LIMIT ?1
            """
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int(statement, 1, Int32(max(1, min(limit, 128))))
        var rows: [LegacyJournalRow] = []
        while true {
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "legacy event migration scan failed"
                )
            }
            rows.append(try readLegacyJournalRow(statement))
        }
        return rows
    }

    private func decodeLegacyJournalRowWithLoss(
        _ row: LegacyJournalRow
    ) throws -> DecodedLegacyJournalRow {
        guard row.identityStorageValid else {
            throw EventStoreError.decodingFailed(
                "legacy identity/raw_json has an invalid SQLite storage class"
            )
        }
        let event = try decoder.decode(Event.self, from: row.rawJSON)
        guard let idText = String(data: row.idBytes, encoding: .utf8),
              let categoryText = String(
                data: row.categoryBytes,
                encoding: .utf8
              ),
              let columnID = UUID(uuidString: idText),
              event.id == columnID,
              row.timestamp.isFinite,
              event.timestamp.timeIntervalSince1970.isFinite,
              event.timestamp.timeIntervalSince1970 == row.timestamp,
              event.eventCategory.rawValue == categoryText else {
            throw EventStoreError.decodingFailed(
                "legacy identity does not match raw_json"
            )
        }
        let expected = expectedLegacyTypedValues(
            for: event,
            preservingRaw: row.typedValues[20]
        )
        let mismatches = legacyTypedMismatchIndexes(
            expected: expected,
            actual: row.typedValues
        )
        let structuredTruncation =
            event.enrichments["payload.truncated"] == "true"
        // rc.12's command-line sanitizer rebuilt ProcessInfo without the later
        // hashes/session/env/audit fields. The only typed evidence capable of
        // recovering that unmarked, shipping writer transformation is SHA-256
        // and launchSource; all other unmarked non-null disagreement is retained
        // in-place as quarantine rather than silently choosing one source.
        let allowedUnmarkedRecovery = Set([37, 43])
        let allowedStructuredRecovery = allowedUnmarkedRecovery.union([
            9, 21, 22, 23, 24, 25, 26, 27, 28, 40, 41, 42,
        ])
        let allowedRecovery = structuredTruncation
            ? allowedStructuredRecovery : allowedUnmarkedRecovery
        guard Set(mismatches).isSubset(of: allowedRecovery) else {
            throw EventStoreError.decodingFailed(
                "legacy typed projection has an unexplained raw_json mismatch"
            )
        }
        let reconstructed = try reconstructLegacyTypedEvent(
            event,
            row: row,
            structuredTruncation: structuredTruncation
        )
        let reconstructedExpected = expectedLegacyTypedValues(
            for: reconstructed,
            preservingRaw: row.typedValues[20]
        )
        let unresolved = legacyTypedMismatchIndexes(
            expected: reconstructedExpected,
            actual: row.typedValues
        )
        guard unresolved.isEmpty else {
            throw EventStoreError.decodingFailed(
                "legacy typed reconstruction did not conserve every available column"
            )
        }
        // Typed equivalence is checked against the original rc.12 projection
        // first. Mixed exact reads then return the same credential-sanitized,
        // normalized value migration will journal, so the API does not change
        // at the transcode boundary.
        let sanitized = try EventJournalAdmissionValidator.prepare(
            reconstructed
        ).event
        let loss: LegacyInheritedLoss?
        if structuredTruncation || !mismatches.isEmpty {
            let originalBytes = structuredTruncation
                ? event.enrichments["payload.original_bytes"].flatMap(Int.init)
                : nil
            guard !structuredTruncation || (originalBytes ?? 0) > 0 else {
                throw EventStoreError.decodingFailed(
                    "legacy structured-truncation marker lacks original byte count"
                )
            }
            loss = LegacyInheritedLoss(
                kind: structuredTruncation
                    ? "structured_truncation" : "sanitizer_rebuild",
                originalBytes: originalBytes,
                // Shipping rc.12 recorded original_bytes but not a digest.
                // Newer rows may carry the added digest; NULL is honest when
                // the old writer never captured it.
                originalSHA256: Self.legacyHexDigest(
                    event.enrichments["payload.original_sha256"]
                ),
                recoveredFields: mismatches.map {
                    Self.legacyTypedEventColumns[$0]
                }.sorted(),
                unavailableFields: Self.legacyUnavailableFieldPaths(
                    event: event,
                    structuredTruncation: structuredTruncation,
                    recoveredMismatchIndexes: mismatches
                )
            )
        } else {
            loss = nil
        }
        return DecodedLegacyJournalRow(
            event: sanitized,
            inheritedLoss: loss
        )
    }

    private func decodeLegacyJournalRow(_ row: LegacyJournalRow) throws -> Event {
        try decodeLegacyJournalRowWithLoss(row).event
    }

    /// Digest every declared `events` value with its column name, SQLite
    /// storage class, and exact byte/numeric representation. The source row is
    /// deliberately retained in place when legacy raw JSON is undecodable; this
    /// digest makes later VACUUM/reopen verification prove that none of its
    /// other typed evidence fields changed or disappeared. `rowid` is excluded
    /// because SQLite may renumber it during VACUUM.
    private func legacyTypedRowDigest(rowID: Int64) throws -> Data {
        let columns = Self.legacyTypedEventColumns.map {
            "\"\($0)\""
        }.joined(separator: ", ")
        let statement = try prepare(
            "SELECT \(columns) FROM events WHERE rowid = ?1 LIMIT 1"
        )
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_int64(statement, 1, rowID)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.decodingFailed(
                "quarantined legacy source row is missing"
            )
        }
        var values: [LegacySQLiteValue] = []
        values.reserveCapacity(Self.legacyTypedEventColumns.count)
        for column in 0..<Int32(Self.legacyTypedEventColumns.count) {
            values.append(try legacySQLiteValue(
                statement,
                column: column
            ))
        }
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "legacy typed row identity is duplicated"
            )
        }
        return try Self.legacyTypedRowDigest(values: values)
    }

    private static func legacyQuarantineSourceMarker(
        typedRowDigest: Data,
        originalRowID: Int64
    ) -> Data {
        var hasher = SHA256()
        hasher.update(data: Data(
            "MacCrab.LegacyQuarantineSource.v1\u{0}".utf8
        ))
        hasher.update(data: typedRowDigest)
        var rowID = UInt64(bitPattern: originalRowID).bigEndian
        withUnsafeBytes(of: &rowID) {
            hasher.update(data: Data($0))
        }
        return Data(hasher.finalize())
    }

    private func validateLegacyQuarantineIntegrity() throws {
        let quarantine = try prepare(
            """
            SELECT source_marker, legacy_rowid, legacy_id_bytes,
                   identity_kind, raw_json, raw_sha256, typed_row_sha256
            FROM event_journal_legacy_quarantine ORDER BY quarantine_id
            """
        )
        defer { sqlite3_finalize(quarantine) }
        while true {
            let rc = sqlite3_step(quarantine)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "legacy quarantine integrity scan failed"
                )
            }
            func bytes(_ column: Int32) throws -> Data {
                let count = Int(sqlite3_column_bytes(quarantine, column))
                if count == 0 { return Data() }
                guard let pointer = sqlite3_column_blob(quarantine, column) else {
                    throw EventStoreError.decodingFailed(
                        "legacy quarantine bytes are unavailable"
                    )
                }
                return Data(bytes: pointer, count: count)
            }
            let sourceMarker = try bytes(0)
            let persistedRowID = sqlite3_column_int64(quarantine, 1)
            _ = try bytes(2) // preserved diagnostic identity bytes
            guard let identityPointer = sqlite3_column_text(quarantine, 3)
            else {
                throw EventStoreError.decodingFailed(
                    "legacy quarantine identity kind is unavailable"
                )
            }
            let identityKind = String(cString: identityPointer)
            let preservedRaw = try bytes(4)
            let rawDigest = try bytes(5)
            let typedDigest = try bytes(6)
            guard sourceMarker.count == SHA256.byteCount,
                  (identityKind == "id" || identityKind == "rowid"),
                  rawDigest.count == SHA256.byteCount,
                  typedDigest.count == SHA256.byteCount,
                  sourceMarker == Self.legacyQuarantineSourceMarker(
                    typedRowDigest: typedDigest,
                    originalRowID: persistedRowID
                  ),
                  Data(SHA256.hash(data: preservedRaw)) == rawDigest else {
                throw EventStoreError.decodingFailed(
                    "legacy quarantine checksum mismatch"
                )
            }
            let source = try prepare(
                """
                SELECT rowid, CAST(raw_json AS BLOB) FROM events
                WHERE journal_block_id IS NULL
                  AND journal_quarantine_marker = ?1
                LIMIT 2
                """
            )
            bindBlob(source, index: 1, value: sourceMarker)
            guard sqlite3_step(source) == SQLITE_ROW else {
                sqlite3_finalize(source)
                throw EventStoreError.decodingFailed(
                    "quarantined legacy source row is missing"
                )
            }
            let sourceRowID = sqlite3_column_int64(source, 0)
            let sourceRawCount = Int(sqlite3_column_bytes(source, 1))
            let sourceRaw: Data
            if sourceRawCount == 0 {
                sourceRaw = Data()
            } else if let pointer = sqlite3_column_blob(source, 1) {
                sourceRaw = Data(bytes: pointer, count: sourceRawCount)
            } else {
                sqlite3_finalize(source)
                throw EventStoreError.decodingFailed(
                    "quarantined legacy source raw bytes are unavailable"
                )
            }
            guard sqlite3_step(source) == SQLITE_DONE else {
                sqlite3_finalize(source)
                throw EventStoreError.decodingFailed(
                    "quarantined legacy source identity is not unique"
                )
            }
            sqlite3_finalize(source)
            guard sourceRaw == preservedRaw,
                  try legacyTypedRowDigest(rowID: sourceRowID)
                    == typedDigest else {
                throw EventStoreError.decodingFailed(
                    "quarantined legacy source row changed after preservation"
                )
            }
        }
        let orphan = try prepare(
            """
            SELECT 1
            FROM events AS e
            LEFT JOIN event_journal_legacy_quarantine AS q
              ON q.source_marker = e.journal_quarantine_marker
            WHERE e.journal_quarantine_marker IS NOT NULL
              AND (e.journal_block_id IS NOT NULL
                   OR q.quarantine_id IS NULL)
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(orphan) }
        guard sqlite3_step(orphan) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "legacy quarantine source marker is orphaned"
            )
        }
    }

    private func quarantineLegacyJournalRow(
        _ row: LegacyJournalRow,
        reason: String
    ) throws {
        let boundedReason = Self.boundIndexedText(reason, maxBytes: 1_024)
        let typedRowDigest = try Self.legacyTypedRowDigest(
            values: row.typedValues
        )
        let sourceMarker = Self.legacyQuarantineSourceMarker(
            typedRowDigest: typedRowDigest,
            originalRowID: row.rowID
        )
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        let logicalBytes = Int64(
            row.rawJSON.count + row.idBytes.count
                + row.categoryBytes.count + boundedReason.utf8.count + 288
        )
        let estimate = eventTransactionEstimate(
            rowMutationBytes: SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: logicalBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumLeafPageTouches: 3
                )
        )
        guard estimate <= reserve else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: estimate,
                    reserveBytes: reserve
                )
        }
        try admitJournalRecoveryTransaction(estimatedBytes: estimate)
        try beginSerializedWrite(
            estimatedBytes: estimate,
            maintenance: true
        )
        do {
            guard try legacyTypedRowDigest(rowID: row.rowID)
                    == typedRowDigest else {
                throw EventStoreError.storageNotReady(
                    "legacy quarantine source moved before its writer lock; retry recovery"
                )
            }
            let markSource = try prepare(
                """
                UPDATE events SET journal_quarantine_marker = ?1
                WHERE rowid = ?2 AND journal_block_id IS NULL
                  AND journal_quarantine_marker IS NULL
                """
            )
            bindBlob(markSource, index: 1, value: sourceMarker)
            sqlite3_bind_int64(markSource, 2, row.rowID)
            let markRC = sqlite3_step(markSource)
            let markedRows = sqlite3_changes(db)
            sqlite3_finalize(markSource)
            guard markRC == SQLITE_DONE, markedRows == 1 else {
                throw EventStoreError.decodingFailed(
                    "legacy quarantine source changed before marking"
                )
            }
            let statement = try prepare(
                """
                INSERT INTO event_journal_legacy_quarantine (
                    source_marker, legacy_rowid, legacy_id_bytes, identity_kind,
                    legacy_timestamp,
                    legacy_category_bytes, raw_json, raw_sha256,
                    typed_row_sha256, reason, quarantined_at
                ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
                """
            )
            bindBlob(statement, index: 1, value: sourceMarker)
            sqlite3_bind_int64(statement, 2, row.rowID)
            bindBlob(statement, index: 3, value: row.idBytes)
            bindText(
                statement,
                index: 4,
                value: row.identityStorageValid ? "id" : "rowid"
            )
            sqlite3_bind_double(statement, 5, row.timestamp)
            bindBlob(statement, index: 6, value: row.categoryBytes)
            bindBlob(statement, index: 7, value: row.rawJSON)
            bindBlob(
                statement,
                index: 8,
                value: Data(SHA256.hash(data: row.rawJSON))
            )
            bindBlob(statement, index: 9, value: typedRowDigest)
            bindText(statement, index: 10, value: boundedReason)
            sqlite3_bind_double(statement, 11, Date().timeIntervalSince1970)
            let insertRC = sqlite3_step(statement)
            sqlite3_finalize(statement)
            guard insertRC == SQLITE_DONE,
                  sqlite3_changes(db) == 1 else {
                throw EventStoreError.stepFailed(
                    "legacy quarantine insert failed"
                )
            }
            // Keep the complete original v7 row in place. Invalid raw_json can
            // coexist with unique evidence in any of the ~45 typed columns;
            // copying only raw bytes would destroy that evidence. The immutable
            // quarantine marker terminally excludes this row from migration,
            // while the untouched source row remains byte/type recoverable.
            let progress = try prepare(
                """
                UPDATE event_journal_migration SET
                    last_legacy_rowid = MAX(last_legacy_rowid, ?1),
                    corrupt_preserved_events = corrupt_preserved_events + 1,
                    remaining_events = remaining_events - 1,
                    updated_at = ?2
                WHERE singleton = 1
                """
            )
            sqlite3_bind_int64(progress, 1, row.rowID)
            sqlite3_bind_double(progress, 2, Date().timeIntervalSince1970)
            let progressRC = sqlite3_step(progress)
            sqlite3_finalize(progress)
            guard progressRC == SQLITE_DONE,
                  sqlite3_changes(db) == 1 else {
                throw EventStoreError.stepFailed(
                    "legacy quarantine progress update failed"
                )
            }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    private func deleteMigratedLegacyRows(
        _ sources: [LegacySourceIdentity],
        mutationBytesPerRow: Int64
    ) throws {
        guard !sources.isEmpty else { return }
        let rowBytes = SQLitePersistentStoreAdmission.saturatingMultiply(
            mutationBytesPerRow,
            by: Int64(sources.count)
        )
        let estimate = eventTransactionEstimate(rowMutationBytes: rowBytes)
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        guard estimate <= reserve else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: estimate,
                    reserveBytes: reserve
                )
        }
        try admitJournalRecoveryTransaction(estimatedBytes: estimate)
        try beginSerializedWrite(
            estimatedBytes: estimate,
            maintenance: true
        )
        do {
            for source in sources {
                guard try legacyTypedRowDigest(rowID: source.rowID)
                        == source.typedRowDigest else {
                    throw EventStoreError.storageNotReady(
                        "legacy cleanup source moved before its writer lock; retry recovery"
                    )
                }
            }
            let rowIDs = sources.map(\.rowID)
            let rowList = rowIDs.map(String.init).joined(separator: ",")
            try execute("DELETE FROM events_fts WHERE rowid IN (\(rowList))")
            try execute("DELETE FROM events WHERE rowid IN (\(rowList))")
            guard sqlite3_changes(db) == Int32(sources.count) else {
                throw EventStoreError.stepFailed(
                    "legacy journal cleanup deleted an unexpected row count"
                )
            }
            let now = Date().timeIntervalSince1970
            let progress = try prepare(
                """
                UPDATE event_journal_migration SET
                    last_legacy_rowid = MAX(last_legacy_rowid, ?1),
                    migrated_events = migrated_events + ?2,
                    remaining_events = remaining_events - ?2,
                    updated_at = ?3
                WHERE singleton = 1
                """
            )
            sqlite3_bind_int64(progress, 1, rowIDs.max() ?? 0)
            sqlite3_bind_int64(progress, 2, Int64(sources.count))
            sqlite3_bind_double(progress, 3, now)
            let progressRC = sqlite3_step(progress)
            sqlite3_finalize(progress)
            guard progressRC == SQLITE_DONE,
                  sqlite3_changes(db) == 1 else {
                throw EventStoreError.stepFailed(
                    "legacy journal cleanup progress update failed"
                )
            }
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    private func migrationSnapshot() throws -> EventJournalRecoverySnapshot {
        let statement = try prepare(
            """
            SELECT source_events, migrated_events, rolled_expired_events,
                   corrupt_preserved_events, remaining_events, stage
            FROM event_journal_migration WHERE singleton = 1
            """
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "event journal migration state is missing"
            )
        }
        let snapshot = EventJournalRecoverySnapshot(
            sourceEvents: Int(sqlite3_column_int64(statement, 0)),
            migratedEvents: Int(sqlite3_column_int64(statement, 1)),
            rolledExpiredEvents: Int(sqlite3_column_int64(statement, 2)),
            corruptPreservedEvents: Int(sqlite3_column_int64(statement, 3)),
            remainingEvents: Int(sqlite3_column_int64(statement, 4)),
            complete: sqlite3_column_int(statement, 5) == 2
        )
        guard snapshot.sourceEvents == snapshot.migratedEvents
                + snapshot.rolledExpiredEvents
                + snapshot.corruptPreservedEvents
                + snapshot.remainingEvents else {
            throw EventStoreError.decodingFailed(
                "event journal migration conservation failed"
            )
        }
        return snapshot
    }

    private func journalRecoveryCheckpointBoundary() throws -> WALCheckpointObservation {
        let checkpoint = try walCheckpointTruncateObservation()
        try checkpoint.requireValidOutcome(context: "event journal recovery checkpoint")
        let footprint = try SQLitePersistentStoreAdmission.measureFamily(
            databasePath
        )
        let cap = storagePolicy?.maxFootprintBytes
            ?? Self.defaultStoragePolicy(for: databasePath).maxFootprintBytes
        guard footprint <= cap else {
            // Only observed SQLite contention/undrained frames may defer this
            // cap decision. Admission, probe and other SQLite failures retain
            // their original causes; none establishes a reader pin.
            if checkpoint.retryableContention {
                try checkpoint.requireTruncated(context:
                    "event journal recovery family footprint \(footprint) exceeds transition cap \(cap)")
            }
            throw EventStoreError.storageNotReady(
                "event journal recovery family footprint \(footprint) exceeds transition cap \(cap)"
            )
        }
        return checkpoint
    }

    private func journalRecoveryBoundaryIsDrained() throws -> Bool {
        try journalRecoveryCheckpointBoundary().truncated
    }

    private func requireJournalRecoveryBoundary() throws {
        try journalRecoveryCheckpointBoundary().requireTruncated(
            context: "event journal recovery boundary")
    }

    private func allocatedBytesForSchemaObject(_ name: String) throws -> Int64 {
        let statement = try prepare(
            "SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?1"
        )
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: name)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "schema object allocation probe failed for \(name)"
            )
        }
        return max(0, sqlite3_column_int64(statement, 0))
    }

    /// Complete deferred legacy-index retirement after canonical transcode
    /// emptied the wide legacy rows.
    /// Every DROP is independently reserve/cap-admitted and followed by a
    /// drained, exact family measurement. No producer may run while an old
    /// detection-era index remains and amplifies sparse-tier writes.
    private func finalizeJournalProjectionSchema() throws {
        guard let db else {
            throw EventStoreError.databaseOpenFailed("database is not open")
        }
        let finalizedProbe = try prepare(
            "SELECT schema_finalized FROM event_journal_migration WHERE singleton = 1"
        )
        guard sqlite3_step(finalizedProbe) == SQLITE_ROW else {
            sqlite3_finalize(finalizedProbe)
            throw EventStoreError.storageNotReady(
                "event journal finalization marker is unavailable"
            )
        }
        let alreadyFinalized = sqlite3_column_int(finalizedProbe, 0) == 1
        guard sqlite3_step(finalizedProbe) == SQLITE_DONE else {
            sqlite3_finalize(finalizedProbe)
            throw EventStoreError.decodingFailed(
                "event journal finalization marker is duplicated"
            )
        }
        sqlite3_finalize(finalizedProbe)
        var startedMutating = false
        for name in Self.supersededEventIndexes {
            guard let object = try Self.schemaObject(on: db, named: name) else {
                continue
            }
            guard object.type == "index" else {
                throw EventStoreError.decodingFailed(
                    "superseded schema name \(name) is not an index"
                )
            }
            if !startedMutating {
                try requireJournalRecoveryBoundary()
                startedMutating = true
            }
            let allocated = try allocatedBytesForSchemaObject(name)
            let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    allocated,
                    by: 2
                ),
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes
            )
            let estimate = SQLitePersistentStoreAdmission
                .conservativeTransactionBytes(
                    rowMutationBytes: rowBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumTreePathPageTouches: 8
            )
            try admitJournalRecoveryTransaction(estimatedBytes: estimate)
            try beginSerializedWrite(
                estimatedBytes: estimate,
                maintenance: true
            )
            do {
                try execute("DROP INDEX \(name)")
                try advanceStorageMutationGeneration()
                try execute("COMMIT")
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
            try requireJournalRecoveryBoundary()
        }

        try Self.validateFinalizedJournalSchemaInventory(on: db)
        try validateFTSExternalContentIntegrity()
        guard !alreadyFinalized else { return }

        // This path is also taken after a crash immediately following the last
        // DROP COMMIT. Even when the inventory is already empty, drain and
        // measure the residual WAL before durably marking finalization.
        try requireJournalRecoveryBoundary()
        let markerEstimate = SQLitePersistentStoreAdmission
            .conservativeTransactionBytes(
                rowMutationBytes: SQLitePersistentStoreAdmission
                    .conservativeRowMutationBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumTreePathPageTouches: 4
        )
        try admitJournalRecoveryTransaction(estimatedBytes: markerEstimate)
        try beginSerializedWrite(
            estimatedBytes: markerEstimate,
            maintenance: true
        )
        do {
            try executeExpectingSingleChange(
                "UPDATE event_journal_migration SET schema_finalized = 1, updated_at = CAST(strftime('%s','now') AS REAL) WHERE singleton = 1 AND schema_finalized = 0",
                context: "event journal schema finalization marker"
            )
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
        try requireJournalRecoveryBoundary()
    }

    private func ensureRollbackBarrierBeforeJournalMigration() throws {
        guard let db else {
            throw EventStoreError.databaseOpenFailed("database is not open")
        }
        // The open/bootstrap path commits the view and every DML guard in one
        // cap-admitted transaction. Recovery never recreates only half of that
        // barrier; it verifies the atomic prerequisite before touching legacy
        // evidence and fails closed if schema state was externally altered.
        try Self.validateRollbackProtection(on: db)
    }

    private func admitJournalRecoveryTransaction(
        estimatedBytes: Int64
    ) throws {
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        guard estimatedBytes >= 0, estimatedBytes <= reserve else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: estimatedBytes,
                    reserveBytes: reserve
                )
        }
        let cap = storagePolicy?.maxFootprintBytes
            ?? Self.defaultStoragePolicy(for: databasePath).maxFootprintBytes
        func fits() throws -> Bool {
            let family = try SQLitePersistentStoreAdmission.measureFamily(
                databasePath
            )
            return SQLitePersistentStoreAdmission.saturatingAdd(
                family, estimatedBytes
            ) <= cap
        }
        if try fits() == false {
            try requireJournalRecoveryBoundary()
            guard try fits() else {
                throw EventStoreError.storageNotReady(
                    "event journal recovery transaction does not fit the hard transition cap"
                )
            }
        }
        try admitStorageMaintenanceWrite(
            estimatedTransactionBytes: estimatedBytes
        )
    }

    /// Crash-resumable rc.12 -> rc.13 transition. Each source row is removed
    /// only in the same transaction that either journals its canonical Event or
    /// preserves its exact original bytes+SHA in the immutable quarantine.
    public func recoverJournalBeforeProducers(
        now: Date = Date()
    ) async throws -> EventJournalRecoverySnapshot {
        terminalSettlementProtectionActive = false
        defer { terminalSettlementProtectionActive = true }
        guard !isReadOnly, try hasJournalSchema(),
              try tableHasColumn("events", "journal_block_id") else {
            throw EventStoreError.stepFailed(
                "event journal transition schema is not ready"
            )
        }
        try ensureRollbackBarrierBeforeJournalMigration()
        try validateLegacyQuarantineIntegrity()
        try ensureJournalIndex()
        let initialLegacy = try legacyJournalRowCount()
        let timestamp = now.timeIntervalSince1970
        let stateEstimate = SQLitePersistentStoreAdmission
            .conservativeTransactionBytes(
                rowMutationBytes: SQLitePersistentStoreAdmission
                    .conservativeRowMutationBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumTreePathPageTouches: 8
            )
        let stateProbe = try prepare(
            "SELECT 1 FROM event_journal_migration WHERE singleton = 1"
        )
        let stateProbeRC = sqlite3_step(stateProbe)
        sqlite3_finalize(stateProbe)
        guard stateProbeRC == SQLITE_ROW || stateProbeRC == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "event journal migration state probe failed"
            )
        }
        if stateProbeRC == SQLITE_DONE {
            try admitJournalRecoveryTransaction(
                estimatedBytes: stateEstimate
            )
            try beginSerializedWrite(
                estimatedBytes: stateEstimate,
                maintenance: true
            )
            do {
                let statement = try prepare(
                    """
                    INSERT INTO event_journal_migration (
                        singleton, last_legacy_rowid, stage, source_events,
                        migrated_events, rolled_expired_events,
                        corrupt_preserved_events, remaining_events,
                        started_at, updated_at
                    ) VALUES (1,0,1,?1,0,0,0,?1,?2,?2)
                    """
                )
                sqlite3_bind_int64(statement, 1, Int64(initialLegacy))
                sqlite3_bind_double(statement, 2, timestamp)
                let rc = sqlite3_step(statement)
                sqlite3_finalize(statement)
                guard rc == SQLITE_DONE,
                      sqlite3_changes(db) == 1 else {
                    throw EventStoreError.stepFailed(
                        "event journal migration initialization failed"
                    )
                }
                try execute("COMMIT")
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
            try requireJournalRecoveryBoundary()
        } else {
            let existingState = try migrationSnapshot()
            guard initialLegacy >= existingState.remainingEvents else {
                throw EventStoreError.decodingFailed(
                    "event journal migration remaining/source row mismatch"
                )
            }
            let newLegacyEvents = initialLegacy
                - existingState.remainingEvents
            if existingState.complete, newLegacyEvents == 0 {
                // A fully-v8 routine reopen is validation-only. In particular,
                // do not rewrite `updated_at`, bump mutation_generation, or
                // force a TRUNCATE checkpoint merely to restate stage=2.
                try finalizeJournalProjectionSchema()
                return existingState
            }
            if newLegacyEvents > 0 {
                try admitJournalRecoveryTransaction(
                    estimatedBytes: stateEstimate
                )
                try beginSerializedWrite(
                    estimatedBytes: stateEstimate,
                    maintenance: true
                )
                do {
                    let statement = try prepare(
                        """
                        UPDATE event_journal_migration SET
                            stage = 1,
                            source_events = source_events + ?1,
                            remaining_events = remaining_events + ?1,
                            reopen_epochs = reopen_epochs + 1,
                            updated_at = ?2
                        WHERE singleton = 1
                        """
                    )
                    sqlite3_bind_int64(
                        statement, 1, Int64(newLegacyEvents)
                    )
                    sqlite3_bind_double(statement, 2, timestamp)
                    let rc = sqlite3_step(statement)
                    sqlite3_finalize(statement)
                    guard rc == SQLITE_DONE,
                          sqlite3_changes(db) == 1 else {
                        throw EventStoreError.stepFailed(
                            "event journal migration reopen epoch failed"
                        )
                    }
                    try execute("COMMIT")
                } catch {
                    try? execute("ROLLBACK")
                    throw error
                }
                try requireJournalRecoveryBoundary()
            }
        }

        let lowerBucket = Int64(floor(
            timestamp - Self.journalRetentionSeconds + 1
        ))
        let upperBucket = Int64(floor(timestamp))
        // Deleting a legacy row dirties the wide events table, every remaining
        // legacy index, and its full-detail FTS postings. This high-water is
        // encoded/page/WAL aware and is deliberately never lowered after old
        // indexes disappear, so every migration chunk is chosen against the
        // complete old+new transaction rather than only the compressed blob.
        let legacyMutationBytesPerRow = maintenanceRowMutationUpperBound()
        let reserve = storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
        var migrationFormationLimit = EventJournalCodec.maximumEventsPerBlock
        migrationLoop: while true {
            let rows = try nextLegacyJournalRows(limit: 128)
            guard !rows.isEmpty else { break }
            var prepared: [PreparedPersistedEvent] = []
            var inheritedLosses: [LegacyInheritedLoss?] = []
            var rowIDs: [Int64] = []
            var sourceIdentities: [LegacySourceIdentity] = []
            var selectedBucket: Int64?
            var framedBytes = 12
            var splitLegacyDelete = false
            var resolvedDurableDuplicate = false
            for row in rows {
                let decoded: DecodedLegacyJournalRow
                do {
                    decoded = try decodeLegacyJournalRowWithLoss(row)
                } catch {
                    try quarantineLegacyJournalRow(
                        row,
                        reason: error.localizedDescription
                    )
                    try requireJournalRecoveryBoundary()
                    continue
                }
                let event = decoded.event
                let eventBucket = max(
                    lowerBucket,
                    min(upperBucket, Int64(floor(
                        event.timestamp.timeIntervalSince1970
                    )))
                )
                if let selectedBucket, selectedBucket != eventBucket {
                    continue
                }
                let candidate = try preparePersistedEvent(event)
                let sourceIdentity = LegacySourceIdentity(
                    rowID: row.rowID,
                    typedRowDigest: try Self.legacyTypedRowDigest(
                        values: row.typedValues
                    )
                )
                if let existing = try existingJournalLocations(
                    for: Set([candidate.event.id])
                )[candidate.event.id] {
                    let block = try loadJournalBlock(blockID: existing.blockID)
                    try validateDuplicate(candidate, at: existing, in: block)
                    try deleteMigratedLegacyRows(
                        [sourceIdentity],
                        mutationBytesPerRow: legacyMutationBytesPerRow
                    )
                    try requireJournalRecoveryBoundary()
                    resolvedDurableDuplicate = true
                    break
                }
                let candidateFramedBytes = framedBytes + 4
                    + candidate.canonicalJSON.count
                let candidateDeleteBytes = SQLitePersistentStoreAdmission
                    .saturatingMultiply(
                        legacyMutationBytesPerRow,
                        by: Int64(prepared.count + 1)
                    )
                let candidateEstimate = journalBlockTransactionEstimate(
                    payloadBytes: candidateFramedBytes,
                    eventCount: prepared.count + 1,
                    legacyRowMutationBytes: candidateDeleteBytes,
                    poisonCount: prepared.reduce(into: 0) { count, item in
                        if item.overflow != nil { count += 1 }
                    } + (candidate.overflow == nil ? 0 : 1)
                )
                if candidateEstimate > reserve {
                    if !prepared.isEmpty { break }
                    let journalOnlyEstimate = journalBlockTransactionEstimate(
                        payloadBytes: candidateFramedBytes,
                        eventCount: 1,
                        poisonCount: candidate.overflow == nil ? 0 : 1
                    )
                    guard journalOnlyEstimate <= reserve else {
                        throw SQLitePersistentStoreAdmissionError
                            .transactionEstimateExceedsReserve(
                                estimatedBytes: journalOnlyEstimate,
                                reserveBytes: reserve
                            )
                    }
                    // A wide legacy row can fit either the new append or the
                    // old-row deletion under 32 MiB but not both. Journal it
                    // first, then delete in a second bounded transaction. A
                    // crash between them is resolved by the UUID/digest path
                    // above, with exact readers deduping the mixed state.
                    splitLegacyDelete = true
                }
                selectedBucket = eventBucket
                framedBytes = candidateFramedBytes
                prepared.append(candidate)
                inheritedLosses.append(decoded.inheritedLoss)
                rowIDs.append(row.rowID)
                sourceIdentities.append(sourceIdentity)
                if splitLegacyDelete
                    || prepared.count == migrationFormationLimit { break }
            }
            if resolvedDurableDuplicate {
                await Task.yield()
                continue
            }
            guard !prepared.isEmpty, let selectedBucket else {
                await Task.yield()
                continue
            }
            // Migration is required transition work. It must not consume the
            // file lane's ordinary priority reserve merely because the legacy
            // record happens to describe a file event.
            let lane = EventPipelineLane.priority
            do {
                if splitLegacyDelete {
                    _ = try insertJournalBlock(
                        prepared,
                        lane: lane,
                        admissionBucketOverride: selectedBucket,
                        projectionMode: .migrationSplit,
                        legacyInheritedLosses: inheritedLosses
                    )
                    try requireJournalRecoveryBoundary()
                    try deleteMigratedLegacyRows(
                        sourceIdentities,
                        mutationBytesPerRow: legacyMutationBytesPerRow
                    )
                } else {
                    _ = try insertJournalBlock(
                        prepared,
                        lane: lane,
                        admissionBucketOverride: selectedBucket,
                        legacyRowIDs: rowIDs,
                        legacySourceDigests:
                            sourceIdentities.map(\.typedRowDigest),
                        legacyInheritedLosses: inheritedLosses,
                        legacyRowMutationBytes:
                            SQLitePersistentStoreAdmission.saturatingMultiply(
                                legacyMutationBytesPerRow,
                                by: Int64(rowIDs.count)
                            ),
                        migrationProgress: (
                            migrated: rowIDs.count,
                            lastRowID: rowIDs.max() ?? 0
                        )
                    )
                }
            } catch EventStoreError.journalBlockRequiresSplit(
                let eventCount
            ) {
                guard eventCount > 1, prepared.count > 1 else {
                    throw SQLitePersistentStoreAdmissionError
                        .transactionEstimateExceedsReserve(
                            estimatedBytes:
                                SQLitePersistentStoreAdmission.saturatingAdd(
                                    reserve,
                                    1
                                ),
                            reserveBytes: reserve
                        )
                }
                migrationFormationLimit = max(1, prepared.count / 2)
                await Task.yield()
                continue migrationLoop
            }
            try requireJournalRecoveryBoundary()
            migrationFormationLimit = EventJournalCodec.maximumEventsPerBlock
            await Task.yield()
        }

        try admitJournalRecoveryTransaction(estimatedBytes: stateEstimate)
        try beginSerializedWrite(
            estimatedBytes: stateEstimate,
            maintenance: true
        )
        do {
            try executeExpectingSingleChange(
                """
                UPDATE event_journal_migration SET stage = 2,
                    remaining_events = 0,
                    updated_at = \(Date().timeIntervalSince1970)
                WHERE singleton = 1 AND remaining_events = 0
                """,
                context: "event journal migration completion"
            )
            try execute("COMMIT")
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
        try requireJournalRecoveryBoundary()
        try finalizeJournalProjectionSchema()
        projectionOwnedUpperBoundBytes = nil
        return try migrationSnapshot()
    }

    /// Startup may defer retained work to avoid a reader-driven boot loop.
    /// A running retention pass instead conserves its frozen cutoff through
    /// the caller's existing bounded busy-retry policy.
    public enum JournalExpiryPinnedEntryBehavior: Sendable {
        case deferUntilNextPass
        case conserveCurrentCutoff
    }

    private static let journalExpiryCheckpointBlockLimit = 64

    private func journalExpiryCheckpointBoundary() throws -> WALCheckpointObservation {
        journalExpiryCheckpointHookForTesting?()
        return try journalRecoveryCheckpointBoundary()
    }

    private func rollbackJournalExpiryTransaction() throws {
        guard let db else {
            throw EventStoreError.storageNotReady("journal expiry lost its database")
        }
        if sqlite3_get_autocommit(db) == 0 {
            try Self.exec(db, "ROLLBACK")
        }
        guard sqlite3_get_autocommit(db) != 0 else {
            throw EventStoreError.storageNotReady(
                "journal expiry rollback left a transaction active"
            )
        }
    }

    private static func isJournalExpiryCapacityRefusal(_ error: Error) -> Bool {
        guard let error = error as? SQLitePersistentStoreAdmissionError else {
            return false
        }
        switch error {
        case .footprintLimit, .lowFreeSpace: return true
        default: return false
        }
    }

    /// Called immediately after precise maintenance admission, under the same
    /// writer lock and before DML. This extra, non-latching check decides only
    /// whether prior committed blocks can wait for a shared checkpoint. It
    /// never borrows the next block's one-reserve recovery allowance or clears
    /// ordinary admission's sticky pressure state.
    private func journalExpiryCanCoalesce(estimatedBytes: Int64) throws -> Bool {
        guard let db, sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else {
            throw SQLitePersistentStoreAdmissionError.schemaTransactionNotSerialized
        }
        let policy = storageAdmission?.policy ?? storagePolicy
            ?? Self.defaultStoragePolicy(for: databasePath)
        let family: Int64
        let free: Int64
        if let admission = storageAdmission,
           let measuredFamily = admission.lastFootprintBytes,
           let measuredFree = admission.lastFreeSpaceBytes {
            family = measuredFamily
            free = measuredFree
        } else {
            family = try SQLitePersistentStoreAdmission.measureFamily(databasePath)
            free = try SQLitePersistentStoreAdmission.measureFreeSpace(
                policy.storageVolumePath
            )
        }
        let protected = terminalSettlementProtectionActive
            ? terminalPoisonSettlementHeadroomBytes : 0
        let projectedFamily = family.addingReportingOverflow(estimatedBytes)
        let requiredFamily = projectedFamily.partialValue
            .addingReportingOverflow(protected)
        guard !projectedFamily.overflow, !requiredFamily.overflow,
              requiredFamily.partialValue <= policy.maxFootprintBytes,
              estimatedBytes >= 0, free >= estimatedBytes else { return false }
        // Maintenance admits with floor zero; the eventual checkpoint must
        // still protect the configured floor and its whole sidecar. Charge
        // the full estimate as both possible WAL growth and consumed free
        // blocks. The actual checkpoint repeats its authoritative gate.
        let main = try SQLitePersistentStoreAdmission.measureMainFile(databasePath)
        return SQLitePersistentStoreAdmission.checkpointAdmissionSnapshot(
            mainFileBytes: main,
            familyFootprintBytes: projectedFamily.partialValue,
            freeSpaceBytes: free - estimatedBytes,
            freeSpaceFloorBytes: policy.freeSpaceFloorBytes
        ).admitted
    }

    /// Expire only whole authenticated admission blocks whose durable
    /// `retained_until` has passed. Exact terminal/promotion-applied Events are
    /// rolled into the existing 30-day aggregate contract in the same
    /// transaction that removes their sparse rows and canonical block. A crash
    /// therefore observes either both rollup+expiry or neither.
    @discardableResult
    public func expireJournalBlocks(
        retainedThrough now: Date = Date(),
        maximumBlocks: Int = 256,
        pinnedEntry: JournalExpiryPinnedEntryBehavior = .deferUntilNextPass
    ) throws -> Int {
        guard !isReadOnly, maximumBlocks > 0 else { return 0 }
        let cutoff = now.timeIntervalSince1970
        guard cutoff.isFinite else {
            throw EventStoreError.decodingFailed(
                "journal expiry cutoff is non-finite"
            )
        }
        try ensureJournalIndex()
        // FTS ceiling recovery also applies when no journal block is eligible:
        // startup must relieve an exhausted legacy index before its next write.
        try recoverExhaustedFTSIndexIfNeeded()
        if journalExpirySummaryCutoff != cutoff {
            journalExpirySummaryCutoff = cutoff
            journalExpirySummaryCursor = 0
        }
        let boundedMaximum = max(1, min(maximumBlocks, 4_096))
        var eligible: [(index: Int, summary: VerifiedJournalSummary)] = []
        eligible.reserveCapacity(boundedMaximum)
        var scanIndex = min(
            journalExpirySummaryCursor,
            verifiedJournalSummaries.count
        )
        while scanIndex < verifiedJournalSummaries.count,
              eligible.count < boundedMaximum {
            let summary = verifiedJournalSummaries[scanIndex]
            if !isJournalBlockTombstoned(summary.blockID),
               summary.metadata.retainedUntil <= cutoff {
                eligible.append((scanIndex, summary))
            }
            scanIndex += 1
        }
        if let first = eligible.first {
            // Everything before the first candidate was either already
            // committed/tombstoned or ineligible for this immutable cutoff.
            journalExpirySummaryCursor = first.index
        } else {
            journalExpirySummaryCursor = scanIndex
        }
        guard !eligible.isEmpty else {
            // The frozen-cutoff drain is complete. Compact the already-
            // authenticated fixed-width cache in one linear pass. Re-decoding
            // every surviving payload here would add a full retained-corpus
            // verification pass to every five-minute sweep.
            if !journalExpiredBlockTombstones.isEmpty {
                let expired = journalExpiredBlockTombstones
                journalBaseLocations.removeAll {
                    var lower = 0
                    var upper = expired.count
                    let blockID = $0.location.blockID
                    while lower < upper {
                        let middle = lower + (upper - lower) / 2
                        if expired[middle] < blockID {
                            lower = middle + 1
                        } else {
                            upper = middle
                        }
                    }
                    return lower < expired.count
                        && expired[lower] == blockID
                }
                journalDeltaLocations.remove(blockIDs: expired)
                verifiedJournalSummaries.removeAll {
                    var lower = 0
                    var upper = expired.count
                    while lower < upper {
                        let middle = lower + (upper - lower) / 2
                        if expired[middle] < $0.blockID {
                            lower = middle + 1
                        } else {
                            upper = middle
                        }
                    }
                    return lower < expired.count
                        && expired[lower] == $0.blockID
                }
                journalExpiredBlockTombstones.removeAll(
                    keepingCapacity: false
                )
                journalIndexedLocationCount = journalBaseLocations.count
                    + journalDeltaLocations.count
                journalVerifiedBlocks = verifiedJournalSummaries.count
                journalIndexedBlockCount = Int64(
                    verifiedJournalSummaries.count
                )
                journalIndexedMinimumBlockID =
                    verifiedJournalSummaries.first?.blockID
                journalIndexedMaximumBlockID =
                    verifiedJournalSummaries.last?.blockID
            }
            journalExpirySummaryCursor = 0
            journalExpirySummaryCutoff = nil
            return 0
        }

        // Only eligible retained work needs an expiry checkpoint or retry.
        // Preserve startup's reader deferral, while the runtime timer explicitly
        // requests typed busy to conserve this frozen cutoff.
        let entryBoundary = try journalExpiryCheckpointBoundary()
        if !entryBoundary.truncated {
            switch pinnedEntry {
            case .deferUntilNextPass: return 0
            case .conserveCurrentCutoff:
                try entryBoundary.requireTruncated(context: "journal expiry entry")
            }
        }

        enum CoalescingBoundary: Error { case checkpointRequired }

        struct AggregateKey: Hashable {
            let day: String
            let category: String
            let signer: String
            let processPath: String
        }
        struct AggregateGapKey: Hashable {
            let day: String
            let category: String
            let reason: String
        }
        struct Coverage {
            let bucket: Int64
            let considered: Int64
            let materialized: Int64
            let materializedBytes: Int64
            let quota: Int64
            let replaced: Int64
            let physical: Int64
            let external: Int64
            let migration: Int64
            let pending: Int64
            let replacementTotal: Int64
        }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        func day(_ date: Date) -> String {
            let parts = calendar.dateComponents(
                [.year, .month, .day],
                from: date
            )
            return String(
                format: "%04d-%02d-%02d",
                parts.year ?? 0,
                parts.month ?? 0,
                parts.day ?? 0
            )
        }

        var expiredEvents = 0
        var committedSinceCheckpoint = 0

        func expireCandidate(
            _ candidate: (index: Int, summary: VerifiedJournalSummary),
            retryableAdmissionStage: inout Bool
        ) throws {
            retryableAdmissionStage = true
            let summary = candidate.summary
            let blockID = summary.blockID
            let reserve = storageTransactionReserveBytes
            // Take the writer lock before reading any mutable overlay or
            // projection state. The exact transaction estimate is derived
            // below from that locked snapshot and admitted before the first
            // DML. Charging the whole 32-MiB reserve here would deadlock the
            // retention operation immediately after any normal append used a
            // portion of that deliberately reserved headroom.
            try beginSerializedWrite(
                estimatedBytes: 0,
                maintenance: true
            )
            retryableAdmissionStage = false
            do {
                let exact = try loadExactJournalBlock(blockID: blockID)
                var aggregates: [AggregateKey: Int64] = [:]
                var aggregateGaps: [AggregateGapKey: Int64] = [:]
                for (ordinal, event) in exact.events.enumerated() {
                    let boundedPath = Self.boundIndexedText(
                        event.process.executable,
                        maxBytes: 2_048
                    )
                    let key = AggregateKey(
                        day: day(event.timestamp),
                        category: event.eventCategory.rawValue,
                        signer: event.process.codeSignature?.signerType.rawValue ?? "",
                        processPath: boundedPath
                    )
                    if exact.poisonByOrdinal[ordinal] != nil {
                        aggregateGaps[AggregateGapKey(
                            day: key.day,
                            category: key.category,
                            reason: "canonical_poison"
                        ), default: 0] += 1
                    } else {
                        aggregates[key, default: 0] += 1
                        if exact.inheritedLossOrdinals.contains(ordinal) {
                            aggregateGaps[AggregateGapKey(
                                day: key.day,
                                category: key.category,
                                reason: "inherited_legacy_loss"
                            ), default: 0] += 1
                        }
                        if boundedPath != event.process.executable {
                            aggregateGaps[AggregateGapKey(
                                day: key.day,
                                category: key.category,
                                reason: "aggregate_key_compacted"
                            ), default: 0] += 1
                        }
                    }
                }

                let coverageStatement = try prepare(
                """
                SELECT bucket_start, considered_count, materialized_count,
                       materialized_bytes, omitted_quota_count,
                       omitted_replaced_count, omitted_physical_count,
                       omitted_external_count, omitted_migration_count,
                       pending_count, replacement_total
                FROM event_projection_block_coverage WHERE block_id = ?1
                """
            )
                sqlite3_bind_int64(coverageStatement, 1, blockID)
                guard sqlite3_step(coverageStatement) == SQLITE_ROW else {
                    sqlite3_finalize(coverageStatement)
                    throw EventStoreError.decodingFailed(
                        "journal expiry is missing block coverage"
                    )
                }
                let coverage = Coverage(
                bucket: sqlite3_column_int64(coverageStatement, 0),
                considered: sqlite3_column_int64(coverageStatement, 1),
                materialized: sqlite3_column_int64(coverageStatement, 2),
                materializedBytes: sqlite3_column_int64(coverageStatement, 3),
                quota: sqlite3_column_int64(coverageStatement, 4),
                replaced: sqlite3_column_int64(coverageStatement, 5),
                physical: sqlite3_column_int64(coverageStatement, 6),
                external: sqlite3_column_int64(coverageStatement, 7),
                migration: sqlite3_column_int64(coverageStatement, 8),
                pending: sqlite3_column_int64(coverageStatement, 9),
                replacementTotal: sqlite3_column_int64(coverageStatement, 10)
            )
                guard coverage.considered == Int64(summary.eventCount),
                      coverage.pending == 0,
                      sqlite3_step(coverageStatement) == SQLITE_DONE else {
                    sqlite3_finalize(coverageStatement)
                    throw EventStoreError.decodingFailed(
                        "journal expiry block coverage is not conserved"
                    )
                }
                sqlite3_finalize(coverageStatement)

                let payloadStatement = try prepare(
                    "SELECT length(payload), event_count, retained_until FROM event_journal_blocks WHERE block_id = ?1"
                )
                sqlite3_bind_int64(payloadStatement, 1, blockID)
                guard sqlite3_step(payloadStatement) == SQLITE_ROW else {
                    sqlite3_finalize(payloadStatement)
                    throw EventStoreError.decodingFailed(
                        "journal expiry payload allocation is unavailable"
                    )
                }
                let payloadBytes = Int(
                    sqlite3_column_int64(payloadStatement, 0)
                )
                let lockedEventCount = Int(
                    sqlite3_column_int64(payloadStatement, 1)
                )
                let lockedRetainedUntil = sqlite3_column_double(
                    payloadStatement, 2
                )
                sqlite3_finalize(payloadStatement)
                guard lockedEventCount == summary.eventCount,
                      lockedRetainedUntil <= cutoff else {
                    throw EventStoreError.decodingFailed(
                        "journal expiry selector changed under writer lock"
                    )
                }
                let overlayUsage = try journalOverlayUsage(
                    blockID: blockID,
                    eventCount: lockedEventCount
                )
                var aggregateLogical: Int64 = 0
                for key in aggregates.keys {
                aggregateLogical = SQLitePersistentStoreAdmission.saturatingAdd(
                    aggregateLogical,
                    Int64(
                        256 + key.day.utf8.count + key.category.utf8.count
                            + key.signer.utf8.count + key.processPath.utf8.count
                    )
                )
                }
                for key in aggregateGaps.keys {
                    aggregateLogical = SQLitePersistentStoreAdmission
                        .saturatingAdd(
                            aggregateLogical,
                            Int64(
                                192 + key.day.utf8.count
                                    + key.category.utf8.count
                                    + key.reason.utf8.count
                            )
                        )
                }
                let aggregateMutation = SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: aggregateLogical,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumLeafPageTouches: max(
                        4,
                        (aggregates.count + aggregateGaps.count) * 2
                    )
                )
                let projectionMutation = SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: max(
                        coverage.materializedBytes,
                        Int64(summary.eventCount * 256)
                    ),
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumLeafPageTouches: max(
                        8,
                        Int(coverage.materialized) * 8 + 8
                    )
                )
                let auxiliaryMutation = SQLitePersistentStoreAdmission
                    .saturatingAdd(aggregateMutation, projectionMutation)
                let cascadePayload = payloadBytes.addingReportingOverflow(
                    overlayUsage.cascadePayloadBytes
                )
                let calculatedEstimate = cascadePayload.overflow
                    ? Int64.max
                    : journalBlockTransactionEstimate(
                        payloadBytes: cascadePayload.partialValue,
                        eventCount: summary.eventCount,
                        legacyRowMutationBytes: auxiliaryMutation,
                        poisonCount: exact.poisonByOrdinal.values.reduce(0) {
                            $0 + $1.count
                        }
                    )
                let estimate = max(
                    calculatedEstimate,
                    try journalExpiryTransactionEstimate(
                        blockID: blockID,
                        exact: exact,
                        overlayCascadePayloadBytes:
                            overlayUsage.cascadePayloadBytes
                    )
                )
                guard estimate <= reserve else {
                    throw SQLitePersistentStoreAdmissionError
                        .transactionEstimateExceedsReserve(
                            estimatedBytes: estimate,
                            reserveBytes: reserve
                        )
                }
                // This is the authoritative, race-free capacity decision. All
                // reads feeding `estimate` occurred after BEGIN IMMEDIATE and
                // no page has been mutated yet.
                retryableAdmissionStage = true
                try requireCurrentFamilyCapacityUnderWriterLock(
                    estimatedBytes: estimate,
                    maintenance: true
                )
                retryableAdmissionStage = false
                if committedSinceCheckpoint > 0,
                   try !journalExpiryCanCoalesce(estimatedBytes: estimate) {
                    throw CoalescingBoundary.checkpointRequired
                }
                let aggregate = try prepare(
                    """
                    INSERT INTO event_aggregates (
                        day, event_category, process_signer, process_path, count
                    ) VALUES (?1,?2,?3,?4,?5)
                    ON CONFLICT(day,event_category,process_signer,process_path)
                    DO UPDATE SET count = count + excluded.count
                    """
                )
                for (key, count) in aggregates {
                    sqlite3_reset(aggregate)
                    sqlite3_clear_bindings(aggregate)
                    bindText(aggregate, index: 1, value: key.day)
                    bindText(aggregate, index: 2, value: key.category)
                    bindText(aggregate, index: 3, value: key.signer)
                    bindText(aggregate, index: 4, value: key.processPath)
                    sqlite3_bind_int64(aggregate, 5, count)
                    guard sqlite3_step(aggregate) == SQLITE_DONE else {
                        sqlite3_finalize(aggregate)
                        throw EventStoreError.stepFailed(
                            "journal expiry aggregate upsert failed"
                        )
                    }
                }
                sqlite3_finalize(aggregate)

                let gap = try prepare(
                    """
                    INSERT INTO event_aggregate_gaps (
                        day, event_category, reason, count
                    ) VALUES (?1,?2,?3,?4)
                    ON CONFLICT(day,event_category,reason)
                    DO UPDATE SET count = count + excluded.count
                    """
                )
                for (key, count) in aggregateGaps {
                    sqlite3_reset(gap)
                    sqlite3_clear_bindings(gap)
                    bindText(gap, index: 1, value: key.day)
                    bindText(gap, index: 2, value: key.category)
                    bindText(gap, index: 3, value: key.reason)
                    sqlite3_bind_int64(gap, 4, count)
                    guard sqlite3_step(gap) == SQLITE_DONE else {
                        sqlite3_finalize(gap)
                        throw EventStoreError.stepFailed(
                            "journal expiry aggregate-gap upsert failed"
                        )
                    }
                }
                sqlite3_finalize(gap)

                let deleteFTS = try prepare(
                    "DELETE FROM events_fts WHERE rowid IN (SELECT rowid FROM events WHERE journal_block_id = ?1)"
                )
                sqlite3_bind_int64(deleteFTS, 1, blockID)
                let ftsRC = sqlite3_step(deleteFTS)
                sqlite3_finalize(deleteFTS)
                guard ftsRC == SQLITE_DONE else {
                    throw EventStoreError.stepFailed(
                        "journal expiry projection FTS delete failed"
                    )
                }
                let deleteProjection = try prepare(
                    "DELETE FROM events WHERE journal_block_id = ?1"
                )
                sqlite3_bind_int64(deleteProjection, 1, blockID)
                let projectionRC = sqlite3_step(deleteProjection)
                let deletedProjection = sqlite3_changes(db)
                sqlite3_finalize(deleteProjection)
                // Reported separately since rc.34. These were one compound
                // guard whose message described only the second clause, so a
                // SQLITE_FULL step failure surfaced as "projection count
                // disagrees with coverage" — sending every investigation after
                // a coverage skew that did not exist.
                guard projectionRC == SQLITE_DONE else {
                    throw EventStoreError.stepFailed(
                        "journal expiry projection delete failed for block "
                            + "\(blockID) (sqlite rc \(projectionRC)): "
                            + String(cString: sqlite3_errmsg(db))
                    )
                }
                guard deletedProjection == Int32(coverage.materialized) else {
                    throw EventStoreError.decodingFailed(
                        "journal expiry projection count disagrees with coverage "
                            + "(deleted \(deletedProjection), coverage "
                            + "\(coverage.materialized))"
                    )
                }

                let subtract = try prepare(
                    """
                    UPDATE event_projection_coverage SET
                        considered_count = considered_count - ?2,
                        materialized_count = materialized_count - ?3,
                        materialized_bytes = materialized_bytes - ?4,
                        omitted_quota_count = omitted_quota_count - ?5,
                        omitted_replaced_count = omitted_replaced_count - ?6,
                        omitted_physical_count = omitted_physical_count - ?7,
                        omitted_external_count = omitted_external_count - ?8,
                        omitted_migration_count = omitted_migration_count - ?9,
                        pending_count = pending_count - ?10,
                        replacement_total = replacement_total - ?11,
                        updated_at = ?12
                    WHERE bucket_start = ?1
                    """
                )
                let values = [
                    coverage.considered, coverage.materialized,
                    coverage.materializedBytes, coverage.quota,
                    coverage.replaced, coverage.physical,
                    coverage.external, coverage.migration,
                    coverage.pending, coverage.replacementTotal,
                ]
                sqlite3_bind_int64(subtract, 1, coverage.bucket)
                for (offset, value) in values.enumerated() {
                    sqlite3_bind_int64(subtract, Int32(offset + 2), value)
                }
                sqlite3_bind_double(subtract, 12, cutoff)
                let subtractRC = sqlite3_step(subtract)
                let changedCoverage = sqlite3_changes(db)
                sqlite3_finalize(subtract)
                guard subtractRC == SQLITE_DONE, changedCoverage == 1 else {
                    throw EventStoreError.decodingFailed(
                        "journal expiry global coverage subtraction failed"
                    )
                }
                let pruneCoverage = try prepare(
                    "DELETE FROM event_projection_coverage WHERE bucket_start = ?1 AND considered_count = 0"
                )
                sqlite3_bind_int64(pruneCoverage, 1, coverage.bucket)
                let pruneCoverageRC = sqlite3_step(pruneCoverage)
                sqlite3_finalize(pruneCoverage)
                guard pruneCoverageRC == SQLITE_DONE else {
                    throw EventStoreError.stepFailed(
                        "journal expiry empty coverage prune failed"
                    )
                }

                let deleteBlock = try prepare(
                    "DELETE FROM event_journal_blocks WHERE block_id = ?1 AND retained_until <= ?2"
                )
                sqlite3_bind_int64(deleteBlock, 1, blockID)
                sqlite3_bind_double(deleteBlock, 2, cutoff)
                let blockRC = sqlite3_step(deleteBlock)
                let deletedBlock = sqlite3_changes(db)
                sqlite3_finalize(deleteBlock)
                guard blockRC == SQLITE_DONE, deletedBlock == 1 else {
                    throw EventStoreError.decodingFailed(
                        "journal expiry retention selector changed before commit"
                    )
                }
                try execute("COMMIT")
                expiredEvents += summary.eventCount
                committedSinceCheckpoint += 1
                addJournalBlockTombstone(blockID)
                journalExpirySummaryCursor = candidate.index + 1
                journalVerifiedBlocks = max(0, journalVerifiedBlocks - 1)
                if let generation = journalIndexTopologyGeneration {
                    journalIndexTopologyGeneration = generation + 1
                    journalIndexedBlockCount = max(
                        0,
                        journalIndexedBlockCount - 1
                    )
                } else {
                    // An uncertain cache state is never patched locally.
                    journalIndexLoaded = false
                }
                projectionOwnedUpperBoundBytes = nil
                journalExpiryPostCommitHookForTesting?()
            } catch {
                try rollbackJournalExpiryTransaction()
                throw error
            }
        }
        for candidate in eligible {
            var retriedAfterCheckpoint = false
            while true {
                var retryableAdmissionStage = false
                do {
                    try expireCandidate(
                        candidate,
                        retryableAdmissionStage: &retryableAdmissionStage
                    )
                } catch {
                    // Capacity retries are permitted only before DML and only
                    // after earlier blocks made progress. A checked rollback is
                    // mandatory before checkpointing this connection.
                    try rollbackJournalExpiryTransaction()
                    let needsBoundary = error is CoalescingBoundary
                        || (retryableAdmissionStage
                            && Self.isJournalExpiryCapacityRefusal(error))
                    guard needsBoundary, committedSinceCheckpoint > 0,
                          !retriedAfterCheckpoint else { throw error }
                    let boundary = try journalExpiryCheckpointBoundary()
                    guard boundary.truncated else { return expiredEvents }
                    committedSinceCheckpoint = 0
                    retriedAfterCheckpoint = true
                    continue
                }
                // A new reader can arrive between checkpoints. Its pin is
                // detected at this bounded boundary, not necessarily after the
                // first block. Once observed, this invocation stops mutating.
                if committedSinceCheckpoint == Self.journalExpiryCheckpointBlockLimit {
                    let boundary = try journalExpiryCheckpointBoundary()
                    guard boundary.truncated else { return expiredEvents }
                    committedSinceCheckpoint = 0
                }
                break
            }
        }
        if committedSinceCheckpoint > 0 {
            let boundary = try journalExpiryCheckpointBoundary()
            guard boundary.truncated else { return expiredEvents }
        }
        return expiredEvents
    }

    // MARK: - Query

    private func withExactReadSnapshot<T>(
        _ body: (UInt64) throws -> T
    ) throws -> T {
        guard let db else {
            throw EventStoreError.databaseOpenFailed("database is not open")
        }
        if sqlite3_get_autocommit(db) == 0 {
            let generation = try currentStorageMutationGeneration()
            return try body(generation)
        }
        try Self.exec(db, "BEGIN DEFERRED TRANSACTION")
        do {
            let generation = try currentStorageMutationGeneration()
            let result = try body(generation)
            try Self.exec(db, "COMMIT")
            return result
        } catch {
            try? Self.exec(db, "ROLLBACK")
            // rc.41 fail-safe: a swallowed ROLLBACK on this process-lifetime
            // connection would leave it permanently inside a read transaction —
            // a silent WAL pin that no later call would ever clear, because the
            // autocommit==0 branch above happily piggybacks on the stuck
            // transaction forever. Make that state loud and try once more,
            // unswallowed, so the failure is at least visible and attributable.
            if sqlite3_get_autocommit(db) == 0 {
                Logger(subsystem: "com.maccrab.storage", category: "event-store")
                    .fault("exact read snapshot ROLLBACK left the connection inside a transaction; retrying rollback so the WAL read-mark is not pinned for the connection lifetime")
                try Self.exec(db, "ROLLBACK")
            }
            throw error
        }
    }

    /// rc.41: exact reads with journal verification hoisted OUTSIDE the read
    /// transaction.
    ///
    /// Every dashboard read used to run `ensureJournalIndex()` as its first
    /// statement INSIDE `withExactReadSnapshot`'s BEGIN DEFERRED. On a cold
    /// connection or after a topology change that verifies (SHA256 + double
    /// JSON-decode) the entire retained journal while holding a WAL read-mark —
    /// minutes, not milliseconds. Two dashboard connections doing this on
    /// overlapping 5s/60s cadences left the writer NO reader-free window: the
    /// WAL could never truncate, grew to 2-5x its 64 MiB limit (147.5 MiB and
    /// 353 MiB measured live), pushed the db+WAL family through the 320 MiB
    /// cap, paused writes, silently dropped ~14k events in 80 minutes — and
    /// once prevented the engine from booting at all. Twice-proven live: the
    /// moment the dashboard process died, the next checkpoint truncated.
    ///
    /// The verify-inside-txn placement existed for one reason: the in-memory
    /// index must match the snapshot the transaction reads. That proof is kept,
    /// cheaply: verify outside any transaction, then inside the transaction
    /// re-check only the single-row topology generation. On a mismatch (a
    /// writer landed a topology change in the microsecond gap) commit out,
    /// re-verify, retry. Under pathological topology churn, fall back to the
    /// exact pre-rc.41 verify-inside behaviour — identical correctness, and
    /// the long read-mark only in a race that retries could not clear.
    private func withVerifiedExactReadSnapshot<T>(
        _ body: (UInt64) throws -> T
    ) throws -> T {
        try checkReadOnlyRetirement()
        if let db, sqlite3_get_autocommit(db) == 0 {
            // Ambient transaction owned by the caller: its lifetime is not
            // ours to bound, and verification must see its snapshot.
            return try withExactReadSnapshot { generation in
                try ensureJournalIndex()
                return try body(generation)
            }
        }
        for _ in 0..<4 {
            try ensureJournalIndex()
            let outcome: T? = try withExactReadSnapshot { generation in
                guard try journalIndexMatchesCurrentTopology() else {
                    return nil
                }
                return try body(generation)
            }
            if let outcome { return outcome }
        }
        return try withExactReadSnapshot { generation in
            try ensureJournalIndex()
            return try body(generation)
        }
    }

    /// Single-row staleness probe for `withVerifiedExactReadSnapshot`: does the
    /// in-memory journal index correspond to the topology generation visible to
    /// the current snapshot? Microseconds, so holding a read-mark across it is
    /// harmless — unlike the full verification it stands in for.
    private func journalIndexMatchesCurrentTopology() throws -> Bool {
        guard journalIndexLoaded else { return false }
        guard try hasJournalSchema() else {
            return journalIndexTopologyGeneration == nil
        }
        let statement = try prepare(
            "SELECT journal_topology_generation FROM event_storage_state WHERE singleton = 1"
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "event journal topology probe failed"
            )
        }
        return journalIndexTopologyGeneration == sqlite3_column_int64(statement, 0)
    }

    private struct ExactEventCandidate {
        let timestamp: Date
        let id: String
        let event: Event?
        let poisonRecords: [EventJournalPoisonRecord]
        let corruptLegacy: Bool
        let inheritedLegacyLoss: Bool
        let retainedBytes: Int
        let ownershipLeases: [EventPipelineMemoryLease]

        init(
            timestamp: Date,
            id: String,
            event: Event?,
            poisonRecords: [EventJournalPoisonRecord],
            corruptLegacy: Bool,
            inheritedLegacyLoss: Bool,
            retainedBytes: Int = 0,
            ownershipLeases: [EventPipelineMemoryLease] = []
        ) {
            self.timestamp = timestamp
            self.id = id
            self.event = event
            self.poisonRecords = poisonRecords
            self.corruptLegacy = corruptLegacy
            self.inheritedLegacyLoss = inheritedLegacyLoss
            self.retainedBytes = retainedBytes
            self.ownershipLeases = ownershipLeases
        }
    }

    private struct RetainedWindowTruth {
        let hasWindow: Bool
        let effectiveSince: Date
        let effectiveUntil: Date
        let retainedOldest: Date?
        let retainedNewest: Date?
        let retainedAdmissionOldest: Date?
        let retainedAdmissionNewest: Date?
        let requestedWindowComplete: Bool
        let gaps: EventQueryGapCounts
    }

    /// Bind source-time query results to the admission-time retention domain.
    /// Journal blocks expire by durable admission time, not by attacker-owned
    /// source timestamps, so MIN(source timestamp) alone cannot prove that an
    /// earlier requested interval was observed. The guaranteed lower boundary
    /// is the later of schema-v8 activation and the fixed retention floor.
    private func retainedWindowTruth(
        requestedSince: Date,
        requestedUntil: Date,
        asOf: Date
    ) throws -> RetainedWindowTruth {
        let lower = requestedSince.timeIntervalSince1970
        let requestedUpper = requestedUntil.timeIntervalSince1970
        let now = asOf.timeIntervalSince1970
        guard lower.isFinite, requestedUpper.isFinite, now.isFinite,
              lower <= requestedUpper else {
            throw EventStoreError.decodingFailed(
                "retained-window query has invalid bounds"
            )
        }

        var sourceMinimum: TimeInterval?
        var sourceMaximum: TimeInterval?
        var admissionMinimum: TimeInterval?
        var admissionMaximum: TimeInterval?
        func include(
            minimum: TimeInterval,
            maximum: TimeInterval,
            admission: TimeInterval? = nil
        ) {
            sourceMinimum = min(sourceMinimum ?? minimum, minimum)
            sourceMaximum = max(sourceMaximum ?? maximum, maximum)
            if let admission {
                admissionMinimum = min(admissionMinimum ?? admission, admission)
                admissionMaximum = max(admissionMaximum ?? admission, admission)
            }
        }
        for summary in verifiedJournalSummaries where
            !isJournalBlockTombstoned(summary.blockID) {
            include(
                minimum: summary.metadata.minimum,
                maximum: summary.metadata.maximum,
                admission: TimeInterval(summary.metadata.admissionBucket)
            )
        }

        var activation = now
        var poison = 0
        var quarantine = 0
        var inherited = 0
        var admissionUnscopedLegacy = 0
        if try hasJournalSchema() {
            // Direct/test stores may receive journal blocks before the daemon's
            // pre-producer recovery creates the migration singleton. Anchor
            // that state to authenticated retained metadata, never the moving
            // query clock, or the first bucket disappears when `now` crosses
            // into the following second.
            let fallbackActivation = admissionMinimum ?? now
            let state = try prepare(
                """
                SELECT
                  COALESCE((SELECT started_at FROM event_journal_migration WHERE singleton = 1), ?1),
                  (SELECT COUNT(*) FROM event_journal_payload_poison),
                  (SELECT COUNT(*) FROM event_journal_legacy_quarantine),
                  (SELECT COUNT(*) FROM event_journal_inherited_loss),
                  COALESCE((SELECT remaining_events FROM event_journal_migration WHERE singleton = 1), 0)
                """
            )
            sqlite3_bind_double(state, 1, fallbackActivation)
            guard sqlite3_step(state) == SQLITE_ROW else {
                sqlite3_finalize(state)
                throw EventStoreError.stepFailed(
                    "retained-window state query failed"
                )
            }
            activation = sqlite3_column_double(state, 0)
            poison = Int(clamping: sqlite3_column_int64(state, 1))
            quarantine = Int(clamping: sqlite3_column_int64(state, 2))
            inherited = Int(clamping: sqlite3_column_int64(state, 3))
            admissionUnscopedLegacy = Int(clamping:
                sqlite3_column_int64(state, 4)
            )
            guard activation.isFinite,
                  sqlite3_step(state) == SQLITE_DONE else {
                sqlite3_finalize(state)
                throw EventStoreError.decodingFailed(
                    "retained-window state is corrupt"
                )
            }
            sqlite3_finalize(state)

            // A validated migration tail is exact, but its source timestamps
            // may extend before schema-v8 activation. Include its bounds while
            // leaving requested-window completeness tied to admission time.
            let legacyBounds = try prepare(
                """
                SELECT MIN(timestamp), MAX(timestamp)
                FROM events
                WHERE journal_block_id IS NULL
                  AND journal_quarantine_marker IS NULL
                  AND typeof(timestamp) IN ('real', 'integer')
                  AND timestamp = timestamp
                """
            )
            if sqlite3_step(legacyBounds) == SQLITE_ROW,
               sqlite3_column_type(legacyBounds, 0) != SQLITE_NULL,
               sqlite3_column_type(legacyBounds, 1) != SQLITE_NULL {
                let minimum = sqlite3_column_double(legacyBounds, 0)
                let maximum = sqlite3_column_double(legacyBounds, 1)
                if minimum.isFinite, maximum.isFinite, minimum <= maximum {
                    include(minimum: minimum, maximum: maximum)
                } else {
                    quarantine = max(1, quarantine)
                }
            }
            guard sqlite3_step(legacyBounds) == SQLITE_DONE else {
                sqlite3_finalize(legacyBounds)
                throw EventStoreError.stepFailed(
                    "retained legacy bounds query failed"
                )
            }
            sqlite3_finalize(legacyBounds)
        } else {
            // Legacy-only stores have no authenticated admission-domain lower
            // bound. Report their visible source bounds, but never claim a
            // requested historical window is complete.
            let legacyBounds = try prepare(
                "SELECT MIN(timestamp), MAX(timestamp) FROM events WHERE typeof(timestamp) IN ('real', 'integer') AND timestamp = timestamp"
            )
            if sqlite3_step(legacyBounds) == SQLITE_ROW,
               sqlite3_column_type(legacyBounds, 0) != SQLITE_NULL,
               sqlite3_column_type(legacyBounds, 1) != SQLITE_NULL {
                let minimum = sqlite3_column_double(legacyBounds, 0)
                let maximum = sqlite3_column_double(legacyBounds, 1)
                if minimum.isFinite, maximum.isFinite, minimum <= maximum {
                    include(minimum: minimum, maximum: maximum)
                }
            }
            guard sqlite3_step(legacyBounds) == SQLITE_DONE else {
                sqlite3_finalize(legacyBounds)
                throw EventStoreError.stepFailed(
                    "legacy retained bounds query failed"
                )
            }
            sqlite3_finalize(legacyBounds)
        }

        let retentionBoundary = max(
            activation,
            now - Self.journalRetentionSeconds
        )
        let effectiveLower = max(lower, retentionBoundary)
        let effectiveUpper = min(requestedUpper, now)
        let hasWindow = effectiveLower <= effectiveUpper
        return RetainedWindowTruth(
            hasWindow: hasWindow,
            effectiveSince: Date(timeIntervalSince1970: effectiveLower),
            effectiveUntil: Date(timeIntervalSince1970: effectiveUpper),
            retainedOldest: sourceMinimum.map(Date.init(timeIntervalSince1970:)),
            retainedNewest: sourceMaximum.map(Date.init(timeIntervalSince1970:)),
            retainedAdmissionOldest: admissionMinimum.map(
                Date.init(timeIntervalSince1970:)
            ),
            retainedAdmissionNewest: admissionMaximum.map(
                Date.init(timeIntervalSince1970:)
            ),
            requestedWindowComplete: hasWindow
                && lower >= retentionBoundary
                && requestedUpper <= now,
            gaps: EventQueryGapCounts(
                canonicalPoisonRecords: poison,
                corruptLegacyRecords: quarantine,
                inheritedLegacyLossRecords: inherited,
                resourceLimitedRecords: admissionUnscopedLegacy
            )
        )
    }

    private func exactEventQuerySnapshot(
        since: Date,
        until: Date? = nil,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        sessionID: String? = nil,
        before cursor: PaginationCursor? = nil,
        limit: Int,
        ascending: Bool
    ) throws -> ExactEventQuerySnapshot {
        let lower = since.timeIntervalSince1970
        let upper = until?.timeIntervalSince1970
            ?? Date.distantFuture.timeIntervalSince1970
        guard lower.isFinite, upper.isFinite, lower <= upper else {
            throw EventStoreError.decodingFailed(
                "exact event query has an invalid time range"
            )
        }
        guard limit > 0 else {
            return try withExactReadSnapshot { generation in
                ExactEventQuerySnapshot(
                    events: [],
                    mutationGeneration: generation,
                    poisonRecords: [],
                    corruptLegacyRecords: 0,
                    inheritedLegacyLossRecords: 0,
                    resourceLimitedRecords: 0,
                    ownershipLeases: []
                )
            }
        }
        let boundedLimit = max(1, min(limit, 10_000))
        return try withVerifiedExactReadSnapshot { generation in
            var candidates: [ExactEventCandidate] = []
            candidates.reserveCapacity(min(boundedLimit * 2, 4_000))
            var unscopedCorruptLegacyRecords = 0
            var retainedCandidateBytes = 0
            var resourceLimitedRecords = 0

            func isBeforeCursor(timestamp: Date, id: String) -> Bool {
                guard let cursor else { return true }
                if timestamp != cursor.timestamp {
                    return timestamp < cursor.timestamp
                }
                return id < cursor.id
            }

            func matches(_ event: Event) -> Bool {
                let timestamp = event.timestamp.timeIntervalSince1970
                guard timestamp >= lower, timestamp <= upper else {
                    return false
                }
                if let category, event.eventCategory != category {
                    return false
                }
                if let severity, event.severity < severity { return false }
                if let sessionID,
                   event.enrichments["ai_tool_session_id"] != sessionID {
                    return false
                }
                return isBeforeCursor(
                    timestamp: event.timestamp,
                    id: event.id.uuidString
                )
            }

            func precedes(
                _ lhs: ExactEventCandidate,
                _ rhs: ExactEventCandidate
            ) -> Bool {
                if lhs.timestamp != rhs.timestamp {
                    return ascending
                        ? lhs.timestamp < rhs.timestamp
                        : lhs.timestamp > rhs.timestamp
                }
                return ascending ? lhs.id < rhs.id : lhs.id > rhs.id
            }

            func trimIfNeeded() {
                guard candidates.count > boundedLimit * 2 else { return }
                candidates.sort(by: precedes)
                let removed = candidates.suffix(
                    candidates.count - boundedLimit
                )
                retainedCandidateBytes -= removed.reduce(0) {
                    $0 + $1.retainedBytes
                }
                candidates.removeLast(removed.count)
            }

            func retainTopK() {
                candidates.sort(by: precedes)
                if candidates.count > boundedLimit {
                    let removed = candidates.suffix(
                        candidates.count - boundedLimit
                    )
                    retainedCandidateBytes -= removed.reduce(0) {
                        $0 + $1.retainedBytes
                    }
                    candidates.removeLast(removed.count)
                }
            }

            func retainCandidate(
                _ candidate: ExactEventCandidate
            ) throws {
                guard let event = candidate.event else {
                    candidates.append(candidate)
                    return
                }
                let charge = try EventJournalAdmissionValidator
                    .preflight(event).sourceRetainedByteEstimate
                let next = retainedCandidateBytes.addingReportingOverflow(
                    charge
                )
                guard charge >= 0, !next.overflow,
                      next.partialValue
                        <= Self.exactQueryResultByteLimit else {
                    resourceLimitedRecords += 1
                    return
                }
                var ownershipLeases = candidate.ownershipLeases
                if ownershipLeases.isEmpty {
                    guard let lease = liveMemoryBudget.tryAcquire(
                        bytes: max(1, charge),
                        owner: .journalPrepared
                    ) else {
                        resourceLimitedRecords += 1
                        return
                    }
                    ownershipLeases = [lease]
                }
                retainedCandidateBytes = next.partialValue
                candidates.append(ExactEventCandidate(
                    timestamp: candidate.timestamp,
                    id: candidate.id,
                    event: event,
                    poisonRecords: candidate.poisonRecords,
                    corruptLegacy: candidate.corruptLegacy,
                    inheritedLegacyLoss: candidate.inheritedLegacyLoss,
                    retainedBytes: charge,
                    ownershipLeases: ownershipLeases
                ))
            }

            let journalSchemaPresent = try hasJournalSchema()
            if journalSchemaPresent {
                // Block summaries are authenticated against the decoded
                // payload at index build. Visit them by the edge relevant to
                // the requested ordering, then stop once the next block cannot
                // beat the retained top-K boundary. Equal timestamps are not
                // skipped because the UUID tie-breaker is per record.
                let orderedSummaries: [(VerifiedJournalSummary, TimeInterval, TimeInterval)] =
                    verifiedJournalSummaries.compactMap { summary in
                        guard !isJournalBlockTombstoned(summary.blockID) else {
                            return nil
                        }
                        let summaryMinimum: TimeInterval
                        let summaryMaximum: TimeInterval
                        if let category {
                            guard let categorySummary =
                                    summary.metadata.byCategory[category],
                                  categorySummary.count > 0,
                                  let minimum = categorySummary.minimum,
                                  let maximum = categorySummary.maximum else {
                                return nil
                            }
                            summaryMinimum = minimum
                            summaryMaximum = maximum
                        } else {
                            summaryMinimum = summary.metadata.minimum
                            summaryMaximum = summary.metadata.maximum
                        }
                        guard summaryMaximum >= lower,
                              summaryMinimum <= upper else { return nil }
                        return (summary, summaryMinimum, summaryMaximum)
                    }.sorted { lhs, rhs in
                        let leftEdge = ascending ? lhs.1 : lhs.2
                        let rightEdge = ascending ? rhs.1 : rhs.2
                        if leftEdge != rightEdge {
                            return ascending
                                ? leftEdge < rightEdge
                                : leftEdge > rightEdge
                        }
                        return ascending
                            ? lhs.0.blockID < rhs.0.blockID
                            : lhs.0.blockID > rhs.0.blockID
                    }
                for (summary, summaryMinimum, summaryMaximum) in orderedSummaries {
                    if candidates.count == boundedLimit,
                       let boundary = candidates.last {
                        let boundaryTimestamp =
                            boundary.timestamp.timeIntervalSince1970
                        if ascending {
                            if summaryMinimum > boundaryTimestamp { break }
                        } else if summaryMaximum < boundaryTimestamp {
                            break
                        }
                    }
                    journalExactQueryBlockDecodes &+= 1
                    let block = try loadExactJournalBlock(
                        blockID: summary.blockID
                    )
                    for (ordinal, event) in block.events.enumerated() {
                        let timestamp = event.timestamp.timeIntervalSince1970
                        guard timestamp >= lower, timestamp <= upper,
                              category == nil
                                || event.eventCategory == category else {
                            continue
                        }
                        if let poison = block.poisonByOrdinal[ordinal] {
                            // UUID/time/category/severity survive the compact
                            // base marker. Session attribution does not, so a
                            // poison in a session query remains an ordered
                            // fail-closed candidate instead of being filtered
                            // out as an unrelated empty-session Event.
                            let terminalSeverityUnknown = poison.contains {
                                $0.kind == .terminal
                            }
                            if (severity == nil
                                    || terminalSeverityUnknown
                                    || event.severity >= severity!),
                               isBeforeCursor(
                                    timestamp: event.timestamp,
                                    id: event.id.uuidString
                               ) {
                                try retainCandidate(ExactEventCandidate(
                                    timestamp: event.timestamp,
                                    id: event.id.uuidString,
                                    event: nil,
                                    poisonRecords: poison,
                                    corruptLegacy: false,
                                    inheritedLegacyLoss:
                                        block.inheritedLossOrdinals.contains(
                                            ordinal
                                        )
                                ))
                            }
                        } else if matches(event) {
                            try retainCandidate(ExactEventCandidate(
                                timestamp: event.timestamp,
                                id: event.id.uuidString,
                                event: event,
                                poisonRecords: [],
                                corruptLegacy: false,
                                inheritedLegacyLoss:
                                    block.inheritedLossOrdinals.contains(
                                        ordinal
                                    ),
                                ownershipLeases:
                                    block.ownershipLeasesByOrdinal[ordinal]
                            ))
                        }
                    }
                    retainTopK()
                }
            }

            let legacyColumns = Self.legacyTypedEventColumns.map {
                "e.\"\($0)\""
            }.joined(separator: ", ")
            let legacySQL = journalSchemaPresent ? """
                SELECT e.rowid, \(legacyColumns),
                       CASE WHEN q.quarantine_id IS NULL THEN 0 ELSE 1 END
                FROM events e
                LEFT JOIN event_journal_legacy_quarantine q
                  ON q.source_marker = e.journal_quarantine_marker
                WHERE e.journal_block_id IS NULL
                """ : """
                SELECT e.rowid, \(legacyColumns), 0
                FROM events e
                """
            let legacy = try prepare(legacySQL)
            defer { sqlite3_finalize(legacy) }
            var cachedDuplicateBlockID: Int64?
            var cachedDuplicateBlock = OwnedJournalBlock(records: [])
            while true {
                let rc = sqlite3_step(legacy)
                if rc == SQLITE_DONE { break }
                guard rc == SQLITE_ROW else {
                    throw EventStoreError.stepFailed(
                        "mixed exact legacy event scan failed"
                    )
                }
                let row = try readLegacyJournalRow(legacy)
                let rawEvent = try? decoder.decode(Event.self, from: row.rawJSON)
                let typedCategory = String(
                    data: row.categoryBytes,
                    encoding: .utf8
                )
                let typedTimestampTrusted: Bool
                if case .real = row.typedValues[1] {
                    typedTimestampTrusted = row.timestamp.isFinite
                } else {
                    typedTimestampTrusted = false
                }
                let typedCategoryValue = typedCategory.flatMap(
                    EventCategory.init(rawValue:)
                )
                let typedOrderingID = String(
                    data: row.idBytes,
                    encoding: .utf8
                ) ?? row.idBytes.base64EncodedString()
                let typedScopeTrusted = typedTimestampTrusted
                    && (category == nil || typedCategoryValue != nil)
                let typedIntersects = typedScopeTrusted
                    && row.timestamp >= lower && row.timestamp <= upper
                    && (category == nil
                        || typedCategoryValue == category)
                    && isBeforeCursor(
                        timestamp: Date(timeIntervalSince1970: row.timestamp),
                        id: typedOrderingID
                    )
                let rawScopeTrusted = rawEvent.map {
                    $0.timestamp.timeIntervalSince1970.isFinite
                } ?? false
                let rawIntersects = rawEvent.map { raw in
                    let timestamp = raw.timestamp.timeIntervalSince1970
                    return timestamp.isFinite
                        && timestamp >= lower && timestamp <= upper
                        && (category == nil || raw.eventCategory == category)
                        && isBeforeCursor(
                            timestamp: raw.timestamp,
                            id: raw.id.uuidString
                        )
                } ?? false
                if sqlite3_column_int(
                    legacy,
                    Int32(Self.legacyTypedEventColumns.count + 1)
                ) != 0 {
                    if typedIntersects || rawIntersects {
                        try retainCandidate(ExactEventCandidate(
                            timestamp: rawIntersects
                                ? (rawEvent?.timestamp ?? Date(
                                    timeIntervalSince1970: row.timestamp
                                  ))
                                : Date(timeIntervalSince1970: row.timestamp),
                            id: rawIntersects
                                ? (rawEvent?.id.uuidString ?? typedOrderingID)
                                : typedOrderingID,
                            event: nil,
                            poisonRecords: [],
                            corruptLegacy: true,
                            inheritedLegacyLoss: false
                        ))
                        trimIfNeeded()
                    } else if !typedScopeTrusted && !rawScopeTrusted {
                        // Neither the typed selector nor raw Event provides a
                        // trustworthy time/category scope. Conservatively gap
                        // every exact window without retaining a fake Event.
                        unscopedCorruptLegacyRecords += 1
                    }
                    continue
                }
                let decoded: DecodedLegacyJournalRow
                do {
                    decoded = try decodeLegacyJournalRowWithLoss(row)
                } catch {
                    if typedIntersects || rawIntersects {
                        let orderingTimestamp = rawIntersects
                            ? (rawEvent?.timestamp ?? Date(
                                timeIntervalSince1970: row.timestamp
                              ))
                            : Date(timeIntervalSince1970: row.timestamp)
                        try retainCandidate(ExactEventCandidate(
                            timestamp: orderingTimestamp,
                            id: rawIntersects
                                ? (rawEvent?.id.uuidString ?? typedOrderingID)
                                : typedOrderingID,
                            event: nil,
                            poisonRecords: [],
                            corruptLegacy: true,
                            inheritedLegacyLoss: false
                        ))
                        trimIfNeeded()
                    } else if !typedScopeTrusted && !rawScopeTrusted {
                        unscopedCorruptLegacyRecords += 1
                    }
                    continue
                }
                let event = decoded.event
                if let location = try existingJournalLocations(
                    for: Set([event.id])
                )[event.id] {
                    if cachedDuplicateBlockID != location.blockID {
                        cachedDuplicateBlock = try loadJournalBlock(
                            blockID: location.blockID
                        )
                        cachedDuplicateBlockID = location.blockID
                    }
                    try validateDuplicate(
                        try preparePersistedEvent(event),
                        at: location,
                        in: cachedDuplicateBlock
                    )
                    continue
                }
                guard matches(event) else { continue }
                try retainCandidate(ExactEventCandidate(
                    timestamp: event.timestamp,
                    id: event.id.uuidString,
                    event: event,
                    poisonRecords: [],
                    corruptLegacy: false,
                    inheritedLegacyLoss: decoded.inheritedLoss != nil
                ))
                trimIfNeeded()
            }
            candidates.sort(by: precedes)
            if candidates.count > boundedLimit {
                candidates.removeLast(candidates.count - boundedLimit)
            }
            return ExactEventQuerySnapshot(
                events: candidates.compactMap(\.event),
                mutationGeneration: generation,
                poisonRecords: candidates.flatMap(\.poisonRecords),
                corruptLegacyRecords: candidates.reduce(
                    into: unscopedCorruptLegacyRecords
                ) {
                    if $1.corruptLegacy { $0 += 1 }
                },
                inheritedLegacyLossRecords: candidates.reduce(into: 0) {
                    if $1.inheritedLegacyLoss { $0 += 1 }
                },
                resourceLimitedRecords: resourceLimitedRecords,
                ownershipLeases: candidates.flatMap(\.ownershipLeases)
            )
        }
    }

    private func requireComplete(
        _ snapshot: ExactEventQuerySnapshot
    ) throws -> [Event] {
        guard snapshot.isComplete else {
            throw EventStoreError.exactEvidenceGap(
                poisonRecords: snapshot.poisonRecords.count,
                corruptLegacyRecords: snapshot.corruptLegacyRecords,
                inheritedLegacyLossRecords:
                    snapshot.inheritedLegacyLossRecords,
                resourceLimitedRecords: snapshot.resourceLimitedRecords
            )
        }
        guard snapshot.events.isEmpty else {
            throw EventStoreError.resourceOwnershipRequired(
                "bare Event array reader; retain ExactEventQuerySnapshot"
            )
        }
        return []
    }

    /// Bare legacy APIs cannot carry coverage metadata, so they fail closed
    /// when any retained canonical/legacy record is explicitly incomplete.
    /// Healthy steady state is three indexed singleton COUNTs; no payload is
    /// decoded merely to prove the absence of a gap.
    private func requireGloballyCompleteExactCorpus() throws {
        guard try hasJournalSchema() else { return }
        let statement = try prepare(
            """
            SELECT
              (SELECT COUNT(*) FROM event_journal_payload_poison),
              (SELECT COUNT(*) FROM event_journal_legacy_quarantine),
              (SELECT COUNT(*) FROM event_journal_inherited_loss)
            """
        )
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "exact retained-gap count failed"
            )
        }
        let poison = Int(sqlite3_column_int64(statement, 0))
        let quarantine = Int(sqlite3_column_int64(statement, 1))
        let inherited = Int(sqlite3_column_int64(statement, 2))
        guard sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "exact retained-gap state is duplicated"
            )
        }
        guard poison == 0, quarantine == 0, inherited == 0 else {
            throw EventStoreError.exactEvidenceGap(
                poisonRecords: poison,
                corruptLegacyRecords: quarantine,
                inheritedLegacyLossRecords: inherited,
                resourceLimitedRecords: 0
            )
        }
    }

    /// Stream the crash-resumable legacy tail one validated row at a time and
    /// suppress only canonical-equal UUIDs already journaled by a split
    /// migration. This keeps count/metric APIs exact without retaining the
    /// legacy corpus or trusting sparse typed SQL as canonical evidence.
    private func forEachExactLegacyEvent(
        _ body: (Event) throws -> Void
    ) throws {
        let columns = Self.legacyTypedEventColumns.map {
            "e.\"\($0)\""
        }.joined(separator: ", ")
        let hasJournal = try hasJournalSchema()
        let sql = hasJournal ? """
            SELECT e.rowid, \(columns),
                   CASE WHEN q.quarantine_id IS NULL THEN 0 ELSE 1 END
            FROM events e
            LEFT JOIN event_journal_legacy_quarantine q
              ON q.source_marker = e.journal_quarantine_marker
            WHERE e.journal_block_id IS NULL
            """ : """
            SELECT e.rowid, \(columns), 0 FROM events e
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        var cachedBlockID: Int64?
        var cachedBlock = OwnedJournalBlock(records: [])
        while true {
            let rc = sqlite3_step(statement)
            if rc == SQLITE_DONE { return }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "exact legacy-tail scan failed"
                )
            }
            let row = try readLegacyJournalRow(statement)
            guard sqlite3_column_int(
                statement,
                Int32(Self.legacyTypedEventColumns.count + 1)
            ) == 0 else {
                throw EventStoreError.exactEvidenceGap(
                    poisonRecords: 0,
                    corruptLegacyRecords: 1,
                    inheritedLegacyLossRecords: 0,
                    resourceLimitedRecords: 0
                )
            }
            let decoded: DecodedLegacyJournalRow
            do {
                decoded = try decodeLegacyJournalRowWithLoss(row)
            } catch {
                throw EventStoreError.exactEvidenceGap(
                    poisonRecords: 0,
                    corruptLegacyRecords: 1,
                    inheritedLegacyLossRecords: 0,
                    resourceLimitedRecords: 0
                )
            }
            guard decoded.inheritedLoss == nil else {
                throw EventStoreError.exactEvidenceGap(
                    poisonRecords: 0,
                    corruptLegacyRecords: 0,
                    inheritedLegacyLossRecords: 1,
                    resourceLimitedRecords: 0
                )
            }
            let event = decoded.event
            if hasJournal,
               let location = try existingJournalLocations(
                    for: Set([event.id])
               )[event.id] {
                if cachedBlockID != location.blockID {
                    cachedBlock = try loadJournalBlock(
                        blockID: location.blockID
                    )
                    cachedBlockID = location.blockID
                }
                try validateDuplicate(
                    try preparePersistedEvent(event),
                    at: location,
                    in: cachedBlock
                )
                continue
            }
            try body(event)
        }
    }

    /// Returns events from the store, optionally filtered by time range, category,
    /// and severity.
    ///
    /// - Parameters:
    ///   - since: Only return events at or after this date.
    ///   - category: If provided, filter to this category only.
    ///   - severity: If provided, filter to this severity or higher.
    ///   - limit: Maximum number of events to return (default 1000).
    /// - Returns: An array of `Event` values decoded from the `raw_json` column.
    public func events(
        since: Date,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        limit: Int = 1000
    ) throws -> [Event] {
        try requireComplete(exactEventsSnapshot(
            since: since,
            category: category,
            severity: severity,
            limit: limit
        ))
    }

    public func exactEventsSnapshot(
        since: Date,
        until: Date = .distantFuture,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        limit: Int = 1000
    ) throws -> ExactEventQuerySnapshot {
        try exactEventQuerySnapshot(
            since: since,
            until: until,
            category: category,
            severity: severity,
            limit: limit,
            ascending: false
        )
    }

    /// Wave-3 P1: all events stamped with a given durable agent session
    /// id, in chronological order — the queryable per-session timeline
    /// (proc/file/net rails today). Backed by idx_events_ai_session.
    public func eventsForAgentSession(_ sessionId: String, limit: Int = 2000) throws -> [Event] {
        try requireComplete(exactEventsForAgentSessionSnapshot(
            sessionId,
            since: .distantPast,
            until: .distantFuture,
            limit: limit
        ))
    }

    /// Phase-5 injection-evidence weld: events for a session bounded to a tight
    /// time window [since, until], chronological. Pushes the "prior N seconds"
    /// retro-scan window into SQL (idx_events_ai_session covers
    /// (ai_tool_session_id, timestamp)) so a busy session that has emitted more
    /// than the plain `limit` of events can't push the recent window out of a
    /// LIMIT-capped ASC scan. `since`/`until` are compared against the same
    /// epoch-seconds `timestamp` column the index is keyed on.
    public func eventsForAgentSession(_ sessionId: String, since: Date, until: Date, limit: Int = 2000) throws -> [Event] {
        try requireComplete(exactEventsForAgentSessionSnapshot(
            sessionId,
            since: since,
            until: until,
            limit: limit
        ))
    }

    public func exactEventsForAgentSessionSnapshot(
        _ sessionID: String,
        since: Date,
        until: Date,
        limit: Int = 2_000
    ) throws -> ExactEventQuerySnapshot {
        try exactEventQuerySnapshot(
            since: since,
            until: until,
            sessionID: sessionID,
            limit: limit,
            ascending: true
        )
    }

    /// Wave-3 P2b: the most-recent durable session id associated with a
    /// process pid. Used MCP-side to attribute a mutation (whose only
    /// correlation handle is the caller's ppid) back to an agent session —
    /// a medium-confidence join (pids recycle; the MCP host pid may differ
    /// from the kernel-work AI-tool root), so callers should label it as
    /// ppid-correlated, not trace-confirmed.
    public func agentSessionForPid(_ pid: Int32) throws -> String? {
        try withVerifiedExactReadSnapshot { _ in
            try requireGloballyCompleteExactCorpus()
            var best: (timestamp: Date, id: String, session: String)?
            func consider(_ event: Event) {
                guard event.process.pid == pid,
                      let session = event.enrichments["ai_tool_session_id"],
                      !session.isEmpty else { return }
                let candidate = (
                    timestamp: event.timestamp,
                    id: event.id.uuidString,
                    session: session
                )
                guard let prior = best else {
                    best = candidate
                    return
                }
                if candidate.timestamp > prior.timestamp
                    || (candidate.timestamp == prior.timestamp
                        && candidate.id > prior.id) {
                    best = candidate
                }
            }
            for summary in verifiedJournalSummaries
                .filter({ !isJournalBlockTombstoned($0.blockID) })
                .sorted(by: {
                    if $0.metadata.maximum != $1.metadata.maximum {
                        return $0.metadata.maximum > $1.metadata.maximum
                    }
                    return $0.blockID > $1.blockID
                }) {
                if let best,
                   summary.metadata.maximum
                    < best.timestamp.timeIntervalSince1970 { break }
                for event in try loadExactJournalBlock(
                    blockID: summary.blockID
                ).events {
                    consider(event)
                }
            }
            try forEachExactLegacyEvent(consider)
            return best?.session
        }
    }

    /// One-line summary per durable agent session, derived from the
    /// stamped events (no separate registry table needed for this slice).
    /// Most-recently-active first. Backed by idx_events_ai_session.
    public struct AgentSessionSummary: Sendable, Hashable {
        public let sessionId: String
        public let tool: String?
        public let projectDir: String?
        public let firstSeen: Date
        public let lastSeen: Date
        public let eventCount: Int
    }

    /// Wave-3 P1b: enumerate agent sessions for list_agent_sessions.
    public func agentSessions(limit: Int = 100) throws -> [AgentSessionSummary] {
        let boundedLimit = max(1, min(limit, 1_000))
        return try withVerifiedExactReadSnapshot { _ in
            try requireGloballyCompleteExactCorpus()
            struct Accumulator {
                var tool: String?
                var projectDir: String?
                var firstSeen: Date
                var lastSeen: Date
                var count: Int
            }
            var sessions: [String: Accumulator] = [:]
            let maximumDistinctSessions = 10_000
            let maximumRetainedSessionBytes = Self.exactQueryResultByteLimit
            var retainedSessionBytes = 0
            func retainedBytes(
                session: String,
                tool: String?,
                projectDir: String?
            ) -> Int {
                let first = session.utf8.count.addingReportingOverflow(
                    tool?.utf8.count ?? 0
                )
                guard !first.overflow else { return Int.max }
                let total = first.partialValue.addingReportingOverflow(
                    projectDir?.utf8.count ?? 0
                )
                return total.overflow ? Int.max : total.partialValue
            }
            func replaceCharge(old: Int, new: Int) throws {
                guard old >= 0, new >= 0, old <= retainedSessionBytes else {
                    throw EventStoreError.decodingFailed(
                        "exact agent-session ownership accounting is invalid"
                    )
                }
                let next = (retainedSessionBytes - old)
                    .addingReportingOverflow(new)
                guard !next.overflow,
                      next.partialValue <= maximumRetainedSessionBytes else {
                    throw EventStoreError.exactEvidenceGap(
                        poisonRecords: 0,
                        corruptLegacyRecords: 0,
                        inheritedLegacyLossRecords: 0,
                        resourceLimitedRecords: 1
                    )
                }
                retainedSessionBytes = next.partialValue
            }
            func lexicalMaximum(_ lhs: String?, _ rhs: String?) -> String? {
                switch (lhs, rhs) {
                case (nil, let value), (let value, nil): return value
                case (let left?, let right?): return max(left, right)
                }
            }
            func include(_ event: Event) throws {
                guard let session = event.enrichments["ai_tool_session_id"],
                      !session.isEmpty else { return }
                if var value = sessions[session] {
                    let oldCharge = retainedBytes(
                        session: session,
                        tool: value.tool,
                        projectDir: value.projectDir
                    )
                    let next = value.count.addingReportingOverflow(1)
                    guard !next.overflow else {
                        throw EventStoreError.decodingFailed(
                            "exact agent-session count overflowed"
                        )
                    }
                    value.count = next.partialValue
                    value.firstSeen = min(value.firstSeen, event.timestamp)
                    value.lastSeen = max(value.lastSeen, event.timestamp)
                    value.tool = lexicalMaximum(
                        value.tool,
                        event.enrichments["ai_tool"]
                    )
                    value.projectDir = lexicalMaximum(
                        value.projectDir,
                        event.process.workingDirectory
                    )
                    try replaceCharge(
                        old: oldCharge,
                        new: retainedBytes(
                            session: session,
                            tool: value.tool,
                            projectDir: value.projectDir
                        )
                    )
                    sessions[session] = value
                } else {
                    guard sessions.count < maximumDistinctSessions else {
                        throw EventStoreError.exactEvidenceGap(
                            poisonRecords: 0,
                            corruptLegacyRecords: 0,
                            inheritedLegacyLossRecords: 0,
                            resourceLimitedRecords: 1
                        )
                    }
                    let tool = event.enrichments["ai_tool"]
                    let projectDir = event.process.workingDirectory
                    try replaceCharge(
                        old: 0,
                        new: retainedBytes(
                            session: session,
                            tool: tool,
                            projectDir: projectDir
                        )
                    )
                    sessions[session] = Accumulator(
                        tool: tool,
                        projectDir: projectDir,
                        firstSeen: event.timestamp,
                        lastSeen: event.timestamp,
                        count: 1
                    )
                }
            }
            for summary in verifiedJournalSummaries where
                !isJournalBlockTombstoned(summary.blockID) {
                for event in try loadExactJournalBlock(
                    blockID: summary.blockID
                ).events {
                    try include(event)
                }
            }
            try forEachExactLegacyEvent(include)
            return sessions.map { session, value in
                AgentSessionSummary(
                    sessionId: session,
                    tool: value.tool,
                    projectDir: value.projectDir,
                    firstSeen: value.firstSeen,
                    lastSeen: value.lastSeen,
                    eventCount: value.count
                )
            }.sorted {
                if $0.lastSeen != $1.lastSeen {
                    return $0.lastSeen > $1.lastSeen
                }
                return $0.sessionId < $1.sessionId
            }.prefix(boundedLimit).map { $0 }
        }
    }

    /// Keyset-paginated variant of `events(...)`. Returns at most
    /// `pageSize` events strictly older than `cursor` (or the newest page
    /// if `cursor == nil`), plus the cursor for the next page.
    ///
    /// Same use case as `AlertStore.alerts(before:)`: backs the "Load older"
    /// UI in the Events tab. Constant-time index seek regardless of page
    /// depth (no OFFSET scan), stable under inserts.
    public func events(
        before cursor: PaginationCursor?,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        pageSize: Int = 100
    ) throws -> PagedResults<Event> {
        let owned = try exactEventsPageSnapshot(
            before: cursor,
            category: category,
            severity: severity,
            pageSize: pageSize
        )
        guard owned.items.isEmpty else {
            throw EventStoreError.resourceOwnershipRequired(
                "bare event page; retain ExactEventPageSnapshot"
            )
        }
        return PagedResults(items: [], nextCursor: owned.nextCursor)
    }

    public func exactEventsPageSnapshot(
        before cursor: PaginationCursor?,
        category: EventCategory? = nil,
        severity: Severity? = nil,
        pageSize: Int = 100
    ) throws -> ExactEventPageSnapshot {
        let clamped = max(1, min(pageSize, 1000))
        let snapshot = try exactEventQuerySnapshot(
            since: .distantPast,
            category: category,
            severity: severity,
            before: cursor,
            limit: clamped,
            ascending: false
        )
        guard snapshot.isComplete else {
            throw EventStoreError.exactEvidenceGap(
                poisonRecords: snapshot.poisonRecords.count,
                corruptLegacyRecords: snapshot.corruptLegacyRecords,
                inheritedLegacyLossRecords:
                    snapshot.inheritedLegacyLossRecords,
                resourceLimitedRecords: snapshot.resourceLimitedRecords
            )
        }
        let rows = snapshot.events

        let next: PaginationCursor?
        if rows.count == clamped, let last = rows.last {
            next = PaginationCursor(
                timestamp: last.timestamp,
                id: last.id.uuidString
            )
        } else {
            next = nil
        }
        return ExactEventPageSnapshot(query: snapshot, nextCursor: next)
    }

    /// Performs a full-text search across indexed event fields.
    ///
    /// Uses the FTS5 virtual table to search process names, paths, command
    /// lines, file paths, network destinations, and TCC fields.
    ///
    /// - Parameters:
    ///   - text: The search query (FTS5 syntax supported).
    ///   - limit: Maximum number of results (default 100).
    /// - Returns: Matching events ordered by relevance.
    public func search(
        text: String,
        since: Date = .distantPast,
        until: Date = .distantFuture,
        limit: Int = 100
    ) throws -> [Event] {
        let snapshot = try searchSnapshot(
            text: text,
            since: since,
            until: until,
            limit: limit
        )
        guard snapshot.isComplete else {
            let omitted = snapshot.projectionOmitted.addingReportingOverflow(
                snapshot.gaps.total
            )
            throw EventStoreError.sparseProjectionIncomplete(
                omittedRecords: omitted.overflow
                    ? Int.max : omitted.partialValue,
                requestedWindowComplete: snapshot.requestedWindowComplete
            )
        }
        guard snapshot.events.isEmpty else {
            throw EventStoreError.resourceOwnershipRequired(
                "bare sparse search; retain EventSearchSnapshot"
            )
        }
        return []
    }

    /// Positive proof that the verified journal's sparse tier has an FTS match
    /// in the requested source-time range. This scalar query retains no Event
    /// graphs and needs no array-result memory lease. It does not prove that a
    /// complete Event can be decoded/returned, or that an empty result proves
    /// absence from the canonical journal. There is deliberately no LIKE
    /// fallback: callers using this as an FTS health proof must keep misses
    /// and failures distinct from a successful FTS match.
    public func containsProjectedFTSMatch(
        text: String,
        since: Date,
        until: Date
    ) throws -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let phrase = "\"" + trimmed.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        return try withVerifiedExactReadSnapshot { _ in
            let statement = try prepare(
                """
                SELECT 1 FROM events e
                JOIN events_fts fts ON e.rowid = fts.rowid
                WHERE events_fts MATCH ?1
                  AND e.timestamp >= ?2 AND e.timestamp <= ?3
                LIMIT 1
                """
            )
            defer { sqlite3_finalize(statement) }
            bindText(statement, index: 1, value: phrase)
            sqlite3_bind_double(statement, 2, since.timeIntervalSince1970)
            sqlite3_bind_double(statement, 3, min(
                until.timeIntervalSince1970, Date().timeIntervalSince1970
            ))
            switch sqlite3_step(statement) {
            case SQLITE_ROW: return true
            case SQLITE_DONE: return false
            default:
                throw EventStoreError.stepFailed("projection FTS presence query failed")
            }
        }
    }

    /// Query the bounded FTS/typed tier while carrying the exact retained
    /// coverage ledger. An empty `events` array means only "no projected
    /// match" unless `isComplete` is true.
    public func searchSnapshot(
        text: String,
        since: Date = .distantPast,
        until: Date = .distantFuture,
        limit: Int = 100
    ) throws -> EventSearchSnapshot {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let requestedLimit = max(1, min(limit, 1_000))
        // Projection JSON is bounded per row, but count-only 1,000-row
        // retention can still breach the process envelope. One fixed 16-MiB
        // J/result lease safely covers the compact 100-row page.
        let boundedLimit = Int32(min(requestedLimit, 100))
        return try withVerifiedExactReadSnapshot { generation in
            let truth = try retainedWindowTruth(
                requestedSince: since,
                requestedUntil: until,
                asOf: Date()
            )
            // Search remains useful for retained late-arriving/old-source-time
            // evidence outside the guaranteed admission interval. Query the
            // caller's full source-time range, but keep
            // requestedWindowComplete=false so absence is never inferred.
            let sinceTs = since.timeIntervalSince1970
            let untilTs = min(
                until.timeIntervalSince1970,
                Date().timeIntervalSince1970
            )
            let coverage = try prepare(
                """
                SELECT COALESCE(SUM(considered_count), 0),
                       COALESCE(SUM(materialized_count), 0),
                       COALESCE(SUM(omitted_quota_count), 0),
                       COALESCE(SUM(omitted_replaced_count), 0),
                       COALESCE(SUM(omitted_physical_count), 0),
                       COALESCE(SUM(omitted_external_count), 0),
                       COALESCE(SUM(omitted_migration_count), 0),
                       COALESCE(SUM(pending_count), 0)
                FROM event_projection_coverage
                """
            )
            guard sqlite3_step(coverage) == SQLITE_ROW else {
                sqlite3_finalize(coverage)
                throw EventStoreError.stepFailed(
                    "sparse search coverage query failed"
                )
            }
            var values: [Int] = []
            values.reserveCapacity(8)
            for column in Int32(0)..<Int32(8) {
                let value = sqlite3_column_int64(coverage, column)
                guard value >= 0 else {
                    sqlite3_finalize(coverage)
                    throw EventStoreError.decodingFailed(
                        "sparse search coverage is negative"
                    )
                }
                values.append(Int(clamping: value))
            }
            guard sqlite3_step(coverage) == SQLITE_DONE else {
                sqlite3_finalize(coverage)
                throw EventStoreError.decodingFailed(
                    "sparse search coverage is duplicated"
                )
            }
            sqlite3_finalize(coverage)

            var rows: [Event] = []
            var resultLease: EventPipelineMemoryLease?
            if !trimmed.isEmpty {
                guard let lease = liveMemoryBudget.tryAcquire(
                    bytes: Self.exactQueryResultByteLimit,
                    owner: .journalPrepared
                ) else {
                    return EventSearchSnapshot(
                        events: [],
                        mutationGeneration: generation,
                        requestedSince: since,
                        requestedUntil: until,
                        effectiveSince: truth.effectiveSince,
                        effectiveUntil: truth.effectiveUntil,
                        retainedOldest: truth.retainedOldest,
                        retainedNewest: truth.retainedNewest,
                        retainedAdmissionOldest:
                            truth.retainedAdmissionOldest,
                        retainedAdmissionNewest:
                            truth.retainedAdmissionNewest,
                        projectionConsidered: values[0],
                        projectionMaterialized: values[1],
                        projectionOmittedQuota: values[2],
                        projectionOmittedReplaced: values[3],
                        projectionOmittedPhysical: values[4],
                        projectionOmittedExternal: values[5],
                        projectionOmittedMigration: values[6],
                        projectionPending: values[7],
                        requestedWindowComplete:
                            truth.requestedWindowComplete,
                        gaps: EventQueryGapCounts(
                            canonicalPoisonRecords:
                                truth.gaps.canonicalPoisonRecords,
                            corruptLegacyRecords:
                                truth.gaps.corruptLegacyRecords,
                            inheritedLegacyLossRecords:
                                truth.gaps.inheritedLegacyLossRecords,
                            resourceLimitedRecords:
                                truth.gaps.resourceLimitedRecords + 1
                        ),
                        ownershipLeases: []
                    )
                }
                resultLease = lease
                let escaped = trimmed.replacingOccurrences(
                    of: "\"", with: "\"\""
                )
                let phraseQuery = "\"\(escaped)\""
                let ftsSQL = """
                    SELECT e.raw_json
                    FROM events e
                    JOIN events_fts fts ON e.rowid = fts.rowid
                    WHERE events_fts MATCH ?1
                      AND e.timestamp >= ?2
                      AND e.timestamp <= ?3
                    ORDER BY e.timestamp DESC
                    LIMIT ?4
                    """
                rows = try queryEventsStrict(sql: ftsSQL, bindings: [
                    (1, .text(phraseQuery)),
                    (2, .double(sinceTs)),
                    (3, .double(untilTs)),
                    (4, .int(boundedLimit)),
                ])
                if rows.isEmpty,
                   !trimmed.contains(where: {
                       !$0.isLetter && !$0.isNumber
                   }) {
                    rows = try queryEventsStrict(sql: ftsSQL, bindings: [
                        (1, .text(trimmed)),
                        (2, .double(sinceTs)),
                        (3, .double(untilTs)),
                        (4, .int(boundedLimit)),
                    ])
                }
                if rows.isEmpty {
                    let likePattern = "%"
                        + trimmed.replacingOccurrences(of: "%", with: "\\%")
                            .replacingOccurrences(of: "_", with: "\\_")
                        + "%"
                    let likeSQL = """
                        SELECT raw_json FROM events
                        WHERE timestamp >= ?2 AND timestamp <= ?3
                          AND (process_path LIKE ?1 ESCAPE '\\'
                            OR process_name LIKE ?1 ESCAPE '\\'
                            OR process_commandline LIKE ?1 ESCAPE '\\'
                            OR file_path LIKE ?1 ESCAPE '\\'
                            OR network_dest_ip LIKE ?1 ESCAPE '\\'
                            OR tcc_service LIKE ?1 ESCAPE '\\'
                            OR tcc_client LIKE ?1 ESCAPE '\\')
                        ORDER BY timestamp DESC
                        LIMIT ?4
                        """
                    rows = try queryEventsStrict(sql: likeSQL, bindings: [
                        (1, .text(likePattern)),
                        (2, .double(sinceTs)),
                        (3, .double(untilTs)),
                        (4, .int(boundedLimit)),
                    ])
                }
            }
            let resourceGap = requestedLimit > Int(boundedLimit) ? 1 : 0
            return EventSearchSnapshot(
                events: rows,
                mutationGeneration: generation,
                requestedSince: since,
                requestedUntil: until,
                effectiveSince: truth.effectiveSince,
                effectiveUntil: truth.effectiveUntil,
                retainedOldest: truth.retainedOldest,
                retainedNewest: truth.retainedNewest,
                retainedAdmissionOldest: truth.retainedAdmissionOldest,
                retainedAdmissionNewest: truth.retainedAdmissionNewest,
                projectionConsidered: values[0],
                projectionMaterialized: values[1],
                projectionOmittedQuota: values[2],
                projectionOmittedReplaced: values[3],
                projectionOmittedPhysical: values[4],
                projectionOmittedExternal: values[5],
                projectionOmittedMigration: values[6],
                projectionPending: values[7],
                requestedWindowComplete: truth.requestedWindowComplete,
                gaps: EventQueryGapCounts(
                    canonicalPoisonRecords:
                        truth.gaps.canonicalPoisonRecords,
                    corruptLegacyRecords:
                        truth.gaps.corruptLegacyRecords,
                    inheritedLegacyLossRecords:
                        truth.gaps.inheritedLegacyLossRecords,
                    resourceLimitedRecords:
                        truth.gaps.resourceLimitedRecords + resourceGap
                ),
                ownershipLeases: rows.isEmpty
                    ? [] : resultLease.map { [$0] } ?? []
            )
        }
    }

    /// Returns a single event by its identifier.
    ///
    /// - Parameter id: The event's unique UUID.
    /// - Returns: The event, or `nil` if not found.
    public func exactEventSnapshot(
        id: UUID
    ) throws -> ExactEventLookupSnapshot {
        try withVerifiedExactReadSnapshot { generation in
            if let location = try existingJournalLocations(
                for: Set([id])
            )[id] {
                let block = try loadExactJournalBlock(
                    blockID: location.blockID
                )
                guard location.ordinal >= 0,
                      location.ordinal < block.events.count,
                      block.events[location.ordinal].id == id else {
                    throw EventStoreError.decodingFailed(
                        "exact event locator identity is invalid"
                    )
                }
                let poison = block.poisonByOrdinal[location.ordinal] ?? []
                let inherited = block.inheritedLossOrdinals.contains(
                    location.ordinal
                )
                guard poison.isEmpty, !inherited else {
                    throw EventStoreError.exactEvidenceGap(
                        poisonRecords: poison.count,
                        corruptLegacyRecords: 0,
                        inheritedLegacyLossRecords: inherited ? 1 : 0,
                        resourceLimitedRecords: 0
                    )
                }
                return ExactEventLookupSnapshot(
                    event: block.events[location.ordinal],
                    mutationGeneration: generation,
                    ownershipLeases:
                        block.ownershipLeasesByOrdinal[location.ordinal]
                )
            }

            // During a crash-resumable migration the exact event may still be
            // in the wide v7 row. Validate/reconstruct the complete typed row;
            // projection raw_json alone is not authoritative. The scan is
            // startup-tail-only and retains one row at a time.
            let columns = Self.legacyTypedEventColumns.map {
                "e.\"\($0)\""
            }.joined(separator: ", ")
            let hasJournal = try hasJournalSchema()
            let sql = hasJournal ? """
                SELECT e.rowid, \(columns),
                       CASE WHEN q.quarantine_id IS NULL THEN 0 ELSE 1 END
                FROM events e
                LEFT JOIN event_journal_legacy_quarantine q
                  ON q.source_marker = e.journal_quarantine_marker
                WHERE e.journal_block_id IS NULL
                """ : """
                SELECT e.rowid, \(columns), 0 FROM events e
                """
            let statement = try prepare(sql)
            defer { sqlite3_finalize(statement) }
            while true {
                let rc = sqlite3_step(statement)
                if rc == SQLITE_DONE {
                    return ExactEventLookupSnapshot(
                        event: nil,
                        mutationGeneration: generation,
                        ownershipLeases: []
                    )
                }
                guard rc == SQLITE_ROW else {
                    throw EventStoreError.stepFailed(
                        "exact legacy event-id scan failed"
                    )
                }
                let row = try readLegacyJournalRow(statement)
                let raw = try? decoder.decode(Event.self, from: row.rawJSON)
                let typedID = String(data: row.idBytes, encoding: .utf8)
                    .flatMap(UUID.init(uuidString:))
                let selectsTarget = raw?.id == id || typedID == id
                let identityScopeUnknown = raw == nil && typedID == nil
                let quarantined = sqlite3_column_int(
                    statement,
                    Int32(Self.legacyTypedEventColumns.count + 1)
                ) != 0
                if quarantined {
                    if selectsTarget || identityScopeUnknown {
                        throw EventStoreError.exactEvidenceGap(
                            poisonRecords: 0,
                            corruptLegacyRecords: 1,
                            inheritedLegacyLossRecords: 0,
                            resourceLimitedRecords: 0
                        )
                    }
                    continue
                }
                do {
                    let decoded = try decodeLegacyJournalRowWithLoss(row)
                    guard decoded.event.id == id else { continue }
                    guard decoded.inheritedLoss == nil else {
                        throw EventStoreError.exactEvidenceGap(
                            poisonRecords: 0,
                            corruptLegacyRecords: 0,
                            inheritedLegacyLossRecords: 1,
                            resourceLimitedRecords: 0
                        )
                    }
                    let charge = try EventJournalAdmissionValidator
                        .preflight(decoded.event).sourceRetainedByteEstimate
                    guard let lease = liveMemoryBudget.tryAcquire(
                        bytes: max(1, charge),
                        owner: .journalPrepared
                    ) else {
                        throw EventStoreError.exactEvidenceGap(
                            poisonRecords: 0,
                            corruptLegacyRecords: 0,
                            inheritedLegacyLossRecords: 0,
                            resourceLimitedRecords: 1
                        )
                    }
                    return ExactEventLookupSnapshot(
                        event: decoded.event,
                        mutationGeneration: generation,
                        ownershipLeases: [lease]
                    )
                } catch let gap as EventStoreError {
                    if case .exactEvidenceGap = gap { throw gap }
                    if selectsTarget || identityScopeUnknown {
                        throw EventStoreError.exactEvidenceGap(
                            poisonRecords: 0,
                            corruptLegacyRecords: 1,
                            inheritedLegacyLossRecords: 0,
                            resourceLimitedRecords: 0
                        )
                    }
                }
            }
        }
    }

    public func event(id: UUID) throws -> Event? {
        let snapshot = try exactEventSnapshot(id: id)
        guard snapshot.event == nil else {
            throw EventStoreError.resourceOwnershipRequired(
                "event(id:); retain ExactEventLookupSnapshot"
            )
        }
        return nil
    }

    /// Returns event counts grouped by `event_category`, restricted to
    /// rows newer than `since`. Used by the heartbeat writer to feed the
    /// rebuilt ES Health panel's per-event-type breakdown. Cheap because
    /// it walks the existing `idx_events_ts_category` composite index.
    public func eventCountsByCategory(since: Date) throws -> [String: Int] {
        let snapshot = try eventCategoryCountSnapshot(since: since)
        guard snapshot.requestedWindowComplete else {
            throw EventStoreError.incompleteRetentionWindow(
                requestedSince: snapshot.requestedSince,
                effectiveSince: snapshot.effectiveSince
            )
        }
        guard snapshot.gaps.total == 0 else {
            throw EventStoreError.exactEvidenceGap(
                poisonRecords: snapshot.gaps.canonicalPoisonRecords,
                corruptLegacyRecords: snapshot.gaps.corruptLegacyRecords,
                inheritedLegacyLossRecords:
                    snapshot.gaps.inheritedLegacyLossRecords,
                resourceLimitedRecords: snapshot.gaps.resourceLimitedRecords
            )
        }
        return snapshot.counts
    }

    /// Exact category totals paired with the admission-retention boundary that
    /// makes their rate denominator honest. Long requested windows are
    /// intersected with the provable retained interval and marked incomplete;
    /// callers must use `effectiveSince...effectiveUntil`, never the requested
    /// duration, when deriving EPS.
    public func eventCategoryCountSnapshot(
        since: Date,
        until: Date = Date()
    ) throws -> EventCategoryCountSnapshot {
        return try withVerifiedExactReadSnapshot { generation in
            let asOf = Date()
            let truth = try retainedWindowTruth(
                requestedSince: since,
                requestedUntil: until,
                asOf: asOf
            )
            // Category summaries are authenticated at admission-bucket
            // granularity. Widen the lower edge to the bucket we actually
            // count and report that widened edge below. A fractional caller
            // cutoff in the same bucket is therefore explicitly incomplete,
            // never a false claim that pre-cutoff admissions were excluded.
            let cutoffBucket = Int64(floor(
                truth.effectiveSince.timeIntervalSince1970
            ))
            let upperBucket = Int64(floor(
                truth.effectiveUntil.timeIntervalSince1970
            ))
            let effectiveBucketSince = truth.hasWindow
                ? Date(timeIntervalSince1970: TimeInterval(cutoffBucket))
                : truth.effectiveSince
            let bucketDoesNotPrecedeRequest =
                effectiveBucketSince >= since
            var totals: [EventCategory: Int] = [:]

            func add(_ count: Int, category: EventCategory) throws {
                guard count >= 0 else {
                    throw EventStoreError.decodingFailed(
                        "exact category count is negative"
                    )
                }
                let next = (totals[category] ?? 0)
                    .addingReportingOverflow(count)
                guard !next.overflow else {
                    throw EventStoreError.decodingFailed(
                        "exact category count overflowed"
                    )
                }
                totals[category] = next.partialValue
            }

            for summary in verifiedJournalSummaries where
                !isJournalBlockTombstoned(summary.blockID) {
                let admissionBucket = summary.metadata.admissionBucket
                guard truth.hasWindow,
                      admissionBucket >= cutoffBucket,
                      admissionBucket <= upperBucket else {
                    continue
                }
                for category in EventCategory.allCases {
                    guard let metadata = summary.metadata.byCategory[category],
                          metadata.count > 0 else { continue }
                    try add(metadata.count, category: category)
                }
            }
            return EventCategoryCountSnapshot(
                counts: Dictionary(uniqueKeysWithValues: totals.compactMap {
                    $0.value > 0 ? ($0.key.rawValue, $0.value) : nil
                }),
                mutationGeneration: generation,
                requestedSince: since,
                requestedUntil: until,
                effectiveSince: effectiveBucketSince,
                effectiveUntil: truth.effectiveUntil,
                retainedOldest: truth.retainedOldest,
                retainedNewest: truth.retainedNewest,
                retainedAdmissionOldest: truth.retainedAdmissionOldest,
                retainedAdmissionNewest: truth.retainedAdmissionNewest,
                requestedWindowComplete: truth.requestedWindowComplete
                    && bucketDoesNotPrecedeRequest,
                gaps: truth.gaps
            )
        }
    }

    /// v1.21.6 (PERF-04): retained wall-clock span per `event_category`, in
    /// seconds (MAX(timestamp) - MIN(timestamp) over the rows still on disk).
    ///
    /// Exists because the CONFIGURED hot tier and the DELIVERED one had diverged
    /// by three orders of magnitude with nothing surfacing it: on the field host
    /// `file` retained 0.5 minutes against a configured 30, while `process`
    /// retained 17.8 — the Layer-3 row-count fallback evicting the fodder
    /// categories to keep the footprint under cap. Any sequence rule, graph rule
    /// or hunt that needs file history beyond ~30 s was silently blind.
    ///
    /// Combines authenticated journal summary bounds with any remaining exact
    /// legacy Events. It does not depend on a sparse category/severity index.
    /// Called at the 30 s heartbeat cadence, never on the insert path.
    public func retainedWindowSecondsByCategory(
        asOf: Date = Date()
    ) throws -> [String: EventCategoryRetentionWindow] {
        let asOfSeconds = asOf.timeIntervalSince1970
        guard asOfSeconds.isFinite else {
            throw EventStoreError.decodingFailed(
                "retained category window has a non-finite snapshot time"
            )
        }
        return try withVerifiedExactReadSnapshot { _ in
            try requireGloballyCompleteExactCorpus()
            var bounds: [EventCategory: (minimum: TimeInterval, maximum: TimeInterval)] = [:]
            func include(_ timestamp: TimeInterval, category: EventCategory) {
                if let prior = bounds[category] {
                    bounds[category] = (
                        min(prior.minimum, timestamp),
                        max(prior.maximum, timestamp)
                    )
                } else {
                    bounds[category] = (timestamp, timestamp)
                }
            }
            for summary in verifiedJournalSummaries where
                !isJournalBlockTombstoned(summary.blockID) {
                for category in EventCategory.allCases {
                    guard let value = summary.metadata.byCategory[category],
                          value.count > 0,
                          let minimum = value.minimum,
                          let maximum = value.maximum else { continue }
                    include(minimum, category: category)
                    include(maximum, category: category)
                }
            }
            try forEachExactLegacyEvent { event in
                include(
                    event.timestamp.timeIntervalSince1970,
                    category: event.eventCategory
                )
            }
            return Dictionary(uniqueKeysWithValues: bounds.map {
                (
                    $0.key.rawValue,
                    EventCategoryRetentionWindow(
                        spanSeconds: Int(max(
                            0,
                            $0.value.maximum - $0.value.minimum
                        )),
                        lookbackSeconds: Int(max(
                            0,
                            asOfSeconds - $0.value.minimum
                        ))
                    )
                )
            })
        }
    }

    public func retainedSpanSecondsByCategory() throws -> [String: Int] {
        try retainedWindowSecondsByCategory().mapValues(\.spanSeconds)
    }

    /// Returns the total number of events in the store.
    public func count() throws -> Int {
        try withVerifiedExactReadSnapshot { _ in
            try requireGloballyCompleteExactCorpus()
            var total = 0
            for summary in verifiedJournalSummaries where
                !isJournalBlockTombstoned(summary.blockID) {
                let next = total.addingReportingOverflow(summary.eventCount)
                guard !next.overflow else {
                    throw EventStoreError.decodingFailed(
                        "exact retained event count overflowed"
                    )
                }
                total = next.partialValue
            }
            try forEachExactLegacyEvent { _ in
                let next = total.addingReportingOverflow(1)
                guard !next.overflow else {
                    throw EventStoreError.decodingFailed(
                        "exact retained event count overflowed"
                    )
                }
                total = next.partialValue
            }
            return total
        }
    }

    /// Physical/canonical cardinality used only to size bounded maintenance
    /// quanta. Unlike `count()`, this does not claim evidence completeness and
    /// therefore remains available when poison/inherited-loss ledgers make an
    /// operator query fail closed. It never converts a read failure to zero.
    public func maintenanceRetainedRecordCount() throws -> Int {
        let journalPresent = try hasJournalSchema()
        let sql = journalPresent ? """
            SELECT
              COALESCE((SELECT SUM(event_count) FROM event_journal_blocks), 0)
              + COALESCE((SELECT COUNT(*) FROM events WHERE journal_block_id IS NULL), 0)
            """ : "SELECT COUNT(*) FROM events"
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "maintenance retained-record count failed"
            )
        }
        let value = sqlite3_column_int64(statement, 0)
        guard value >= 0, value <= Int64(Int.max),
              sqlite3_step(statement) == SQLITE_DONE else {
            throw EventStoreError.decodingFailed(
                "maintenance retained-record count is corrupt"
            )
        }
        return Int(value)
    }

    // MARK: - Pruning

    private struct AggregateRollupFailure: Error {
        let underlying: any Error
    }

    /// Keep aggregate accounting, FTS deletion, and source deletion in one
    /// transaction. If trend aggregation alone fails, roll the whole attempt
    /// back and retry an atomic FTS+source delete so disk-cap convergence still
    /// outranks best-effort trend data without double-counting on a later run.
    private func deleteEventBatchAtomically(
        aggregateSQL: String?,
        ftsSQL: String,
        eventsSQL: String,
        estimatedTransactionBytes: Int64,
        bind: (OpaquePointer) -> Void
    ) throws -> Int {
        func run(aggregate: String?) throws -> Int {
            try beginSerializedWrite(
                estimatedBytes: estimatedTransactionBytes,
                maintenance: true
            )
            var committed = false
            do {
                if let aggregate {
                    do {
                        let statement = try prepare(aggregate)
                        bind(statement)
                        let rc = sqlite3_step(statement)
                        sqlite3_finalize(statement)
                        guard rc == SQLITE_DONE else {
                            try throwLatchedStoragePressureIfPresent(
                                resultCode: rc
                            )
                            throw EventStoreError.stepFailed(
                                "event aggregate step failed"
                            )
                        }
                    } catch {
                        throw AggregateRollupFailure(underlying: error)
                    }
                }

                let fts = try prepare(ftsSQL)
                bind(fts)
                let ftsRC = sqlite3_step(fts)
                sqlite3_finalize(fts)
                guard ftsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: ftsRC)
                    throw EventStoreError.stepFailed("event FTS delete failed")
                }

                let events = try prepare(eventsSQL)
                bind(events)
                let eventsRC = sqlite3_step(events)
                sqlite3_finalize(events)
                guard eventsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(
                        resultCode: eventsRC
                    )
                    throw EventStoreError.stepFailed("event delete failed")
                }
                let deleted = Int(sqlite3_changes(db))
                try execute("COMMIT")
                committed = true
                return deleted
            } catch {
                if !committed { try? execute("ROLLBACK") }
                throw error
            }
        }

        if aggregateSQL != nil {
            do {
                return try run(aggregate: aggregateSQL)
            } catch let failure as AggregateRollupFailure {
                Logger(subsystem: "com.maccrab.storage", category: "event-store")
                    .warning("Layer-3 roll-up failed and was rolled back; retrying the FTS+event delete atomically without trend data: \(failure.underlying.localizedDescription, privacy: .public)")
            }
        }
        return try run(aggregate: nil)
    }

    /// Deletes events older than the specified date for data retention.
    ///
    /// Deletes in batches of 100,000 rows and yields between batches so that
    /// concurrent event inserts are not blocked for extended periods. At high
    /// event volumes a single bulk delete can take hours; batching keeps each
    /// individual write lock short.
    ///
    /// Also removes corresponding FTS entries to keep the search index consistent.
    ///
    /// - Parameter date: Events with timestamps before this date will be deleted.
    /// - Parameters:
    ///   - protectedCategory: If supplied with `floorCutoff`, rows in this
    ///     category that are newer than `floorCutoff` are SPARED even though
    ///     they are older than `date` — the per-category retention floor. Lets
    ///     a tightened size-cap cutoff roll up the file firehose without
    ///     evicting the low-volume process/exec channel out from under its
    ///     floor. Nil (default) = category-blind, unchanged behavior.
    ///   - floorCutoff: The floor boundary for `protectedCategory` (see above).
    /// - Returns: The total number of events deleted across all batches.
    @discardableResult
    public func prune(
        olderThan date: Date,
        protecting protectedCategory: EventCategory? = nil,
        newerThan floorCutoff: Date? = nil,
        // v1.21.4 (audit): set true when the CALLER already holds an open write
        // transaction (rollUpAndPrune). Inside a transaction we must NOT suspend
        // (Task.yield) — the actor would reenter and a concurrent
        // insert(events:lane:)
        // would issue a nested BEGIN, which SQLite rejects, silently losing that
        // insert's whole batch. We also skip incremental_vacuum (illegal inside a
        // transaction); the caller vacuums after COMMIT.
        withinTransaction: Bool = false
    ) async throws -> Int {
        guard !withinTransaction else {
            throw EventStoreError.stepFailed(
                "prune within an unbounded caller transaction is disabled; use reserve-bounded batches"
            )
        }
        let batchSize = maintenanceBatchRowLimit(mutationsPerCandidate: 2)
        let batchEstimate = maintenanceEstimate(
            rowCount: Int(batchSize),
            mutationsPerCandidate: 2
        )
        let timestamp = date.timeIntervalSince1970
        var totalDeleted = 0

        // Base predicate: older than the retention cutoff. When a protected
        // category + floor are supplied, spare protected-category rows still
        // newer than the floor (bound to ?3/?4).
        let hasFloor = protectedCategory != nil && floorCutoff != nil
        let legacyOnly = "journal_block_id IS NULL AND journal_quarantine_marker IS NULL"
        let selector = hasFloor
            ? "timestamp < ?1 AND (event_category <> ?3 OR timestamp < ?4)"
            : "timestamp < ?1"
        let safeSelector = "\(legacyOnly) AND (\(selector))"

        // Batch: delete FTS entries for the next batch of stale events, then delete
        // the events themselves. Repeat until no rows remain older than `date`.
        //
        // Using a rowid IN (SELECT rowid … LIMIT N) subquery avoids the need for
        // the SQLITE_ENABLE_UPDATE_DELETE_LIMIT compile-time flag, which may not
        // be set in the system SQLite.
        let deleteFTS = """
            DELETE FROM events_fts WHERE rowid IN (
                SELECT rowid FROM events WHERE \(safeSelector)
                ORDER BY rowid LIMIT ?2
            )
            """
        let deleteEvents = """
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events WHERE \(safeSelector)
                ORDER BY rowid LIMIT ?2
            )
            """

        func bindSelector(_ stmt: OpaquePointer) {
            sqlite3_bind_double(stmt, 1, timestamp)
            sqlite3_bind_int(stmt, 2, batchSize)
            if let protectedCategory, let floorCutoff {
                bindText(stmt, index: 3, value: protectedCategory.rawValue)
                sqlite3_bind_double(stmt, 4, floorCutoff.timeIntervalSince1970)
            }
        }

        while true {
            let rowsDeleted = try deleteEventBatchAtomically(
                aggregateSQL: nil,
                ftsSQL: deleteFTS,
                eventsSQL: deleteEvents,
                estimatedTransactionBytes: batchEstimate,
                bind: bindSelector
            )
            totalDeleted += rowsDeleted

            // No more rows in this batch — pruning is complete.
            if rowsDeleted == 0 { break }

            // Yield to the actor's cooperative executor so concurrent inserts and
            // queries are not starved between batches — but NEVER while a caller
            // holds an open transaction (see withinTransaction: a suspension here
            // lets a reentrant insert issue a nested BEGIN and lose its batch).
            await Task.yield()
        }

        // v1.10.0 perf: incremental_vacuum reclaims pages freed by the
        // prune above. Without this, events.db file grows monotonically
        // even when the row count is bounded — heavy-event machines
        // that keep 30 days of data accumulate freelist pages until a
        // full VACUUM runs (rare). incremental_vacuum is non-blocking
        // and operates on the already-released pages from this prune.
        // Cap to 5K pages (~20 MB) per call so we don't stall the
        // actor on a freshly-pruned giant DB.
        // incremental_vacuum is illegal inside a transaction — skip it when the
        // caller holds one (rollUpAndPrune runs it after COMMIT instead).
        if totalDeleted > 0, let db {
            let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
                requestedPages: Int.max,
                reserveBytes: storageTransactionReserveBytes,
                pageSizeBytes: sqlitePageSizeBytes
            )
            guard plan.pages > 0 else { return totalDeleted }
            try withSerializedWrite(
                estimatedBytes: plan.estimatedTransactionBytes,
                maintenance: true
            ) {
                let rc = sqlite3_exec(
                    db,
                    "PRAGMA incremental_vacuum(\(plan.pages))",
                    nil,
                    nil,
                    nil
                )
                if rc != SQLITE_OK {
                    try throwLatchedStoragePressureIfPresent(resultCode: rc)
                    throw EventStoreError.stepFailed(
                        "bounded incremental VACUUM failed after prune"
                    )
                }
            }
        }

        return totalDeleted
    }

    /// Delete the oldest `count` events (by timestamp). Used by the
    /// size-cap enforcer when the DB file exceeds `maxDatabaseSizeMB`
    /// despite retention-based pruning — e.g. a 30-day retention on a
    /// heavy-event machine. Prunes events and their FTS rows together.
    ///
    /// Batching matches `prune(olderThan:)` so a single 1M-event
    /// prune doesn't hold the write lock too long.
    ///
    /// ## Per-category floor (v1.21.4)
    ///
    /// When `protectedCategory` + `floorCutoff` are supplied the eviction
    /// becomes **category-aware**: rows that are NOT the protected category
    /// (plus protected-category rows already older than `floorCutoff`) are
    /// evicted first, oldest-first. This spares the low-volume — but
    /// high-value — process/exec channel from a cheap file-write flood that
    /// would otherwise collapse the whole window and take exec rows with it.
    ///
    /// **Soft-floor safety valve.** If the eligible (non-protected/aged) rows
    /// are exhausted before `count` is met — i.e. the protected process rows
    /// within the floor ALONE are keeping the DB over cap — the loop falls
    /// back to unconditional oldest-first (even on protected rows) for the
    /// remaining count. Without the separate hard floor below, this guarantees
    /// `pruneOldest` removes `count` rows (or the whole table), no matter how
    /// large the protected category gets.
    ///
    /// `hardFloorCutoff` is different: when supplied, no category newer than
    /// that timestamp is eligible in either phase and the method may return
    /// fewer rows than requested. This is the store primitive used when the
    /// daemon must prefer honest storage shedding/degraded state over silently
    /// deleting the entire recent forensic/correlation window to make a
    /// configured byte target appear feasible.
    @discardableResult
    public func pruneOldest(
        count: Int,
        protecting protectedCategory: EventCategory? = nil,
        newerThan floorCutoff: Date? = nil,
        preservingAllNewerThan hardFloorCutoff: Date? = nil
    ) async throws -> Int {
        guard count > 0 else { return 0 }
        let batchSize: Int32 = min(
            maintenanceBatchRowLimit(mutationsPerCandidate: 3),
            Int32(clamping: count)
        )
        var remaining = count
        var totalDeleted = 0

        // Phase 1 — category-aware eviction. "Eligible" = any row NOT in the
        // protected category, OR a protected-category row already older than
        // the floor. Oldest-first within that eligible set. Protected rows
        // newer than the floor are spared here. Delete FTS first so the rowid
        // subquery sees a stable event set, then the events (same pattern as
        // prune(olderThan:)).
        if let protectedCategory, let floorCutoff {
            let floorTs = floorCutoff.timeIntervalSince1970
            // v1.21.6 (audit DL-04). The eligible set used to be "everything
            // that is not the protected category", which made the SCARCE,
            // high-signal channels the FIRST rows evicted while the protected
            // firehose was spared entirely. Layer 3 asks for at least 10,000
            // rows (DaemonTimers.runAdaptiveRollupSweep) and network/auth/tcc
            // together hold only a few hundred, so Phase 1 drained them to ZERO
            // on every sweep before the valve below touched a single protected
            // row — the exact inverse of forensic value. Field-observed: this
            // host's events.db held only `process` and `file` rows, with no
            // network, authentication or tcc rows on disk at all, so `hunt` and
            // `get_events` could not answer the outbound-connection / DNS /
            // permission-grant questions a responder asks first.
            //
            // Fix: INSIDE the floor window only the bulk channels are fodder;
            // network (which also carries DNS), authentication and tcc get the
            // same freshness guarantee the protected category already gets.
            // Anything ALREADY older than the floor stays fully eligible
            // regardless of category, so the cap still converges and the
            // soft-floor valve in Phase 2 is untouched.
            //
            // NOT the auditor's suggested inversion (protect network/dns/tcc,
            // evict process first): process/exec is the substrate for lineage,
            // sequence rules and campaign correlation, and the v1.21.4 floor
            // exists precisely because a file-write flood collapsing it was a
            // detection outage. Both channels are protected; only `file` and
            // `registry` are fodder inside the window.
            //
            // Kept as ONE interpolated predicate so the FTS delete, the events
            // delete, and the Layer-3 roll-up can never drift apart. Shape is
            // unchanged (leading `timestamp` term, no expression in ORDER BY),
            // so idx_events_ts_category still drives an ordered top-N scan
            // rather than a full sort of the eligible set.
            let hardFloorPredicate = hardFloorCutoff == nil
                ? ""
                : " AND timestamp < ?4"
            let eligibleWhere = """
                journal_block_id IS NULL
                AND journal_quarantine_marker IS NULL
                AND
                (timestamp < ?2
                   OR (event_category <> ?1
                       AND event_category NOT IN ('network', 'authentication', 'tcc')))
                \(hardFloorPredicate)
                """
            let deleteEligibleFTS = """
                DELETE FROM events_fts WHERE rowid IN (
                    SELECT rowid FROM events
                    WHERE \(eligibleWhere)
                    ORDER BY timestamp ASC LIMIT ?3
                )
                """
            let deleteEligibleEvents = """
                DELETE FROM events WHERE rowid IN (
                    SELECT rowid FROM events
                    WHERE \(eligibleWhere)
                    ORDER BY timestamp ASC LIMIT ?3
                )
                """
            // v1.21.6 (audit DL-05): roll each batch up BEFORE deleting it.
            // Layer 3 does nearly all the pruning on a busy host (field log,
            // one sweep: Layer 2 = 140 rows, Layer 3 = 42,595 rows) and it used
            // to issue DELETEs with no INSERT at all — only rollUpAndPrune
            // aggregated. So the advertised `aggregateDays: 90` day-history
            // silently lost whole days: 500K-1M events/day through mid-July,
            // then 255,154 on 7/22, 11,798 on 7/25, 658 on 7/26, NOTHING on
            // 7/27, 156 on 7/28. Nothing warned — event_aggregates still
            // existed and still answered queries, so the dashboard's long-
            // horizon trend simply drew a flat line that looked like calm.
            //
            // Same upsert as rollUpAndPrune and the SAME `eligibleWhere`
            // predicate + LIMIT as the DELETEs below, so the rows counted are
            // exactly the rows removed.
            let aggregateEligible = """
                INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
                SELECT
                    strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                    event_category,
                    COALESCE(process_signer, ''),
                    COALESCE(process_path, ''),
                    COUNT(*) AS c
                FROM events WHERE rowid IN (
                    SELECT rowid FROM events
                    WHERE \(eligibleWhere)
                    ORDER BY timestamp ASC LIMIT ?3
                )
                GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
                ON CONFLICT(day, event_category, process_signer, process_path)
                DO UPDATE SET count = count + excluded.count
            """
            while remaining > 0 {
                let thisBatch = min(batchSize, Int32(clamping: remaining))
                let estimate = maintenanceEstimate(
                    rowCount: Int(thisBatch),
                    mutationsPerCandidate: 3
                )
                let deleted = try deleteEventBatchAtomically(
                    aggregateSQL: aggregateEligible,
                    ftsSQL: deleteEligibleFTS,
                    eventsSQL: deleteEligibleEvents,
                    estimatedTransactionBytes: estimate
                ) { statement in
                    bindText(
                        statement,
                        index: 1,
                        value: protectedCategory.rawValue
                    )
                    sqlite3_bind_double(statement, 2, floorTs)
                    sqlite3_bind_int(statement, 3, thisBatch)
                    if let hardFloorCutoff {
                        sqlite3_bind_double(
                            statement, 4,
                            hardFloorCutoff.timeIntervalSince1970
                        )
                    }
                }
                if deleted == 0 { break }  // no more eligible rows — engage valve below
                totalDeleted += deleted
                remaining -= deleted
                await Task.yield()
            }
            // Soft-floor valve: fall through to the plain oldest-first loop
            // below with the (possibly reduced) `remaining`, which can now
            // touch protected rows. When the floor was fully honored above,
            // `remaining == 0` and the loop is a no-op.
        }

        // Phase 2 — plain oldest-first. The whole job when no floor is
        // configured; the safety-valve tail otherwise.
        let immutableLegacyWhere = "journal_block_id IS NULL AND journal_quarantine_marker IS NULL"
        let hardFloorWhere = hardFloorCutoff == nil
            ? " WHERE \(immutableLegacyWhere)"
            : " WHERE \(immutableLegacyWhere) AND timestamp < ?2"
        let deleteFTS = """
            DELETE FROM events_fts WHERE rowid IN (
                SELECT rowid FROM events\(hardFloorWhere)
                ORDER BY timestamp ASC LIMIT ?1
            )
            """
        let deleteEvents = """
            DELETE FROM events WHERE rowid IN (
                SELECT rowid FROM events\(hardFloorWhere)
                ORDER BY timestamp ASC LIMIT ?1
            )
            """
        // v1.21.6 (audit DL-05): same roll-up-before-delete as Phase 1. This
        // loop is BOTH the whole job when no floor is configured AND the
        // soft-floor valve tail, so leaving it un-aggregated would keep losing
        // history on exactly the hosts where the valve engages most.
        let aggregateOldest = """
            INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
            SELECT
                strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                event_category,
                COALESCE(process_signer, ''),
                COALESCE(process_path, ''),
                COUNT(*) AS c
            FROM events WHERE rowid IN (
                SELECT rowid FROM events\(hardFloorWhere)
                ORDER BY timestamp ASC LIMIT ?1
            )
            GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
            ON CONFLICT(day, event_category, process_signer, process_path)
            DO UPDATE SET count = count + excluded.count
            """

        while remaining > 0 {
            let thisBatch = min(batchSize, Int32(clamping: remaining))
            let estimate = maintenanceEstimate(
                rowCount: Int(thisBatch),
                mutationsPerCandidate: 3
            )
            let deleted = try deleteEventBatchAtomically(
                aggregateSQL: aggregateOldest,
                ftsSQL: deleteFTS,
                eventsSQL: deleteEvents,
                estimatedTransactionBytes: estimate
            ) { statement in
                sqlite3_bind_int(statement, 1, thisBatch)
                if let hardFloorCutoff {
                    sqlite3_bind_double(
                        statement, 2,
                        hardFloorCutoff.timeIntervalSince1970
                    )
                }
            }
            if deleted == 0 { break }  // table empty
            totalDeleted += deleted
            remaining -= deleted
            await Task.yield()
        }
        return totalDeleted
    }

    // MARK: - Tiered retention (v1.8.0)

    /// One row of the `event_aggregates` rollup table. Replaces the full event
    /// payload for traffic older than the 24h hot tier — keeps just the
    /// information needed for trend charts and "show me events from path X
    /// over the last week" summaries.
    public struct AggregateRow: Sendable, Codable, Equatable {
        public let day: String              // ISO date "2026-04-15"
        public let category: EventCategory
        public let processSigner: String    // empty string if unsigned/unknown
        public let processPath: String      // empty string for non-process events
        public let count: Int
    }

    /// Read aggregated event counts for any window, optionally narrowed to a
    /// category. Used by the Overview trends widget and the SIEM-style time
    /// histogram in v1.8 — both want "how many process exec / file / network
    /// events per day in the last 7d?" without paying the cost of scanning
    /// the hot tier.
    public func aggregates(
        sinceDay: String,
        category: EventCategory? = nil
    ) throws -> [AggregateRow] {
        if try hasJournalSchema() {
            var gapSQL = "SELECT COALESCE(SUM(count), 0) FROM event_aggregate_gaps WHERE day >= ?1"
            if category != nil {
                gapSQL += " AND event_category = ?2"
            }
            let gaps = try prepare(gapSQL)
            bindText(gaps, index: 1, value: sinceDay)
            if let category {
                bindText(gaps, index: 2, value: category.rawValue)
            }
            guard sqlite3_step(gaps) == SQLITE_ROW else {
                sqlite3_finalize(gaps)
                throw EventStoreError.stepFailed(
                    "aggregate gap conservation lookup failed"
                )
            }
            let gapCount = Int(sqlite3_column_int64(gaps, 0))
            sqlite3_finalize(gaps)
            guard gapCount == 0 else {
                throw EventStoreError.aggregateEvidenceGap(
                    records: gapCount
                )
            }
        }
        var sql = "SELECT day, event_category, process_signer, process_path, count FROM event_aggregates WHERE day >= ?1"
        var bindings: [(Int32, BindingValue)] = [(1, .text(sinceDay))]
        var nextIndex: Int32 = 2
        if let category {
            sql += " AND event_category = ?\(nextIndex)"
            bindings.append((nextIndex, .text(category.rawValue)))
            nextIndex += 1
        }
        sql += " ORDER BY day DESC, count DESC"

        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        for (idx, val) in bindings {
            switch val {
            case .text(let s): bindText(stmt, index: idx, value: s)
            case .double(let d): sqlite3_bind_double(stmt, idx, d)
            case .int(let i): sqlite3_bind_int(stmt, idx, i)
            case .null: sqlite3_bind_null(stmt, idx)
            }
        }
        // Inline the column→String reader. EventStore doesn't have a
        // shared helper like AlertStore's `columnTextOrNil`; sqlite3
        // returns nil if the column is NULL.
        func readText(_ s: OpaquePointer, _ idx: Int32) -> String? {
            guard let cstr = sqlite3_column_text(s, idx) else { return nil }
            return String(cString: cstr)
        }
        var rows: [AggregateRow] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let dayStr = readText(stmt, 0),
                  let catStr = readText(stmt, 1),
                  let cat = EventCategory(rawValue: catStr)
            else { continue }
            let signer = readText(stmt, 2) ?? ""
            let path = readText(stmt, 3) ?? ""
            let count = Int(sqlite3_column_int64(stmt, 4))
            rows.append(AggregateRow(
                day: dayStr, category: cat,
                processSigner: signer, processPath: path,
                count: count
            ))
        }
        return rows
    }

    /// Number of aggregate rows. Cheap; used by tests + the Overview widget
    /// to decide whether to render an empty state.
    public func aggregateCount() throws -> Int {
        let stmt = try prepare("SELECT COUNT(*) FROM event_aggregates")
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// v1.8.0: SQL-side histogram bin counts.
    ///
    /// Pre-fix, the dashboard's Events-tab histogram was built from the
    /// 500-row in-memory event cache. On a high-volume machine (264
    /// events/sec measured) those 500 events span ~2 seconds, so every
    /// bin collapsed into one regardless of window size — the chart was
    /// effectively broken since Phase 2c shipped.
    ///
    /// This query bins counts directly on the SQL side: GROUP BY a
    /// truncated-to-bucket-step timestamp expression. Indexed on the
    /// `timestamp` column so even a 24h window over 1.2 GB events.db
    /// scans only the relevant range.
    ///
    /// Returns one (bucketDate, count) per occupied bin, sorted ascending
    /// by time. Caller is expected to backfill 0-count bins for empty
    /// portions of the window.
    public func histogramBins(
        spanSeconds: TimeInterval,
        stepSeconds: Int,
        endingAt: Date = Date(),
        category: EventCategory? = nil
    ) throws -> [(Date, Int)] {
        guard stepSeconds > 0, spanSeconds > 0 else { return [] }
        let snapshot = try histogramSnapshot(
            spanSeconds: spanSeconds,
            stepSeconds: stepSeconds,
            endingAt: endingAt,
            category: category
        )
        guard snapshot.requestedWindowComplete else {
            throw EventStoreError.incompleteRetentionWindow(
                requestedSince: snapshot.requestedSince,
                effectiveSince: snapshot.effectiveSince
            )
        }
        guard snapshot.gaps.total == 0 else {
            throw EventStoreError.exactEvidenceGap(
                poisonRecords: snapshot.gaps.canonicalPoisonRecords,
                corruptLegacyRecords: snapshot.gaps.corruptLegacyRecords,
                inheritedLegacyLossRecords:
                    snapshot.gaps.inheritedLegacyLossRecords,
                resourceLimitedRecords: snapshot.gaps.resourceLimitedRecords
            )
        }
        return snapshot.bins.map { ($0.start, $0.count) }
    }

    public func histogramSnapshot(
        spanSeconds: TimeInterval,
        stepSeconds: Int,
        endingAt: Date = Date(),
        category: EventCategory? = nil
    ) throws -> EventHistogramSnapshot {
        guard stepSeconds > 0, spanSeconds > 0 else {
            throw EventStoreError.decodingFailed(
                "histogram span and step must be positive"
            )
        }
        let lo = endingAt.timeIntervalSince1970 - spanSeconds
        let hi = endingAt.timeIntervalSince1970
        guard lo.isFinite, hi.isFinite, lo <= hi else {
            throw EventStoreError.decodingFailed(
                "exact histogram window is non-finite"
            )
        }
        let step = TimeInterval(stepSeconds)
        func bucket(_ timestamp: TimeInterval) -> Int64 {
            Int64(floor(timestamp / step)) * Int64(stepSeconds)
        }
        return try withVerifiedExactReadSnapshot { generation in
            let truth = try retainedWindowTruth(
                requestedSince: Date(timeIntervalSince1970: lo),
                requestedUntil: endingAt,
                asOf: Date()
            )
            // Preserve every retained source-time bin in the requested range.
            // Coverage is still false when the lower bound predates the
            // admission-retention guarantee, so callers cannot synthesize
            // missing older bins as observed zero.
            let effectiveLo = lo
            let effectiveHi = min(hi, Date().timeIntervalSince1970)
            var bins: [Int64: Int] = [:]
            let maximumOccupiedBins = 10_000
            var resourceLimitedRecords = truth.gaps.resourceLimitedRecords
            func add(_ count: Int, to key: Int64) throws {
                guard count >= 0 else {
                    throw EventStoreError.decodingFailed(
                        "exact histogram count is negative"
                    )
                }
                if bins[key] == nil, bins.count >= maximumOccupiedBins {
                    resourceLimitedRecords = max(1, resourceLimitedRecords)
                    return
                }
                let next = (bins[key] ?? 0).addingReportingOverflow(count)
                guard !next.overflow else {
                    throw EventStoreError.decodingFailed(
                        "exact histogram count overflowed"
                    )
                }
                bins[key] = next.partialValue
            }

            for summary in verifiedJournalSummaries where
                !isJournalBlockTombstoned(summary.blockID) {
                let count: Int
                let minimum: TimeInterval
                let maximum: TimeInterval
                if let category {
                    guard let value = summary.metadata.byCategory[category],
                          value.count > 0,
                          let low = value.minimum,
                          let high = value.maximum else { continue }
                    count = value.count
                    minimum = low
                    maximum = high
                } else {
                    count = summary.eventCount
                    minimum = summary.metadata.minimum
                    maximum = summary.metadata.maximum
                }
                guard maximum >= effectiveLo,
                      minimum <= effectiveHi else { continue }
                if minimum >= effectiveLo, maximum <= effectiveHi,
                   bucket(minimum) == bucket(maximum) {
                    try add(count, to: bucket(minimum))
                    continue
                }
                // Only a cross-bin or window-boundary block is decoded.
                for event in try loadJournalBlock(blockID: summary.blockID) {
                    let timestamp = event.timestamp.timeIntervalSince1970
                    guard timestamp >= effectiveLo, timestamp <= effectiveHi,
                          category == nil
                            || event.eventCategory == category else { continue }
                    try add(1, to: bucket(timestamp))
                }
            }
            if truth.gaps.corruptLegacyRecords == 0,
               truth.gaps.inheritedLegacyLossRecords == 0 {
                try forEachExactLegacyEvent { event in
                    let timestamp = event.timestamp.timeIntervalSince1970
                    guard timestamp >= effectiveLo,
                          timestamp <= effectiveHi,
                          category == nil
                            || event.eventCategory == category else {
                        return
                    }
                    try add(1, to: bucket(timestamp))
                }
            }
            return EventHistogramSnapshot(
                bins: bins.keys.sorted().map {
                    EventHistogramBin(
                        start: Date(timeIntervalSince1970: TimeInterval($0)),
                        count: bins[$0] ?? 0
                    )
                },
                mutationGeneration: generation,
                requestedSince: Date(timeIntervalSince1970: lo),
                requestedUntil: endingAt,
                effectiveSince: Date(timeIntervalSince1970: effectiveLo),
                effectiveUntil: Date(timeIntervalSince1970: effectiveHi),
                retainedOldest: truth.retainedOldest,
                retainedNewest: truth.retainedNewest,
                retainedAdmissionOldest: truth.retainedAdmissionOldest,
                retainedAdmissionNewest: truth.retainedAdmissionNewest,
                requestedWindowComplete: truth.requestedWindowComplete,
                gaps: EventQueryGapCounts(
                    canonicalPoisonRecords:
                        truth.gaps.canonicalPoisonRecords,
                    corruptLegacyRecords:
                        truth.gaps.corruptLegacyRecords,
                    inheritedLegacyLossRecords:
                        truth.gaps.inheritedLegacyLossRecords,
                    resourceLimitedRecords: resourceLimitedRecords
                )
            )
        }
    }

    /// Select a bounded, deterministic set of already-persisted events leading
    /// up to an alert. This is a read-only source operation: new evidence is
    /// owned and written by AlertStore in alerts.db.
    ///
    /// The inner ordering chooses the strongest/closest candidates; the outer
    /// ordering returns the selected set chronologically for incident review.
    /// Both caller-controlled bounds are clamped to the fixed policy ceiling.
    /// Full Events are compacted immediately while scanning; retained ranking
    /// ownership is therefore bounded to the shared <=64-KiB representation.
    public func alertEvidenceCandidates(
        alertTimestamp: Date,
        windowSeconds: TimeInterval = AlertEvidencePolicy.lookbackSeconds,
        maxRows: Int = AlertEvidencePolicy.maximumEventsPerAlert
    ) throws -> [AlertEvidenceCandidate] {
        let snapshot = try exactAlertEvidenceSnapshot(
            alertTimestamp: alertTimestamp,
            windowSeconds: windowSeconds,
            maxRows: maxRows
        )
        guard snapshot.isComplete else {
            throw EventStoreError.exactEvidenceGap(
                poisonRecords: snapshot.poisonRecords.count,
                corruptLegacyRecords: snapshot.corruptLegacyRecords,
                inheritedLegacyLossRecords:
                    snapshot.inheritedLegacyLossRecords,
                resourceLimitedRecords: snapshot.resourceLimitedRecords
            )
        }
        return snapshot.candidates
    }

    /// Exact capture-time context from the canonical journal plus the validated
    /// unmigrated legacy tail. Ranking is performed on the terminal/promotion-
    /// applied Event; the selected payload is then independently compacted by
    /// the shared alert-owned representation instead of being dropped at 64KiB.
    public func exactAlertEvidenceSnapshot(
        alertTimestamp: Date,
        windowSeconds: TimeInterval = AlertEvidencePolicy.lookbackSeconds,
        maxRows: Int = AlertEvidencePolicy.maximumEventsPerAlert
    ) throws -> ExactAlertEvidenceSnapshot {
        let requestedRows = min(
            AlertEvidencePolicy.maximumEventsPerAlert,
            max(0, maxRows)
        )
        guard requestedRows > 0 else {
            return ExactAlertEvidenceSnapshot(
                candidates: [],
                mutationGeneration: try currentStorageMutationGeneration(),
                poisonRecords: [],
                corruptLegacyRecords: 0,
                inheritedLegacyLossRecords: 0,
                resourceLimitedRecords: 0
            )
        }
        let boundedWindow = min(
            AlertEvidencePolicy.lookbackSeconds,
            max(0, windowSeconds)
        )
        let alertTs = alertTimestamp.timeIntervalSince1970
        let lowerTs = alertTs - boundedWindow
        guard alertTs.isFinite, lowerTs.isFinite else {
            throw EventStoreError.decodingFailed(
                "alert evidence window is non-finite"
            )
        }
        struct RankedCandidate {
            let timestamp: Date
            let id: String
            let severityRank: Int
            let evidence: AlertEvidenceCandidate?
            let poison: [EventJournalPoisonRecord]
            let corruptLegacy: Bool
            let inheritedLegacyLoss: Bool
            let resourceLimited: Bool
        }
        func rank(_ severity: Severity) -> Int {
            switch severity {
            case .critical: return 0
            case .high: return 1
            case .medium: return 2
            case .low: return 3
            default: return 4
            }
        }
        func precedes(_ lhs: RankedCandidate, _ rhs: RankedCandidate) -> Bool {
            if lhs.severityRank != rhs.severityRank {
                return lhs.severityRank < rhs.severityRank
            }
            let lhsDistance = abs(lhs.timestamp.timeIntervalSince1970 - alertTs)
            let rhsDistance = abs(rhs.timestamp.timeIntervalSince1970 - alertTs)
            if lhsDistance != rhsDistance { return lhsDistance < rhsDistance }
            if lhs.timestamp != rhs.timestamp {
                return lhs.timestamp > rhs.timestamp
            }
            return lhs.id < rhs.id
        }
        return try withVerifiedExactReadSnapshot { generation in
            var ranked: [RankedCandidate] = []
            ranked.reserveCapacity(requestedRows * 2)
            var unscopedCorruptLegacyRecords = 0
            func trim() {
                guard ranked.count > requestedRows * 2 else { return }
                ranked.sort(by: precedes)
                ranked.removeLast(ranked.count - requestedRows)
            }

            let journalSchemaPresent = try hasJournalSchema()
            if journalSchemaPresent {
                for summary in verifiedJournalSummaries where
                    !isJournalBlockTombstoned(summary.blockID)
                        && summary.metadata.maximum >= lowerTs
                        && summary.metadata.minimum <= alertTs {
                    let block = try loadExactJournalBlock(
                        blockID: summary.blockID
                    )
                    for (ordinal, event) in block.events.enumerated() {
                        let timestamp = event.timestamp.timeIntervalSince1970
                        guard timestamp >= lowerTs, timestamp <= alertTs else {
                            continue
                        }
                        let isPoisoned = block.poisonByOrdinal[ordinal] != nil
                        let terminalSeverityUnknown =
                            block.poisonByOrdinal[ordinal]?.contains {
                                $0.kind == .terminal
                            } == true
                        let compactEvidence = isPoisoned
                            ? nil
                            : EventSnapshot.prepare(event).evidenceCandidate
                        ranked.append(RankedCandidate(
                            timestamp: event.timestamp,
                            id: event.id.uuidString,
                            severityRank: terminalSeverityUnknown
                                ? rank(.critical) : rank(event.severity),
                            evidence: compactEvidence,
                            poison: block.poisonByOrdinal[ordinal] ?? [],
                            corruptLegacy: false,
                            inheritedLegacyLoss:
                                block.inheritedLossOrdinals.contains(ordinal),
                            resourceLimited: !isPoisoned
                                && compactEvidence == nil
                        ))
                    }
                    trim()
                }
            }

            let legacyColumns = Self.legacyTypedEventColumns.map {
                "e.\"\($0)\""
            }.joined(separator: ", ")
            let legacySQL = journalSchemaPresent ? """
                SELECT e.rowid, \(legacyColumns),
                       CASE WHEN q.quarantine_id IS NULL THEN 0 ELSE 1 END
                FROM events e
                LEFT JOIN event_journal_legacy_quarantine q
                  ON q.source_marker = e.journal_quarantine_marker
                WHERE e.journal_block_id IS NULL
                """ : """
                SELECT e.rowid, \(legacyColumns), 0
                FROM events e
                """
            let legacy = try prepare(legacySQL)
            defer { sqlite3_finalize(legacy) }
            var cachedDuplicateBlockID: Int64?
            var cachedDuplicateBlock = OwnedJournalBlock(records: [])
            while true {
                let rc = sqlite3_step(legacy)
                if rc == SQLITE_DONE { break }
                guard rc == SQLITE_ROW else {
                    throw EventStoreError.stepFailed(
                        "exact alert legacy scan failed"
                    )
                }
                let row = try readLegacyJournalRow(legacy)
                let raw = try? decoder.decode(Event.self, from: row.rawJSON)
                let rawTimestamp = raw?.timestamp.timeIntervalSince1970
                let rawScopeTrusted = rawTimestamp?.isFinite == true
                let rawIntersects = rawTimestamp?.isFinite == true
                    && (rawTimestamp ?? 0) >= lowerTs
                    && (rawTimestamp ?? 0) <= alertTs
                let typedScopeTrusted: Bool
                if case .real = row.typedValues[1] {
                    typedScopeTrusted = row.timestamp.isFinite
                } else {
                    typedScopeTrusted = false
                }
                let typedIntersects = typedScopeTrusted
                    && row.timestamp >= lowerTs && row.timestamp <= alertTs
                if sqlite3_column_int(
                    legacy,
                    Int32(Self.legacyTypedEventColumns.count + 1)
                ) != 0 {
                    if typedIntersects || rawIntersects {
                        ranked.append(RankedCandidate(
                            timestamp: rawIntersects
                                ? (raw?.timestamp ?? Date(
                                    timeIntervalSince1970: row.timestamp
                                  ))
                                : Date(timeIntervalSince1970: row.timestamp),
                            id: String(data: row.idBytes, encoding: .utf8)
                                ?? row.idBytes.base64EncodedString(),
                            severityRank: 0,
                            evidence: nil,
                            poison: [],
                            corruptLegacy: true,
                            inheritedLegacyLoss: false,
                            resourceLimited: false
                        ))
                        trim()
                    } else if !typedScopeTrusted && !rawScopeTrusted {
                        unscopedCorruptLegacyRecords += 1
                    }
                    continue
                }
                let decoded: DecodedLegacyJournalRow
                do {
                    decoded = try decodeLegacyJournalRowWithLoss(row)
                } catch {
                    if typedIntersects || rawIntersects {
                        ranked.append(RankedCandidate(
                            timestamp: rawIntersects
                                ? (raw?.timestamp ?? Date(
                                    timeIntervalSince1970: row.timestamp
                                  ))
                                : Date(timeIntervalSince1970: row.timestamp),
                            id: String(data: row.idBytes, encoding: .utf8)
                                ?? row.idBytes.base64EncodedString(),
                            severityRank: 0,
                            evidence: nil,
                            poison: [],
                            corruptLegacy: true,
                            inheritedLegacyLoss: false,
                            resourceLimited: false
                        ))
                        trim()
                    } else if !typedScopeTrusted && !rawScopeTrusted {
                        unscopedCorruptLegacyRecords += 1
                    }
                    continue
                }
                let event = decoded.event
                let timestamp = event.timestamp.timeIntervalSince1970
                guard timestamp >= lowerTs, timestamp <= alertTs else { continue }
                if let location = try existingJournalLocations(
                    for: Set([event.id])
                )[event.id] {
                    if cachedDuplicateBlockID != location.blockID {
                        cachedDuplicateBlock = try loadJournalBlock(
                            blockID: location.blockID
                        )
                        cachedDuplicateBlockID = location.blockID
                    }
                    try validateDuplicate(
                        try preparePersistedEvent(event),
                        at: location,
                        in: cachedDuplicateBlock
                    )
                    continue
                }
                let compactEvidence = EventSnapshot.prepare(event)
                    .evidenceCandidate
                ranked.append(RankedCandidate(
                    timestamp: event.timestamp,
                    id: event.id.uuidString,
                    severityRank: rank(event.severity),
                    evidence: compactEvidence,
                    poison: [],
                    corruptLegacy: false,
                    inheritedLegacyLoss: decoded.inheritedLoss != nil,
                    resourceLimited: compactEvidence == nil
                ))
                trim()
            }
            ranked.sort(by: precedes)
            if ranked.count > requestedRows {
                ranked.removeLast(ranked.count - requestedRows)
            }
            var selected = ranked.compactMap(\.evidence)
            selected.sort {
                if $0.timestamp != $1.timestamp {
                    return $0.timestamp < $1.timestamp
                }
                return $0.eventId < $1.eventId
            }
            return ExactAlertEvidenceSnapshot(
                candidates: selected,
                mutationGeneration: generation,
                poisonRecords: ranked.flatMap(\.poison),
                corruptLegacyRecords: ranked.reduce(
                    unscopedCorruptLegacyRecords
                ) { $0 + ($1.corruptLegacy ? 1 : 0) },
                inheritedLegacyLossRecords: ranked.reduce(into: 0) {
                    if $1.inheritedLegacyLoss { $0 += 1 }
                },
                resourceLimitedRecords: ranked.reduce(into: 0) {
                    if $1.resourceLimited { $0 += 1 }
                }
            )
        }
    }

    /// LEGACY COMPATIBILITY WRITE ONLY. New production alert capture must use
    /// `alertEvidenceCandidates` followed by `AlertStore.captureEvidence`.
    /// Existing events.db evidence remains readable and receives retention /
    /// explicit-delete cleanup, but no shipping call site may grow this table.
    ///
    /// Capture a snapshot of the `windowSeconds` of events immediately
    /// PRECEDING the alert into legacy `events.db.alert_evidence`. Idempotent —
    /// re-running for the same `alertId` is safe (PRIMARY KEY on
    /// (alert_id, id) silently dedupes).
    ///
    /// Called synchronously from the alert-firing path so the dashboard's alert
    /// detail view can show "what led up to this?" even after the hot-tier
    /// retention drops the surrounding events.
    ///
    /// BACKWARD-looking by construction (audit corr-storage): because capture
    /// runs at fire time, only events already persisted at/before the alert
    /// timestamp exist, so the window is `[alertTimestamp - windowSeconds,
    /// alertTimestamp]`. There is no forward half to populate — the prior
    /// "±windowSeconds" framing described a range that is always empty at
    /// capture time. (A caller wanting post-alert context would have to
    /// schedule a deferred second capture; none does today.)
    ///
    /// v1.8.0-rc6: capped at `maxRows` (default 50) to keep the evidence table
    /// bounded on high-volume hosts. Pre-cap, a 264 events/sec machine could
    /// drop ~30K rows per alert into evidence, and 1.6K alerts pushed the
    /// table past 800K rows / 2.4 GB on the field test host. Selection prefers
    /// higher-severity rows so the cap doesn't drop the most informative
    /// context — same-severity rows tie-break by closeness to the alert
    /// timestamp.
    @available(*, deprecated, message: "Legacy test/compatibility write; new capture belongs to AlertStore")
    func recordAlertEvidence(
        alertId: String,
        alertTimestamp: Date,
        windowSeconds: TimeInterval = 30,
        maxRows: Int = 50
    ) throws {
        let requestedRows = max(1, maxRows)
        let alertTs = alertTimestamp.timeIntervalSince1970
        let lo = alertTs - windowSeconds
        // Backward-only: the upper bound is the alert timestamp itself. A
        // forward bound (alertTs + windowSeconds) never matched anything —
        // those events do not exist yet when this runs at fire time — so it is
        // dropped to make the contract honest and the SQL intent explicit.
        let hi = alertTs
        let sql = """
            INSERT OR IGNORE INTO alert_evidence (
                alert_id, id, timestamp,
                event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json,
                mcp_server_name, mcp_server_category, ai_tool_session_id
            )
            SELECT
                ?1, id, timestamp,
                event_category, event_type, event_action, severity,
                process_pid, process_name, process_path, process_commandline,
                process_ppid, process_signer, process_team_id, process_signing_id,
                file_path, file_action, network_dest_ip, network_dest_port,
                tcc_service, tcc_client, raw_json,
                mcp_server_name, mcp_server_category, ai_tool_session_id
            FROM events
            WHERE timestamp BETWEEN ?2 AND ?3
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                ABS(timestamp - ?4) ASC
            LIMIT ?5 OFFSET ?6
            """
        var offset = 0
        while offset < requestedRows {
            let plan = try alertEvidenceBatchPlan(
                alertId: alertId,
                lowerTimestamp: lo,
                upperTimestamp: hi,
                alertTimestamp: alertTs,
                offset: offset,
                maximumRows: requestedRows - offset
            )
            guard plan.rowCount > 0 else { break }
            var committedPlan = plan
            try withSerializedWrite(
                estimatedBytes: plan.estimatedTransactionBytes,
                lane: .priority
            ) {
                // Projection rows can change while this connection waits for a
                // cross-process writer. Re-plan the exact prefix under lock and
                // admit its authoritative size before the first INSERT.
                committedPlan = try alertEvidenceBatchPlan(
                    alertId: alertId,
                    lowerTimestamp: lo,
                    upperTimestamp: hi,
                    alertTimestamp: alertTs,
                    offset: offset,
                    maximumRows: requestedRows - offset
                )
                try requireCurrentFamilyCapacityUnderWriterLock(
                    estimatedBytes:
                        committedPlan.estimatedTransactionBytes,
                    lane: .priority
                )
                guard committedPlan.rowCount > 0 else { return }
                let stmt = try prepare(sql)
                bindText(stmt, index: 1, value: alertId)
                sqlite3_bind_double(stmt, 2, lo)
                sqlite3_bind_double(stmt, 3, hi)
                sqlite3_bind_double(stmt, 4, alertTs)
                sqlite3_bind_int(
                    stmt, 5, Int32(clamping: committedPlan.rowCount)
                )
                sqlite3_bind_int(stmt, 6, Int32(clamping: offset))
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: rc)
                    let msg = db.flatMap {
                        String(cString: sqlite3_errmsg($0))
                    } ?? "unknown"
                    throw EventStoreError.stepFailed(
                        "recordAlertEvidence failed: \(msg)"
                    )
                }
            }
            guard committedPlan.rowCount > 0 else { break }
            maintenanceRowMutationHighWaterBytes = max(
                maintenanceRowMutationHighWaterBytes ?? 0,
                committedPlan.maximumRowMutationBytes
            )
            offset += committedPlan.rowCount
        }
    }

    /// Read the exact source rows selected by the following INSERT...SELECT and
    /// choose the largest prefix that fits the reserve. This closes the old
    /// 64-KiB non-raw assumption: legacy/adversarial projected columns are
    /// charged at their actual stored byte lengths before any evidence write.
    private func alertEvidenceBatchPlan(
        alertId: String,
        lowerTimestamp: Double,
        upperTimestamp: Double,
        alertTimestamp: Double,
        offset: Int,
        maximumRows: Int
    ) throws -> (
        rowCount: Int,
        estimatedTransactionBytes: Int64,
        maximumRowMutationBytes: Int64
    ) {
        let sql = """
            SELECT id, timestamp, event_category, event_type, event_action,
                   severity, process_pid, process_name, process_path,
                   process_commandline, process_ppid, process_signer,
                   process_team_id, process_signing_id, file_path, file_action,
                   network_dest_ip, network_dest_port, tcc_service, tcc_client,
                   raw_json, mcp_server_name, mcp_server_category,
                   ai_tool_session_id
            FROM events
            WHERE timestamp BETWEEN ?1 AND ?2
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4
                END,
                ABS(timestamp - ?3) ASC
            LIMIT ?4 OFFSET ?5
            """
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        sqlite3_bind_double(statement, 1, lowerTimestamp)
        sqlite3_bind_double(statement, 2, upperTimestamp)
        sqlite3_bind_double(statement, 3, alertTimestamp)
        sqlite3_bind_int(statement, 4, Int32(clamping: max(0, maximumRows)))
        sqlite3_bind_int(statement, 5, Int32(clamping: max(0, offset)))

        let fixed = SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 16
        )
        var rowBytes: Int64 = 0
        var maximumRowMutationBytes: Int64 = 0
        var count = 0
        var step = sqlite3_step(statement)
        while step == SQLITE_ROW {
            func bytes(_ column: Int32) -> Int64 {
                sqlite3_column_type(statement, column) == SQLITE_NULL
                    ? 0 : Int64(sqlite3_column_bytes(statement, column))
            }
            var logical = Int64(25 * 16 + 3 * 16)
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    Int64(clamping: alertId.utf8.count), by: 3
                )
            )
            for column in Int32(0)..<Int32(24) {
                logical = SQLitePersistentStoreAdmission.saturatingAdd(
                    logical, bytes(column)
                )
            }
            // id is copied into the composite PK and event-id index.
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical,
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    bytes(0), by: 2
                )
            )
            let candidate = SQLitePersistentStoreAdmission
                .conservativeEncodedRowMutationBytes(
                    logicalRepresentationBytes: logical,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumLeafPageTouches: 4
                )
            let nextRows = SQLitePersistentStoreAdmission.saturatingAdd(
                rowBytes, candidate
            )
            let nextTransaction = SQLitePersistentStoreAdmission.saturatingAdd(
                fixed, nextRows
            )
            if nextTransaction > storageTransactionReserveBytes {
                if count == 0 {
                    throw SQLitePersistentStoreAdmissionError
                        .transactionEstimateExceedsReserve(
                            estimatedBytes: nextTransaction,
                            reserveBytes: storageTransactionReserveBytes
                        )
                }
                break
            }
            rowBytes = nextRows
            maximumRowMutationBytes = max(maximumRowMutationBytes, candidate)
            count += 1
            step = sqlite3_step(statement)
        }
        if step != SQLITE_DONE && step != SQLITE_ROW {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw EventStoreError.stepFailed("alert evidence estimate step failed")
        }
        return (
            count,
            SQLitePersistentStoreAdmission.saturatingAdd(fixed, rowBytes),
            maximumRowMutationBytes
        )
    }

    /// v1.8.0-rc6: trim alert_evidence to at most `perAlertMax` rows per
    /// alert. Selection prefers higher-severity + closer-to-alert rows.
    /// Used by the rollup sweep to bound an existing oversize evidence
    /// table — recordAlertEvidence above caps writes going forward, but
    /// existing rows from earlier releases need cleanup.
    @discardableResult
    public func pruneAlertEvidenceCap(perAlertMax: Int) async throws -> Int {
        guard perAlertMax > 0 else { return 0 }
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        // Window function (SQLite 3.25+) ranks rows within each alert; we
        // delete those that fall outside the cap. macOS 13 ships SQLite
        // 3.39+, so this is safe.
        let sql = """
            DELETE FROM alert_evidence
            WHERE rowid IN (
                SELECT rowid FROM (
                    SELECT rowid,
                           ROW_NUMBER() OVER (
                               PARTITION BY alert_id
                               ORDER BY
                                   CASE severity
                                       WHEN 'critical' THEN 0
                                       WHEN 'high' THEN 1
                                       WHEN 'medium' THEN 2
                                       WHEN 'low' THEN 3
                                       ELSE 4
                                   END,
                                   timestamp ASC
                           ) AS rn
                    FROM alert_evidence
                )
                WHERE rn > ?1
                LIMIT ?2
            )
            """
        var total = 0
        while true {
            let deleted: Int = try withSerializedWrite(
                estimatedBytes: estimate,
                maintenance: true
            ) {
                let stmt = try prepare(sql)
                sqlite3_bind_int(stmt, 1, Int32(clamping: perAlertMax))
                sqlite3_bind_int(stmt, 2, batch)
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: rc)
                    let msg = db.flatMap {
                        String(cString: sqlite3_errmsg($0))
                    } ?? "unknown"
                    throw EventStoreError.stepFailed(
                        "pruneAlertEvidenceCap failed: \(msg)"
                    )
                }
                return Int(sqlite3_changes(db))
            }
            total += deleted
            if deleted == 0 { break }
            await Task.yield()
        }
        return total
    }

    /// v1.8.0-rc6: drop alert_evidence rows older than `cutoff`. Aligns
    /// evidence retention with the parent alerts.db retention, so an
    /// orphaned evidence row whose alert was already pruned doesn't
    /// outlive the alert.
    @discardableResult
    public func pruneAlertEvidence(olderThan cutoff: Date) async throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            DELETE FROM alert_evidence WHERE rowid IN (
                SELECT rowid FROM alert_evidence
                WHERE timestamp < ?1 ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            let deleted: Int = try withSerializedWrite(
                estimatedBytes: estimate,
                maintenance: true
            ) {
                let stmt = try prepare(sql)
                sqlite3_bind_double(
                    stmt, 1, cutoff.timeIntervalSince1970
                )
                sqlite3_bind_int(stmt, 2, batch)
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: rc)
                    let msg = db.flatMap {
                        String(cString: sqlite3_errmsg($0))
                    } ?? "unknown"
                    throw EventStoreError.stepFailed(
                        "pruneAlertEvidence failed: \(msg)"
                    )
                }
                return Int(sqlite3_changes(db))
            }
            total += deleted
            if deleted == 0 { break }
            await Task.yield()
        }
        return total
    }

    /// v1.17.5 (RC H2): bound the alert_evidence table by TOTAL payload size.
    /// Age + per-alert-cap pruning leave total size ungoverned, so on a busy
    /// host the table outgrew the events cap (field-observed 194 MB inside the
    /// 365-day window). Evicts the OLDEST rows across all alerts until the
    /// raw_json payload total is <= maxBytes. Returns rows deleted.
    @discardableResult
    public func pruneAlertEvidenceBySize(maxBytes: Int64, batchSize: Int = 2000) async throws -> Int {
        guard maxBytes > 0 else { return 0 }
        let batch = min(
            max(1, batchSize),
            Int(maintenanceBatchRowLimit())
        )
        let estimate = maintenanceEstimate(rowCount: batch)
        // `maxBytes` is a PHYSICAL footprint budget. The raw_json text is only
        // part of each row's on-disk cost (25 columns + 3 indexes), so the prior
        // SUM(LENGTH(raw_json)) cap let the physical table grow ~1.7x past the
        // budget — which kept events.db permanently over its size cap and
        // re-triggered the hourly full VACUUM on every maintenance tick (v1.18
        // audit). Bound the physical footprint instead. DELETE doesn't reclaim
        // pages until VACUUM (so dbstat can't drive the delete loop), so we derive
        // the physical/logical multiplier from dbstat once, scale the raw_json
        // budget by it, and loop on raw_json (which shrinks per delete). The
        // post-sweep VACUUM in the maintenance path reclaims the freed pages.
        func rawJsonBytes() throws -> Int64 {
            let stmt = try prepare("SELECT COALESCE(SUM(LENGTH(raw_json)), 0) FROM alert_evidence")
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
            return sqlite3_column_int64(stmt, 0)
        }
        // Physical page bytes of the table + its indexes via DBSTAT_VTAB. nil if
        // dbstat isn't compiled into this SQLite build (→ conservative fallback).
        func physicalBytes() -> Int64? {
            let sql = """
                SELECT COALESCE(SUM(pgsize), 0) FROM dbstat
                WHERE name = 'alert_evidence'
                   OR name IN (SELECT name FROM sqlite_master
                               WHERE type = 'index' AND tbl_name = 'alert_evidence')
                """
            guard let stmt = try? prepare(sql) else { return nil }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
            let bytes = sqlite3_column_int64(stmt, 0)
            return bytes > 0 ? bytes : nil
        }
        let logical = try rawJsonBytes()
        guard logical > 0 else { return 0 }
        // Scale the raw_json budget by the physical/logical ratio — but only when
        // the table is large enough that b-tree + index overhead is real signal,
        // not sub-page rounding on a tiny table (which would over-prune). dbstat
        // absent → a conservative fixed estimate so production still bounds size.
        let multiplier: Double
        switch physicalBytes() {
        case .some(let phys) where phys > 1_048_576:
            multiplier = max(1.0, Double(phys) / Double(logical))   // large table: measured ratio
        case .some:
            multiplier = 1.0                                        // small table: raw_json ≈ footprint
        case .none:
            multiplier = 1.8                                        // dbstat unavailable: conservative
        }
        let rawJsonBudget = Int64(Double(maxBytes) / multiplier)
        var total = logical
        guard total > rawJsonBudget else { return 0 }
        var deleted = 0
        // Delete oldest rows in batches until under the (scaled) budget. Bounded
        // to 4096 iterations so a pathological table can't wedge the sweep.
        for _ in 0..<4096 {
            if total <= rawJsonBudget { break }
            let n: Int = try withSerializedWrite(
                estimatedBytes: estimate,
                maintenance: true
            ) {
                let stmt = try prepare(
                    "DELETE FROM alert_evidence WHERE rowid IN (SELECT rowid FROM alert_evidence ORDER BY timestamp ASC LIMIT \(batch))"
                )
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: rc)
                    let msg = db.flatMap {
                        String(cString: sqlite3_errmsg($0))
                    } ?? "unknown"
                    throw EventStoreError.stepFailed(
                        "pruneAlertEvidenceBySize failed: \(msg)"
                    )
                }
                return Int(sqlite3_changes(db))
            }
            deleted += n
            if n == 0 { break }
            total = try rawJsonBytes()
        }
        return deleted
    }

    /// Exact ownership of the preserved pre-schema-v8 evidence tier.
    ///
    /// New evidence is never written here, but an upgrade may retain up to a
    /// year of existing rows. Daemon storage admission uses this cold-path
    /// measurement to grant only the transition reserve those rows need. The
    /// DBSTAT query deliberately throws when page ownership cannot be proven;
    /// callers then retain the full configured reserve rather than stranding a
    /// live events database below an unknowable floor.
    public func legacyAlertEvidenceBudgetSnapshot(
        maxBytes: Int64
    ) throws -> AlertEvidenceBudgetSnapshot {
        let exists = try prepare(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alert_evidence' LIMIT 1"
        )
        defer { sqlite3_finalize(exists) }
        let existenceStep = sqlite3_step(exists)
        if existenceStep == SQLITE_DONE {
            return AlertEvidenceBudgetSnapshot(
                rowCount: 0,
                logicalBytes: 0,
                allocatedBytes: 0,
                chargedBytes: 0,
                maxBytes: max(0, maxBytes)
            )
        }
        guard existenceStep == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "legacy alert evidence schema lookup failed"
            )
        }

        let logical = try prepare(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(CAST(raw_json AS BLOB))), 0) FROM alert_evidence"
        )
        defer { sqlite3_finalize(logical) }
        guard sqlite3_step(logical) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "legacy alert evidence logical-size query failed"
            )
        }
        let rowCount = Int(sqlite3_column_int64(logical, 0))
        let logicalBytes = max(0, sqlite3_column_int64(logical, 1))
        guard rowCount > 0 else {
            return AlertEvidenceBudgetSnapshot(
                rowCount: 0,
                logicalBytes: 0,
                allocatedBytes: 0,
                chargedBytes: 0,
                maxBytes: max(0, maxBytes)
            )
        }

        let allocated = try prepare(
            """
            SELECT COALESCE(SUM(pgsize), 0) FROM dbstat
            WHERE name = 'alert_evidence'
               OR name IN (
                   SELECT name FROM sqlite_master
                   WHERE type = 'index' AND tbl_name = 'alert_evidence'
               )
            """
        )
        defer { sqlite3_finalize(allocated) }
        guard sqlite3_step(allocated) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "legacy alert evidence DBSTAT ownership query failed"
            )
        }
        let allocatedBytes = max(0, sqlite3_column_int64(allocated, 0))
        return AlertEvidenceBudgetSnapshot(
            rowCount: rowCount,
            logicalBytes: logicalBytes,
            allocatedBytes: allocatedBytes,
            chargedBytes: max(logicalBytes, allocatedBytes),
            maxBytes: max(0, maxBytes)
        )
    }

    /// Authoritative cold-path proof for a legacy-evidence reserve change.
    ///
    /// The evidence table's DBSTAT ownership determines the *candidate*
    /// reserve, but never proves that events.db can actually adopt the lower
    /// hard ceiling. Before publishing a shrink, callers also need a fresh
    /// family footprint after a fully drained checkpoint. A pinned reader is
    /// reported through `walCheckpointDrained == false`; freelist pages remain
    /// charged in both `pageCount` and the physical family measurement until
    /// maintenance has really reclaimed them.
    public func legacyAlertEvidenceTransitionMeasurement(
        maxBytes: Int64
    ) throws -> LegacyAlertEvidenceTransitionMeasurement {
        guard db != nil else {
            throw EventStoreError.stepFailed(
                "legacy alert-evidence transition probe requires an open database"
            )
        }

        // Checkpoint first, then stat the complete family. The checkpoint is
        // deliberately non-destructive: failure/pinning leaves the previous
        // reserve applied and exposes a pending candidate to the operator.
        let checkpointDrained = walCheckpoint()
        let evidence = try legacyAlertEvidenceBudgetSnapshot(maxBytes: maxBytes)
        let family = try SQLitePersistentStoreAdmission.measureFamily(
            databasePath
        )
        let pageSize = try strictPragmaInt64("PRAGMA page_size")
        let pageCount = try strictPragmaInt64("PRAGMA page_count")
        let freelistCount = try strictPragmaInt64("PRAGMA freelist_count")
        guard pageSize > 0, pageCount >= 0, freelistCount >= 0,
              freelistCount <= pageCount else {
            throw EventStoreError.stepFailed(
                "legacy alert-evidence transition page accounting is invalid"
            )
        }
        return LegacyAlertEvidenceTransitionMeasurement(
            evidence: evidence,
            familyFootprintBytes: family,
            walCheckpointDrained: checkpointDrained,
            pageSizeBytes: pageSize,
            pageCount: pageCount,
            freelistCount: freelistCount
        )
    }

    private func strictPragmaInt64(_ sql: String) throws -> Int64 {
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw EventStoreError.stepFailed(
                "SQLite transition accounting pragma failed"
            )
        }
        return sqlite3_column_int64(statement, 0)
    }

    /// Read events captured for `alertId` by `recordAlertEvidence`. Returns
    /// the ~windowSeconds of preceding activity that the alert detail view
    /// renders. Empty if the alert pre-dates v1.8 evidence capture.
    public func evidenceFor(alertId: String) throws -> [Event] {
        let sql = "SELECT raw_json FROM alert_evidence WHERE alert_id = ?1 ORDER BY timestamp ASC"
        return try queryEvents(sql: sql, bindings: [(1, .text(alertId))])
    }

    /// Delete all `alert_evidence` rows copied for `alertId`. Returns the row
    /// count removed.
    ///
    /// Companion to `AlertStore.delete(alertId:)` (audit corr-storage):
    /// `recordAlertEvidence` copies the surrounding events into events.db's
    /// `alert_evidence`, but deleting the alert row only touches alerts.db —
    /// the evidence copy (which can hold the very PII the operator is trying to
    /// wipe) survives until the retention sweep. The caller that owns BOTH
    /// stores (the delete-alert path) must invoke this alongside
    /// `AlertStore.delete` so the wipe is complete. Idempotent — a no-match is
    /// a successful 0.
    @discardableResult
    public func deleteEvidence(alertId: String) throws -> Int {
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        let sql = """
            DELETE FROM alert_evidence WHERE rowid IN (
                SELECT rowid FROM alert_evidence
                WHERE alert_id = ?1 ORDER BY rowid LIMIT ?2
            )
            """
        var total = 0
        while true {
            let deleted: Int = try withSerializedWrite(
                estimatedBytes: estimate,
                maintenance: true
            ) {
                let stmt = try prepare(sql)
                bindText(stmt, index: 1, value: alertId)
                sqlite3_bind_int(stmt, 2, batch)
                let rc = sqlite3_step(stmt)
                sqlite3_finalize(stmt)
                guard rc == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: rc)
                    let msg = db.flatMap {
                        String(cString: sqlite3_errmsg($0))
                    } ?? "unknown"
                    throw EventStoreError.stepFailed(
                        "deleteEvidence failed: \(msg)"
                    )
                }
                return Int(sqlite3_changes(db))
            }
            total += deleted
            if deleted == 0 { break }
        }
        return total
    }

    /// The 24h roll-up sweep that replaces the legacy size-cap-and-VACUUM
    /// dance. Runs from the daemon's 6h timer.
    ///
    /// Three steps in a single SQL transaction so a crash mid-sweep can
    /// either retry cleanly or finish on next tick:
    ///
    ///   1. Update `event_aggregates` with daily counts grouped by
    ///      (day, category, signer, path) for events older than `cutoff`.
    ///      `INSERT … ON CONFLICT DO UPDATE` makes re-runs idempotent.
    ///   2. (alert evidence is captured eagerly at alert-firing time, not
    ///      here — this method assumes evidence is already in place. It
    ///      would be wasted work to scan the whole hot tier here.)
    ///   3. Delete the rolled-up events from the hot table + drop their
    ///      FTS5 entries.
    ///
    /// Also: drops `event_aggregates` rows older than 30 days, keeping
    /// the rollup table tiny indefinitely.
    ///
    /// Returns the number of events deleted from the hot tier.
    ///
    /// `aggregateRetentionDays` controls the trim cutoff for the
    /// `event_aggregates` table (Step 3 below). v1.8.0 made this
    /// configurable from `StorageConfig.aggregateDays` — pre-v1.8 it was
    /// hardcoded at 30 days.
    ///
    /// v1.21.4: `protectedCategory` + `floorCutoff` extend the per-category
    /// retention floor to the time-based rollup. When supplied, protected-
    /// category rows newer than `floorCutoff` are excluded from BOTH the
    /// aggregation and the delete (the same predicate), so they stay as raw
    /// rows and are NOT double-counted — a later sweep whose cutoff has aged
    /// past the floor rolls them up normally. Keeps aggregate/delete
    /// symmetric under the floor.
    @discardableResult
    public func rollUpAndPrune(
        olderThan cutoff: Date,
        aggregateRetentionDays: Int = 30,
        protecting protectedCategory: EventCategory? = nil,
        newerThan floorCutoff: Date? = nil
    ) async throws -> Int {
        guard let db = db else { return 0 }
        // Each chunk is independently atomic: aggregate + FTS delete + event
        // delete either all commit or all roll back. The old implementation
        // wrapped every eligible row on the host in one transaction, allowing
        // an arbitrarily large WAL despite the nominal reserve. A default
        // 32 MiB event reserve and three conservative row mutations yields 42
        // source rows per transaction, followed by a fresh family/free probe.
        let batch = maintenanceBatchRowLimit(mutationsPerCandidate: 3)
        let transactionEstimate = maintenanceEstimate(
            rowCount: Int(batch),
            mutationsPerCandidate: 3
        )
        let hasFloor = protectedCategory != nil && floorCutoff != nil
        let floorPredicate = hasFloor
            ? " AND (event_category <> ?2 OR timestamp < ?3)"
            : ""
        let selector = """
            SELECT rowid FROM events
            WHERE journal_block_id IS NULL
              AND journal_quarantine_marker IS NULL
              AND timestamp < ?1\(floorPredicate)
            ORDER BY rowid LIMIT ?4
            """
        let aggregateSQL = """
            INSERT INTO event_aggregates (day, event_category, process_signer, process_path, count)
            SELECT
                strftime('%Y-%m-%d', timestamp, 'unixepoch') AS d,
                event_category,
                COALESCE(process_signer, ''),
                COALESCE(process_path, ''),
                COUNT(*) AS c
            FROM events WHERE rowid IN (\(selector))
            GROUP BY d, event_category, COALESCE(process_signer, ''), COALESCE(process_path, '')
            ON CONFLICT(day, event_category, process_signer, process_path)
            DO UPDATE SET count = count + excluded.count
            """
        let deleteFTS = "DELETE FROM events_fts WHERE rowid IN (\(selector))"
        let deleteEvents = "DELETE FROM events WHERE rowid IN (\(selector))"

        func bindChunk(_ stmt: OpaquePointer) {
            sqlite3_bind_double(stmt, 1, cutoff.timeIntervalSince1970)
            if let protectedCategory, let floorCutoff {
                bindText(stmt, index: 2, value: protectedCategory.rawValue)
                sqlite3_bind_double(stmt, 3, floorCutoff.timeIntervalSince1970)
            }
            sqlite3_bind_int(stmt, 4, batch)
        }

        var deleted = 0
        while true {
            try beginSerializedWrite(
                estimatedBytes: transactionEstimate,
                maintenance: true
            )
            var committed = false
            do {
                let aggregate = try prepare(aggregateSQL)
                bindChunk(aggregate)
                let aggregateRC = sqlite3_step(aggregate)
                sqlite3_finalize(aggregate)
                guard aggregateRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: aggregateRC)
                    throw EventStoreError.stepFailed(
                        "rollUp aggregate failed: \(String(cString: sqlite3_errmsg(db)))"
                    )
                }

                let fts = try prepare(deleteFTS)
                bindChunk(fts)
                let ftsRC = sqlite3_step(fts)
                sqlite3_finalize(fts)
                guard ftsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: ftsRC)
                    throw EventStoreError.stepFailed(
                        "rollUp FTS prune failed: \(String(cString: sqlite3_errmsg(db)))"
                    )
                }

                let events = try prepare(deleteEvents)
                bindChunk(events)
                let eventsRC = sqlite3_step(events)
                sqlite3_finalize(events)
                guard eventsRC == SQLITE_DONE else {
                    try throwLatchedStoragePressureIfPresent(resultCode: eventsRC)
                    throw EventStoreError.stepFailed(
                        "rollUp event prune failed: \(String(cString: sqlite3_errmsg(db)))"
                    )
                }
                let thisBatch = Int(sqlite3_changes(db))
                try execute("COMMIT")
                committed = true
                deleted += thisBatch
                if thisBatch == 0 { break }
            } catch {
                if !committed { try? execute("ROLLBACK") }
                throw error
            }
            await Task.yield()
        }

        if deleted > 0 {
            let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
                requestedPages: Int.max,
                reserveBytes: storageTransactionReserveBytes,
                pageSizeBytes: sqlitePageSizeBytes
            )
            guard plan.pages > 0 else { return deleted }
            try withSerializedWrite(
                estimatedBytes: plan.estimatedTransactionBytes,
                maintenance: true
            ) {
                let rc = sqlite3_exec(
                    db,
                    "PRAGMA incremental_vacuum(\(plan.pages))",
                    nil,
                    nil,
                    nil
                )
                if rc != SQLITE_OK {
                    try throwLatchedStoragePressureIfPresent(
                        resultCode: rc
                    )
                    throw EventStoreError.stepFailed(
                        "bounded incremental VACUUM failed"
                    )
                }
            }
        }

        // Step 3: trim aggregates older than `aggregateRetentionDays`.
        // Independent + idempotent — runs outside the main transaction so it
        // doesn't block on Step 2's long delete batch. A crash here just
        // leaves stale aggregates that the next sweep cleans up.
        let aggDays = max(1, aggregateRetentionDays)
        let cutoffDay = Self.isoDay(Date().addingTimeInterval(-Double(aggDays) * 86400))
        let trimBatch = maintenanceBatchRowLimit()
        let trimEstimate = maintenanceEstimate(rowCount: Int(trimBatch))
        let trimSQL = """
            DELETE FROM event_aggregates WHERE rowid IN (
                SELECT rowid FROM event_aggregates
                WHERE day < ?1 ORDER BY rowid LIMIT ?2
            )
        """
        while true {
            let changed: Int32 = try withSerializedWrite(
                estimatedBytes: trimEstimate,
                maintenance: true
            ) {
                let trimStmt = try prepare(trimSQL)
                bindText(trimStmt, index: 1, value: cutoffDay)
                sqlite3_bind_int(trimStmt, 2, trimBatch)
                let trimRC = sqlite3_step(trimStmt)
                sqlite3_finalize(trimStmt)
                if trimRC != SQLITE_DONE {
                    try throwLatchedStoragePressureIfPresent(
                        resultCode: trimRC
                    )
                    throw EventStoreError.stepFailed(
                        "aggregate retention trim failed"
                    )
                }
                return sqlite3_changes(db)
            }
            if changed == 0 { break }
            await Task.yield()
        }

        if try hasJournalSchema() {
            let gapTrimSQL = """
                DELETE FROM event_aggregate_gaps
                WHERE (day, event_category, reason) IN (
                    SELECT day, event_category, reason
                    FROM event_aggregate_gaps
                    WHERE day < ?1
                    ORDER BY day, event_category, reason
                    LIMIT ?2
                )
            """
            while true {
                let changed: Int32 = try withSerializedWrite(
                    estimatedBytes: trimEstimate,
                    maintenance: true
                ) {
                    let gapTrim = try prepare(gapTrimSQL)
                    bindText(gapTrim, index: 1, value: cutoffDay)
                    sqlite3_bind_int(gapTrim, 2, trimBatch)
                    let gapRC = sqlite3_step(gapTrim)
                    let changed = sqlite3_changes(db)
                    sqlite3_finalize(gapTrim)
                    guard gapRC == SQLITE_DONE else {
                        try throwLatchedStoragePressureIfPresent(
                            resultCode: gapRC
                        )
                        throw EventStoreError.stepFailed(
                            "aggregate gap retention trim failed"
                        )
                    }
                    return changed
                }
                if changed == 0 { break }
                await Task.yield()
            }
        }

        return deleted
    }

    /// ISO date string ("2026-04-15") for `date` in UTC. Matches the
    /// `strftime('%Y-%m-%d', timestamp, 'unixepoch')` format used in the
    /// aggregate roll-up so day strings sort + compare as text.
    private static func isoDay(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: date)
    }

    /// Run `VACUUM` to reclaim free pages into on-disk file size.
    /// SQLite's `DELETE` marks pages free but doesn't shrink the
    /// file; without this call, the size-cap enforcer prunes rows
    /// but the `.db` file stays the same size. Costly (rewrites the
    /// whole DB) AND requires ~= DB size of temp scratch space,
    /// so only called after a size-driven prune when
    /// `checkpointAndVacuum()` has confirmed there's enough free
    /// disk to do it safely.
    ///
    /// **WAL discipline**: the function checkpoints the WAL before
    /// and after VACUUM. Older SQLite (≤3.43, the macOS-bundled
    /// libsqlite3 we used pre-CSQLCipher migration) auto-checkpointed
    /// inside VACUUM, making the pattern caller-checkpoint-free.
    /// SQLite ≥3.53 (vendored via SQLCipher 4.16.0) no longer
    /// guarantees this — VACUUM can return SQLITE_OK without
    /// touching the WAL, leaving post-VACUUM file sizes identical
    /// to pre-VACUUM and silently breaking the size-cap shrink
    /// contract. Pre-checkpoint guarantees VACUUM operates on a
    /// drained main DB; post-checkpoint truncates the WAL that
    /// VACUUM itself produced so the on-disk footprint reflects the
    /// rebuilt DB.
    public func vacuum() async throws {
        guard let db = db else { return }
        guard walCheckpoint() else {
            throw EventStoreError.busy(
                "VACUUM refused because the pre-checkpoint did not fully drain"
            )
        }
        // One-shot auto_vacuum conversion (audit corr-storage): `PRAGMA
        // auto_vacuum = INCREMENTAL` is a SILENT no-op on an already-populated
        // DB — the mode only changes on the next VACUUM. Fresh installs get
        // mode 2 from applyEventStorePragmas (the pragma DOES take on an empty
        // header), but a DB that existed before that shipped stays in mode 0
        // (NONE) forever, so incrementalVacuum() — the low-disk reclaim path —
        // is permanently a no-op. Setting the pragma here means this full
        // VACUUM (already disk-pre-flighted by the size-cap caller) also
        // converts the file to INCREMENTAL, so subsequent low-disk sweeps can
        // reclaim in place. Idempotent + harmless once already mode 2.
        let autoVacuumRC = sqlite3_exec(
            db,
            "PRAGMA auto_vacuum = INCREMENTAL",
            nil,
            nil,
            nil
        )
        if autoVacuumRC != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: autoVacuumRC)
            throw EventStoreError.stepFailed("auto_vacuum conversion failed")
        }
        // Re-probe at the exact whole-file rewrite boundary. Caller preflights
        // are advisory and may race another disk consumer.
        try admitStorageFullVacuum()
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.stepFailed("VACUUM failed: \(msg)")
        }
        guard walCheckpointTruncate() else {
            throw EventStoreError.busy(
                "VACUUM completed but its WAL could not be fully drained/truncated"
            )
        }
    }

    /// Checkpoint the WAL into the main DB file. Uses the non-
    /// blocking PASSIVE mode first; if that doesn't fully drain the
    /// WAL, escalates to RESTART which briefly parks new writers
    /// but doesn't require zero readers (unlike TRUNCATE).
    ///
    /// After a successful RESTART checkpoint, the main `.db` file
    /// carries every row that's been committed, and a subsequent
    /// VACUUM will produce a shrunken file that the Settings UI
    /// actually shows as "Current size".
    ///
    /// Returns `true` iff the checkpoint drained the WAL (pages
    /// moved from `.db-wal` to `.db`). Returns `false` on partial
    /// or no progress; the caller should still be able to VACUUM
    /// but the shrink may be smaller than expected.
    @discardableResult
    public func walCheckpoint() -> Bool {
        guard let db = db else { return false }
        guard (try? admitStorageCheckpoint()) != nil else { return false }
        // PASSIVE: never blocks. Returns immediately; may leave
        // pages in the WAL if readers are active.
        var passiveLog: Int32 = 0
        var passiveCkpt: Int32 = 0
        let rcPassive = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_PASSIVE),
            &passiveLog, &passiveCkpt
        )
        let passiveDrained = (rcPassive == SQLITE_OK && passiveLog == passiveCkpt)
        if passiveDrained { return true }
        guard rcPassive == SQLITE_OK else {
            if rcPassive != SQLITE_BUSY, rcPassive != SQLITE_LOCKED {
                _ = latchStoragePressureIfPresent(resultCode: rcPassive)
            }
            return false
        }

        // PASSIVE may have grown main and consumed free blocks. Re-probe before
        // the blocking attempt; a pre-PASSIVE observation is stale here.
        guard (try? admitStorageCheckpoint()) != nil else { return false }

        // RESTART: parks new writers very briefly; forces all
        // readers to start from the new WAL file (existing ones
        // finish their current transactions first). Safer than
        // TRUNCATE (which requires truly zero readers).
        var restartLog: Int32 = 0
        var restartCkpt: Int32 = 0
        let rcRestart = sqlite3_wal_checkpoint_v2(
            db, nil,
            Int32(SQLITE_CHECKPOINT_RESTART),
            &restartLog, &restartCkpt
        )
        if rcRestart != SQLITE_OK,
           rcRestart != SQLITE_BUSY,
           rcRestart != SQLITE_LOCKED {
            _ = latchStoragePressureIfPresent(resultCode: rcRestart)
        }
        return rcRestart == SQLITE_OK && restartLog == restartCkpt
    }

    /// TRUNCATE checkpoint — drains the WAL into the main DB AND shrinks the
    /// `-wal` sidecar back to zero bytes. `walCheckpoint()` above (PASSIVE→
    /// RESTART) drains the WAL *content* but leaves the *file* pinned at its
    /// high-water mark; under `journalSizeLimitBytes` (64 MB) that means
    /// events.db-wal can sit at up to 64 MB indefinitely — invisible to a
    /// file-only size check yet real resident footprint.
    ///
    /// v1.21.4 (#23): with `eventWalAutocheckpointPages` raised to 16 MB the
    /// healthy high-water mark is ~16 MB, so the background size-cap sweep
    /// runs this each pass to reclaim it back to zero — footprint-neutral in
    /// steady state, matching the trace/tracegraph stores' `walCheckpointTruncate`
    /// discipline (DaemonTimers). Best-effort: TRUNCATE degrades to RESTART-
    /// like progress under an active reader, which is still fine.
    @discardableResult
    public func walCheckpointTruncate() -> Bool {
        (try? walCheckpointTruncateObservation().truncated) ?? false
    }

    /// Exact checkpoint result for callers whose retry/error policy depends on
    /// the cause. The Boolean compatibility method is only best-effort.
    struct WALCheckpointObservation: Sendable, Equatable {
        let failure: SQLiteFailureDetails
        let logFrames: Int32
        let checkpointedFrames: Int32
        let duration: Duration
        let connectionInTransaction: Bool

        var truncated: Bool {
            failure.resultCode == SQLITE_OK && logFrames >= 0
                && checkpointedFrames >= 0 && logFrames == checkpointedFrames
        }

        var retryableContention: Bool {
            let primary = failure.resultCode & 0xff
            return primary == SQLITE_BUSY || primary == SQLITE_LOCKED
                || (primary == SQLITE_OK && logFrames >= 0
                    && checkpointedFrames >= 0 && checkpointedFrames < logFrames)
        }

        var diagnostic: String {
            let elapsed = duration.components
            let seconds = Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18
            return "rc=\(failure.resultCode), extended=\(failure.extendedResultCode), errno=\(failure.systemErrno), frames=\(checkpointedFrames)/\(logFrames), checkpoint_seconds=\(seconds), connection_in_transaction=\(connectionInTransaction)"
        }

        func requireValidOutcome(context: String) throws {
            guard !truncated, !retryableContention else { return }
            if failure.resultCode == SQLITE_OK {
                throw EventStoreError.storageNotReady(
                    "\(context) returned no established drained boundary (\(diagnostic))")
            }
            throw EventStoreError.sqliteFailure(
                context: context, message: diagnostic,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno)
        }

        func requireTruncated(context: String) throws {
            try requireValidOutcome(context: context)
            guard !truncated else { return }
            throw EventStoreError.busy(
                "\(context) has checkpoint contention (\(diagnostic))", failure: failure)
        }
    }

    /// Shared production primitive; the admission closure is evaluated before
    /// SQLite and throws unchanged. Ordinary fixtures can use two independent
    /// private connections without exposing this actor's live handle.
    nonisolated static func truncateCheckpoint(
        on handle: OpaquePointer,
        admit: () throws -> Void
    ) throws -> WALCheckpointObservation {
        try Task.checkCancellation()
        try admit()
        let inTransaction = sqlite3_get_autocommit(handle) == 0
        var log: Int32 = -1
        var ckpt: Int32 = -1
        let started = ContinuousClock.now
        // SQLite leaves frame outputs undefined when zDb is nil (all attached
        // databases). This operation admits and measures the events main family.
        let rc = sqlite3_wal_checkpoint_v2(
            handle, "main",
            Int32(SQLITE_CHECKPOINT_TRUNCATE),
            &log, &ckpt
        )
        // Capture before any follow-up SQLite call can replace the cause.
        let failure = SQLiteFailureDetails(resultCode: rc, db: handle)
        return WALCheckpointObservation(failure: failure, logFrames: log,
            checkpointedFrames: ckpt, duration: started.duration(to: .now),
            connectionInTransaction: inTransaction)
    }

    func walCheckpointTruncateObservation() throws -> WALCheckpointObservation {
        guard let db, !isReadOnly else {
            throw EventStoreError.storageNotReady("checkpoint requires an open writable event store")
        }
        let result = try Self.truncateCheckpoint(on: db) {
            try admitStorageCheckpoint()
        }
        // Keep the existing pressure latch, using the captured original codes.
        let primary = result.failure.resultCode & 0xff
        if primary != SQLITE_OK, primary != SQLITE_BUSY, primary != SQLITE_LOCKED,
           var admission = storageAdmission {
            _ = admission.latchSQLitePressure(details: result.failure)
            storageAdmission = admission
        }
        if !result.truncated {
            Logger(subsystem: "com.maccrab", category: "event-checkpoint")
                .warning("Event WAL checkpoint incomplete: \(result.diagnostic, privacy: .public)")
        }
        return result
    }

    // MARK: - Disabled off-actor full VACUUM compatibility entry point

    /// Retained only so older maintenance callers fail with a specific error.
    /// A detached connection cannot prevent the ingestion actor from committing
    /// between the final free-space probe and acquisition of SQLite's VACUUM
    /// writer lock. Full VACUUM must run through the owning actor's `vacuum()`
    /// method, which serializes checkpoint -> admission -> rewrite.
    public static func vacuumOnDedicatedConnection(
        at path: String,
        storagePolicy suppliedPolicy: SQLitePersistentStorePolicy? = nil
    ) async throws {
        _ = path
        _ = suppliedPolicy
        // Fail closed: a detached connection cannot prevent the ingestion
        // actor from committing between its final stat and acquisition of the
        // VACUUM writer lock. Call `vacuum()` on the owning EventStore actor so
        // checkpoint -> headroom gate -> rewrite is one serialized operation.
        throw EventStoreError.stepFailed(
            "concurrent dedicated VACUUM is disabled; use EventStore.vacuum() on the owning actor"
        )
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // Reclaim freelist pages from the end of the file in place — no
    // scratch disk required. Drives the low-disk fallback in
    // `enforceDatabaseSizeCap` when a full VACUUM would need more
    // headroom than the volume has.
    //
    // Returns the number of pages physically removed from the file
    // (delta in `PRAGMA freelist_count`). Zero means either:
    //   - The DB isn't in `auto_vacuum = INCREMENTAL` mode (pre-v1.10
    //     EventStore DBs that never had the one-shot conversion run),
    //   - The freelist was already empty,
    //   - Or `maxPages == 0`.
    //
    // The caller can divide by `Int64(maxPages) * Int64(pageSize)` to
    // estimate the file-size reduction, but the size-cap enforcer
    // reads the on-disk footprint directly via `statvfs` so it gets
    // exact numbers including the WAL/SHM sidecars.
    @discardableResult
    public func incrementalVacuum(maxPages: Int) async throws -> Int {
        guard let db = db else { return 0 }
        guard StoragePragmas.readAutoVacuumMode(db) == 2 else { return 0 }
        let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: max(0, maxPages),
            reserveBytes: storageTransactionReserveBytes,
            pageSizeBytes: sqlitePageSizeBytes
        )
        guard plan.pages > 0 else { return 0 }
        // The shared incremental-vacuum primitive cannot safely checkpoint:
        // it has no path/floor/family probes. Drain through this actor's fresh
        // whole-sidecar gate, then re-probe ordinary maintenance headroom.
        guard walCheckpoint() else {
            throw EventStoreError.stepFailed(
                "incremental VACUUM refused because the pre-checkpoint did not fully drain"
            )
        }
        do {
            let result = try withSerializedWrite(
                estimatedBytes: plan.estimatedTransactionBytes,
                maintenance: true
            ) {
                try StoragePragmas.runIncrementalVacuum(
                    on: db,
                    maxPages: plan.pages
                )
            }
            guard walCheckpointTruncate() else {
                throw EventStoreError.stepFailed(
                    "incremental VACUUM completed but its WAL could not be fully drained/truncated"
                )
            }
            return result.pagesReclaimed
        } catch let error as StoragePragmas.IncrementalVacuumError {
            try throwLatchedStoragePressureIfPresent(
                details: error.sqliteFailureMetadata.publicDetails
            )
            throw error
        }
    }

    /// Bytes the file owns but does not use — `freelist_count * page_size`.
    ///
    /// These pages are charged in full to `page_count`, to the on-disk file
    /// size, and therefore to every family-footprint measurement the size-cap
    /// sweep and storage admission take. `incrementalVacuum` returns them to
    /// the OS with no scratch disk, so a large value here is reclaimable slack,
    /// NOT consumed budget. The sweep consults this so the reclaim is driven by
    /// what is actually reclaimable rather than by where one instantaneous
    /// footprint sample happened to land.
    ///
    /// Returns 0 when the store is closed or is not in `auto_vacuum =
    /// INCREMENTAL` mode — in either case the reclaim path cannot act on the
    /// freelist, so reporting slack would only invite a no-op sweep.
    public func reclaimableFreelistBytes() -> Int64 {
        guard let db else { return 0 }
        guard StoragePragmas.readAutoVacuumMode(db) == 2 else { return 0 }
        let pages = Int64(StoragePragmas.readFreelistCount(db))
        guard pages > 0, sqlitePageSizeBytes > 0 else { return 0 }
        return SQLitePersistentStoreAdmission.saturatingMultiply(
            pages,
            by: sqlitePageSizeBytes
        )
    }

    /// Read the file's `PRAGMA auto_vacuum` mode at runtime. Returns
    /// 0/1/2 (NONE / FULL / INCREMENTAL); 0 on closed/error. The
    /// size-cap enforcer reads this so it can log when the DB is not
    /// in INCREMENTAL mode — incrementalVacuum is a no-op in that
    /// case, and the operator may want to schedule a one-shot
    /// `maccrabctl maintenance vacuum` to convert.
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }

    // MARK: - FTS5 segment-ceiling recovery (v1.21.6-rc.34)
    //
    // FTS5 has a HARD compile-time ceiling of 2000 live segments
    // (`FTS5_MAX_SEGMENT`). At the ceiling every operation that must allocate a
    // segid fails with SQLITE_FULL — including `optimize`, so the index cannot
    // compact its way out. Only `rebuild` escapes, because it resets the index
    // structure before allocating.
    //
    // This store reaches that ceiling through its OWN retention path. Writes run
    // with `automerge=0` (see openDatabase) so segments never merge inline, and
    // each expired journal block issues a `DELETE FROM events_fts`, which writes
    // a tombstone segment. Enough expiries and the index is full: an installed
    // host reached 2000 segments holding only 635 events.
    //
    // Left alone that is a CLOSED LOOP, and an unrecoverable one:
    //
    //   segments accumulate -> ceiling -> boot expiry fails SQLITE_FULL
    //     -> boot never reaches ready -> the background sweep that calls
    //     mergeFTS/optimizeFTS never runs -> ceiling persists forever
    //
    // The compaction that would fix it is driven only from DaemonTimers' post-
    // ready sweep, so it can never run on an affected host. Recovery therefore
    // has to happen HERE, on the boot path, before expiry needs a segid.
    //
    // DETECTION-SAFE: `events_fts` is an external-content index over `events`,
    // read only by `search()`/hunt and never by the detection engine. A rebuild
    // regenerates it from the content table; it changes physical layout only,
    // never which rows a MATCH returns, and cannot lose event data.

    /// FTS5's hard `FTS5_MAX_SEGMENT` ceiling.
    static let ftsSegmentCeiling = 2_000

    /// Recover well before the ceiling. At 2000 the index is frozen, so waiting
    /// for the wall leaves no working escape.
    static let ftsSegmentRecoveryThreshold = 1_500

    /// Live segment count, or nil if it cannot be determined.
    func liveFTSSegmentCount() -> Int? {
        guard db != nil else { return nil }
        guard let stmt = try? prepare(
            "SELECT count(DISTINCT (id >> 37)) FROM events_fts_data WHERE id > 10"
        ) else {
            // rc.36: a failed probe is not "no pressure". Returning nil silently
            // makes recovery decline to run and walk into SQLITE_FULL with
            // nothing in the log naming the check that opted out — the same
            // failure-invisibility this release removed elsewhere.
            Logger(subsystem: "com.maccrab.storage", category: "event-store").error(
                "could not probe events_fts segment count; ceiling recovery cannot evaluate this store"
            )
            return nil
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            Logger(subsystem: "com.maccrab.storage", category: "event-store").error(
                "events_fts segment-count probe returned no row; ceiling recovery cannot evaluate this store"
            )
            return nil
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Sweep-facing wrapper: never throws, always reports. The background sweep
    /// must be able to call ceiling recovery unconditionally without a throw
    /// aborting the rest of its maintenance.
    @discardableResult
    public func recoverExhaustedFTSIndexIfNeededForSweep() async -> Bool {
        do {
            return try recoverExhaustedFTSIndexIfNeeded()
        } catch {
            Logger(subsystem: "com.maccrab.storage", category: "event-store").error(
                "events_fts ceiling recovery failed in sweep; the index may be unable to allocate a segment: \(String(describing: error), privacy: .public)"
            )
            return false
        }
    }

    /// Rebuild `events_fts` when its segment count is close enough to the
    /// ceiling that the next segid allocation could fail. Returns true when a
    /// rebuild ran.
    ///
    /// Deliberately uses `rebuild` rather than `optimize`: at or near the
    /// ceiling `optimize` needs a fresh segid and fails with SQLITE_FULL, so it
    /// cannot be the escape hatch.
    @discardableResult
    func recoverExhaustedFTSIndexIfNeeded() throws -> Bool {
        guard let db = db, !isReadOnly else { return false }
        guard let segments = liveFTSSegmentCount(),
              segments >= Self.ftsSegmentRecoveryThreshold else { return false }

        Logger(subsystem: "com.maccrab.storage", category: "event-store").warning(
            "events_fts is at \(segments) of \(Self.ftsSegmentCeiling) FTS5 segments; rebuilding the index before it can no longer allocate one"
        )
        try withSerializedWrite(
            estimatedBytes: storageTransactionReserveBytes,
            maintenance: true
        ) {
            let rc = sqlite3_exec(
                db,
                "INSERT INTO events_fts(events_fts) VALUES('rebuild')",
                nil, nil, nil
            )
            guard rc == SQLITE_OK else {
                throw EventStoreError.stepFailed(
                    "events_fts rebuild failed (sqlite rc \(rc)): "
                        + String(cString: sqlite3_errmsg(db))
                )
            }
        }
        Logger(subsystem: "com.maccrab.storage", category: "event-store").warning(
            "events_fts rebuilt; segments now \(self.liveFTSSegmentCount() ?? -1)"
        )
        return true
    }

    // MARK: - FTS5 index merge (v1.21.4 Tier-A perf)
    //
    // Companion to the `automerge=0` setting in `openDatabase`. With
    // per-insert automerge disabled and crisismerge raised to 1999, the
    // `events_fts` index accumulates more small b-tree segments between
    // compactions than the old default (4) allowed. This runs an explicit, BOUNDED incremental
    // merge OFF the hot write path — driven from the background size-cap sweep
    // — so hunt-query (`search()`) latency stays healthy without the insert
    // path paying the merge cost.
    //
    // `pages` bounds the work: FTS5's `('merge', N)` command runs a merge
    // until at least N leaf pages have been written to the database (or the
    // index is fully merged), then stops. A bounded budget keeps the actor
    // responsive; when there is nothing to merge the command is a cheap no-op.
    //
    // DETECTION-SAFE: `events_fts` is read ONLY by `search()` (threat
    // hunting), never by the detection engine. A merge changes only the
    // index's physical segment layout, never which rows a MATCH returns.
    // No-op on a read-only store (the dashboard has no business rewriting the
    // owner's index).
    @discardableResult
    public func mergeFTS(pages: Int = 1000) async -> Bool {
        guard let db = db, !isReadOnly else { return false }
        // rc.34: bounded merge cannot rescue an index that has already run out
        // of segids — it needs one itself and fails with SQLITE_FULL. Measured
        // against the real schema, ordinary batched ingestion produces roughly
        // one segment per two rows with automerge=0, so the ceiling is reachable
        // without any expiry at all. Check for exhaustion before merging.
        do {
            if try recoverExhaustedFTSIndexIfNeeded() { return true }
        } catch {
            Logger(subsystem: "com.maccrab.storage", category: "event-store").error(
                "events_fts exhaustion recovery failed: \(String(describing: error), privacy: .public)"
            )
        }
        let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: max(1, pages),
            reserveBytes: storageTransactionReserveBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            fixedTreePageTouches: 16,
            // Vendored FTS5 performs merge work in 64-leaf-page quanta.
            overshootPages: 64
        )
        guard plan.pages > 0 else { return false }
        let sql = "INSERT INTO events_fts(events_fts, rank) VALUES('merge', \(plan.pages))"
        do {
            try withSerializedWrite(
                estimatedBytes: plan.estimatedTransactionBytes,
                maintenance: true
            ) {
                let rc = sqlite3_exec(db, sql, nil, nil, nil)
                guard rc == SQLITE_OK else {
                    _ = latchStoragePressureIfPresent(resultCode: rc)
                    throw EventStoreError.stepFailed(
                        "bounded FTS merge failed (sqlite rc \(rc)): "
                            + String(cString: sqlite3_errmsg(db))
                    )
                }
            }
        } catch {
            // rc.34: previously a bare `return false`. This is the maintenance
            // that exists to keep events_fts away from its segment ceiling, so
            // silently swallowing its failures removed the only warning that it
            // had stopped working — and the index filled anyway.
            Logger(subsystem: "com.maccrab.storage", category: "event-store").error(
                "bounded FTS merge failed, segment pressure will keep growing: \(String(describing: error), privacy: .public)"
            )
            return false
        }
        return true
    }

    /// A larger, still reserve-bounded FTS5 merge pass. The historical
    /// `optimize` command rewrote the entire index in one autocommit statement;
    /// a fragmented 48-MiB projection could therefore append more than the
    /// fixed 32-MiB WAL reserve, especially when a second connection pinned the
    /// WAL after the timer's preflight. Repeated bounded merge quanta converge
    /// without ever bypassing the serialized family/terminal-poison floor.
    ///
    /// DETECTION-SAFE: `events_fts` is read ONLY by `search()`/hunt, never by the
    /// detection engine; optimize changes only the index's physical layout, never
    /// which rows a MATCH returns. No-op on a read-only store.
    /// Timestamp of the last large merge attempt, or nil if none has run
    /// since this store was opened — so a restart always permits one pass.
    /// Actor-isolated; deliberately not persisted.
    private var lastFullFTSOptimizeAt: Date?

    /// Minimum spacing between full FTS `optimize` passes. See optimizeFTS.
    private static let minFullFTSOptimizeInterval: TimeInterval = 6 * 3600

    @discardableResult
    public func optimizeFTS() async -> Bool {
        guard let db = db, !isReadOnly else { return false }
        // Rate-limit the larger maintenance quantum so ordinary bounded merges
        // retain their normal cadence without monopolizing the actor.
        let now = Date()
        if let last = lastFullFTSOptimizeAt,
           now.timeIntervalSince(last) < Self.minFullFTSOptimizeInterval {
            Logger(subsystem: "com.maccrab.storage", category: "event-store")
                .debug("optimizeFTS skipped: last full optimize was \(Int(now.timeIntervalSince(last)))s ago (min interval \(Int(Self.minFullFTSOptimizeInterval))s); bounded mergeFTS still runs each sweep")
            return false
        }
        let plan = SQLitePersistentStoreAdmission.boundedPageOperationPlan(
            requestedPages: Int.max,
            reserveBytes: storageTransactionReserveBytes,
            pageSizeBytes: sqlitePageSizeBytes,
            fixedTreePageTouches: 16,
            overshootPages: 64
        )
        guard plan.pages > 0 else { return false }
        // Stamp before the write so a repeatedly failing compaction cannot
        // be re-attempted on every subsequent sweep.
        lastFullFTSOptimizeAt = now
        do {
            try withSerializedWrite(
                estimatedBytes: plan.estimatedTransactionBytes,
                maintenance: true
            ) {
                let sql = "INSERT INTO events_fts(events_fts, rank) VALUES('merge', \(plan.pages))"
                let rc = sqlite3_exec(db, sql, nil, nil, nil)
                guard rc == SQLITE_OK else {
                    _ = latchStoragePressureIfPresent(resultCode: rc)
                    throw EventStoreError.stepFailed(
                        "large bounded FTS merge failed"
                    )
                }
            }
        } catch {
            // rc.36: log rather than swallow. mergeFTS's identical bare
            // `return false` is what hid the fact that FTS compaction had
            // stopped working while the index filled to its ceiling; this
            // sibling kept the same blind spot 60 lines away.
            Logger(subsystem: "com.maccrab.storage", category: "event-store").error(
                "full FTS optimize failed; segment pressure will keep growing: \(String(describing: error), privacy: .public)"
            )
            return false
        }
        return true
    }

    // MARK: - Reentrancy guard for size-cap enforcement
    //
    // The hourly size-cap timer, a user-invoked "Prune now", and a
    // CLI `maccrabctl prune --to-cap` can all end up here. Without a
    // guard, two invocations serialize behind the actor but each
    // runs a full prune + VACUUM pass — wasteful at best, unhelpful
    // at worst (second pass re-scans an already-pruned DB). The
    // guard returns `nil` from `beginSizeCapPrune()` when another
    // pass is already in flight.

    private var _isPruningForSizeCap = false
    private var journalExpiryPendingTicks: UInt64 = 0
    private var journalExpiryLeaseDeferrals: UInt64 = 0
    private var journalExpiryFailedPasses: UInt64 = 0

    /// Acquire the size-cap pruning exclusion. Returns `nil` if
    /// another pass is already active. Callers that receive `nil`
    /// should simply log and return.
    public func beginSizeCapPrune() -> Bool {
        if _isPruningForSizeCap { return false }
        _isPruningForSizeCap = true
        return true
    }

    /// Journal expiry uses the same exclusion as legacy convergence, but a
    /// missed tick is conserved rather than discarded for another five-minute
    /// period. The timer keeps its task pending and retries promptly.
    public func beginJournalExpiryPrune() -> Bool {
        if _isPruningForSizeCap { return false }
        _isPruningForSizeCap = true
        return true
    }

    /// Count one coalesced scheduler tick, not every 250-ms acquisition poll.
    public func recordJournalExpiryPendingTick() {
        journalExpiryPendingTicks &+= 1
    }

    public func recordJournalExpiryFailure() {
        journalExpiryFailedPasses &+= 1
    }

    /// Count one tick that was conserved because the pipeline's bounded record
    /// ownership was fully committed, not one that failed. Counted once per
    /// tick rather than per 250-ms retry, matching `pendingTicks`.
    public func recordJournalExpiryLeaseDeferral() {
        journalExpiryLeaseDeferrals &+= 1
    }

    public func journalExpirySchedulingCounters() -> (
        pendingTicks: UInt64,
        failedPasses: UInt64,
        leaseDeferrals: UInt64
    ) {
        (
            journalExpiryPendingTicks,
            journalExpiryFailedPasses,
            journalExpiryLeaseDeferrals
        )
    }

    /// Release the size-cap pruning exclusion. Must be called from
    /// a `defer` block so it runs even on throws.
    public func endSizeCapPrune() {
        _isPruningForSizeCap = false
    }

    // MARK: - Mid-run corruption self-heal (C-04)
    //
    // Init-time recovery (DaemonSetup.recoverEventStore) handles a store that
    // is already corrupt at open. This path handles a store that corrupts
    // *while the daemon is live* — a `SQLITE_CORRUPT` / `SQLITE_NOTADB` on an
    // insert step. Without it, every subsequent insert throws forever and
    // ingestion is silently dead until the next daemon restart.
    //
    // The self-heal is: close → quarantine the corrupt files aside → reopen a
    // fresh DB. It is *bounded* (at most `selfHealMaxAttempts` for the process
    // lifetime) and *rate-limited* (`selfHealMinInterval` between attempts) so
    // a persistently-failing device can't thrash open/close/backup in a hot
    // loop. Backups reuse the shared `CorruptDBBackup` naming + retention, so
    // they stay bounded exactly like the init-time quarantine.

    /// Attempts so far this process. Bounded so a device that keeps corrupting
    /// (failing hardware) doesn't churn forever — after the cap we stop trying
    /// and inserts simply keep failing (surfaced via StorageErrorTracker).
    private var selfHealCount = 0
    private var lastSelfHealAt = Date.distantPast
    private static let selfHealMaxAttempts = 3
    private static let selfHealMinInterval: TimeInterval = 300  // 5 minutes

    /// SQLite primary result code for a step failure that indicates on-disk
    /// corruption (as opposed to a transient lock / disk-full). Extended codes
    /// (e.g. `SQLITE_CORRUPT_VTAB`) share the low byte with their primary code.
    static func isCorruptionResultCode(_ rc: Int32) -> Bool {
        SQLiteFailureClassifier.isExplicitCorruption(
            resultCode: rc,
            extendedResultCode: rc
        )
    }

    /// Close the current connection, quarantine the corrupt DB (+ sidecars)
    /// aside, and reopen a fresh one. Returns `true` if the store is usable
    /// again afterwards. Bounded + rate-limited (see above). No-op (returns
    /// `false`) on a read-only store — the dashboard has no business rewriting
    /// the owner's DB.
    ///
    /// `now:` is injectable for tests; production callers use the default.
    @discardableResult
    func attemptCorruptionSelfHeal(
        failure: SQLiteFailureDetails,
        reason: String,
        now: Date = Date()
    ) -> Bool {
        let log = Logger(subsystem: "com.maccrab.storage", category: "event-store")
        // This guard belongs at the mutating boundary, not only at the caller.
        // A future recovery caller cannot accidentally quarantine on BUSY,
        // LOCKED, PERM, READONLY, IOERR, FULL, or a misleading error string.
        guard failure.isExplicitCorruption else { return false }
        guard !isReadOnly else { return false }
        guard selfHealCount < Self.selfHealMaxAttempts else {
            log.error("EventStore: corruption self-heal cap (\(Self.selfHealMaxAttempts, privacy: .public)) reached — not reopening. reason=\(reason, privacy: .public)")
            return false
        }
        guard now.timeIntervalSince(lastSelfHealAt) >= Self.selfHealMinInterval else {
            // Rate-limited: a burst of corrupt steps must not thrash the file.
            return false
        }
        lastSelfHealAt = now
        selfHealCount += 1
        log.error("EventStore: mid-run corruption detected (reason=\(reason, privacy: .public)); quarantining DB and reopening (attempt \(self.selfHealCount, privacy: .public)/\(Self.selfHealMaxAttempts, privacy: .public)).")

        // Close: finalize the cached insert statement, then close the handle.
        // insertStmt is the only long-lived statement on this connection
        // (queries prepare + finalize locally), so a v1 close succeeds cleanly.
        if let insertStmt { sqlite3_finalize(insertStmt) }
        insertStmt = nil
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
        checkpointController = nil
        db = nil

        // Quarantine the corrupt files aside (bounded retention). This *moves*
        // events.db* out of the way, so the reopen below starts from a clean
        // slate. `moveItem`/`removeItem` act on the final path component and
        // never follow a symlinked leaf; `openDatabase` re-checks the symlink
        // guard on the privileged path before it recreates the file.
        let dir = (databasePath as NSString).deletingLastPathComponent
        let base = (databasePath as NSString).lastPathComponent
        do {
            try CorruptDBBackup.quarantineAtomically(directory: dir, base: base)
            // Any chunks committed before this corruption event now live only
            // in the quarantined family, not the active store. Advance the
            // generation before reopening (including if reopen later fails).
            activeDatabaseGeneration &+= 1
        } catch {
            log.error("EventStore: corruption quarantine FAILED: \(error.localizedDescription, privacy: .public). Original DB family was rolled back; refusing to create a fresh store.")
            return false
        }

        // Reopen from the (now-empty) path. openDatabase re-applies pragmas +
        // schema + re-prepares the insert statement.
        do {
            // v1.21.5 (audit sec-storage-crypto): recreate the fresh DB with
            // the same 0o027/0o640 (group read-only, not group-write) as the
            // primary init — a self-heal must not silently re-loosen perms.
            let oldUmask = umask(0o027)
            defer { umask(oldUmask) }
            let (handle, ro, stmt, admission, pageSize, controller) = try Self.openDatabase(
                at: databasePath,
                forceReadOnly: false,
                storagePolicy: storagePolicy,
                liveMemoryBudget: liveMemoryBudget
            )
            db = handle
            isReadOnly = ro
            insertStmt = stmt
            storageAdmission = admission
            sqlitePageSizeBytes = pageSize
            checkpointController = controller
            chmod(databasePath, 0o640)
            chmod(databasePath + "-wal", 0o640)
            chmod(databasePath + "-shm", 0o640)
            log.notice("EventStore: reopened fresh DB after corruption self-heal.")
            return true
        } catch {
            log.error("EventStore: reopen after corruption self-heal FAILED: \(error.localizedDescription, privacy: .public). Inserts will keep failing until restart.")
            return false
        }
    }

    // MARK: - Private Helpers

    /// A sum type for binding values to prepared statements.
    private enum BindingValue {
        case text(String)
        case double(Double)
        case int(Int32)
        case null
    }

    /// Executes a SQL statement that does not return rows.
    private func execute(
        _ sql: String,
        maintenance: Bool = false,
        estimatedTransactionBytes: Int64? = nil,
        lane: EventPipelineLane? = nil
    ) throws {
        if sql.trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased().hasPrefix("BEGIN") {
            guard let estimatedTransactionBytes else {
                throw EventStoreError.stepFailed(
                    "BEGIN requires an explicit bounded transaction estimate"
                )
            }
            if maintenance {
                try admitStorageMaintenanceWrite(
                    estimatedTransactionBytes: estimatedTransactionBytes
                )
            } else {
                guard let lane else {
                    throw EventStoreError.stepFailed(
                        "BEGIN requires an explicit event pipeline lane"
                    )
                }
                try admitStorageWrite(
                    estimatedTransactionBytes: estimatedTransactionBytes,
                    lane: lane
                )
            }
        }
        var errmsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
        if rc != SQLITE_OK {
            try throwLatchedStoragePressureIfPresent(resultCode: rc)
            let failure = SQLiteFailureDetails(resultCode: rc, db: db)
            let msg = errmsg.flatMap { String(cString: $0) } ?? "unknown error"
            sqlite3_free(errmsg)
            // #13: BEGIN/COMMIT can return SQLITE_BUSY/LOCKED under WAL contention
            // (past busy_timeout) — transient, retryable. Surface it distinctly.
            if rc == SQLITE_BUSY || rc == SQLITE_LOCKED {
                throw EventStoreError.busy(msg, failure: failure)
            }
            throw EventStoreError.sqliteFailure(
                context: sql,
                message: msg,
                resultCode: failure.resultCode,
                extendedResultCode: failure.extendedResultCode,
                systemErrno: failure.systemErrno
            )
        }
    }

    /// Exact DB+WAL+SHM+journal admission immediately before growth writes. The
    /// controller is a value so copy it out and always write it back, including
    /// on a thrown probe, preserving the sticky pressure latch.
    private func admitStorageWrite(
        estimatedTransactionBytes: Int64,
        lane: EventPipelineLane
    ) throws {
        guard var admission = storageAdmission else { return }
        let wasBlocked = admission.growthBlocked
        let writerSetupPending = !isReadOnly && insertStmt == nil
        do {
            try admitFreshStorageWrite(
                &admission,
                estimatedTransactionBytes: estimatedTransactionBytes,
                lane: lane
            )
        } catch {
            storageAdmission = admission
            throw error
        }
        let recovered = wasBlocked && !admission.growthBlocked
        storageAdmission = admission
        if recovered || (writerSetupPending && !admission.growthBlocked) {
            try reopenAfterStorageRecovery()

            // Opening or preparing a replacement connection can grow or
            // reshape the SQLite family. Re-run BOTH the shared admission and
            // the lane reserve against a new authoritative probe before BEGIN.
            try revalidateStorageWriteAfterReopen(
                estimatedTransactionBytes: estimatedTransactionBytes,
                lane: lane
            )

            // Space can disappear between the successful probe and the fresh
            // open. A shed-only reopen has no insert statement. Retry admission
            // once with the SAME full transaction estimate; a successful retry
            // reopens again and the caller acquires only the new statement.
            if !isReadOnly, insertStmt == nil {
                try reopenAfterStorageRecovery()
                try revalidateStorageWriteAfterReopen(
                    estimatedTransactionBytes: estimatedTransactionBytes,
                    lane: lane
                )
                if insertStmt == nil,
                   let failure = storageAdmission?.latchedFailure {
                    throw failure
                }
            }
        }
    }

    /// Run the shared latching admission first so `lastFootprintBytes` is the
    /// authoritative measurement taken at this exact write boundary, then
    /// apply the file-only reserve without mutating the shared latch.
    private func admitFreshStorageWrite(
        _ admission: inout SQLitePersistentStoreAdmission,
        estimatedTransactionBytes: Int64,
        lane: EventPipelineLane
    ) throws {
        try admission.admitWrite(
            estimatedTransactionBytes: estimatedTransactionBytes,
            on: db
        )
        try enforceFileLaneReserve(
            admission,
            estimatedTransactionBytes: estimatedTransactionBytes,
            lane: lane
        )
    }

    private func revalidateStorageWriteAfterReopen(
        estimatedTransactionBytes: Int64,
        lane: EventPipelineLane
    ) throws {
        guard var admission = storageAdmission else { return }
        do {
            try admitFreshStorageWrite(
                &admission,
                estimatedTransactionBytes: estimatedTransactionBytes,
                lane: lane
            )
        } catch {
            storageAdmission = admission
            throw error
        }
        storageAdmission = admission
    }

    private func enforceFileLaneReserve(
        _ admission: SQLitePersistentStoreAdmission,
        estimatedTransactionBytes: Int64,
        lane: EventPipelineLane
    ) throws {
        guard lane == .file else { return }
        guard let footprint = admission.lastFootprintBytes else {
            throw EventStoreError.stepFailed(
                "File-lane admission completed without a footprint measurement"
            )
        }
        // A file-lane write must additionally leave the priority reserve free.
        //
        // This is a SEPARATE, NON-LATCHING check rather than an adjustment
        // to `admitWrite`, for two reasons that both matter:
        //
        //  * `estimatedTransactionBytes` feeds a per-TRANSACTION sanity bound
        //    (`transactionEstimateExceedsReserve`), not the footprint
        //    comparison. Inflating it does not tighten the footprint test — it
        //    makes every file write fail validation outright.
        //  * `admitWrite` latches its failure into `latchedFailure`, which is
        //    shared state consulted by every subsequent writer. Routing a
        //    file-lane refusal through it would latch the store closed against
        //    the PRIORITY lane too, which is precisely the outcome the reserve
        //    exists to prevent.
        //
        // So the lane test consumes the fresh measurement produced by the
        // immediately preceding `admitWrite`, throws directly, and leaves the
        // shared latch untouched.
        let cap = admission.policy.maxFootprintBytes
        let reserve = Self.priorityLaneReserveBytes(maxFootprintBytes: cap)
        let required = SQLitePersistentStoreAdmission.saturatingAdd(
            SQLitePersistentStoreAdmission.saturatingAdd(
                footprint,
                estimatedTransactionBytes
            ),
            reserve
        )
        if required > cap {
            // v1.21.6-rc.46: report every term the test actually used.
            //
            // This threw `reserveBytes: reserve`, omitting
            // `estimatedTransactionBytes` — so the operator-visible message
            // read "family footprint 266848656 plus 33554432 reserve exceeds
            // 335544320 bytes", an arithmetic claim that is false on its face
            // (286.5 MiB does not exceed 320 MiB; 33.5 MiB was spare). A
            // refusal whose stated numbers do not justify it teaches the
            // operator to distrust the message rather than the condition.
            throw SQLitePersistentStoreAdmissionError.footprintLimit(
                footprintBytes: footprint,
                reserveBytes: SQLitePersistentStoreAdmission.saturatingAdd(
                    estimatedTransactionBytes,
                    reserve
                ),
                maxFootprintBytes: cap
            )
        }
    }

    /// Retention/reclaim writes are the bounded route back under the ceiling.
    private func admitStorageMaintenanceWrite(
        estimatedTransactionBytes: Int64
    ) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitMaintenanceWrite(
            estimatedTransactionBytes: estimatedTransactionBytes
        )
    }

    /// A checkpoint can copy the complete WAL into main while leaving the WAL
    /// allocated. It therefore has a whole-sidecar gate, not the small ordinary
    /// maintenance transaction gate.
    private func admitStorageCheckpoint() throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitCheckpoint()
    }

    private var storageTransactionReserveBytes: Int64 {
        storageAdmission?.transactionReserveBytes
            ?? SQLitePersistentStorePolicy.eventTransactionReserveBytes
    }

    private func maintenanceRowMutationUpperBound() -> Int64 {
        if maintenanceHighWaterScannedExistingRows,
           let cached = maintenanceRowMutationHighWaterBytes {
            return max(
                SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
                cached
            )
        }
        guard let db else { return storageTransactionReserveBytes }

        func maximumLogicalBytes(
            table: String,
            columns: [String],
            duplicatedIndexColumns: [String],
            indexRepresentationCount: Int64,
            ftsColumns: [String] = []
        ) -> Int64? {
            func length(_ column: String) -> String {
                "COALESCE(length(CAST(\"\(column)\" AS BLOB)), 0)"
            }
            var terms = columns.map(length)
            terms.append(contentsOf: duplicatedIndexColumns.map(length))
            terms.append(contentsOf: ftsColumns.map {
                "4 * \(length($0))"
            })
            let fixed = SQLitePersistentStoreAdmission.saturatingAdd(
                Int64(columns.count * 16),
                SQLitePersistentStoreAdmission.saturatingMultiply(
                    indexRepresentationCount, by: 16
                )
            )
            let expression = ([String(fixed)] + terms)
                .joined(separator: " + ")
            var statement: OpaquePointer?
            guard sqlite3_prepare_v2(
                db,
                "SELECT COALESCE(MAX(\(expression)), 0) FROM \"\(table)\"",
                -1,
                &statement,
                nil
            ) == SQLITE_OK, let statement else {
                sqlite3_finalize(statement)
                return nil
            }
            defer { sqlite3_finalize(statement) }
            guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
            return max(0, sqlite3_column_int64(statement, 0))
        }

        let eventColumns = [
            "id", "timestamp", "event_category", "event_type", "event_action",
            "severity", "process_pid", "process_name", "process_path",
            "process_commandline", "process_ppid", "process_signer",
            "process_team_id", "process_signing_id", "file_path", "file_action",
            "network_dest_ip", "network_dest_port", "tcc_service", "tcc_client",
            "raw_json", "mcp_server_name", "mcp_server_category",
            "ai_tool_session_id", "agent_trace_id", "agent_span_id", "agent_tool",
            "machine_agent_confidence", "agent_evidence_json", "user_id",
            "user_name", "group_id", "working_directory", "responsible_pid",
            "architecture", "is_platform_binary", "is_notarized",
            "process_sha256", "parent_name", "parent_executable",
            "parent_signer_type", "ai_tool", "ai_tool_child",
            "session_launch_source", "tcc_decision",
        ]
        let eventIndexes = [
            "id", "event_category", "event_category", "event_category",
            "event_category", "severity", "severity", "severity",
            "process_path", "mcp_server_name", "agent_trace_id",
            "ai_tool_session_id", "user_id", "ai_tool", "parent_executable",
        ]
        let eventFTS = [
            "process_name", "process_path", "process_commandline", "file_path",
            "network_dest_ip", "tcc_service", "tcc_client",
        ]
        let evidenceColumns = [
            "alert_id", "id", "timestamp", "event_category", "event_type",
            "event_action", "severity", "process_pid", "process_name",
            "process_path", "process_commandline", "process_ppid",
            "process_signer", "process_team_id", "process_signing_id",
            "file_path", "file_action", "network_dest_ip", "network_dest_port",
            "tcc_service", "tcc_client", "raw_json", "mcp_server_name",
            "mcp_server_category", "ai_tool_session_id",
        ]
        let candidates: [Int64?] = [
            maximumLogicalBytes(
                table: "events",
                columns: eventColumns,
                duplicatedIndexColumns: eventIndexes,
                indexRepresentationCount: 14,
                ftsColumns: eventFTS
            ),
            maximumLogicalBytes(
                table: "alert_evidence",
                columns: evidenceColumns,
                duplicatedIndexColumns: ["alert_id", "alert_id", "id", "id"],
                indexRepresentationCount: 3
            ),
            maximumLogicalBytes(
                table: "event_aggregates",
                columns: ["day", "event_category", "process_signer", "process_path", "count"],
                duplicatedIndexColumns: [
                    "day", "day", "day", "event_category", "event_category",
                    "process_signer", "process_path",
                ],
                indexRepresentationCount: 3
            ),
            maximumLogicalBytes(
                table: "attribution_overrides",
                columns: [
                    "event_id", "machine_confidence", "user_verdict", "user_note",
                    "schema_version", "created_at", "updated_at",
                ],
                duplicatedIndexColumns: ["event_id", "user_verdict"],
                indexRepresentationCount: 3
            ),
        ]
        var upper = max(
            SQLitePersistentStoreAdmission.conservativeRowMutationBytes,
            maintenanceRowMutationHighWaterBytes ?? 0
        )
        for logical in candidates.compactMap({ $0 }) {
            upper = max(
                upper,
                SQLitePersistentStoreAdmission
                    .conservativeEncodedRowMutationBytes(
                        logicalRepresentationBytes: logical,
                        pageSizeBytes: sqlitePageSizeBytes,
                        maximumLeafPageTouches: 20
                    )
            )
        }
        maintenanceRowMutationHighWaterBytes = upper
        maintenanceHighWaterScannedExistingRows = true
        return upper
    }

    private func maintenanceBatchRowLimit(
        mutationsPerCandidate: Int = 1
    ) -> Int32 {
        let fixed = SQLitePersistentStoreAdmission.transactionFixedOverheadBytes(
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 48
        )
        let bytesPerCandidate = SQLitePersistentStoreAdmission
            .saturatingMultiply(
                maintenanceRowMutationUpperBound(),
                by: Int64(max(1, mutationsPerCandidate))
            )
        let available = max(0, storageTransactionReserveBytes - fixed)
        let rows = SQLitePersistentStoreAdmission.maximumRowsPerTransaction(
            reserveBytes: available,
            bytesPerRow: bytesPerCandidate
        )
        return Int32(clamping: max(1, rows))
    }

    private func maintenanceEstimate(
        rowCount: Int,
        mutationsPerCandidate: Int = 1
    ) -> Int64 {
        let rowBytes = SQLitePersistentStoreAdmission.saturatingMultiply(
            maintenanceRowMutationUpperBound(),
            by: Int64(max(1, mutationsPerCandidate))
        )
        return SQLitePersistentStoreAdmission.conservativeTransactionBytes(
            rowMutationBytes: SQLitePersistentStoreAdmission.saturatingMultiply(
                Int64(max(0, rowCount)), by: rowBytes
            ),
            pageSizeBytes: sqlitePageSizeBytes,
            maximumTreePathPageTouches: 48
        )
    }

    private func admitStorageSchemaRebuild(operationCount: Int = 1) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitSchemaRebuild(operationCount: operationCount)
    }

    private func admitStorageFullVacuum() throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        try admission.admitFullVacuum()
    }

    private func throwLatchedStoragePressureIfPresent(resultCode: Int32) throws {
        if let pressure = latchStoragePressureIfPresent(resultCode: resultCode) {
            throw pressure
        }
    }

    @discardableResult
    private func latchStoragePressureIfPresent(
        resultCode: Int32
    ) -> SQLitePersistentStoreAdmissionError? {
        guard var admission = storageAdmission else { return nil }
        defer { storageAdmission = admission }
        return admission.latchSQLitePressure(resultCode: resultCode, db: db)
    }

    private func throwLatchedStoragePressureIfPresent(
        details: SQLiteFailureDetails
    ) throws {
        guard var admission = storageAdmission else { return }
        defer { storageAdmission = admission }
        if let pressure = admission.latchSQLitePressure(details: details) {
            throw pressure
        }
    }

    public func storageAdmissionSnapshot() -> SQLitePersistentStoreAdmissionSnapshot? {
        guard var admission = storageAdmission else { return nil }
        defer { storageAdmission = admission }
        return admission.snapshot()
    }

    /// Proves capacity for a maximum supported fresh base in `lane`, including
    /// the full post-commit terminal reserve, while holding SQLite's writer
    /// lock. The empty transaction is rolled back without DML. Maintenance
    /// cannot clear a sticky pressure latch, so recovery first runs the normal
    /// reopening path, then proves the stronger serialized producer boundary.
    @discardableResult
    public func reprobeStorageAdmissionForWrite(
        lane: EventPipelineLane
    ) throws -> SQLitePersistentStoreAdmissionSnapshot {
        guard !isReadOnly, db != nil else {
            throw EventStoreError.stepFailed(
                "event storage admission reprobe requires a writable database"
            )
        }
        guard storageAdmission != nil else {
            throw EventStoreError.stepFailed(
                "event storage admission reprobe requires an active policy"
            )
        }

        // Keep the ordinary gate: it reopens a recovered shed-only connection
        // and prepares its writer. It can replace db, and proves only one
        // reserve, so it cannot itself authorize a fresh journal base.
        try admitStorageWrite(
            estimatedTransactionBytes: storageTransactionReserveBytes,
            lane: lane
        )

        guard insertStmt != nil, let db else {
            throw EventStoreError.stepFailed(
                "event storage admission recovered without a writer statement"
            )
        }
        let reserve = storageTransactionReserveBytes
        try beginSerializedWrite(
            estimatedBytes: reserve,
            postCommitHeadroomBytes: reserve,
            lane: lane
        )
        do {
            // Use the exact measurements admitted under this writer lock.
            // The public status snapshot re-probes best-effort and could
            // replace them with unvalidated values or suppress a probe error.
            guard let admission = storageAdmission,
                  let footprint = admission.lastFootprintBytes,
                  let freeSpace = admission.lastFreeSpaceBytes,
                  admission.latchedFailure == nil,
                  !admission.pageLimitPending else {
                throw EventStoreError.stepFailed(
                    "event storage admission remained blocked after serialized reprobe"
                )
            }
            let snapshot = SQLitePersistentStoreAdmissionSnapshot(
                enabled: true,
                footprintBytes: footprint,
                freeSpaceBytes: freeSpace,
                maxFootprintBytes: admission.policy.maxFootprintBytes,
                freeSpaceFloorBytes: admission.policy.freeSpaceFloorBytes,
                transactionReserveBytes: admission.transactionReserveBytes,
                latchedFailure: nil,
                pageLimitPending: false
            )
            // A rollback failure is a failed proof. Never return success while
            // this connection might still own the empty writer transaction.
            try Self.exec(db, "ROLLBACK")
            return snapshot
        } catch {
            try? Self.exec(db, "ROLLBACK")
            throw error
        }
    }

    /// Focused admission fixtures replace measurements, retaining the actual
    /// private SQLite connection, policy and installed page ceiling.
    internal func setStorageAdmissionProbesForTesting(
        footprint: @escaping SQLitePersistentStoreAdmission.FootprintProbe,
        freeSpace: @escaping SQLitePersistentStoreAdmission.FreeSpaceProbe
    ) throws {
        guard !isReadOnly, let db, let policy = storagePolicy,
              sqlite3_get_autocommit(db) != 0 else {
            throw EventStoreError.stepFailed(
                "admission fixture requires an idle writable connection"
            )
        }
        var admission = try SQLitePersistentStoreAdmission(
            databasePath: databasePath,
            policy: policy,
            footprintProbe: footprint,
            freeSpaceProbe: freeSpace
        )
        try admission.installPageLimit(on: db)
        storageAdmission = admission
    }

    internal func storageAdmissionConnectionStateForTesting() throws -> (
        inTransaction: Bool, totalChanges: Int64
    ) {
        guard let db else {
            throw EventStoreError.stepFailed("admission fixture has no database")
        }
        return (sqlite3_get_autocommit(db) == 0, sqlite3_total_changes64(db))
    }

    public func updateStorageAdmission(
        _ policy: SQLitePersistentStorePolicy
    ) throws -> SQLitePersistentStoreAdmissionSnapshot? {
        guard !isReadOnly, let db else { return nil }
        guard var admission = storageAdmission else {
            var created = try SQLitePersistentStoreAdmission(
                databasePath: databasePath,
                policy: policy,
                latchOperationalPressure: true
            )
            try checkpointController?.updateFamily(
                schema: "main",
                configuration: SQLiteControlledCheckpointFamily(
                    databasePath: databasePath,
                    policy: policy
                )
            )
            do {
                try created.installPageLimit(on: db)
            } catch let error as SQLitePersistentStoreAdmissionError
                where error.isOperationalPressure {
                // Retained as a sticky pending ceiling.
            } catch {
                storagePolicy = policy
                storageAdmission = created
                throw error
            }
            storagePolicy = policy
            storageAdmission = created
            return created.snapshot()
        }
        let wasBlocked = admission.growthBlocked
        let writerSetupPending = !isReadOnly && insertStmt == nil
        let result: SQLitePersistentStoreAdmissionSnapshot
        do {
            result = try admission.updatePolicy(policy, on: db)
        } catch {
            storageAdmission = admission
            storagePolicy = policy
            try? checkpointController?.updateFamily(
                schema: "main",
                configuration: SQLiteControlledCheckpointFamily(
                    databasePath: databasePath,
                    policy: policy
                )
            )
            throw error
        }
        storageAdmission = admission
        storagePolicy = policy
        try checkpointController?.updateFamily(
            schema: "main",
            configuration: SQLiteControlledCheckpointFamily(
                databasePath: databasePath,
                policy: policy
            )
        )
        if (wasBlocked || writerSetupPending) && !admission.growthBlocked {
            try reopenAfterStorageRecovery()
            return storageAdmissionSnapshot()
        }
        return result
    }

    private func reopenAfterStorageRecovery() throws {
        guard let policy = storagePolicy else { return }
        let (
            newDB,
            newReadOnly,
            newStatement,
            newAdmission,
            newPageSizeBytes,
            newCheckpointController
        ) = try Self.openDatabase(
            at: databasePath,
            forceReadOnly: false,
            storagePolicy: policy,
            liveMemoryBudget: liveMemoryBudget
        )
        if let insertStmt { sqlite3_finalize(insertStmt) }
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
        db = newDB
        isReadOnly = newReadOnly
        insertStmt = newStatement
        storageAdmission = newAdmission
        sqlitePageSizeBytes = newPageSizeBytes
        checkpointController = newCheckpointController
    }

    /// Prepares a SQL statement.
    private func prepare(_ sql: String) throws -> OpaquePointer {
        try checkReadOnlyRetirement()
        var stmt: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard rc == SQLITE_OK, let stmt else {
            let msg = db.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            throw EventStoreError.prepareFailed(msg)
        }
        return stmt
    }

    /// Runs a short-lived statement and guarantees finalization on every
    /// success and throw path. Exact-evidence reads deliberately use this
    /// instead of branch-local finalization: a surviving reader can pin the
    /// WAL indefinitely and prevent the retention controller from recovering.
    private func withPreparedStatement<T>(
        _ sql: String,
        _ body: (OpaquePointer) throws -> T
    ) throws -> T {
        let statement = try prepare(sql)
        defer { sqlite3_finalize(statement) }
        return try body(statement)
    }

    /// Binds a non-nil text value to a prepared statement parameter.
    ///
    /// Uses `SQLITE_TRANSIENT` so SQLite copies the string immediately,
    /// making it safe even though the C string pointer is only valid inside
    /// the `withCString` closure.
    private func bindText(_ stmt: OpaquePointer, index: Int32, value: String) {
        _ = value.withCString { cstr in
            sqlite3_bind_text(stmt, index, cstr, -1,
                              unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        }
    }

    /// Bind an owned Data value with SQLITE_TRANSIENT semantics.
    private func bindBlob(_ stmt: OpaquePointer, index: Int32, value: Data) {
        value.withUnsafeBytes { bytes in
            _ = sqlite3_bind_blob(
                stmt,
                index,
                bytes.baseAddress,
                Int32(value.count),
                unsafeBitCast(-1, to: sqlite3_destructor_type.self)
            )
        }
    }

    /// Binds a text value or NULL to a prepared statement parameter.
    private func bindTextOrNull(_ stmt: OpaquePointer, index: Int32, value: String?) {
        if let value {
            bindText(stmt, index: index, value: value)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    /// Runs a SELECT query that returns `raw_json` as the first column and
    /// decodes each row into an `Event`.
    private func queryEvents(
        sql: String,
        bindings: [(Int32, BindingValue)]
    ) throws -> [Event] {
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }

        for (index, value) in bindings {
            switch value {
            case .text(let s):
                bindText(stmt, index: index, value: s)
            case .double(let d):
                sqlite3_bind_double(stmt, index, d)
            case .int(let i):
                sqlite3_bind_int(stmt, index, i)
            case .null:
                sqlite3_bind_null(stmt, index)
            }
        }

        var results: [Event] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let cstr = sqlite3_column_text(stmt, 0) else { continue }
            let jsonString = String(cString: cstr)
            guard let jsonData = jsonString.data(using: .utf8) else { continue }
            do {
                let event = try decoder.decode(Event.self, from: jsonData)
                results.append(event)
            } catch {
                // Skip malformed rows rather than failing the entire query.
                continue
            }
        }
        return results
    }

    /// Projection rows are authenticated against canonical journal state at
    /// open/finalization. Proof-carrying sparse search must nevertheless fail
    /// closed if a malformed row appears later; silently skipping it would turn
    /// a corruption into a plausible empty or partial match set.
    private func queryEventsStrict(
        sql: String,
        bindings: [(Int32, BindingValue)]
    ) throws -> [Event] {
        let stmt = try prepare(sql)
        defer { sqlite3_finalize(stmt) }
        for (index, value) in bindings {
            switch value {
            case .text(let string):
                bindText(stmt, index: index, value: string)
            case .double(let value):
                sqlite3_bind_double(stmt, index, value)
            case .int(let value):
                sqlite3_bind_int(stmt, index, value)
            case .null:
                sqlite3_bind_null(stmt, index)
            }
        }
        var results: [Event] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return results }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "proof-carrying sparse event query failed"
                )
            }
            guard sqlite3_column_type(stmt, 0) == SQLITE_TEXT,
                  let pointer = sqlite3_column_text(stmt, 0) else {
                throw EventStoreError.decodingFailed(
                    "sparse projection raw_json has an invalid storage class"
                )
            }
            let count = Int(sqlite3_column_bytes(stmt, 0))
            guard count > 0 else {
                throw EventStoreError.decodingFailed(
                    "sparse projection raw_json is empty"
                )
            }
            let data = Data(bytes: pointer, count: count)
            do {
                results.append(try decoder.decode(Event.self, from: data))
            } catch {
                throw EventStoreError.decodingFailed(
                    "sparse projection raw_json is malformed"
                )
            }
        }
    }

    // MARK: - v1.9 PR-4: attribution_overrides

    /// Insert or replace an operator verdict for an event. Idempotent on
    /// `(eventId)`: a second call REPLACES the prior verdict and bumps
    /// `updated_at`. Documents Plan v3 review #10's "single source of
    /// truth per event" contract.
    public func recordAttributionOverride(_ override: AttributionOverride) throws {
        let logicalBytes = [
            override.eventId,
            override.machineConfidence,
            override.verdict.rawValue,
            override.userNote,
        ].reduce(Int64(64)) { total, value in
            SQLitePersistentStoreAdmission.saturatingAdd(
                total,
                Int64(value?.utf8.count ?? 0)
            )
        }
        let indexedLogicalBytes = SQLitePersistentStoreAdmission.saturatingAdd(
            logicalBytes,
            Int64(override.eventId.utf8.count
                + override.verdict.rawValue.utf8.count + 3 * 16)
        )
        let newRowBytes = SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: indexedLogicalBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 4
            )
        let preflightEstimate = SQLitePersistentStoreAdmission
            .conservativeTransactionBytes(
                rowMutationBytes: newRowBytes,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumTreePathPageTouches: 8
            )
        try beginSerializedWrite(
            estimatedBytes: preflightEstimate,
            lane: .priority
        )
        guard let db else {
            try? execute("ROLLBACK")
            throw EventStoreError.databaseOpenFailed("db not open")
        }
        let sql = """
            INSERT INTO attribution_overrides (
                event_id, machine_confidence, user_verdict, user_note,
                schema_version, created_at, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(event_id) DO UPDATE SET
                user_verdict = excluded.user_verdict,
                user_note = excluded.user_note,
                machine_confidence = excluded.machine_confidence,
                schema_version = excluded.schema_version,
                updated_at = excluded.updated_at
            """
        do {
            // The old row can change while a caller waits for SQLite's writer
            // lock. Charge its exact stored representation only after BEGIN
            // IMMEDIATE, then repeat the authoritative family/free-space gate
            // before the first UPSERT page is touched.
            let rowBytes = SQLitePersistentStoreAdmission.saturatingAdd(
                newRowBytes,
                try existingAttributionOverrideMutationBytes(
                    eventId: override.eventId
                )
            )
            let estimate = SQLitePersistentStoreAdmission
                .conservativeTransactionBytes(
                    rowMutationBytes: rowBytes,
                    pageSizeBytes: sqlitePageSizeBytes,
                    maximumTreePathPageTouches: 8
                )
            try requireCurrentFamilyCapacityUnderWriterLock(
                estimatedBytes: estimate,
                postCommitHeadroomBytes:
                    terminalPoisonSettlementHeadroomBytes,
                lane: .priority
            )
            var stmt: OpaquePointer?
            defer { if let s = stmt { sqlite3_finalize(s) } }
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw EventStoreError.prepareFailed(
                    String(cString: sqlite3_errmsg(db))
                )
            }
            let transient = unsafeBitCast(
                OpaquePointer(bitPattern: -1)!,
                to: sqlite3_destructor_type.self
            )
            sqlite3_bind_text(stmt, 1, override.eventId, -1, transient)
            if let mc = override.machineConfidence {
                sqlite3_bind_text(stmt, 2, mc, -1, transient)
            } else {
                sqlite3_bind_null(stmt, 2)
            }
            sqlite3_bind_text(
                stmt, 3, override.verdict.rawValue, -1, transient
            )
            if let note = override.userNote {
                sqlite3_bind_text(stmt, 4, note, -1, transient)
            } else {
                sqlite3_bind_null(stmt, 4)
            }
            sqlite3_bind_int(stmt, 5, Int32(override.schemaVersion))
            sqlite3_bind_double(
                stmt, 6, override.createdAt.timeIntervalSince1970
            )
            sqlite3_bind_double(
                stmt, 7, override.updatedAt.timeIntervalSince1970
            )
            let rc = sqlite3_step(stmt)
            guard rc == SQLITE_DONE else {
                try throwLatchedStoragePressureIfPresent(resultCode: rc)
                throw EventStoreError.stepFailed(
                    String(cString: sqlite3_errmsg(db))
                )
            }
            try execute("COMMIT")
            maintenanceRowMutationHighWaterBytes = max(
                maintenanceRowMutationHighWaterBytes ?? 0,
                rowBytes
            )
        } catch {
            try? execute("ROLLBACK")
            throw error
        }
    }

    private func existingAttributionOverrideMutationBytes(
        eventId: String
    ) throws -> Int64 {
        guard let db else { return 0 }
        let sql = """
            SELECT event_id, machine_confidence, user_verdict, user_note,
                   schema_version, created_at, updated_at
            FROM attribution_overrides WHERE event_id = ?1 LIMIT 1
            """
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK,
              let statement else {
            sqlite3_finalize(statement)
            throw EventStoreError.prepareFailed(
                "existing attribution override estimate"
            )
        }
        defer { sqlite3_finalize(statement) }
        bindText(statement, index: 1, value: eventId)
        let step = sqlite3_step(statement)
        if step == SQLITE_DONE { return 0 }
        guard step == SQLITE_ROW else {
            try throwLatchedStoragePressureIfPresent(resultCode: step)
            throw EventStoreError.stepFailed(
                "existing attribution override estimate step"
            )
        }
        func bytes(_ column: Int32) -> Int64 {
            sqlite3_column_type(statement, column) == SQLITE_NULL
                ? 0 : Int64(sqlite3_column_bytes(statement, column))
        }
        var logical = Int64(7 * 16)
        for column in Int32(0)..<Int32(7) {
            logical = SQLitePersistentStoreAdmission.saturatingAdd(
                logical, bytes(column)
            )
        }
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical,
            SQLitePersistentStoreAdmission.saturatingAdd(
                bytes(0), bytes(2)
            )
        )
        logical = SQLitePersistentStoreAdmission.saturatingAdd(
            logical, 3 * 16
        )
        return SQLitePersistentStoreAdmission
            .conservativeEncodedRowMutationBytes(
                logicalRepresentationBytes: logical,
                pageSizeBytes: sqlitePageSizeBytes,
                maximumLeafPageTouches: 4
            )
    }

    /// Look up the operator verdict for a given event, or nil if none.
    public func attributionOverride(for eventId: String) throws -> AttributionOverride? {
        guard let db else { return nil }
        let sql = """
            SELECT machine_confidence, user_verdict, user_note,
                   schema_version, created_at, updated_at
            FROM attribution_overrides
            WHERE event_id = ?1
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.prepareFailed(msg)
        }
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(stmt, 1, eventId, -1, TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
        let mc: String? = sqlite3_column_type(stmt, 0) == SQLITE_NULL
            ? nil
            : String(cString: sqlite3_column_text(stmt, 0))
        let verdictRaw = String(cString: sqlite3_column_text(stmt, 1))
        // Tolerant decode: unknown future verdicts surface as `.unknown`.
        let verdict = AttributionOverride.Verdict(rawValue: verdictRaw) ?? .unknown
        let note: String? = sqlite3_column_type(stmt, 2) == SQLITE_NULL
            ? nil
            : String(cString: sqlite3_column_text(stmt, 2))
        let schemaVersion = Int(sqlite3_column_int(stmt, 3))
        let createdAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
        let updatedAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 5))
        return AttributionOverride(
            eventId: eventId,
            machineConfidence: mc,
            verdict: verdict,
            userNote: note,
            createdAt: createdAt,
            updatedAt: updatedAt,
            schemaVersion: schemaVersion
        )
    }

    /// Compute aggregate stats. Plan v3 review #11: the metric only makes
    /// sense in the "rated" frame; callers must use
    /// `formattedAccuracyLine` to print it.
    public func attributionOverrideStats() throws -> AttributionOverrideStats {
        guard let db else {
            return AttributionOverrideStats(
                ratedCount: 0, confirmedCount: 0,
                wrongToolCount: 0, noAgentCount: 0, unknownVerdictCount: 0,
                totalEventsWithMachineAttribution: 0
            )
        }
        // Per-verdict counts
        let sql1 = """
            SELECT user_verdict, COUNT(*)
            FROM attribution_overrides
            GROUP BY user_verdict
            """
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        guard sqlite3_prepare_v2(db, sql1, -1, &stmt, nil) == SQLITE_OK else {
            let msg = String(cString: sqlite3_errmsg(db))
            throw EventStoreError.prepareFailed(msg)
        }
        var rated = 0, confirmed = 0, wrongTool = 0, noAgent = 0, unknownVerdict = 0
        while sqlite3_step(stmt) == SQLITE_ROW {
            let verdict = String(cString: sqlite3_column_text(stmt, 0))
            let count = Int(sqlite3_column_int64(stmt, 1))
            rated += count
            switch verdict {
            case AttributionOverride.Verdict.confirmed.rawValue: confirmed = count
            case AttributionOverride.Verdict.wrongTool.rawValue: wrongTool = count
            case AttributionOverride.Verdict.noAgent.rawValue:   noAgent = count
            case AttributionOverride.Verdict.unknown.rawValue:   unknownVerdict = count
            default: break
            }
        }

        // Machine attribution belongs to the exact canonical corpus, not the
        // four-row/sec interactive projection.
        let total = try eventCountWithMachineAttribution()

        return AttributionOverrideStats(
            ratedCount: rated,
            confirmedCount: confirmed,
            wrongToolCount: wrongTool,
            noAgentCount: noAgent,
            unknownVerdictCount: unknownVerdict,
            totalEventsWithMachineAttribution: total
        )
    }

    /// v1.9 PR-5 audit (B3): roll-up surface used by AttributionOverrideStore
    /// to compute `AttributionOverrideStats`. This is a read-only query
    /// — works under the dashboard's read-only fallback path on a
    /// root-owned `events.db`. Counts events that received any machine
    /// attribution (either via TRACEPARENT or lineage).
    public func eventCountWithMachineAttribution() throws -> Int {
        try withVerifiedExactReadSnapshot { _ in
            try requireGloballyCompleteExactCorpus()
            var total = 0
            func include(_ event: Event) throws {
                guard event.enrichments["agent_trace_id"] != nil
                        || event.enrichments["agent_tool"] != nil else {
                    return
                }
                let next = total.addingReportingOverflow(1)
                guard !next.overflow else {
                    throw EventStoreError.decodingFailed(
                        "exact machine-attribution count overflowed"
                    )
                }
                total = next.partialValue
            }
            for summary in verifiedJournalSummaries where
                !isJournalBlockTombstoned(summary.blockID) {
                for event in try loadExactJournalBlock(
                    blockID: summary.blockID
                ).events {
                    try include(event)
                }
            }
            try forEachExactLegacyEvent(include)
            return total
        }
    }

    /// Called only while this connection owns BEGIN IMMEDIATE. Resolve retained
    /// existence against the authenticated UUID roster plus the validated
    /// migration tail/quarantine, never against the sparse `events` projection.
    private func exactEventExistsUnderWriterLock(_ id: UUID) throws -> Bool {
        try ensureJournalIndex()
        if try existingJournalLocations(for: Set([id]))[id] != nil {
            return true
        }
        let legacy = try prepare(
            "SELECT 1 FROM events WHERE journal_block_id IS NULL AND id = ?1 LIMIT 1"
        )
        bindText(legacy, index: 1, value: id.uuidString)
        let legacyRC = sqlite3_step(legacy)
        sqlite3_finalize(legacy)
        if legacyRC == SQLITE_ROW { return true }
        guard legacyRC == SQLITE_DONE else {
            throw EventStoreError.stepFailed(
                "exact attribution legacy-existence lookup failed"
            )
        }
        guard try hasJournalSchema() else { return false }
        // A malformed typed UUID can still have a trustworthy canonical raw
        // UUID in a retained quarantine row. Quarantine is low-cardinality and
        // this sweep is operator-scale, so stream one bounded raw value at a
        // time instead of constructing an identity Set.
        let quarantine = try prepare(
            "SELECT raw_json FROM event_journal_legacy_quarantine ORDER BY quarantine_id"
        )
        defer { sqlite3_finalize(quarantine) }
        while true {
            let rc = sqlite3_step(quarantine)
            if rc == SQLITE_DONE { return false }
            guard rc == SQLITE_ROW else {
                throw EventStoreError.stepFailed(
                    "exact attribution quarantine-existence lookup failed"
                )
            }
            let count = Int(sqlite3_column_bytes(quarantine, 0))
            guard count >= 0,
                  count == 0 || sqlite3_column_blob(quarantine, 0) != nil else {
                throw EventStoreError.decodingFailed(
                    "exact attribution quarantine raw bytes are unavailable"
                )
            }
            let raw = count == 0 ? Data() : Data(
                bytes: sqlite3_column_blob(quarantine, 0)!,
                count: count
            )
            if (try? decoder.decode(Event.self, from: raw))?.id == id {
                return true
            }
        }
    }

    /// Sweep override rows whose `event_id` no longer points at a row in
    /// `events`. Pass 12 invariant: every override row has a matching
    /// event row, so this is called from the existing retention sweep.
    /// Returns the number of orphaned rows removed.
    @discardableResult
    public func purgeOrphanedAttributionOverrides() throws -> Int {
        guard let db else { return 0 }
        let batch = maintenanceBatchRowLimit()
        let estimate = maintenanceEstimate(rowCount: Int(batch))
        var changes = 0
        var lastRowID: Int64 = 0
        while true {
            try beginSerializedWrite(
                estimatedBytes: estimate,
                maintenance: true
            )
            do {
                let select = try prepare(
                    "SELECT rowid, event_id FROM attribution_overrides WHERE rowid > ?1 ORDER BY rowid LIMIT ?2"
                )
                sqlite3_bind_int64(select, 1, lastRowID)
                sqlite3_bind_int(select, 2, batch)
                var rows: [(rowID: Int64, eventID: UUID?)] = []
                var selectRC = sqlite3_step(select)
                while selectRC == SQLITE_ROW {
                    let rowID = sqlite3_column_int64(select, 0)
                    let eventID = sqlite3_column_text(select, 1).flatMap {
                        UUID(uuidString: String(cString: $0))
                    }
                    rows.append((rowID, eventID))
                    selectRC = sqlite3_step(select)
                }
                sqlite3_finalize(select)
                guard selectRC == SQLITE_DONE else {
                    throw EventStoreError.stepFailed(
                        "purge attribution override scan failed"
                    )
                }
                guard !rows.isEmpty else {
                    try execute("COMMIT")
                    break
                }
                var orphanRowIDs: [Int64] = []
                for row in rows {
                    guard let eventID = row.eventID else {
                        orphanRowIDs.append(row.rowID)
                        continue
                    }
                    if try !exactEventExistsUnderWriterLock(eventID) {
                        orphanRowIDs.append(row.rowID)
                    }
                }
                if !orphanRowIDs.isEmpty {
                    let list = orphanRowIDs.map(String.init)
                        .joined(separator: ",")
                    try execute(
                        "DELETE FROM attribution_overrides WHERE rowid IN (\(list))"
                    )
                    guard sqlite3_changes(db)
                            == Int32(orphanRowIDs.count) else {
                        throw EventStoreError.stepFailed(
                            "purge attribution overrides deleted an unexpected row count"
                        )
                    }
                    changes += orphanRowIDs.count
                }
                lastRowID = rows.last?.rowID ?? lastRowID
                let complete = rows.count < Int(batch)
                try execute("COMMIT")
                if complete { break }
            } catch {
                try? execute("ROLLBACK")
                throw error
            }
        }
        return changes
    }
}
