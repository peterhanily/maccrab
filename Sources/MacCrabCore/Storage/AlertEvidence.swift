// AlertEvidence.swift
// MacCrabCore
//
// Durable alert context belongs to alerts.db, alongside the alert whose
// lifetime owns it. events.db remains the bounded raw-event/search tier.

import Foundation

/// One already-persisted event selected as context for an alert.
///
/// The source store returns the original `raw_json` bytes rather than a second
/// projection of Event's fields. AlertStore validates the payload before it is
/// admitted, then stores only this record's four durable values.
public struct AlertEvidenceCandidate: Sendable, Equatable {
    public let eventId: String
    public let timestamp: Date
    public let rawJSON: String

    public init(eventId: String, timestamp: Date, rawJSON: String) {
        self.eventId = eventId
        self.timestamp = timestamp
        self.rawJSON = rawJSON
    }
}

/// Fixed capture bounds. These are code invariants rather than configuration
/// knobs so a malformed request cannot turn one alert into an unbounded copy
/// of the event stream.
public enum AlertEvidencePolicy {
    public static let lookbackSeconds: TimeInterval = 30
    public static let maximumEventsPerAlert = 50
    public static let maximumRawPayloadBytes = 65_536
}

/// Result of one best-effort post-alert evidence capture.
public struct AlertEvidenceCaptureResult: Sendable, Equatable {
    public let insertedRows: Int
    public let duplicateRows: Int
    public let prunedRows: Int

    public init(insertedRows: Int, duplicateRows: Int, prunedRows: Int) {
        self.insertedRows = insertedRows
        self.duplicateRows = duplicateRows
        self.prunedRows = prunedRows
    }
}

/// One actor-consistent view of the bounded post-commit capture lane.
///
/// Every accepted alert owns exactly one terminal or outstanding state:
///
///     offered = completed + failures + shed + pending + inFlight
///
/// `completed` includes successful captures that found no eligible event rows;
/// those jobs still reached a terminal, non-loss outcome. `shed` includes both
/// queue-cap rejection and offers made after the lane was sealed for shutdown.
public struct AlertEvidenceCaptureTelemetry: Sendable, Equatable {
    public let offered: Int
    public let completed: Int
    public let shed: Int
    public let shedAtShutdownDeadline: Int
    public let failures: Int
    public let pending: Int
    public let inFlight: Int
    public let capturedRows: Int
    public let prunedRows: Int
    public let budgetBytes: Int64
    public let queueCapacity: Int
    public let accepting: Bool
    /// Prefix barriers that did not settle before their bounded deadline.
    /// The triggering Event carried by the request is still captured, but the
    /// wider preceding window may be incomplete and must be reported as such.
    public let prefixBarrierTimeouts: Int
    /// Alert rows refused after the terminal seal, including pre-seal methods
    /// that were suspended in dedup and had not started their durable write.
    /// These are distinct from rule deduplication and evidence-queue shedding.
    public let alertsRejectedAfterSeal: Int
    /// Alert submissions accepted before the seal but still executing across
    /// an actor suspension at snapshot time.
    public let alertAdmissionsInFlight: Int

    public var conserved: Bool {
        offered == completed + shed + failures + pending + inFlight
    }

    public init(
        offered: Int,
        completed: Int,
        shed: Int,
        shedAtShutdownDeadline: Int = 0,
        failures: Int,
        pending: Int,
        inFlight: Int,
        capturedRows: Int,
        prunedRows: Int,
        budgetBytes: Int64,
        queueCapacity: Int,
        accepting: Bool,
        prefixBarrierTimeouts: Int = 0,
        alertsRejectedAfterSeal: Int = 0,
        alertAdmissionsInFlight: Int = 0
    ) {
        self.offered = offered
        self.completed = completed
        self.shed = shed
        self.shedAtShutdownDeadline = shedAtShutdownDeadline
        self.failures = failures
        self.pending = pending
        self.inFlight = inFlight
        self.capturedRows = capturedRows
        self.prunedRows = prunedRows
        self.budgetBytes = budgetBytes
        self.queueCapacity = queueCapacity
        self.accepting = accepting
        self.prefixBarrierTimeouts = prefixBarrierTimeouts
        self.alertsRejectedAfterSeal = alertsRejectedAfterSeal
        self.alertAdmissionsInFlight = alertAdmissionsInFlight
    }
}

/// Result of the sink's bounded terminal seal.
///
/// `completed`, `failed`, and `shedAtDeadline` describe evidence jobs. A job
/// still running when the deadline expires remains `pending`; it is never
/// relabelled as completed or failed merely to make shutdown look clean.
/// `alertAdmissionsInFlight` similarly exposes pre-seal alert submissions that
/// have not returned from their durable-store operation. New submissions are
/// synchronously refused as soon as shutdown begins.
public struct AlertSinkShutdownResult: Sendable, Equatable {
    public let completed: Int
    public let failed: Int
    public let shedAtDeadline: Int
    public let pending: Int
    public let alertAdmissionsInFlight: Int
    public let alertsRejectedAfterSeal: Int
    public let deadlineExpired: Bool

    public var clean: Bool {
        !deadlineExpired && pending == 0 && alertAdmissionsInFlight == 0
    }

    public init(
        completed: Int,
        failed: Int,
        shedAtDeadline: Int,
        pending: Int,
        alertAdmissionsInFlight: Int,
        alertsRejectedAfterSeal: Int,
        deadlineExpired: Bool
    ) {
        self.completed = completed
        self.failed = failed
        self.shedAtDeadline = shedAtDeadline
        self.pending = pending
        self.alertAdmissionsInFlight = alertAdmissionsInFlight
        self.alertsRejectedAfterSeal = alertsRejectedAfterSeal
        self.deadlineExpired = deadlineExpired
    }
}

/// Honest evidence-tier accounting for heartbeat, maintenance, and tests.
/// `chargedBytes` is the larger of exact logical row ownership and either exact
/// SQLite page ownership or its conservative cached upper bound (distinguished
/// by `allocatedBytesExact`). The separate alerts.db family admission remains
/// authoritative for DB + WAL + SHM combined.
public struct AlertEvidenceBudgetSnapshot: Sendable, Equatable {
    public let rowCount: Int
    public let logicalBytes: Int64
    public let allocatedBytes: Int64
    public let chargedBytes: Int64
    public let maxBytes: Int64
    /// True when `allocatedBytes` came from DBSTAT after the most recent table
    /// mutation. When false, `chargedBytes` remains a conservative upper bound
    /// built from that observation plus admitted mutation estimates.
    public let allocatedBytesExact: Bool
    /// Monotonic actor-local generation. Useful for proving that a cached
    /// snapshot and its exactness flag describe the same mutation boundary.
    public let mutationGeneration: UInt64
    /// Number of DBSTAT-bearing ownership refreshes since this store opened.
    /// Initial/explicit refreshes also re-run COUNT/SUM; cap slow paths can
    /// refresh only allocation because their logical counters are incremental.
    public let fullRefreshesTotal: UInt64

    public var overBudget: Bool { chargedBytes > maxBytes }

    public init(
        rowCount: Int,
        logicalBytes: Int64,
        allocatedBytes: Int64,
        chargedBytes: Int64,
        maxBytes: Int64,
        allocatedBytesExact: Bool = true,
        mutationGeneration: UInt64 = 0,
        fullRefreshesTotal: UInt64 = 0
    ) {
        self.rowCount = rowCount
        self.logicalBytes = logicalBytes
        self.allocatedBytes = allocatedBytes
        self.chargedBytes = chargedBytes
        self.maxBytes = maxBytes
        self.allocatedBytesExact = allocatedBytesExact
        self.mutationGeneration = mutationGeneration
        self.fullRefreshesTotal = fullRefreshesTotal
    }
}

/// One cold-path, actor-consistent proof used before shrinking the temporary
/// events.db upgrade reserve. Logical evidence ownership alone is insufficient:
/// deleted rows can remain as freelist pages and a reader can pin committed WAL
/// frames. The hard gate therefore uses the post-checkpoint DB+WAL+SHM family
/// footprint, while the page/freelist values explain why a candidate remains
/// pending.
public struct LegacyAlertEvidenceTransitionMeasurement: Sendable, Equatable {
    public let evidence: AlertEvidenceBudgetSnapshot
    public let familyFootprintBytes: Int64
    public let walCheckpointDrained: Bool
    public let pageSizeBytes: Int64
    public let pageCount: Int64
    public let freelistCount: Int64

    public var freelistBytes: Int64 {
        guard freelistCount >= 0, pageSizeBytes > 0 else {
            return Int64.max
        }
        return SQLitePersistentStoreAdmission.saturatingMultiply(
            freelistCount,
            by: pageSizeBytes
        )
    }

    public init(
        evidence: AlertEvidenceBudgetSnapshot,
        familyFootprintBytes: Int64,
        walCheckpointDrained: Bool,
        pageSizeBytes: Int64,
        pageCount: Int64,
        freelistCount: Int64
    ) {
        self.evidence = evidence
        self.familyFootprintBytes = familyFootprintBytes
        self.walCheckpointDrained = walCheckpointDrained
        self.pageSizeBytes = pageSizeBytes
        self.pageCount = pageCount
        self.freelistCount = freelistCount
    }
}

/// New alerts read evidence from AlertStore first. A missing new snapshot falls
/// back to the preserved legacy events.db table; no migration or destructive
/// conversion is performed implicitly.
public enum AlertEvidenceResolver {
    public static func evidenceFor(
        alertId: String,
        alertStore: AlertStore?,
        legacyEventStore: EventStore?
    ) async -> [Event] {
        if let alertStore,
           let current = try? await alertStore.evidenceFor(alertId: alertId),
           !current.isEmpty {
            return current
        }
        guard let legacyEventStore else { return [] }
        return (try? await legacyEventStore.evidenceFor(alertId: alertId)) ?? []
    }
}
