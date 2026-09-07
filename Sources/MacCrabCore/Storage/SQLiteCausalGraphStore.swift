// SQLiteCausalGraphStore.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-6b) — SQLite-backed implementation of
// `CausalGraphStore` per §13 / §15.5 of the v1.10.0 spec.
//
// Backed by `tracegraph.db` (separate file from `events.db` and
// `traces.db` per §13.0). All 7 tables from §13 are created via the
// existing SchemaMigrator pattern. WAL + per-connection pragmas
// follow the TraceStore template.
//
// Encryption: `attributes_json` (entities) and `evidence_json` (edges)
// are encrypted at rest via the optional DatabaseEncryption (§13.0).
// Tests pass nil for plaintext storage; production wires the
// shared keychain-backed AES-256-GCM key.
//
// Graph traversal: BFS over edges within the time window, bounded
// by depth. v1.10.0 graphs are small (≤ 250 entities in the context
// budget per §14.3) so the iterative shape stays well under the
// performance budget; recursive CTE is a future optimization.
//
// Critical-path scoring (relation weights, confidence-weighted) is
// PR-8's responsibility. PR-6b returns an unweighted shortest path
// — the protocol contract is "shortest path subject to maxDepth";
// caller does the rest.

import Foundation
import Darwin
import Dispatch
import CSQLCipher
import os.log

// MARK: - Error

public enum CausalGraphStoreError: Error, LocalizedError {
    case databaseOpenFailed(String)
    case schemaFailed(String)
    case sqliteFailure(
        context: String,
        message: String,
        resultCode: Int32,
        extendedResultCode: Int32,
        systemErrno: Int32
    )
    case transactionFailed(String)
    case prepareFailed(String)
    case bindFailed(String)
    case stepFailed(String)
    case decodeFailed(String)
    case unexpectedNull(String)

    public var errorDescription: String? {
        switch self {
        case .databaseOpenFailed(let m): return "CausalGraphStore: open failed: \(m)"
        case .schemaFailed(let m): return "CausalGraphStore: schema failed: \(m)"
        case let .sqliteFailure(context, message, rc, extended, systemErrno):
            return "CausalGraphStore: \(context) failed (rc=\(rc), extended=\(extended), system_errno=\(systemErrno)): \(message)"
        case .transactionFailed(let m):
            return "CausalGraphStore: transaction state uncertain: \(m)"
        case .prepareFailed(let m): return "CausalGraphStore: prepare failed: \(m)"
        case .bindFailed(let m): return "CausalGraphStore: bind failed: \(m)"
        case .stepFailed(let m): return "CausalGraphStore: step failed: \(m)"
        case .decodeFailed(let m): return "CausalGraphStore: decode failed: \(m)"
        case .unexpectedNull(let m): return "CausalGraphStore: unexpected null: \(m)"
        }
    }

    var sqliteFailureMetadata: SQLiteFailureMetadata? {
        guard case let .sqliteFailure(
            _, _, resultCode, extendedResultCode, systemErrno
        ) = self else { return nil }
        return SQLiteFailureMetadata(
            resultCode: resultCode,
            extendedResultCode: extendedResultCode,
            systemErrno: systemErrno
        )
    }
}

// MARK: - Storage admission / bounded recovery

/// Why the TraceGraph writer is currently refusing growth mutations.
///
/// Storage admission is deliberately owned by the SQLite actor rather than by
/// `RollingCausalGraph`: several legitimate writers (rule hits, replay rows,
/// continuity records, demo/import tools) never pass through the rolling graph.
public enum CausalGraphStorageBlockReason: String, Codable, Sendable, Equatable {
    case footprintLimit = "footprint_limit"
    case lowFreeSpace = "low_free_space"
    case probeFailure = "probe_failure"
    case mutationTooLarge = "mutation_too_large"
    case recoveryInProgress = "recovery_in_progress"
}

public enum CausalGraphStorageAdmissionError: Error, LocalizedError, Sendable, Equatable {
    case footprintLimit(footprintBytes: Int64, admissionThresholdBytes: Int64, capBytes: Int64)
    case lowFreeSpace(freeBytes: Int64, floorBytes: Int64, requiredFreeBytes: Int64)
    case probeFailed(String)
    case mutationTooLarge(estimatedBytes: Int64, transactionReserveBytes: Int64)
    case recoveryInProgress

    public var errorDescription: String? {
        switch self {
        case .footprintLimit(let footprint, let threshold, let cap):
            return "TraceGraph storage paused: SQLite-family footprint \(footprint) bytes reached the \(threshold)-byte admission threshold (absolute cap \(cap) bytes)"
        case .lowFreeSpace(let free, let floor, let required):
            return "TraceGraph storage paused: \(free) bytes free is below the \(required)-byte preflight requirement (\(floor)-byte hard floor plus this transaction's reserved growth)"
        case .probeFailed(let probe):
            return "TraceGraph storage paused: configured \(probe) probe failed"
        case .mutationTooLarge(let estimated, let reserve):
            return "TraceGraph storage paused: mutation upper bound \(estimated) bytes exceeds the \(reserve)-byte transaction reserve"
        case .recoveryInProgress:
            return "TraceGraph storage paused while bounded recovery is running"
        }
    }

    fileprivate var blockReason: CausalGraphStorageBlockReason {
        switch self {
        case .footprintLimit: return .footprintLimit
        case .lowFreeSpace: return .lowFreeSpace
        case .probeFailed: return .probeFailure
        case .mutationTooLarge: return .mutationTooLarge
        case .recoveryInProgress: return .recoveryInProgress
        }
    }
}

/// A pathological number of independent TraceGraph writers attempted to wait
/// behind one bounded recovery quantum. This is deliberately distinct from a
/// storage-admission shed: normal daemon ingestion has one coalesced store
/// write in flight, while the fixed ceiling prevents an accidental task storm
/// from turning maintenance serialization into unbounded actor-owned memory.
public enum CausalGraphRecoverySerializationError: Error, LocalizedError, Sendable, Equatable {
    case waiterLimitReached(limit: Int)

    public var errorDescription: String? {
        switch self {
        case .waiterLimitReached(let limit):
            return "TraceGraph recovery writer queue reached its \(limit)-mutation safety limit"
        }
    }
}

public struct CausalGraphStorageAdmissionStatus: Sendable, Equatable {
    public let enabled: Bool
    /// True only for a live read-write SQLite handle. Filesystem headroom is
    /// not proof that the daemon can admit its first graph mutation.
    public let writableHandle: Bool
    /// True when an ordinary growth call can either enter SQLite immediately
    /// or join the bounded recovery handoff queue. This is deliberately
    /// separate from `recovering`: healthy maintenance remains writable.
    public let acceptingMutations: Bool
    /// Hard storage admission only (footprint, free-space, probe, SQLite, or
    /// deferred-schema pressure). Recovery by itself is never `blocked`.
    public let blocked: Bool
    public let reason: CausalGraphStorageBlockReason?
    public let maxFootprintBytes: Int64?
    public let admissionThresholdBytes: Int64?
    public let resumeBelowBytes: Int64?
    public let transactionReserveBytes: Int64?
    public let footprintBytes: Int64?
    public let freeSpaceBytes: Int64?
    public let freeSpaceFloorBytes: Int64?
    public let shedMutationsTotal: UInt64
    public let pinnedReader: Bool
    public let recovering: Bool
    public let autoVacuumMode: Int
    public let footprintLatchTripsTotal: UInt64
    public let footprintLatchClearsTotal: UInt64
    public let recoveryRunsTotal: UInt64
    public let recoveryTracesDeletedTotal: UInt64
    public let recoveryTraceChildRowsDeletedTotal: UInt64
    public let recoveryEdgesDeletedTotal: UInt64
    public let recoveryEntitiesDeletedTotal: UInt64
    public let recoveryVacuumPagesReclaimedTotal: UInt64
    public let recoveryNoPhysicalProgressTotal: UInt64
    public let lastRecoveryFootprintBeforeBytes: Int64?
    public let lastRecoveryFootprintAfterBytes: Int64?
    public let proactiveRecoveryThresholdBytes: Int64?
    /// Current bytes still required to cross strictly below the recovery
    /// target. Unlike `blocked`, this remains non-zero during proactive drain.
    public let recoveryDeficitBytes: Int64?
    /// Whether the most recent bounded pass left rows eligible under the exact
    /// trace/orphan cutoffs supplied by its caller. nil means measurement failed.
    public let lastRecoveryEligibleBacklogRemaining: Bool?
    /// Growth calls suspended behind the active bounded recovery quantum.
    public let recoveryMutationWaiters: Int
    /// Fixed actor-owned waiter ceiling. Production graph ingest coalesces to a
    /// single physical writer; this cap is a final task-storm backstop.
    public let recoveryMutationWaiterLimit: Int
    public let recoveryMutationQueueSaturated: Bool
    public let recoveryMutationWaiterHighWatermark: Int
    public let recoveryMutationWaitsTotal: UInt64
    /// Mutually exclusive terminal queue outcomes. At every actor snapshot:
    /// waits = current waiters + releases + cancellations + closed outcomes.
    public let recoveryMutationWaitReleasesTotal: UInt64
    public let recoveryMutationWaitCancellationsTotal: UInt64
    public let recoveryMutationWaitClosedTotal: UInt64
    public let recoveryMutationWaitSaturationsTotal: UInt64
    /// Sum and maximum queue residence, measured with monotonic uptime at the
    /// exact point each waiter is removed. These exclude later actor scheduling.
    public let recoveryMutationWaitNanosecondsTotal: UInt64
    public let recoveryMutationMaxWaitNanoseconds: UInt64
    /// Monotonic residence of the oldest waiter still in the queue.
    public let recoveryMutationOldestWaitNanoseconds: UInt64
    /// Recovery passes that stopped after their current bounded SQLite quantum
    /// because foreground evidence was waiting.
    public let recoveryWriterPreemptionsTotal: UInt64
}

public struct CausalGraphStorageRecoveryResult: Sendable, Equatable {
    public let pinnedReader: Bool
    public let tracesDeleted: Int
    public let traceChildRowsDeleted: Int
    public let edgesDeleted: Int
    public let entitiesDeleted: Int
    public let vacuumPagesReclaimed: Int
    public let footprintBeforeBytes: Int64?
    public let footprintBytes: Int64?
    public let autoVacuumMode: Int
    public let recoveryTargetBytes: Int64?
    public let recoveryDeficitBytes: Int64?
    public let traceBacklogRemaining: Bool?
    public let orphanBacklogRemaining: Bool?
    public let eligibleBacklogRemaining: Bool?
}

/// Why an awaited boot-time TraceGraph drain could not restore ordinary
/// mutation admission before ingestion producers were started.
public enum CausalGraphStartupRecoveryNonconvergenceReason: String, Sendable, Equatable {
    case storeUnavailable = "store_unavailable"
    case writableHandleUnavailable = "writable_handle_unavailable"
    case protectedEvidenceFloor = "protected_evidence_floor"
    case boundedPassLimit = "bounded_pass_limit"
    case pinnedReader = "pinned_reader"
    case incrementalVacuumUnavailable = "incremental_vacuum_unavailable"
    case noRecoverableProgress = "no_recoverable_progress"
    case admissionMeasurementUnavailable = "admission_measurement_unavailable"
    case admissionRemainsBlocked = "admission_remains_blocked"
    case recoveryFailed = "recovery_failed"
}

public enum CausalGraphStartupRecoveryDisposition: Sendable, Equatable {
    case writable
    case nonconverged(CausalGraphStartupRecoveryNonconvergenceReason)
}

/// Exact result of the awaited pre-producer recovery lane. The daemon retains
/// this result in its bootstrap handles so a degraded start cannot be mistaken
/// for proof that normal TraceGraph writes were restored.
public struct CausalGraphStartupRecoveryResult: Sendable, Equatable {
    public let disposition: CausalGraphStartupRecoveryDisposition
    public let initiallyBlocked: Bool
    public let passes: Int
    public let attemptedCutoffHours: [Int]
    public let finalAdmission: CausalGraphStorageAdmissionStatus?
    public let lastRecovery: CausalGraphStorageRecoveryResult?
    public let failureDetail: String?

    public var writableBeforeProducers: Bool {
        guard disposition == .writable,
              let finalAdmission,
              finalAdmission.acceptingMutations else {
            return false
        }
        // A floor-only policy has no byte target; a successful ordinary-write
        // reprobe is the complete proof. With a footprint cap, however, retain
        // the stronger headroom proof: a recovery pass must cross the durable
        // low watermark, while a healthy zero-pass start must still remain
        // strictly below the proactive boundary that caused rc.11 to relatch.
        guard finalAdmission.maxFootprintBytes != nil else { return true }
        if passes > 0 {
            return finalAdmission.recoveryDeficitBytes == 0
        }
        guard let footprint = finalAdmission.footprintBytes,
              let proactive = finalAdmission.proactiveRecoveryThresholdBytes else {
            return false
        }
        return footprint < proactive
    }

    public var normalWriteAdmissionRestored: Bool {
        initiallyBlocked && writableBeforeProducers
    }

    /// Replace the early recovery snapshot with the no-maintenance admission
    /// remeasurement taken at the actual producer-activation boundary. This
    /// keeps the retained Bootstrap/heartbeat proof and its diagnostics from
    /// describing stale free-space or SQLite-family state.
    public func refreshed(finalAdmission: CausalGraphStorageAdmissionStatus) -> Self {
        Self(
            disposition: disposition,
            initiallyBlocked: initiallyBlocked,
            passes: passes,
            attemptedCutoffHours: attemptedCutoffHours,
            finalAdmission: finalAdmission,
            lastRecovery: lastRecovery,
            failureDetail: failureDetail
        )
    }

    public static func unavailable(
        reason: CausalGraphStorageBlockReason?,
        detail: String? = nil
    ) -> Self {
        Self(
            disposition: .nonconverged(.storeUnavailable),
            initiallyBlocked: reason != nil,
            passes: 0,
            attemptedCutoffHours: [],
            finalAdmission: nil,
            lastRecovery: nil,
            failureDetail: detail ?? reason?.rawValue
        )
    }
}

/// Injectable probes keep admission failure modes deterministic in tests. A
/// `nil` result is a failure, and is fail-closed only when that probe's policy
/// is configured.
public typealias CausalGraphStorageProbe = @Sendable (_ path: String) -> Int64?

/// Test-only fault seam for SQLite transaction-control statements. Production
/// callers leave this nil; tests can skip one control statement while
/// preserving exact rc/extended-rc/VFS errno classification.
public struct CausalGraphInjectedSQLiteFailure: Sendable, Equatable {
    public let resultCode: Int32
    public let extendedResultCode: Int32
    public let systemErrno: Int32

    public init(
        resultCode: Int32,
        extendedResultCode: Int32? = nil,
        systemErrno: Int32 = 0
    ) {
        self.resultCode = resultCode
        self.extendedResultCode = extendedResultCode ?? resultCode
        self.systemErrno = systemErrno
    }
}

public enum CausalGraphTransactionOperation: String, Sendable, Equatable {
    case begin
    case commit
    case rollback
}

public typealias CausalGraphTransactionFailureProbe = @Sendable (
    _ operation: CausalGraphTransactionOperation
) -> CausalGraphInjectedSQLiteFailure?

public enum CausalGraphPageLimitOperation: String, Sendable, Equatable {
    case readPageSize
    case readPageCount
    case installLimit
}

public typealias CausalGraphPageLimitFailureProbe = @Sendable (
    _ operation: CausalGraphPageLimitOperation
) -> CausalGraphInjectedSQLiteFailure?

/// Single production policy shared by daemon boot, SIGHUP reload, and tools
/// that deliberately opt into the live-store safety contract.
public enum TraceGraphStoragePolicy {
    public static let bytesPerMiB: Int64 = 1_048_576
    public static let minimumCapMiB = 50
    public static let freeSpaceFloorBytes: Int64 = 1_024 * bytesPerMiB

    public static func capBytes(maxSizeMiB: Int) -> Int64 {
        let clampedMiB = max(
            minimumCapMiB,
            min(maxSizeMiB, Int(Int64.max / bytesPerMiB))
        )
        return Int64(clampedMiB) * bytesPerMiB
    }
}

// MARK: - SQLiteCausalGraphStore

public actor SQLiteCausalGraphStore: CausalGraphStore {

    private enum RecoveryMutationWaitOutcome: Sendable {
        case released
        case cancelled
        case closed
    }

    private struct RecoveryMutationWaiter {
        let id: UUID
        let enqueuedAtNanoseconds: UInt64
        let continuation: CheckedContinuation<RecoveryMutationWaitOutcome, Never>
    }

    // MARK: Configuration

    private var db: OpaquePointer?
    private var checkpointController: SQLiteControlledCheckpointController?
    private let databasePath: String
    private let encryption: DatabaseEncryption?
    /// True when the handle ended up read-only — either because the caller
    /// asked (`forceReadOnly`) or because a read-write open failed and we
    /// fell back (e.g. a non-root reader against the root-owned 0o640 DB).
    /// Migrations / chmod / WAL-setup are all gated on this being false.
    private var isReadOnly = false
    private let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "graph-store")

    /// The cap is absolute across main DB, WAL, SHM, and rollback journal.
    /// Admission stops at `cap - transactionReserve`, leaving enough room for
    /// the largest permitted transaction. `PRAGMA max_page_count` independently
    /// prevents the main file growing through that high-water mark.
    private var maxFootprintBytes: Int64?
    private var freeSpaceFloorBytes: Int64?
    private var transactionReserveBytes: Int64?
    private var admissionThresholdBytes: Int64?
    private var resumeBelowBytes: Int64?
    private let storageVolumePath: String
    private let footprintProbe: CausalGraphStorageProbe
    private let freeSpaceProbe: CausalGraphStorageProbe
    private let transactionFailureProbe: CausalGraphTransactionFailureProbe?
    private let pageLimitFailureProbe: CausalGraphPageLimitFailureProbe?
    /// Deterministic test seam at the actor yield between cascade quanta.
    /// Production callers leave this nil.
    private let cascadeYieldHook: (@Sendable () async throws -> Void)?
    private var lastFootprintBytes: Int64?
    private var lastFreeSpaceBytes: Int64?
    private var storageBlockReason: CausalGraphStorageBlockReason?
    private var footprintAdmissionLatched = false
    private var shedMutationsTotal: UInt64 = 0
    private var pinnedReader = false
    private var recovering = false
    /// A recovery pass owns SQLite across several actor suspension points. A
    /// growth call arriving at one of those points waits here instead of being
    /// falsely classified as shed. Recovery notices the waiter after its
    /// current count/byte-bounded SQLite quantum and returns, so foreground
    /// evidence never waits behind the remainder of a full maintenance budget.
    private var recoveryMutationWaiters: [RecoveryMutationWaiter] = []
    private let recoveryMutationWaiterLimit: Int
    private var recoveryMutationWaiterHighWatermark = 0
    private var recoveryMutationWaitsTotal: UInt64 = 0
    private var recoveryMutationWaitReleasesTotal: UInt64 = 0
    private var recoveryMutationWaitCancellationsTotal: UInt64 = 0
    private var recoveryMutationWaitClosedTotal: UInt64 = 0
    private var recoveryMutationWaitSaturationsTotal: UInt64 = 0
    private var recoveryMutationWaitNanosecondsTotal: UInt64 = 0
    private var recoveryMutationMaxWaitNanoseconds: UInt64 = 0
    private var recoveryWriterPreemptionsTotal: UInt64 = 0
    /// Released waiters get first claim over a new recovery pass. Each waiter
    /// clears one handoff synchronously before re-running fresh admission.
    private var recoveryMutationHandoffsOutstanding = 0
    private var recoveryCompletionWaiters: [CheckedContinuation<Void, Never>] = []
    private var closeRequested = false
    /// Recovery-only scan cursor. Field databases can contain millions of
    /// traces but each pass may mutate at most 256 parents. Re-running an
    /// unindexed effective-activity predicate plus `ORDER BY updated_at` from
    /// the beginning on every pass made boot work O(passes x all traces).
    /// Keep a rowid cursor for one exact cutoff instead; selected parents that
    /// are not fully drained leave the cursor in place, so no evidence can be
    /// skipped when a child-fanout quantum is exhausted.
    private var recoveryTraceScanCutoff: Double?
    private var recoveryTraceScanAfterRowID: Int64 = 0
    private var footprintLatchTripsTotal: UInt64 = 0
    private var footprintLatchClearsTotal: UInt64 = 0
    private var recoveryRunsTotal: UInt64 = 0
    private var recoveryTracesDeletedTotal: UInt64 = 0
    private var recoveryTraceChildRowsDeletedTotal: UInt64 = 0
    private var recoveryEdgesDeletedTotal: UInt64 = 0
    private var recoveryEntitiesDeletedTotal: UInt64 = 0
    private var recoveryVacuumPagesReclaimedTotal: UInt64 = 0
    private var recoveryNoPhysicalProgressTotal: UInt64 = 0
    private var lastRecoveryFootprintBeforeBytes: Int64?
    private var lastRecoveryFootprintAfterBytes: Int64?
    private var lastRecoveryEligibleBacklogRemaining: Bool?
    /// Bound associated with the currently executing actor-isolated growth
    /// mutation. Used to translate SQLite's own FULL/ENOSPC backstop into the
    /// same typed admission signal if the conservative preflight is exhausted.
    private var lastAdmittedMutationUpperBoundBytes: Int64 = 0
    private var sqliteStorageFailure: CausalGraphStorageAdmissionError?
    private var sqliteStorageFailureGeneration: UInt64 = 0
    /// An inherited over-budget database may defer additive indexes/triggers so
    /// boot can run bounded deletion first. Growth stays fail-closed until the
    /// deferred migration has run and its objects have been verified.
    private var deferredMigrationsPending = false
    private var deferredMigrationFailure: String?
    /// Sticky for this handle: an inherited duplicate at the global maximum
    /// means there is no unique predecessor to extend. Never pick one fork
    /// arbitrarily and continue emitting apparently-valid evidence.
    private var continuityIntegrityFailure: String?

    private static let mib: Int64 = 1_048_576
    private static let defaultMinimumTransactionReserve: Int64 = 8 * mib
    private static let defaultMaximumTransactionReserve: Int64 = 64 * mib
    /// Conservative per-row allowance for B-tree/index page splits in addition
    /// to eight times the caller-controlled UTF-8 payload.
    private static let mutationBaseBytes: Int64 = 1 * mib
    private static let mutationBytesPerRow: Int64 = 64 * 1024
    /// Parent trace IDs handled together. Child fanout is independently
    /// bounded below; limiting IDs alone did not bound a pathological trace.
    private static let traceCascadeBatchSize = 8
    /// Narrow child rows (membership/hash-chain) can be deleted in larger
    /// quanta; JSON-bearing rule-hit/replay rows use a smaller quantum because
    /// one row can span many SQLite overflow pages.
    private static let traceCascadeNarrowChildBatchSize = 256
    private static let traceCascadeWideChildBatchSize = 8
    /// Total child rows a daemon recovery tick may cascade. Public operator
    /// prune calls may drain fully, but recovery remains bounded in both trace
    /// count and fanout even for inherited pre-cap databases.
    private static let traceRecoveryChildRowBudget = 16_384
    /// Orphan rows are narrower than a whole trace cascade, but public legacy
    /// prune APIs must share the same bounded write shape as recovery.
    private static let substrateDeleteBatchSize = 256

    /// One inherited trace is retention-eligible only when neither the parent
    /// nor any timed child contains evidence at/after the caller's cutoff.
    /// Future child writes also advance `traces.updated_at`, but these guards
    /// are required for rows created by older releases and imported fixtures.
    /// Keep this single predicate shared by selection and exact backlog
    /// measurement so protected children cannot create a false perpetual
    /// backlog at a coarser recovery rung.
    private static let traceRecoveryEligibilityPredicateSQL = """
        MAX(traces.created_at, traces.updated_at) < ?1
        AND NOT EXISTS (
            SELECT 1 FROM trace_membership m
             WHERE m.trace_id = traces.id AND m.added_at >= ?1)
        AND NOT EXISTS (
            SELECT 1 FROM trace_rule_hits h
             WHERE h.trace_id = traces.id AND h.matched_at >= ?1)
        AND NOT EXISTS (
            SELECT 1 FROM trace_replay_runs r
             WHERE r.trace_id = traces.id
               AND (r.started_at >= ?1 OR r.completed_at >= ?1))
        AND NOT EXISTS (
            SELECT 1 FROM trace_hash_chain c
             WHERE c.trace_id = traces.id AND c.created_at >= ?1)
        """

    /// Recover one complete admitted-transaction reserve below the high-water.
    /// A single 2,048-page vacuum quantum is only about 8 MiB and field runs
    /// proved that clearing there immediately refills/re-latches. The reserve
    /// is already the actor's conservative bound for one mutation plus SQLite
    /// family growth, so reusing it gives admission durable writable headroom.
    nonisolated static func recoveryResumeBelowBytes(
        capBytes cap: Int64,
        admissionThresholdBytes threshold: Int64,
        transactionReserveBytes reserve: Int64
    ) -> Int64 {
        guard threshold > 1 else { return 0 }
        let boundedReserve = min(max(1, reserve), max(1, threshold / 2))
        return max(0, min(cap, threshold - boundedReserve))
    }

    nonisolated static func recoveryDeficitBytes(
        footprintBytes footprint: Int64?,
        recoveryTargetBytes target: Int64?
    ) -> Int64? {
        guard let footprint, let target else { return nil }
        guard footprint >= target else { return 0 }
        let (delta, overflow) = footprint.subtractingReportingOverflow(target)
        guard !overflow, delta < Int64.max else { return Int64.max }
        return delta + 1
    }

    nonisolated static func proactiveRecoveryThresholdBytes(
        admissionThresholdBytes threshold: Int64?,
        transactionReserveBytes reserve: Int64?
    ) -> Int64? {
        guard let threshold, threshold > 1, let reserve, reserve > 0 else { return nil }
        let desiredLead = max(mib, reserve / 4)
        let lead = min(desiredLead, max(1, threshold / 2))
        return max(0, threshold - lead)
    }

    // SQLITE_TRANSIENT lives at file scope (see bottom of file) — used
    // by every sqlite3_bind_text call site here.

    // MARK: Schema

    nonisolated static let schemaMigrations: [Migration] = [
        Migration(
            version: 1,
            name: "tracegraph_baseline",
            sql: [
                """
                CREATE TABLE IF NOT EXISTS trace_entities (
                    id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    stable_key TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    attributes_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    observation_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(entity_type, stable_key)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_entities_type_seen ON trace_entities(entity_type, last_seen)",
                """
                CREATE TABLE IF NOT EXISTS trace_edges (
                    id TEXT PRIMARY KEY,
                    source_entity_id TEXT NOT NULL,
                    target_entity_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    confidence_tier TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    event_ids_json TEXT NOT NULL,
                    FOREIGN KEY(source_entity_id) REFERENCES trace_entities(id),
                    FOREIGN KEY(target_entity_id) REFERENCES trace_entities(id),
                    UNIQUE(source_entity_id, target_entity_id, relation)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_edges_source ON trace_edges(source_entity_id, last_seen)",
                "CREATE INDEX IF NOT EXISTS idx_edges_target ON trace_edges(target_entity_id, last_seen)",
                "CREATE INDEX IF NOT EXISTS idx_edges_relation ON trace_edges(relation, last_seen)",
                """
                CREATE TABLE IF NOT EXISTS traces (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    anchor_event_id TEXT NOT NULL,
                    root_entity_id TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    summary_json TEXT,
                    attack_json TEXT,
                    evidence_bundle_status TEXT DEFAULT 'not_created',
                    daemon_version TEXT NOT NULL,
                    ruleset_version TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL,
                    policy_snapshot_json TEXT NOT NULL,
                    trace_signing_key_mode TEXT NOT NULL,
                    replay_scope TEXT NOT NULL,
                    attribution_override_policy TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_traces_status_created ON traces(status, created_at)",
                """
                CREATE TABLE IF NOT EXISTS trace_membership (
                    trace_id TEXT NOT NULL,
                    entity_id TEXT,
                    edge_id TEXT,
                    role TEXT NOT NULL,
                    layer TEXT NOT NULL DEFAULT 'core',
                    added_at REAL NOT NULL,
                    PRIMARY KEY(trace_id, entity_id, edge_id),
                    CHECK ((entity_id IS NOT NULL) <> (edge_id IS NOT NULL))
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_membership_trace_layer ON trace_membership(trace_id, layer)",
                """
                CREATE TABLE IF NOT EXISTS trace_rule_hits (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    rule_title TEXT NOT NULL,
                    rule_version TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    matched_event_id TEXT,
                    matched_entity_id TEXT,
                    matched_edge_id TEXT,
                    matched_at REAL NOT NULL,
                    explanation_json TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_rule_hits_trace ON trace_rule_hits(trace_id, matched_at)",
                """
                CREATE TABLE IF NOT EXISTS trace_replay_runs (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    bundle_id TEXT NOT NULL,
                    ruleset_version TEXT NOT NULL,
                    daemon_version TEXT NOT NULL,
                    normalization_version TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    completed_at REAL,
                    deterministic INTEGER NOT NULL,
                    result_json TEXT NOT NULL
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_replay_runs_trace ON trace_replay_runs(trace_id, started_at)",
                """
                CREATE TABLE IF NOT EXISTS trace_hash_chain (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    previous_hash TEXT,
                    current_hash TEXT NOT NULL,
                    event_id TEXT,
                    edge_id TEXT,
                    chain_head_signature TEXT,
                    chain_head_published_to_unified_log INTEGER DEFAULT 0,
                    created_at REAL NOT NULL,
                    UNIQUE(sequence_number)
                )
                """,
                "CREATE INDEX IF NOT EXISTS idx_hash_chain_trace_seq ON trace_hash_chain(trace_id, sequence_number)",
            ]
        ),
        Migration(
            version: 2,
            name: "substrate_lastseen_indexes",
            sql: [
                // v1.18: standalone last_seen indexes so the substrate
                // retention sweep (pruneOrphanedGraph / pruneOldestGraph)
                // can range-scan and ORDER BY last_seen without a full
                // table scan. The v1 composite indexes all LEAD with
                // entity_type / source / target / relation, so a bare
                // `WHERE last_seen < ?` or `ORDER BY last_seen` cannot use
                // them.
                "CREATE INDEX IF NOT EXISTS idx_entities_lastseen ON trace_entities(last_seen)",
                "CREATE INDEX IF NOT EXISTS idx_edges_lastseen ON trace_edges(last_seen)",
            ]
        ),
        Migration(
            version: 3,
            name: "global_continuity_sequence_guard",
            sql: [
                // Existing stores may already contain historical duplicate
                // global sequence numbers from the old cross-connection race.
                // A UNIQUE index would make that evidence DB unopenable. This
                // trigger preserves existing rows for verification while
                // failing closed on every new duplicate. Fresh v1 tables also
                // carry the native UNIQUE(sequence_number) constraint.
                // The shipped v1 legacy index leads with trace_id, so neither
                // the trigger lookup nor the global-head ORDER BY can seek on
                // sequence_number. This non-unique index remains buildable on
                // stores that already contain historical duplicates.
                "CREATE INDEX IF NOT EXISTS idx_hash_chain_global_seq ON trace_hash_chain(sequence_number)",
                """
                CREATE TRIGGER IF NOT EXISTS trg_hash_chain_global_sequence_unique
                BEFORE INSERT ON trace_hash_chain
                WHEN EXISTS (
                    SELECT 1 FROM trace_hash_chain
                     WHERE sequence_number = NEW.sequence_number
                )
                BEGIN
                    SELECT RAISE(ABORT, 'duplicate global continuity sequence_number');
                END
                """,
            ]
        ),
    ]

    // MARK: Lifecycle

    /// - Parameters:
    ///   - databasePath: Filesystem path to `tracegraph.db`.
    ///   - encryption: Optional encryption layer for `attributes_json` /
    ///     `evidence_json` payloads.
    ///   - forceReadOnly: When `true`, open the database with
    ///     `SQLITE_OPEN_READONLY` and skip migrations / chmod. The
    ///     dashboard (MacCrabApp/V2LiveDataProvider) sets this to
    ///     guarantee its long-lived handle never holds shared/upgrade
    ///     locks that block the daemon's `VACUUM` /
    ///     `wal_checkpoint(TRUNCATE)`. Field background (v1.12.6 RC1,
    ///     Wave 9A): `tracegraph.db` grew to 11 GB while the size cap
    ///     was 300 MB because the daemon's VACUUM was blocked by the
    ///     dashboard's RW connection. See `EventStore.openDatabase` for
    ///     the full incident notes.
    ///   - maxFootprintBytes: Optional hard budget for the main database plus
    ///     its `-wal` and `-shm` sidecars. `nil`/non-positive disables size
    ///     admission, preserving compatibility for read-only and test stores.
    ///   - freeSpaceFloorBytes: Optional available-space floor. Probe failure
    ///     is fail-closed only when this value is configured.
    public init(
        databasePath: String,
        encryption: DatabaseEncryption? = nil,
        forceReadOnly: Bool = false,
        maxFootprintBytes: Int64? = nil,
        freeSpaceFloorBytes: Int64? = nil,
        transactionReserveBytes: Int64? = nil,
        storageVolumePath: String? = nil,
        footprintProbe: CausalGraphStorageProbe? = nil,
        freeSpaceProbe: CausalGraphStorageProbe? = nil,
        transactionFailureProbe: CausalGraphTransactionFailureProbe? = nil,
        pageLimitFailureProbe: CausalGraphPageLimitFailureProbe? = nil,
        cascadeYieldHook: (@Sendable () async throws -> Void)? = nil,
        recoveryMutationWaiterLimit: Int = 1_024
    ) async throws {
        // Resolve only the existing parent directory, then keep the leaf name
        // literal. macOS exposes trusted aliases such as /tmp -> /private/tmp;
        // opening the canonical, ownership-validated parent prevents an
        // attacker-controlled ancestor symlink from redirecting SQLite after
        // our check while still supporting those platform paths.
        let secureDatabasePath = try Self.canonicalDatabasePath(databasePath)
        self.databasePath = secureDatabasePath
        self.encryption = encryption
        self.storageVolumePath = storageVolumePath
            ?? (secureDatabasePath as NSString).deletingLastPathComponent
        self.footprintProbe = footprintProbe ?? { Self.exactSQLiteFootprintBytes(databasePath: $0) }
        self.freeSpaceProbe = freeSpaceProbe ?? { Self.availableFilesystemBytes(path: $0) }
        self.transactionFailureProbe = transactionFailureProbe
        self.pageLimitFailureProbe = pageLimitFailureProbe
        self.cascadeYieldHook = cascadeYieldHook
        self.recoveryMutationWaiterLimit = max(1, recoveryMutationWaiterLimit)

        let cap = maxFootprintBytes.flatMap { $0 > 0 ? $0 : nil }
        let floor = freeSpaceFloorBytes.flatMap { $0 > 0 ? $0 : nil }
        self.maxFootprintBytes = cap
        self.freeSpaceFloorBytes = floor
        if let cap {
            let requested = transactionReserveBytes.flatMap { $0 > 0 ? $0 : nil }
            let automatic = min(
                Self.defaultMaximumTransactionReserve,
                max(Self.defaultMinimumTransactionReserve, cap / 4)
            )
            // Leave at least one SQLite page for the admission high-water.
            let reserve = min(requested ?? automatic, max(4_096, cap - 4_096))
            self.transactionReserveBytes = reserve
            let threshold = max(0, cap - reserve)
            self.admissionThresholdBytes = threshold
            self.resumeBelowBytes = Self.recoveryResumeBelowBytes(
                capBytes: cap,
                admissionThresholdBytes: threshold,
                transactionReserveBytes: reserve
            )
        } else {
            self.transactionReserveBytes = nil
            self.admissionThresholdBytes = nil
            self.resumeBelowBytes = nil
        }
        try openDatabase(forceReadOnly: forceReadOnly)
        // Migrations write to the schema (CREATE INDEX, ALTER TABLE). A
        // RO connection cannot run them — and shouldn't need to: the
        // daemon's RW connection has already applied the migrations
        // before any RO open (dashboard, MCP, CLI) ever happens. Gate on
        // the ACTUAL open outcome, not just the requested mode, so a
        // read-write request that FELL BACK to read-only (non-root reader
        // against the root-owned 0o640 DB) also skips migrations instead
        // of failing.
        if !isReadOnly {
            refreshAdmissionMeasurementsAndLatch()
            if let admission = currentMeasuredAdmissionError() {
                if hasUsableRuntimeSchema() {
                    // An inherited DB already has the complete runtime tables.
                    // Defer idempotent CREATE INDEX repair until recovery has
                    // restored headroom; do not amplify its WAL during boot.
                    logger.fault("TraceGraph schema migration deferred by storage admission: \(admission.localizedDescription, privacy: .public)")
                    deferredMigrationsPending = true
                } else {
                    // A fresh/incomplete DB cannot safely serve runtime queries
                    // without its schema. Fail typed so DaemonSetup preserves
                    // any existing file and never labels pressure corruption.
                    throw admission
                }
            } else {
                do {
                    try applyMigrations()
                    // Re-apply after migration in case SQLite changed page metadata.
                    try configureMaximumPageCount()
                } catch let admission as CausalGraphStorageAdmissionError {
                    guard hasUsableRuntimeSchema() else { throw admission }
                    // Ordinary admission can be healthy while a missing index
                    // still lacks its main-file/page-limit/scratch headroom.
                    // Preserve the usable v1 runtime schema and let awaited
                    // startup recovery reclaim to the exact migration bound.
                    deferredMigrationsPending = true
                    logger.fault("TraceGraph schema migration deferred by exact storage admission: \(admission.localizedDescription, privacy: .public)")
                }
            }
        }
        refreshAdmissionMeasurementsAndLatch()
        try Self.validateSQLiteFileFamily(
            databasePath: secureDatabasePath,
            createMainIfMissing: false
        )
    }

    deinit {
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
        }
    }

    public func close() async {
        closeRequested = true
        if recovering {
            await withCheckedContinuation { continuation in
                // The actor cannot interleave between the `recovering` check
                // above and this registration. Recovery resumes the closer from
                // its defer after its current bounded SQLite quantum has ended.
                recoveryCompletionWaiters.append(continuation)
            }
        }
        finishRecoveryMutationWaiters(outcome: .closed)
        if let db {
            checkpointController?.detach(from: db)
            sqlite3_close(db)
            self.db = nil
            checkpointController = nil
        }
    }

    private var recoveryHasForegroundPressure: Bool {
        closeRequested || !recoveryMutationWaiters.isEmpty
    }

    /// Suspend one growth call behind the active recovery pass. The caller
    /// resumes only after recovery's defer has cleared `recovering`; it then
    /// performs the normal footprint/free-space probes from scratch. Therefore
    /// waiting never grants admission and cannot weaken either hard boundary.
    private func awaitRecoveryMutationBarrier() async throws {
        try Task.checkCancellation()
        guard !closeRequested, db != nil else {
            throw CausalGraphStoreError.databaseOpenFailed("closed")
        }
        guard recovering else { return }
        guard recoveryMutationWaiters.count < recoveryMutationWaiterLimit else {
            recoveryMutationWaitSaturationsTotal &+= 1
            throw CausalGraphRecoverySerializationError.waiterLimitReached(
                limit: recoveryMutationWaiterLimit)
        }

        let waiterID = UUID()
        let enqueuedAt = DispatchTime.now().uptimeNanoseconds
        recoveryMutationWaitsTotal &+= 1
        let outcome = await withTaskCancellationHandler {
            await withCheckedContinuation {
                (continuation: CheckedContinuation<RecoveryMutationWaitOutcome, Never>) in
                recoveryMutationWaiters.append(RecoveryMutationWaiter(
                    id: waiterID,
                    enqueuedAtNanoseconds: enqueuedAt,
                    continuation: continuation
                ))
                recoveryMutationWaiterHighWatermark = max(
                    recoveryMutationWaiterHighWatermark,
                    recoveryMutationWaiters.count
                )
                // Cancellation can win the race immediately before the
                // continuation is registered. Remove it synchronously here so
                // a cancelled producer never waits for maintenance to finish.
                if Task.isCancelled {
                    cancelRecoveryMutationWaiter(waiterID)
                }
            }
        } onCancel: {
            Task { await self.cancelRecoveryMutationWaiter(waiterID) }
        }

        if outcome == .released {
            recoveryMutationHandoffsOutstanding = max(
                0, recoveryMutationHandoffsOutstanding - 1)
        }

        // Cancellation can race a normal recovery handoff after the waiter was
        // removed from the array. Honor it before any fresh admission/SQLite
        // work, while still clearing the handoff count above.
        if Task.isCancelled {
            throw CancellationError()
        }
        switch outcome {
        case .released:
            guard !closeRequested, db != nil else {
                throw CausalGraphStoreError.databaseOpenFailed("closed")
            }
        case .cancelled:
            throw CancellationError()
        case .closed:
            throw CausalGraphStoreError.databaseOpenFailed("closed")
        }
    }

    private func cancelRecoveryMutationWaiter(_ waiterID: UUID) {
        guard let index = recoveryMutationWaiters.firstIndex(where: {
            $0.id == waiterID
        }) else { return }
        let waiter = recoveryMutationWaiters.remove(at: index)
        recordRecoveryMutationWaitOutcome(waiter, outcome: .cancelled)
        recoveryMutationWaitCancellationsTotal &+= 1
        waiter.continuation.resume(returning: .cancelled)
    }

    private func recordRecoveryMutationWaitOutcome(
        _ waiter: RecoveryMutationWaiter,
        outcome: RecoveryMutationWaitOutcome
    ) {
        let elapsed = DispatchTime.now().uptimeNanoseconds
            &- waiter.enqueuedAtNanoseconds
        let (sum, overflow) = recoveryMutationWaitNanosecondsTotal
            .addingReportingOverflow(elapsed)
        recoveryMutationWaitNanosecondsTotal = overflow ? UInt64.max : sum
        recoveryMutationMaxWaitNanoseconds = max(
            recoveryMutationMaxWaitNanoseconds, elapsed)
        switch outcome {
        case .released:
            recoveryMutationWaitReleasesTotal &+= 1
        case .cancelled:
            break // Counted by the cancellation owner after removal.
        case .closed:
            recoveryMutationWaitClosedTotal &+= 1
        }
    }

    private func finishRecoveryMutationWaiters(
        outcome: RecoveryMutationWaitOutcome
    ) {
        guard !recoveryMutationWaiters.isEmpty else { return }
        let waiters = recoveryMutationWaiters
        recoveryMutationWaiters.removeAll(keepingCapacity: true)
        if outcome == .released {
            recoveryMutationHandoffsOutstanding += waiters.count
        }
        for waiter in waiters {
            recordRecoveryMutationWaitOutcome(waiter, outcome: outcome)
            waiter.continuation.resume(returning: outcome)
        }
    }

    private func finishRecoverySerialization() {
        finishRecoveryMutationWaiters(
            outcome: closeRequested ? .closed : .released)
        let completionWaiters = recoveryCompletionWaiters
        recoveryCompletionWaiters.removeAll(keepingCapacity: true)
        for continuation in completionWaiters {
            continuation.resume()
        }
    }

    // MARK: Storage admission

    /// Exact logical file footprint used by both hot-path admission and
    /// heartbeat telemetry. Missing WAL/SHM sidecars contribute zero; a
    /// missing/unreadable main database makes the probe fail.
    nonisolated static func exactSQLiteFootprintBytes(databasePath: String) -> Int64? {
        func size(_ path: String, required: Bool) -> Int64? {
            var info = stat()
            let rc = path.withCString { Darwin.lstat($0, &info) }
            if rc != 0 {
                return !required && errno == ENOENT ? 0 : nil
            }
            // The store rejects sidecar symlinks at open; keep probes fail-
            // closed if one appears later rather than following it.
            guard (info.st_mode & S_IFMT) == S_IFREG else { return nil }
            let value = Int64(info.st_size)
            return value >= 0 ? value : nil
        }
        guard let main = size(databasePath, required: true),
              let wal = size(databasePath + "-wal", required: false),
              let shm = size(databasePath + "-shm", required: false),
              let journal = size(databasePath + "-journal", required: false),
              main <= Int64.max - wal,
              main + wal <= Int64.max - shm,
              main + wal + shm <= Int64.max - journal
        else { return nil }
        return main + wal + shm + journal
    }

    /// Actual immediately-available blocks (`f_bavail`), intentionally not
    /// APFS "important usage" capacity, which includes purgeable/snapshot
    /// optimism and can remain large while ordinary writes receive ENOSPC.
    nonisolated static func availableFilesystemBytes(path: String) -> Int64? {
        var info = statfs()
        guard statfs(path, &info) == 0 else { return nil }
        let blocks = UInt64(info.f_bavail)
        let blockSize = UInt64(info.f_bsize)
        guard blockSize == 0 || blocks <= UInt64(Int64.max) / blockSize else { return nil }
        return Int64(blocks * blockSize)
    }

    /// Read the live SQLite-family footprint without changing admission state.
    public func storageFootprintBytes() -> Int64? {
        footprintProbe(databasePath)
    }

    /// Runtime SIGHUP hook. Lowering a cap measures and latches immediately;
    /// raising it permits the next mutation as soon as both probes are healthy.
    @discardableResult
    public func updateStorageAdmission(
        maxFootprintBytes: Int64?,
        freeSpaceFloorBytes: Int64?,
        transactionReserveBytes requestedReserve: Int64? = nil
    ) -> CausalGraphStorageAdmissionStatus {
        // A config reload is an explicit retry boundary (the operator may also
        // have freed disk space). SQLite will re-latch immediately if its own
        // FULL/ENOSPC backstop still fires.
        sqliteStorageFailure = nil
        let cap = maxFootprintBytes.flatMap { $0 > 0 ? $0 : nil }
        self.maxFootprintBytes = cap
        self.freeSpaceFloorBytes = freeSpaceFloorBytes.flatMap { $0 > 0 ? $0 : nil }
        try? checkpointController?.updateFamily(
            schema: "main",
            configuration: SQLiteControlledCheckpointFamily(
                databasePath: databasePath,
                storageVolumePath: storageVolumePath,
                freeSpaceFloorBytes: self.freeSpaceFloorBytes ?? 0,
                footprintProbe: footprintProbe,
                freeSpaceProbe: freeSpaceProbe
            )
        )
        if let cap {
            let automatic = min(
                Self.defaultMaximumTransactionReserve,
                max(Self.defaultMinimumTransactionReserve, cap / 4)
            )
            let reserve = min(
                requestedReserve.flatMap { $0 > 0 ? $0 : nil } ?? automatic,
                max(4_096, cap - 4_096)
            )
            transactionReserveBytes = reserve
            let threshold = max(0, cap - reserve)
            admissionThresholdBytes = threshold
            resumeBelowBytes = Self.recoveryResumeBelowBytes(
                capBytes: cap,
                admissionThresholdBytes: threshold,
                transactionReserveBytes: reserve
            )
        } else {
            transactionReserveBytes = nil
            admissionThresholdBytes = nil
            resumeBelowBytes = nil
            setFootprintAdmissionLatch(false)
        }
        do {
            try configureMaximumPageCount()
        } catch let admission as CausalGraphStorageAdmissionError {
            // `throwSQLiteFailure` already latched this exact typed failure.
            sqliteStorageFailure = admission
        } catch {
            // Runtime reload cannot change its established non-throwing API.
            // Keep the writer fail-closed and surface the exact underlying
            // error in the log/status transition instead of silently running
            // without the SQLite backstop.
            let admission = CausalGraphStorageAdmissionError.probeFailed(
                "max_page_count backstop: \(error.localizedDescription)")
            sqliteStorageFailure = admission
            sqliteStorageFailureGeneration &+= 1
            logger.fault("\(admission.localizedDescription, privacy: .public)")
        }
        refreshAdmissionMeasurementsAndLatch()
        return makeStorageAdmissionStatus()
    }

    public func storageAdmissionStatus() -> CausalGraphStorageAdmissionStatus {
        refreshAdmissionMeasurementsAndLatch()
        return makeStorageAdmissionStatus()
    }

    private func makeStorageAdmissionStatus() -> CausalGraphStorageAdmissionStatus {
        let writableHandle = db != nil && !isReadOnly && !closeRequested
        let hardBlocked = storageBlockReason != nil || footprintAdmissionLatched
        let recoveryMutationQueueSaturated = recovering
            && recoveryMutationWaiters.count >= recoveryMutationWaiterLimit
        let recoveryMutationOldestWaitNanoseconds = recoveryMutationWaiters
            .first.map {
                DispatchTime.now().uptimeNanoseconds &- $0.enqueuedAtNanoseconds
            } ?? 0
        return CausalGraphStorageAdmissionStatus(
            enabled: maxFootprintBytes != nil || freeSpaceFloorBytes != nil
                || deferredMigrationsPending || sqliteStorageFailure != nil,
            writableHandle: writableHandle,
            acceptingMutations: writableHandle && !hardBlocked
                && !recoveryMutationQueueSaturated,
            blocked: hardBlocked,
            reason: storageBlockReason,
            maxFootprintBytes: maxFootprintBytes,
            admissionThresholdBytes: admissionThresholdBytes,
            resumeBelowBytes: resumeBelowBytes,
            transactionReserveBytes: transactionReserveBytes,
            footprintBytes: lastFootprintBytes,
            freeSpaceBytes: lastFreeSpaceBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            shedMutationsTotal: shedMutationsTotal,
            pinnedReader: pinnedReader,
            recovering: recovering,
            autoVacuumMode: db.map { Int(StoragePragmas.readAutoVacuumMode($0)) } ?? 0,
            footprintLatchTripsTotal: footprintLatchTripsTotal,
            footprintLatchClearsTotal: footprintLatchClearsTotal,
            recoveryRunsTotal: recoveryRunsTotal,
            recoveryTracesDeletedTotal: recoveryTracesDeletedTotal,
            recoveryTraceChildRowsDeletedTotal: recoveryTraceChildRowsDeletedTotal,
            recoveryEdgesDeletedTotal: recoveryEdgesDeletedTotal,
            recoveryEntitiesDeletedTotal: recoveryEntitiesDeletedTotal,
            recoveryVacuumPagesReclaimedTotal: recoveryVacuumPagesReclaimedTotal,
            recoveryNoPhysicalProgressTotal: recoveryNoPhysicalProgressTotal,
            lastRecoveryFootprintBeforeBytes: lastRecoveryFootprintBeforeBytes,
            lastRecoveryFootprintAfterBytes: lastRecoveryFootprintAfterBytes,
            proactiveRecoveryThresholdBytes: Self.proactiveRecoveryThresholdBytes(
                admissionThresholdBytes: admissionThresholdBytes,
                transactionReserveBytes: transactionReserveBytes
            ),
            recoveryDeficitBytes: Self.recoveryDeficitBytes(
                footprintBytes: lastFootprintBytes,
                recoveryTargetBytes: resumeBelowBytes
            ),
            lastRecoveryEligibleBacklogRemaining: lastRecoveryEligibleBacklogRemaining,
            recoveryMutationWaiters: recoveryMutationWaiters.count,
            recoveryMutationWaiterLimit: recoveryMutationWaiterLimit,
            recoveryMutationQueueSaturated: recoveryMutationQueueSaturated,
            recoveryMutationWaiterHighWatermark: recoveryMutationWaiterHighWatermark,
            recoveryMutationWaitsTotal: recoveryMutationWaitsTotal,
            recoveryMutationWaitReleasesTotal:
                recoveryMutationWaitReleasesTotal,
            recoveryMutationWaitCancellationsTotal:
                recoveryMutationWaitCancellationsTotal,
            recoveryMutationWaitClosedTotal: recoveryMutationWaitClosedTotal,
            recoveryMutationWaitSaturationsTotal:
                recoveryMutationWaitSaturationsTotal,
            recoveryMutationWaitNanosecondsTotal:
                recoveryMutationWaitNanosecondsTotal,
            recoveryMutationMaxWaitNanoseconds:
                recoveryMutationMaxWaitNanoseconds,
            recoveryMutationOldestWaitNanoseconds:
                recoveryMutationOldestWaitNanoseconds,
            recoveryWriterPreemptionsTotal: recoveryWriterPreemptionsTotal
        )
    }

    private func setFootprintAdmissionLatch(_ latched: Bool) {
        guard footprintAdmissionLatched != latched else { return }
        footprintAdmissionLatched = latched
        if latched {
            footprintLatchTripsTotal &+= 1
        } else {
            footprintLatchClearsTotal &+= 1
        }
    }

    private func refreshAdmissionMeasurementsAndLatch() {
        var measuredReason: CausalGraphStorageBlockReason?
        if maxFootprintBytes != nil {
            lastFootprintBytes = footprintProbe(databasePath)
            if lastFootprintBytes == nil {
                measuredReason = .probeFailure
            } else if let footprint = lastFootprintBytes,
                      let threshold = admissionThresholdBytes,
                      footprint > threshold {
                setFootprintAdmissionLatch(true)
            } else if footprintAdmissionLatched,
                      let footprint = lastFootprintBytes,
                      let resume = resumeBelowBytes,
                      footprint < resume {
                setFootprintAdmissionLatch(false)
            }
            if footprintAdmissionLatched { measuredReason = .footprintLimit }
        } else {
            lastFootprintBytes = nil
            setFootprintAdmissionLatch(false)
        }

        if freeSpaceFloorBytes != nil {
            lastFreeSpaceBytes = freeSpaceProbe(storageVolumePath)
            if lastFreeSpaceBytes == nil {
                measuredReason = .probeFailure
            } else if let free = lastFreeSpaceBytes,
                      let floor = freeSpaceFloorBytes,
                      free < freeSpaceAdmissionRequirement(floorBytes: floor) {
                measuredReason = .lowFreeSpace
            }
        } else {
            lastFreeSpaceBytes = nil
        }
        if measuredReason == nil, deferredMigrationsPending {
            measuredReason = .probeFailure
        }
        storageBlockReason = sqliteStorageFailure?.blockReason ?? measuredReason
    }

    nonisolated static func validateInstalledMaximumPageCount(
        requestedPages: Int64,
        currentPages: Int64,
        installedPages: Int64
    ) throws {
        guard requestedPages > 0, currentPages >= 0, installedPages > 0 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "SQLite max_page_count backstop returned invalid values: requested \(requestedPages), page_count \(currentPages), installed \(installedPages)")
        }
        // SQLite cannot lower max_page_count below the inherited page_count.
        // Every other mismatch means the hard backstop did not install.
        let expected = max(requestedPages, currentPages)
        guard installedPages == expected else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "SQLite max_page_count backstop mismatch: requested \(requestedPages), page_count \(currentPages), installed \(installedPages)")
        }
    }

    private func readPageLimitPragma(
        db: OpaquePointer,
        sql: String,
        operation: CausalGraphPageLimitOperation
    ) throws -> Int64 {
        if let injected = pageLimitFailureProbe?(operation) {
            try throwSQLiteFailure(
                metadata: SQLiteFailureMetadata(
                    resultCode: injected.resultCode,
                    extendedResultCode: injected.extendedResultCode,
                    systemErrno: injected.systemErrno
                ),
                db: db,
                context: operation.rawValue
            )
        }
        var stmt: OpaquePointer?
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRC == SQLITE_OK else {
            try throwSQLiteFailure(
                rc: prepareRC, db: db, context: "prepare \(operation.rawValue)")
        }
        defer { sqlite3_finalize(stmt) }
        let stepRC = sqlite3_step(stmt)
        guard stepRC == SQLITE_ROW else {
            try throwSQLiteFailure(
                rc: stepRC, db: db, context: operation.rawValue)
        }
        return sqlite3_column_int64(stmt, 0)
    }

    private func configureMaximumPageCount() throws {
        guard let db, !isReadOnly else { return }
        let pageSize = try readPageLimitPragma(
            db: db, sql: "PRAGMA page_size", operation: .readPageSize)
        guard pageSize >= 512, pageSize <= 65_536,
              pageSize.nonzeroBitCount == 1 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "SQLite returned invalid page_size \(pageSize) while installing max_page_count")
        }
        let currentPages = try readPageLimitPragma(
            db: db, sql: "PRAGMA page_count", operation: .readPageCount)
        guard currentPages >= 0 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "SQLite returned invalid page_count \(currentPages) while installing max_page_count")
        }
        let requestedPages = admissionThresholdBytes.map {
            max(1, $0 / pageSize)
        } ?? 2_147_483_646
        let installedPages = try readPageLimitPragma(
            db: db,
            sql: "PRAGMA max_page_count = \(requestedPages)",
            operation: .installLimit
        )
        try Self.validateInstalledMaximumPageCount(
            requestedPages: requestedPages,
            currentPages: currentPages,
            installedPages: installedPages
        )
    }

    /// Upper bound reserved for one transaction. The fixed per-row allowance
    /// covers B-tree/index page splits; caller-controlled strings are charged
    /// eightfold. Calls whose bound exceeds the reserve are rejected rather
    /// than being allowed to consume an unbounded WAL in one transaction.
    private func mutationUpperBound(payloadBytes: Int, rows: Int) -> Int64 {
        let payload = Int64(max(0, payloadBytes))
        let rowCount = Int64(max(1, rows))
        let payloadCharge = payload > Int64.max / 8 ? Int64.max : payload * 8
        let rowCharge = rowCount > Int64.max / Self.mutationBytesPerRow
            ? Int64.max
            : rowCount * Self.mutationBytesPerRow
        guard payloadCharge <= Int64.max - rowCharge,
              payloadCharge + rowCharge <= Int64.max - Self.mutationBaseBytes
        else { return Int64.max }
        return Self.mutationBaseBytes + payloadCharge + rowCharge
    }

    private func payloadAdd(_ lhs: Int, _ rhs: Int) -> Int {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int.max : sum
    }

    private func payloadBytes(_ entity: TraceEntity) -> Int {
        var total = entity.id.utf8.count
        total = payloadAdd(total, entity.entityType.utf8.count)
        total = payloadAdd(total, entity.stableKey.utf8.count)
        total = payloadAdd(total, entity.displayName.utf8.count)
        total = payloadAdd(total, entity.attributesJson.utf8.count)
        return payloadAdd(total, entity.source.utf8.count)
    }

    private func payloadBytes(_ edge: TraceEdge) -> Int {
        var total = edge.id.utf8.count
        total = payloadAdd(total, edge.sourceEntityId.utf8.count)
        total = payloadAdd(total, edge.targetEntityId.utf8.count)
        total = payloadAdd(total, edge.relation.utf8.count)
        total = payloadAdd(total, edge.confidenceTier.utf8.count)
        total = payloadAdd(total, edge.evidenceJson.utf8.count)
        return payloadAdd(total, edge.eventIdsJson.utf8.count)
    }

    private func payloadBytes(_ trace: Trace) -> Int {
        let values: [String?] = [
            trace.id, trace.title, trace.anchorEventId, trace.rootEntityId,
            trace.severity, trace.status, trace.summaryJson, trace.attackJson,
            trace.evidenceBundleStatus, trace.daemonVersion,
            trace.rulesetVersion, trace.policyId, trace.policyVersion,
            trace.policySha256, trace.policySnapshotJson,
            trace.traceSigningKeyMode, trace.replayScope,
            trace.attributionOverridePolicy,
        ]
        return values.reduce(0) { payloadAdd($0, $1?.utf8.count ?? 0) }
    }

    private func payloadBytes(_ member: TraceMembership) -> Int {
        [member.traceId.utf8.count, member.entityId?.utf8.count ?? 0,
         member.edgeId?.utf8.count ?? 0, member.role.utf8.count,
         member.layer.utf8.count]
            .reduce(0, payloadAdd)
    }

    private func payloadBytes(_ hit: TraceRuleHit) -> Int {
        let values: [String?] = [
            hit.id, hit.traceId, hit.ruleId, hit.ruleTitle, hit.ruleVersion,
            hit.severity, hit.matchedEventId, hit.matchedEntityId,
            hit.matchedEdgeId, hit.explanationJson,
        ]
        return values.reduce(0) { payloadAdd($0, $1?.utf8.count ?? 0) }
    }

    private func payloadBytes(_ run: TraceReplayRun) -> Int {
        [run.id, run.traceId, run.bundleId, run.rulesetVersion,
         run.daemonVersion, run.normalizationVersion, run.resultJson]
            .reduce(0) { payloadAdd($0, $1.utf8.count) }
    }

    private func payloadBytes(_ entry: TraceHashChainEntry) -> Int {
        let values: [String?] = [
            entry.id, entry.traceId, entry.previousHash, entry.currentHash,
            entry.eventId, entry.edgeId, entry.chainHeadSignature,
        ]
        return values.reduce(0) { payloadAdd($0, $1?.utf8.count ?? 0) }
    }

    private func payloadBytes(_ entities: [TraceEntity]) -> Int {
        entities.reduce(0) { payloadAdd($0, payloadBytes($1)) }
    }

    private func payloadBytes(_ edges: [TraceEdge]) -> Int {
        edges.reduce(0) { payloadAdd($0, payloadBytes($1)) }
    }

    private func payloadBytes(_ members: [TraceMembership]) -> Int {
        members.reduce(0) { payloadAdd($0, payloadBytes($1)) }
    }

    private func payloadBytes(_ strings: [String]) -> Int {
        strings.reduce(0) { payloadAdd($0, $1.utf8.count) }
    }

    /// Defer even explicit payload accounting until admission is configured.
    /// Legacy/test/read-only callers keep their old hot path; production still
    /// performs fresh filesystem probes for every write.
    private func admitGrowth(
        payloadBytes: @autoclosure () -> Int,
        rows: Int
    ) async throws {
        try await awaitRecoveryMutationBarrier()
        guard maxFootprintBytes != nil || freeSpaceFloorBytes != nil
                || deferredMigrationsPending else { return }
        try admitGrowth(upperBoundBytes: mutationUpperBound(
            payloadBytes: payloadBytes(), rows: rows))
    }

    private func admitGrowth(upperBoundBytes: Int64) throws {
        let admissionConfigured = maxFootprintBytes != nil
            || freeSpaceFloorBytes != nil
        guard admissionConfigured || deferredMigrationsPending else { return }
        if let sqliteStorageFailure {
            try rejectGrowth(sqliteStorageFailure)
        }
        if let reserve = transactionReserveBytes, upperBoundBytes > reserve {
            try rejectGrowth(.mutationTooLarge(
                estimatedBytes: upperBoundBytes,
                transactionReserveBytes: reserve
            ))
        }
        lastAdmittedMutationUpperBoundBytes = max(0, upperBoundBytes)

        if let floor = freeSpaceFloorBytes {
            guard let free = freeSpaceProbe(storageVolumePath) else {
                lastFreeSpaceBytes = nil
                try rejectGrowth(.probeFailed("free-space"))
            }
            lastFreeSpaceBytes = free
            // Keep a stable reserve above the hard floor, even for a small
            // mutation. Status refresh and recovery use this same threshold,
            // so a blocked store cannot momentarily report healthy and emit a
            // second transition merely because the next payload is smaller.
            let requiredFree = freeSpaceAdmissionRequirement(
                floorBytes: floor,
                mutationUpperBoundBytes: lastAdmittedMutationUpperBoundBytes
            )
            if free < requiredFree {
                try rejectGrowth(.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: requiredFree
                ))
            }
        }

        if let cap = maxFootprintBytes, let threshold = admissionThresholdBytes {
            guard let footprint = footprintProbe(databasePath) else {
                lastFootprintBytes = nil
                try rejectGrowth(.probeFailed("SQLite-family footprint"))
            }
            lastFootprintBytes = footprint
            if footprintAdmissionLatched {
                let resume = resumeBelowBytes ?? threshold
                if footprint >= resume {
                    try rejectGrowth(.footprintLimit(
                        footprintBytes: footprint,
                        admissionThresholdBytes: threshold,
                        capBytes: cap
                    ))
                }
                setFootprintAdmissionLatch(false)
            }
            if footprint > threshold {
                setFootprintAdmissionLatch(true)
                try rejectGrowth(.footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: threshold,
                    capBytes: cap
                ))
            }
        }

        // An over-budget inherited DB can boot on its complete v1 runtime
        // tables so bounded recovery has something to query. It must not resume
        // ordinary growth until the deferred v2/v3 indexes and uniqueness
        // trigger have completed and passed shape verification.
        if deferredMigrationsPending {
            if let failure = deferredMigrationFailure {
                try rejectGrowth(.probeFailed(
                    "deferred schema migration failed: \(failure)"))
            }
            try completeDeferredMigrations()
            // Index creation itself writes pages/WAL. Re-sample before the
            // caller's mutation so migration growth cannot cross the admission
            // threshold and then immediately admit another transaction.
            refreshAdmissionMeasurementsAndLatch()
            if let admission = currentMeasuredAdmissionError() {
                try rejectGrowth(admission)
            }
        }

        if storageBlockReason != nil {
            logger.notice("TraceGraph storage admission recovered; mutations resumed")
        }
        storageBlockReason = nil
    }

    private func saturatingAdd(_ lhs: Int64, _ rhs: Int64) -> Int64 {
        let (sum, overflow) = lhs.addingReportingOverflow(rhs)
        return overflow ? Int64.max : sum
    }

    private func freeSpaceAdmissionRequirement(
        floorBytes: Int64,
        mutationUpperBoundBytes: Int64 = 0
    ) -> Int64 {
        let stableReserve = transactionReserveBytes
            ?? Self.defaultMinimumTransactionReserve
        return saturatingAdd(
            floorBytes,
            max(stableReserve, max(0, mutationUpperBoundBytes))
        )
    }

    /// Maintenance is allowed to checkpoint with only enough scratch to merge
    /// the current WAL into the main file, because that operation can itself
    /// restore free space. DELETE/vacuum transactions need the stronger
    /// ordinary reserve. Keep this probe side-effect-free with respect to shed
    /// counters: declining maintenance is not a failed graph mutation.
    private func recoveryMutationHeadroomAdmitted() -> Bool {
        guard let floor = freeSpaceFloorBytes else { return true }
        guard let free = freeSpaceProbe(storageVolumePath) else {
            lastFreeSpaceBytes = nil
            storageBlockReason = .probeFailure
            return false
        }
        lastFreeSpaceBytes = free
        let required = freeSpaceAdmissionRequirement(floorBytes: floor)
        guard free >= required else {
            storageBlockReason = .lowFreeSpace
            return false
        }
        return true
    }

    private func rejectGrowth(_ error: CausalGraphStorageAdmissionError) throws -> Never {
        shedMutationsTotal &+= 1
        if storageBlockReason != error.blockReason {
            logger.fault("\(error.localizedDescription, privacy: .public). Detection continues; TraceGraph persistence is shed.")
        }
        storageBlockReason = error.blockReason
        throw error
    }

    /// Convert SQLite's final file-growth backstop into the same typed,
    /// transition-logged shed path as preflight admission. `SQLITE_FULL` covers
    /// max_page_count and ordinary ENOSPC. Some VFS paths surface disk/quota
    /// exhaustion as IOERR_WRITE/FSYNC, so retain the SQLite connection's
    /// system-errno ENOSPC/EDQUOT signal.
    private func throwSQLiteFailure(
        rc: Int32,
        db: OpaquePointer,
        context: String
    ) throws -> Never {
        try throwSQLiteFailure(
            metadata: SQLiteFailureMetadata(resultCode: rc, db: db),
            db: db,
            context: context
        )
    }

    private func throwSQLiteFailure(
        metadata failure: SQLiteFailureMetadata,
        db: OpaquePointer,
        context: String
    ) throws -> Never {

        if let error = latchSQLiteStorageFailure(failure, context: context) {
            try rejectGrowth(error)
        }

        throw CausalGraphStoreError.sqliteFailure(
            context: context,
            message: String(cString: sqlite3_errmsg(db)),
            resultCode: failure.resultCode,
            extendedResultCode: failure.extendedResultCode,
            systemErrno: failure.systemErrno
        )
    }

    /// Preserve SQLite's rc/extended-rc/VFS errno classification at the point
    /// of failure and latch configured writers. Internal (rather than private)
    /// so focused fault-classification tests can inject FULL/IOERR metadata
    /// without requiring a destructive real ENOSPC fixture.
    @discardableResult
    func latchSQLiteStorageFailure(
        _ failure: SQLiteFailureMetadata,
        context: String
    ) -> CausalGraphStorageAdmissionError? {
        guard failure.isStorageExhaustion,
              maxFootprintBytes != nil || freeSpaceFloorBytes != nil else {
            return nil
        }
        let error = storageAdmissionErrorForSQLiteExhaustion(context: context)
        sqliteStorageFailure = error
        sqliteStorageFailureGeneration &+= 1
        if storageBlockReason != error.blockReason {
            logger.fault("\(error.localizedDescription, privacy: .public). SQLite maintenance failure is latched; TraceGraph growth remains disabled.")
        }
        storageBlockReason = error.blockReason
        return error
    }

    private func storageAdmissionErrorForSQLiteExhaustion(
        context: String
    ) -> CausalGraphStorageAdmissionError {
        if let floor = freeSpaceFloorBytes {
            let required = freeSpaceAdmissionRequirement(
                floorBytes: floor,
                mutationUpperBoundBytes: lastAdmittedMutationUpperBoundBytes
            )
            guard let free = freeSpaceProbe(storageVolumePath) else {
                return .probeFailed("free-space after SQLite storage exhaustion during \(context)")
            }
            lastFreeSpaceBytes = free
            if free < required {
                return .lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                )
            }
        }
        if let cap = maxFootprintBytes,
           let threshold = admissionThresholdBytes {
            let footprint = footprintProbe(databasePath)
                ?? lastFootprintBytes
                ?? threshold
            lastFootprintBytes = footprint
            setFootprintAdmissionLatch(true)
            return .footprintLimit(
                footprintBytes: footprint,
                admissionThresholdBytes: threshold,
                capBytes: cap
            )
        }
        return .probeFailed("SQLite storage exhaustion during \(context)")
    }

    private func sqliteStorageRetryHeadroomIsHealthy() -> Bool {
        if let resume = resumeBelowBytes {
            guard let footprint = lastFootprintBytes, footprint < resume else { return false }
        }
        if let floor = freeSpaceFloorBytes {
            let required = freeSpaceAdmissionRequirement(floorBytes: floor)
            guard let free = lastFreeSpaceBytes, free >= required else { return false }
        }
        return true
    }

    // MARK: Open + migrate

    private static func canonicalDatabasePath(_ path: String) throws -> String {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        guard standardized.hasPrefix("/") else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "database path must be absolute: \(path)")
        }
        let leaf = (standardized as NSString).lastPathComponent
        guard !leaf.isEmpty, leaf != ".", leaf != ".." else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "invalid database filename: \(path)")
        }
        let requestedParent = (standardized as NSString).deletingLastPathComponent
        guard let resolvedParent = requestedParent.withCString({ realpath($0, nil) }) else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "cannot resolve database parent \(requestedParent): errno \(errno)")
        }
        defer { free(resolvedParent) }
        let canonicalParent = String(cString: resolvedParent)
        try validateTrustedDirectoryChain(canonicalParent)
        return (canonicalParent as NSString).appendingPathComponent(leaf)
    }

    /// Every mutable ancestor must be controlled exclusively by root or this
    /// process. Sticky directories are deliberately rejected: sticky semantics
    /// prevent one user from renaming another user's child, but still let an
    /// attacker pre-create a predictable database/WAL name and retain an open
    /// descriptor to it. SQLite's path-only open cannot make that safe.
    private static func validateTrustedDirectoryChain(_ directoryPath: String) throws {
        let effectiveUID = geteuid()
        var current = "/"
        for component in directoryPath.split(separator: "/") {
            current = (current as NSString).appendingPathComponent(String(component))
            var info = stat()
            guard current.withCString({ Darwin.lstat($0, &info) }) == 0 else {
                throw CausalGraphStoreError.databaseOpenFailed(
                    "cannot inspect database ancestor \(current): errno \(errno)")
            }
            let fileType = info.st_mode & mode_t(S_IFMT)
            guard fileType == mode_t(S_IFDIR) else {
                throw CausalGraphStoreError.databaseOpenFailed(
                    "database ancestor is not a directory: \(current)")
            }
            guard info.st_uid == 0 || info.st_uid == effectiveUID else {
                throw CausalGraphStoreError.databaseOpenFailed(
                    "database ancestor has untrusted owner uid \(info.st_uid): \(current)")
            }
            let writableByOthers = (info.st_mode & mode_t(S_IWGRP | S_IWOTH)) != 0
            guard !writableByOthers else {
                throw CausalGraphStoreError.databaseOpenFailed(
                    "database ancestor is writable by an untrusted principal: \(current)")
            }
        }
    }

    /// Validate an already-open SQLite family member. The descriptor, rather
    /// than a prior lstat result, is authoritative. Combined with the trusted
    /// (non-group/world-writable) directory chain, another uid cannot replace
    /// the pathname between this check and SQLite's open.
    private static func validateSQLiteFileDescriptor(
        _ fd: Int32,
        displayPath: String
    ) throws {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "cannot fstat SQLite file \(displayPath): errno \(errno)")
        }
        let fileType = info.st_mode & mode_t(S_IFMT)
        guard fileType == mode_t(S_IFREG) else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "refusing non-regular SQLite file: \(displayPath)")
        }
        guard info.st_nlink == 1 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "refusing multiply-linked SQLite file: \(displayPath)")
        }
        let effectiveUID = geteuid()
        guard info.st_uid == 0 || info.st_uid == effectiveUID else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "SQLite file has untrusted owner uid \(info.st_uid): \(displayPath)")
        }
        // Accept read-only exposure from legacy 0644 files plus the intended
        // 0640 root:admin shape. Reject group/world write, execute bits, and
        // special bits. An old 0660 file is unsafe to open first and chmod
        // later: a group member may already hold a writable descriptor.
        let permissions = info.st_mode & mode_t(0o7777)
        let allowed = mode_t(0o644)
        guard (permissions & ~allowed) == 0,
              (permissions & mode_t(S_IRUSR)) != 0 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "SQLite file has unsafe mode \(String(permissions, radix: 8)): \(displayPath)")
        }
    }

    /// Open one family member relative to the already-validated parent. A
    /// missing optional sidecar is normal. O_NOFOLLOW plus fstat prevents a
    /// symlink/device/FIFO leaf from being accepted.
    @discardableResult
    private static func validateSQLiteFileAt(
        parentFD: Int32,
        name: String,
        displayPath: String,
        allowMissing: Bool
    ) throws -> Bool {
        let fd = name.withCString {
            Darwin.openat(parentFD, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        if fd < 0 {
            let openErrno = errno
            if allowMissing && openErrno == ENOENT { return false }
            throw CausalGraphStoreError.databaseOpenFailed(
                "cannot securely open SQLite file \(displayPath): errno \(openErrno)")
        }
        defer { Darwin.close(fd) }
        try validateSQLiteFileDescriptor(fd, displayPath: displayPath)
        return true
    }

    /// Anchor all leaf operations to the trusted parent directory descriptor.
    /// For a writer, pre-create a missing main file atomically with the final
    /// safe mode so SQLite never races a path-only O_CREAT against another uid.
    private static func validateSQLiteFileFamily(
        databasePath: String,
        createMainIfMissing: Bool
    ) throws {
        let parent = (databasePath as NSString).deletingLastPathComponent
        let leaf = (databasePath as NSString).lastPathComponent
        try validateTrustedDirectoryChain(parent)
        let parentFD = parent.withCString {
            Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard parentFD >= 0 else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "cannot securely open database parent \(parent): errno \(errno)")
        }
        defer { Darwin.close(parentFD) }

        var mainExists = try validateSQLiteFileAt(
            parentFD: parentFD,
            name: leaf,
            displayPath: databasePath,
            allowMissing: true
        )
        if !mainExists && createMainIfMissing {
            let createdFD = leaf.withCString {
                Darwin.openat(
                    parentFD, $0,
                    O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    mode_t(0o640)
                )
            }
            if createdFD >= 0 {
                defer { Darwin.close(createdFD) }
                try validateSQLiteFileDescriptor(createdFD, displayPath: databasePath)
                mainExists = true
            } else if errno == EEXIST {
                // Only root/euid can create in this directory, but still
                // validate the winner's descriptor rather than trusting errno.
                mainExists = try validateSQLiteFileAt(
                    parentFD: parentFD,
                    name: leaf,
                    displayPath: databasePath,
                    allowMissing: false
                )
            } else {
                throw CausalGraphStoreError.databaseOpenFailed(
                    "cannot atomically create database \(databasePath): errno \(errno)")
            }
        }
        if !createMainIfMissing && !mainExists {
            throw CausalGraphStoreError.databaseOpenFailed(
                "database does not exist: \(databasePath)")
        }

        for suffix in ["-wal", "-shm", "-journal"] {
            _ = try validateSQLiteFileAt(
                parentFD: parentFD,
                name: leaf + suffix,
                displayPath: databasePath + suffix,
                allowMissing: true
            )
        }
    }

    private func openDatabase(forceReadOnly: Bool = false) throws {
        try Self.validateSQLiteFileFamily(
            databasePath: databasePath,
            createMainIfMissing: !forceReadOnly
        )

        // v1.21.5 (audit sec-storage-crypto): umask 0o027 ⇒ new SQLite
        // WAL/SHM files are created 0o640 (owner rw, group read-only),
        // mirroring EventStore/AlertStore/CampaignStore/TraceStore. The
        // evidence DBs are root-owned; a non-root admin process must not be
        // able to open tracegraph.db read-write. Column payloads are
        // AES-GCM encrypted, so the group-write exposure was deletion / DoS
        // rather than forgery, but it's still closed here.
        //
        // When the open ends up read-only — either forceReadOnly (the
        // dashboard guaranteeing its long-lived handle never holds locks
        // that block the daemon's VACUUM) or a read-write open that FALLS
        // BACK to read-only because the caller can't write the root-owned
        // file — we skip chmod, the WAL setup, and (in init) migrations:
        // the daemon's RW connection owns all of that.
        var handle: OpaquePointer?
        var flags: Int32
        var rc: Int32
        if forceReadOnly {
            flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
            rc = SQLiteOpenPathPolicy.open(
                databasePath,
                database: &handle,
                flags: flags
            )
            self.isReadOnly = true
        } else {
            flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_FULLMUTEX
            let oldUmask = umask(0o027)
            rc = SQLiteOpenPathPolicy.open(
                databasePath,
                database: &handle,
                flags: flags
            )
            umask(oldUmask)
            // Fall back to a read-only handle if the read-write open failed
            // — e.g. a non-root MCP/CLI trace reader against the root-owned
            // 0o640 DB. Mirrors the sibling stores' openDatabase so the
            // trace-read tools keep working after the perms were tightened.
            if rc != SQLITE_OK {
                if let handle { sqlite3_close(handle) }
                handle = nil
                flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
                rc = SQLiteOpenPathPolicy.open(
                    databasePath,
                    database: &handle,
                    flags: flags
                )
                self.isReadOnly = true
            }
        }
        guard rc == SQLITE_OK, let openedHandle = handle else {
            let msg = handle.flatMap { String(cString: sqlite3_errmsg($0)) } ?? "unknown error"
            if let handle { sqlite3_close(handle) }
            throw CausalGraphStoreError.databaseOpenFailed(msg)
        }
        self.db = openedHandle
        var openCompleted = false
        defer {
            if !openCompleted, self.db == openedHandle {
                checkpointController?.detach(from: openedHandle)
                sqlite3_close(openedHandle)
                checkpointController = nil
                self.db = nil
            }
        }
        if !isReadOnly {
            checkpointController = try .install(
                on: openedHandle,
                thresholdPages: StoragePragmas.walAutocheckpointPages,
                families: [
                    "main": SQLiteControlledCheckpointFamily(
                        databasePath: databasePath,
                        storageVolumePath: storageVolumePath,
                        freeSpaceFloorBytes: freeSpaceFloorBytes ?? 0,
                        footprintProbe: footprintProbe,
                        freeSpaceProbe: freeSpaceProbe
                    ),
                ]
            )
        }
        // Revalidate the descriptor-backed family immediately after SQLite's
        // pathname open. The trusted directory means no untrusted uid can win
        // a rename race between our openat/fstat and sqlite3_open_v2.
        try Self.validateSQLiteFileFamily(
            databasePath: databasePath,
            createMainIfMissing: false
        )
        if !isReadOnly {
            // Earliest point at which the handle exists: install the main-file
            // limit and measure pressure before journal-mode or schema writes.
            try configureMaximumPageCount()
            refreshAdmissionMeasurementsAndLatch()
        }
        // Per-connection pragmas: smaller than EventStore (graph data is
        // moderate volume), larger than alerts (recursive walks are
        // common). Roughly midway: 16 MB cache, 64 MB mmap.
        //
        // journal_mode = WAL is the only pragma that touches the file
        // (it changes the journaling format) — skip it on a RO handle
        // since the daemon already set the file's mode. The remaining
        // pragmas are per-connection state and are safe to apply
        // either way.
        // Wave 9B.1 (v1.12.6 RC2): auto_vacuum MUST come BEFORE journal_mode
        // — SQLite silently refuses to flip auto_vacuum after the WAL setup
        // dirties the DB header. Pre-9B.1 tracegraph.db never set
        // auto_vacuum, so it stayed in mode 0 (NONE) and incrementalVacuum
        // was a no-op. Field-confirmed bug: tracegraph.db at 11 GB in
        // mode 0 on a v1.12.6 RC1 user machine.
        if !isReadOnly, storageBlockReason == nil {
            try admitSchemaStorageWork(SchemaStorageWork(
                boundedMetadataStatementCount: 1,
                rebuildStatementCount: 0
            ))
            let oldUmask = umask(0o027)
            sqlite3_exec(openedHandle, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
            sqlite3_exec(openedHandle, "PRAGMA journal_mode = WAL", nil, nil, nil)
            umask(oldUmask)
            sqlite3_exec(openedHandle, "PRAGMA synchronous = NORMAL", nil, nil, nil)
            // v1.18: bound the WAL so it can't outgrow the main DB (see
            // StoragePragmas.journalSizeLimitBytes).
            sqlite3_exec(openedHandle, "PRAGMA journal_size_limit = \(StoragePragmas.journalSizeLimitBytes)", nil, nil, nil)
        }
        sqlite3_exec(openedHandle, "PRAGMA cache_size = -16000", nil, nil, nil)
        sqlite3_exec(openedHandle, "PRAGMA mmap_size = 33554432", nil, nil, nil) // 32 MB (v1.21.4: trim daemon resident-file-page ceiling; pages are reclaimable/clean)
        sqlite3_exec(openedHandle, "PRAGMA temp_store = MEMORY", nil, nil, nil)
        sqlite3_busy_timeout(openedHandle, CausalGraphWriteResponsiveness.sqliteBusyTimeoutMilliseconds)
        sqlite3_exec(openedHandle, "PRAGMA foreign_keys = ON", nil, nil, nil)
        // journal_mode can create WAL/SHM after the first validation. Inspect
        // every member by descriptor again before returning the live handle.
        try Self.validateSQLiteFileFamily(
            databasePath: databasePath,
            createMainIfMissing: false
        )
        openCompleted = true
    }

    private func currentMeasuredAdmissionError() -> CausalGraphStorageAdmissionError? {
        if let floor = freeSpaceFloorBytes {
            guard let free = lastFreeSpaceBytes else {
                return .probeFailed("free-space")
            }
            let required = freeSpaceAdmissionRequirement(floorBytes: floor)
            if free < required {
                return .lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                )
            }
        }
        switch storageBlockReason {
        case .footprintLimit:
            guard let cap = maxFootprintBytes,
                  let threshold = admissionThresholdBytes else { return nil }
            return .footprintLimit(
                footprintBytes: lastFootprintBytes ?? threshold,
                admissionThresholdBytes: threshold,
                capBytes: cap
            )
        case .lowFreeSpace:
            guard let floor = freeSpaceFloorBytes else { return nil }
            let required = freeSpaceAdmissionRequirement(floorBytes: floor)
            return .lowFreeSpace(
                freeBytes: lastFreeSpaceBytes ?? 0,
                floorBytes: floor,
                requiredFreeBytes: required
            )
        case .probeFailure:
            if freeSpaceFloorBytes != nil, lastFreeSpaceBytes == nil {
                return .probeFailed("free-space")
            }
            return .probeFailed("SQLite-family footprint")
        case .mutationTooLarge, .recoveryInProgress, .none:
            return nil
        }
    }

    /// Baseline v1 contains all runtime tables; v2 adds only performance
    /// indexes. If these tables exist, an over-budget inherited DB can safely
    /// defer idempotent migrations while bounded recovery runs.
    private func hasUsableRuntimeSchema() -> Bool {
        guard let db else { return false }
        let sql = """
        SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table'
           AND name IN ('trace_entities', 'trace_edges', 'traces',
                        'trace_membership', 'trace_rule_hits',
                        'trace_replay_runs', 'trace_hash_chain')
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            return false
        }
        defer { sqlite3_finalize(stmt) }
        return sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 7
    }

    private func applyMigrations() throws {
        guard let db else {
            throw CausalGraphStoreError.databaseOpenFailed("nil handle at migration time")
        }
        do {
            // v1.12.0 RC23: skip the per-init quick_check. Field-measured
            // boot path: tracegraph.db reached 7 GB on a long-running
            // install, and PRAGMA quick_check on a 7 GB SQLite file took
            // ~27 s — eating the whole daemon TraceGraph wiring step.
            // Same trade-off as EventStore: real corruption surfaces
            // immediately on actual queries, and an explicit operator
            // path exists in `maccrabctl maintenance check`.
            try SchemaMigrator.run(
                on: db,
                migrations: Self.schemaMigrations,
                logger: { msg in
                    self.logger.debug("\(msg, privacy: .public)")
                },
                skipQuickCheck: true,
                beforeStorageWork: { work in
                    try self.admitSchemaStorageWork(work)
                }
            )
            try verifyRequiredMigrationObjects(db: db)
        } catch let error as SchemaMigrationError {
            // max_page_count is installed before migrations. If it fires, this
            // is a storage-pressure condition, not evidence of corruption. Keep
            // the typed error intact so daemon startup preserves (rather than
            // quarantines) the existing evidence database.
            if let failure = error.sqliteFailureMetadata {
                if let admission = latchSQLiteStorageFailure(
                    failure, context: "schema migration") {
                    try rejectGrowth(admission)
                }
                // Preserve explicit SQLite classification for the daemon's
                // corruption policy. CORRUPT/NOTADB may be quarantined;
                // BUSY/LOCKED/PERM/READONLY/other IOERR must not be mislabeled.
                throw CausalGraphStoreError.sqliteFailure(
                    context: "schema migration",
                    message: error.localizedDescription,
                    resultCode: failure.resultCode,
                    extendedResultCode: failure.extendedResultCode,
                    systemErrno: failure.systemErrno
                )
            }
            throw CausalGraphStoreError.schemaFailed(error.localizedDescription)
        }
    }

    /// Schema repairs run during boot and during post-reclaim deferred
    /// recovery, so they cannot use `admitGrowth`: that method intentionally
    /// tries to complete deferred migrations and would recurse. Re-probe here
    /// at the exact DDL boundary. Metadata work keeps the ordinary stable
    /// reserve; index construction gets main-file-scaled growth and scratch.
    private func schemaStorageAdmissionError(
        for work: SchemaStorageWork
    ) -> CausalGraphStorageAdmissionError? {
        guard !work.isEmpty else { return nil }
        let configured = maxFootprintBytes != nil || freeSpaceFloorBytes != nil
        guard configured else { return nil }

        let metadataEstimate = work.boundedTransactionEstimateBytes
        if let reserve = transactionReserveBytes,
           metadataEstimate > reserve {
            return .mutationTooLarge(
                estimatedBytes: metadataEstimate,
                transactionReserveBytes: reserve
            )
        }

        guard let footprint = footprintProbe(databasePath) else {
            lastFootprintBytes = nil
            return .probeFailed("schema SQLite-family footprint")
        }
        lastFootprintBytes = footprint
        guard let free = freeSpaceProbe(storageVolumePath) else {
            lastFreeSpaceBytes = nil
            return .probeFailed("schema free-space")
        }
        lastFreeSpaceBytes = free

        if work.rebuildStatementCount > 0 {
            let main: Int64
            do {
                main = try SQLitePersistentStoreAdmission.measureMainFile(
                    databasePath
                )
            } catch {
                return .probeFailed(
                    "schema main-file measurement: \(error.localizedDescription)"
                )
            }
            let operations = Int64(work.rebuildStatementCount)
            let growth = SQLitePersistentStoreAdmission.saturatingMultiply(
                main,
                by: operations
            )
            let scratch = SQLitePersistentStoreAdmission.saturatingAdd(
                main,
                growth
            )
            let projected = SQLitePersistentStoreAdmission.saturatingAdd(
                footprint,
                growth
            )
            let projectedMain = SQLitePersistentStoreAdmission.saturatingAdd(
                main,
                growth
            )
            if let threshold = admissionThresholdBytes,
               projectedMain > threshold {
                return .footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: max(0, threshold - growth),
                    capBytes: maxFootprintBytes ?? threshold
                )
            }
            if let cap = maxFootprintBytes,
               projected > cap {
                return .footprintLimit(
                    footprintBytes: footprint,
                    admissionThresholdBytes: max(0, cap - growth),
                    capBytes: cap
                )
            }
            let floor = freeSpaceFloorBytes ?? 0
            let required = SQLitePersistentStoreAdmission.saturatingAdd(
                floor,
                scratch
            )
            if growth == Int64.max || scratch == Int64.max
                || projectedMain == Int64.max
                || projected == Int64.max || required == Int64.max
                || free < required {
                return .lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                )
            }
            return nil
        }

        if let cap = maxFootprintBytes,
           let threshold = admissionThresholdBytes,
           footprint > threshold {
            return .footprintLimit(
                footprintBytes: footprint,
                admissionThresholdBytes: threshold,
                capBytes: cap
            )
        }
        if let floor = freeSpaceFloorBytes {
            let required = freeSpaceAdmissionRequirement(
                floorBytes: floor,
                mutationUpperBoundBytes: metadataEstimate
            )
            if free < required {
                return .lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    requiredFreeBytes: required
                )
            }
        }
        return nil
    }

    private func admitSchemaStorageWork(_ work: SchemaStorageWork) throws {
        if let refusal = schemaStorageAdmissionError(for: work) {
            try rejectGrowth(refusal)
        }
    }

    private func migrationIndexColumns(
        db: OpaquePointer,
        name: String
    ) throws -> [String] {
        var stmt: OpaquePointer?
        let sql = "PRAGMA index_info('\(name)')"
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRC == SQLITE_OK else {
            try throwSQLiteFailure(
                rc: prepareRC, db: db,
                context: "prepare migration index verification \(name)")
        }
        defer { sqlite3_finalize(stmt) }
        var columns: [String] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return columns }
            guard rc == SQLITE_ROW else {
                try throwSQLiteFailure(
                    rc: rc, db: db,
                    context: "migration index verification \(name)")
            }
            if let raw = sqlite3_column_text(stmt, 2) {
                columns.append(String(cString: raw))
            }
        }
    }

    /// SchemaMigrator deliberately treats already-exists as idempotent. Verify
    /// the load-bearing v2/v3 objects and their shapes so a same-named but
    /// incorrect inherited object cannot make a deferred migration look done.
    private func verifyRequiredMigrationObjects(db: OpaquePointer) throws {
        let expectedIndexes: [(String, [String])] = [
            ("idx_entities_lastseen", ["last_seen"]),
            ("idx_edges_lastseen", ["last_seen"]),
            ("idx_hash_chain_global_seq", ["sequence_number"]),
        ]
        for (name, expectedColumns) in expectedIndexes {
            let actual = try migrationIndexColumns(db: db, name: name)
            guard actual == expectedColumns else {
                throw CausalGraphStoreError.schemaFailed(
                    "migration verification failed for \(name): expected \(expectedColumns), found \(actual)")
            }
        }

        var stmt: OpaquePointer?
        let sql = """
        SELECT tbl_name, sql
          FROM sqlite_master
         WHERE type = 'trigger'
           AND name = 'trg_hash_chain_global_sequence_unique'
        """
        let prepareRC = sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
        guard prepareRC == SQLITE_OK else {
            try throwSQLiteFailure(
                rc: prepareRC, db: db,
                context: "prepare continuity-trigger migration verification")
        }
        defer { sqlite3_finalize(stmt) }
        let stepRC = sqlite3_step(stmt)
        guard stepRC == SQLITE_ROW,
              let tableRaw = sqlite3_column_text(stmt, 0),
              let sqlRaw = sqlite3_column_text(stmt, 1) else {
            if stepRC != SQLITE_DONE {
                try throwSQLiteFailure(
                    rc: stepRC, db: db,
                    context: "continuity-trigger migration verification")
            }
            throw CausalGraphStoreError.schemaFailed(
                "migration verification failed: continuity uniqueness trigger missing")
        }
        let table = String(cString: tableRaw)
        let triggerSQL = String(cString: sqlRaw).lowercased()
        guard table == "trace_hash_chain",
              triggerSQL.contains("sequence_number = new.sequence_number"),
              triggerSQL.contains("raise(abort") else {
            throw CausalGraphStoreError.schemaFailed(
                "migration verification failed: continuity uniqueness trigger has an unexpected definition")
        }
        let trailingRC = sqlite3_step(stmt)
        guard trailingRC == SQLITE_DONE else {
            try throwSQLiteFailure(
                rc: trailingRC, db: db,
                context: "continuity-trigger migration verification trailing row")
        }
    }

    private func completeDeferredMigrations() throws {
        guard deferredMigrationsPending else { return }
        if let failure = deferredMigrationFailure {
            throw CausalGraphStorageAdmissionError.probeFailed(
                "deferred schema migration failed: \(failure)")
        }
        do {
            try applyMigrations()
            try configureMaximumPageCount()
            deferredMigrationsPending = false
            deferredMigrationFailure = nil
            refreshAdmissionMeasurementsAndLatch()
            logger.notice("TraceGraph deferred schema migrations completed and verified")
        } catch let admission as CausalGraphStorageAdmissionError {
            // Storage failures are retryable after another bounded reclaim.
            throw admission
        } catch {
            deferredMigrationFailure = error.localizedDescription
            storageBlockReason = .probeFailure
            logger.fault("TraceGraph deferred schema migration failed; growth remains disabled: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    private func pendingDeferredMigrationStorageWork() throws -> SchemaStorageWork {
        guard let db else {
            throw CausalGraphStoreError.databaseOpenFailed(
                "nil handle while planning deferred migrations")
        }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(
            db, "PRAGMA user_version", -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(
                String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(
                "could not read user_version while planning deferred migrations")
        }
        let currentVersion = Int(sqlite3_column_int(stmt, 0))
        var metadata = 0
        var rebuilds = 0
        for migration in Self.schemaMigrations {
            let pending = SchemaMigrator.pendingStorageWork(
                on: db,
                statements: migration.sql
            )
            metadata += pending.boundedMetadataStatementCount
            rebuilds += pending.rebuildStatementCount
            if migration.version > currentVersion {
                metadata += 1 // PRAGMA user_version header mutation
            }
        }
        return SchemaStorageWork(
            boundedMetadataStatementCount: metadata,
            rebuildStatementCount: rebuilds
        )
    }

    private func deferredMigrationHasStorageHeadroom() -> Bool {
        guard let work = try? pendingDeferredMigrationStorageWork() else {
            return false
        }
        return schemaStorageAdmissionError(for: work) == nil
    }

    // MARK: - upsertEntity

    public func upsertEntity(_ entity: TraceEntity) async throws {
        try await admitGrowth(payloadBytes: payloadBytes(entity), rows: 1)
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT INTO trace_entities (
            id, entity_type, stable_key, display_name,
            first_seen, last_seen, attributes_json, source,
            confidence, observation_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_type, stable_key) DO UPDATE SET
            last_seen = max(trace_entities.last_seen, excluded.last_seen),
            observation_count = trace_entities.observation_count + excluded.observation_count,
            attributes_json = excluded.attributes_json,
            confidence = excluded.confidence,
            display_name = excluded.display_name
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        let encryptedAttrs = encryption?.encrypt(entity.attributesJson) ?? entity.attributesJson

        sqlite3_bind_text(stmt, 1, entity.id, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, entity.entityType, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, entity.stableKey, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 4, entity.displayName, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 5, entity.firstSeen.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 6, entity.lastSeen.timeIntervalSince1970)
        sqlite3_bind_text(stmt, 7, encryptedAttrs, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 8, entity.source, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 9, entity.confidence)
        sqlite3_bind_int64(stmt, 10, Int64(max(1, entity.observationCount)))

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwSQLiteFailure(rc: rc, db: db, context: "upsertEntity")
        }
    }

    // MARK: - upsertEdge

    public func upsertEdge(_ edge: TraceEdge) async throws {
        try await admitGrowth(payloadBytes: payloadBytes(edge), rows: 1)
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT INTO trace_edges (
            id, source_entity_id, target_entity_id, relation,
            first_seen, last_seen, confidence, confidence_tier,
            evidence_json, event_ids_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_entity_id, target_entity_id, relation) DO UPDATE SET
            last_seen = max(trace_edges.last_seen, excluded.last_seen),
            confidence = excluded.confidence,
            confidence_tier = excluded.confidence_tier,
            evidence_json = excluded.evidence_json,
            event_ids_json = excluded.event_ids_json
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        let encryptedEvidence = encryption?.encrypt(edge.evidenceJson) ?? edge.evidenceJson

        sqlite3_bind_text(stmt, 1, edge.id, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, edge.sourceEntityId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 3, edge.targetEntityId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 4, edge.relation, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 5, edge.firstSeen.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 6, edge.lastSeen.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 7, edge.confidence)
        sqlite3_bind_text(stmt, 8, edge.confidenceTier, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 9, encryptedEvidence, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 10, edge.eventIdsJson, -1, SQLITE_TRANSIENT)

        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwSQLiteFailure(rc: rc, db: db, context: "upsertEdge")
        }
    }

    // MARK: - upsertBatch  (v1.17.4 perf)
    //
    // Persist all entities then all edges for one or more observations inside
    // a SINGLE transaction, reusing one prepared statement per table
    // (reset + rebind).
    // instead of prepare/step/finalize + autocommit PER ROW. Pre-fix a
    // single event's ~7 upserts were ~7 autocommit transactions + 7
    // prepares (RollingCausalGraph.ingest called the store one row at a
    // time). The transaction MUST live here, in the store actor: there is
    // no `await` between BEGIN and COMMIT, so no other actor call can
    // interleave (wrapping it from RollingCausalGraph across the await
    // boundary would be unsafe). Entities are inserted before edges so the
    // trace_edges→trace_entities FKs hold for in-batch endpoints. Per-row
    // failures (e.g. an edge whose endpoint is neither in the batch nor the
    // DB) abort and roll back the whole batch. In particular SQLITE_FULL from
    // `max_page_count` must never be logged-and-committed as partial success.
    public func upsertBatch(entities: [TraceEntity], edges: [TraceEdge]) async throws {
        guard !entities.isEmpty || !edges.isEmpty else { return }
        try await admitGrowth(
            payloadBytes: payloadAdd(payloadBytes(entities), payloadBytes(edges)),
            rows: entities.count + edges.count
        )
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }

        try execTransaction(.begin, db: db)
        do {
            if !entities.isEmpty {
                let sql = """
                INSERT INTO trace_entities (
                    id, entity_type, stable_key, display_name,
                    first_seen, last_seen, attributes_json, source,
                    confidence, observation_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_type, stable_key) DO UPDATE SET
                    last_seen = max(trace_entities.last_seen, excluded.last_seen),
                    observation_count = trace_entities.observation_count + excluded.observation_count,
                    attributes_json = excluded.attributes_json,
                    confidence = excluded.confidence,
                    display_name = excluded.display_name
                """
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
                }
                defer { sqlite3_finalize(stmt) }
                for entity in entities {
                    let encryptedAttrs = encryption?.encrypt(entity.attributesJson) ?? entity.attributesJson
                    sqlite3_bind_text(stmt, 1, entity.id, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 2, entity.entityType, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 3, entity.stableKey, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 4, entity.displayName, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_double(stmt, 5, entity.firstSeen.timeIntervalSince1970)
                    sqlite3_bind_double(stmt, 6, entity.lastSeen.timeIntervalSince1970)
                    sqlite3_bind_text(stmt, 7, encryptedAttrs, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 8, entity.source, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_double(stmt, 9, entity.confidence)
                    sqlite3_bind_int64(stmt, 10, Int64(max(1, entity.observationCount)))
                    let rc = sqlite3_step(stmt)
                    if rc != SQLITE_DONE {
                        try throwSQLiteFailure(
                            rc: rc, db: db, context: "upsertBatch entity")
                    }
                    sqlite3_reset(stmt)
                    sqlite3_clear_bindings(stmt)
                }
            }
            if !edges.isEmpty {
                let sql = """
                INSERT INTO trace_edges (
                    id, source_entity_id, target_entity_id, relation,
                    first_seen, last_seen, confidence, confidence_tier,
                    evidence_json, event_ids_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_entity_id, target_entity_id, relation) DO UPDATE SET
                    last_seen = max(trace_edges.last_seen, excluded.last_seen),
                    confidence = excluded.confidence,
                    confidence_tier = excluded.confidence_tier,
                    evidence_json = excluded.evidence_json,
                    event_ids_json = excluded.event_ids_json
                """
                var stmt: OpaquePointer?
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
                }
                defer { sqlite3_finalize(stmt) }
                for edge in edges {
                    let encryptedEvidence = encryption?.encrypt(edge.evidenceJson) ?? edge.evidenceJson
                    sqlite3_bind_text(stmt, 1, edge.id, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 2, edge.sourceEntityId, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 3, edge.targetEntityId, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 4, edge.relation, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_double(stmt, 5, edge.firstSeen.timeIntervalSince1970)
                    sqlite3_bind_double(stmt, 6, edge.lastSeen.timeIntervalSince1970)
                    sqlite3_bind_double(stmt, 7, edge.confidence)
                    sqlite3_bind_text(stmt, 8, edge.confidenceTier, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 9, encryptedEvidence, -1, SQLITE_TRANSIENT)
                    sqlite3_bind_text(stmt, 10, edge.eventIdsJson, -1, SQLITE_TRANSIENT)
                    let rc = sqlite3_step(stmt)
                    if rc != SQLITE_DONE {
                        try throwSQLiteFailure(
                            rc: rc, db: db, context: "upsertBatch edge")
                    }
                    sqlite3_reset(stmt)
                    sqlite3_clear_bindings(stmt)
                }
            }
            try execTransaction(.commit, db: db)
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    // MARK: - entity / edge lookups

    public func entity(id: String) async throws -> TraceEntity? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, entity_type, stable_key, display_name,
               first_seen, last_seen, attributes_json, source,
               confidence, observation_count
          FROM trace_entities WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeEntityRow(stmt!)
    }

    /// Batch entity lookup via `WHERE id IN (…)` — one round trip in place of
    /// N `entity(id:)` calls (the dashboard's trace-member resolution path).
    /// Returns one row per DISTINCT matching id; unknown ids are simply absent
    /// (never nil placeholders), matching the protocol contract. Callers pass
    /// bounded id sets (a trace's members are ≤ the §14.3 context budget, well
    /// under SQLite's 999 host-parameter ceiling), so a single statement suffices.
    public func entities(ids: [String]) async throws -> [TraceEntity] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard !ids.isEmpty else { return [] }
        let placeholders = ids.map { _ in "?" }.joined(separator: ", ")
        let sql = """
        SELECT id, entity_type, stable_key, display_name,
               first_seen, last_seen, attributes_json, source,
               confidence, observation_count
          FROM trace_entities WHERE id IN (\(placeholders))
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        for (idx, id) in ids.enumerated() {
            sqlite3_bind_text(stmt, Int32(1 + idx), id, -1, SQLITE_TRANSIENT)
        }
        var out: [TraceEntity] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeEntityRow(stmt!))
        }
        return out
    }

    public func edge(id: String) async throws -> TraceEdge? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, source_entity_id, target_entity_id, relation,
               first_seen, last_seen, confidence, confidence_tier,
               evidence_json, event_ids_json
          FROM trace_edges WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeEdgeRow(stmt!)
    }

    // MARK: - Graph traversal (BFS)

    public func ancestors(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree {
        try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .incoming,
            relations: ["spawned"]
        )
    }

    public func descendants(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree {
        try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .outgoing,
            relations: ["spawned"]
        )
    }

    public func neighborhood(of entityId: String, depth: Int, within window: TimeWindow) async throws -> GraphSubtree {
        // Bidirectional, all relations.
        let inSubtree = try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .incoming,
            relations: nil
        )
        let outSubtree = try walk(
            startId: entityId,
            depth: depth,
            window: window,
            edgeDirection: .outgoing,
            relations: nil
        )
        // Include the anchor entity itself in neighborhood results.
        var anchorEntities: [TraceEntity] = []
        if let anchor = try lookupEntitySync(id: entityId) {
            anchorEntities.append(anchor)
        }
        let mergedEntities = mergeUniqueEntities(anchorEntities + inSubtree.entities + outSubtree.entities)
        let mergedEdges = mergeUniqueEdges(inSubtree.edges + outSubtree.edges)
        let truncated = inSubtree.truncated || outSubtree.truncated
        return GraphSubtree(entities: mergedEntities, edges: mergedEdges, truncated: truncated)
    }

    public func criticalPath(from source: String, to target: String, maxDepth: Int) async throws -> [TraceEdge] {
        // Unweighted BFS shortest path (PR-8 will layer
        // confidence-weighted scoring on top).
        //
        // v1.12.0 RC4 fix (Perf-NEW-2): cap the frontier per BFS
        // level. Pre-fix this was the same unbounded-fan-out shape
        // that Perf-H2 closed in `walk()`. criticalPath is called
        // from TraceMaterializer.materialize on EVERY anchor (hot
        // path), so a widely-fanned process burst would re-introduce
        // the same actor-starvation symptom on the SQLite causal-
        // graph store. Frontier cap 256 matches `walk()`'s; we don't
        // signal truncation back to the caller because path-not-
        // found returns the same empty result.
        guard maxDepth > 0 else { return [] }
        if source == target { return [] }

        var visited: Set<String> = [source]
        var parentEdge: [String: TraceEdge] = [:]   // entityId → edge that reached it
        var frontier: [String] = [source]
        let frontierCap = 256

        for _ in 0 ..< maxDepth {
            var next: [String] = []
            outer: for current in frontier {
                let outgoing = try fetchEdges(
                    pivotId: current,
                    direction: .outgoing,
                    window: .unlimited,
                    relations: nil
                )
                for edge in outgoing {
                    let neighbor = edge.targetEntityId
                    if visited.contains(neighbor) { continue }
                    visited.insert(neighbor)
                    parentEdge[neighbor] = edge
                    if neighbor == target {
                        return reconstructPath(target: target, parentEdge: parentEdge)
                    }
                    next.append(neighbor)
                    if next.count >= frontierCap { break outer }
                }
            }
            if next.isEmpty { break }
            frontier = next
        }
        return []
    }

    private enum EdgeDirection { case incoming, outgoing }

    private func walk(
        startId: String,
        depth: Int,
        window: TimeWindow,
        edgeDirection: EdgeDirection,
        relations: Set<String>?
    ) throws -> GraphSubtree {
        guard depth > 0 else { return .empty }
        var visited: Set<String> = [startId]
        var entitiesById: [String: TraceEntity] = [:]
        var collectedEdges: [TraceEdge] = []
        var frontier: Set<String> = [startId]
        var truncated = false

        // v1.12.0 RC3 (Perf-H2): cap the frontier per BFS level. A
        // widely-fanned process (e.g. a `bun` shell with many
        // spawned children + many file edges) at depth-3 can pull
        // thousands of edges per walk. Under adversarial burst this
        // serializes on the single SQLiteCausalGraphStore actor that
        // is also handling the hot-path event writes — main pump
        // starves. Frontier cap of 256/level keeps the walk bounded;
        // when we hit the cap we set `truncated=true`.
        let frontierCap = 256
        for _ in 0 ..< depth {
            var nextFrontier: Set<String> = []
            outer: for pivot in frontier {
                let edges = try fetchEdges(
                    pivotId: pivot,
                    direction: edgeDirection,
                    window: window,
                    relations: relations
                )
                for edge in edges {
                    let other = (edgeDirection == .incoming) ? edge.sourceEntityId : edge.targetEntityId
                    if visited.contains(other) { continue }
                    visited.insert(other)
                    nextFrontier.insert(other)
                    collectedEdges.append(edge)
                    if let entity = try lookupEntitySync(id: other) {
                        entitiesById[other] = entity
                    }
                    if nextFrontier.count >= frontierCap {
                        truncated = true
                        break outer
                    }
                }
            }
            if nextFrontier.isEmpty { break }
            frontier = nextFrontier
        }

        // Truncation flag: did the BFS terminate because depth was hit
        // even though there were more frontier nodes available? We
        // detect this conservatively — if the loop exited via running
        // out of iterations rather than empty frontier.
        // (For v1.10.0 the simpler heuristic is: if the final frontier
        // had outgoing edges we didn't explore, mark truncated.)
        //
        // v1.12.0 RC4 fix (Perf-NEW-1): skip the post-pass entirely
        // when `truncated` is already true from the frontier-cap
        // path. The post-pass re-issues `fetchEdges` against every
        // node in the final frontier (up to 256 nodes from the
        // frontierCap) — a hot-path SQLite burst that partially
        // defeats Perf-H2's bound. If we already know we're
        // truncated, there's nothing new to learn.
        if !truncated {
            for pivot in frontier {
                let unexplored = try fetchEdges(
                    pivotId: pivot,
                    direction: edgeDirection,
                    window: window,
                    relations: relations
                )
                for edge in unexplored {
                    let other = (edgeDirection == .incoming) ? edge.sourceEntityId : edge.targetEntityId
                    if !visited.contains(other) {
                        truncated = true
                        break
                    }
                }
                if truncated { break }
            }
        }

        return GraphSubtree(
            entities: Array(entitiesById.values),
            edges: collectedEdges,
            truncated: truncated
        )
    }

    private func fetchEdges(
        pivotId: String,
        direction: EdgeDirection,
        window: TimeWindow,
        relations: Set<String>?
    ) throws -> [TraceEdge] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let pivotColumn = (direction == .incoming) ? "target_entity_id" : "source_entity_id"
        var sql = """
        SELECT id, source_entity_id, target_entity_id, relation,
               first_seen, last_seen, confidence, confidence_tier,
               evidence_json, event_ids_json
          FROM trace_edges
         WHERE \(pivotColumn) = ?
           AND last_seen >= ? AND last_seen <= ?
        """
        if let relations, !relations.isEmpty {
            let placeholders = relations.map { _ in "?" }.joined(separator: ", ")
            sql += " AND relation IN (\(placeholders))"
        }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, pivotId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_double(stmt, 2, window.start.timeIntervalSince1970)
        sqlite3_bind_double(stmt, 3, window.end.timeIntervalSince1970)
        if let relations, !relations.isEmpty {
            for (idx, rel) in relations.sorted().enumerated() {
                sqlite3_bind_text(stmt, Int32(4 + idx), rel, -1, SQLITE_TRANSIENT)
            }
        }

        var out: [TraceEdge] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeEdgeRow(stmt!))
        }
        return out
    }

    private func lookupEntitySync(id: String) throws -> TraceEntity? {
        guard let db else { return nil }
        let sql = """
        SELECT id, entity_type, stable_key, display_name,
               first_seen, last_seen, attributes_json, source,
               confidence, observation_count
          FROM trace_entities WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc != SQLITE_ROW { return nil }
        return try decodeEntityRow(stmt!)
    }

    private func reconstructPath(target: String, parentEdge: [String: TraceEdge]) -> [TraceEdge] {
        var path: [TraceEdge] = []
        var current = target
        while let edge = parentEdge[current] {
            path.append(edge)
            current = edge.sourceEntityId
            if path.count > 1024 { break }   // pathological-loop guard
        }
        return path.reversed()
    }

    // MARK: - Trace lifecycle

    public func saveTrace(_ trace: Trace, members: [TraceMembership]) async throws {
        try await admitGrowth(
            payloadBytes: payloadAdd(payloadBytes(trace), payloadBytes(members)),
            rows: members.count + 2
        )
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        try execTransaction(.begin, db: db)
        do {
            try insertOrReplaceTraceRow(trace, db: db)
            // Purge prior memberships for this trace id so re-saves are idempotent.
            try execBound(
                db: db,
                sql: "DELETE FROM trace_membership WHERE trace_id = ?",
                bindings: { stmt in
                    sqlite3_bind_text(stmt, 1, trace.id, -1, SQLITE_TRANSIENT)
                }
            )
            for member in members {
                try insertMembership(member, db: db)
            }
            if let latestMembership = members.map(\.addedAt).max() {
                try advanceTraceUpdatedAt(
                    traceId: trace.id,
                    through: latestMembership,
                    db: db
                )
            }
            try execTransaction(.commit, db: db)
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    public func loadTrace(id: String) async throws -> (trace: Trace, members: [TraceMembership])? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard let trace = try fetchTraceRow(id: id, db: db) else { return nil }
        let members = try fetchTraceMembership(traceId: id, db: db)
        return (trace, members)
    }

    /// Return every relation-typed edge whose BOTH endpoints are member
    /// entities of the given trace — the real causal skeleton the dashboard's
    /// Investigation graph draws (source→target) instead of the fabricated
    /// anchor→every-node hub-spokes it falls back to when no edges are known.
    ///
    /// Member entity ids come from `trace_membership` (entity rows only). An
    /// edge is kept only when its source AND target are both in that set, so a
    /// context edge that dangles to an entity outside the trace is excluded.
    /// Returns [] when the trace has no member entities. Member sets are bounded
    /// (≤ the §14.3 context budget), so 2×|members| bind params stays under
    /// SQLite's 999-parameter ceiling.
    public func edgesAmongTraceMembers(traceId: String) async throws -> [TraceEdge] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        // 1. Resolve the trace's member entity ids.
        let memberSql = """
        SELECT entity_id FROM trace_membership
         WHERE trace_id = ? AND entity_id IS NOT NULL
        """
        var memberStmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, memberSql, -1, &memberStmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        sqlite3_bind_text(memberStmt, 1, traceId, -1, SQLITE_TRANSIENT)
        var memberIds: [String] = []
        while sqlite3_step(memberStmt) == SQLITE_ROW {
            if let idc = sqlite3_column_text(memberStmt, 0) {
                memberIds.append(String(cString: idc))
            }
        }
        sqlite3_finalize(memberStmt)
        guard !memberIds.isEmpty else { return [] }

        // 2. Fetch edges whose source AND target are both member entities.
        let placeholders = memberIds.map { _ in "?" }.joined(separator: ", ")
        let edgeSql = """
        SELECT id, source_entity_id, target_entity_id, relation,
               first_seen, last_seen, confidence, confidence_tier,
               evidence_json, event_ids_json
          FROM trace_edges
         WHERE source_entity_id IN (\(placeholders))
           AND target_entity_id IN (\(placeholders))
        """
        var edgeStmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, edgeSql, -1, &edgeStmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(edgeStmt) }
        // Same id list bound twice: once for the source IN-list, once for target.
        for (idx, id) in memberIds.enumerated() {
            sqlite3_bind_text(edgeStmt, Int32(1 + idx), id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(edgeStmt, Int32(1 + memberIds.count + idx), id, -1, SQLITE_TRANSIENT)
        }
        var out: [TraceEdge] = []
        while sqlite3_step(edgeStmt) == SQLITE_ROW {
            out.append(try decodeEdgeRow(edgeStmt!))
        }
        return out
    }

    public func updateTraceStatus(id: String, status: String, updatedAt: Date) async throws {
        try await admitGrowth(
            payloadBytes: id.utf8.count + status.utf8.count, rows: 1)
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        try execBound(
            db: db,
            sql: "UPDATE traces SET status = ?, updated_at = ? WHERE id = ?",
            bindings: { stmt in
                sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT)
                sqlite3_bind_double(stmt, 2, updatedAt.timeIntervalSince1970)
                sqlite3_bind_text(stmt, 3, id, -1, SQLITE_TRANSIENT)
            }
        )
    }

    public func listTraces(limit: Int) async throws -> [Trace] {
        try await listTraces(limit: limit, status: nil)
    }

    /// v1.11.1 (audit perf MEDIUM): status-filtered listTraces. Pushes
    /// the filter into SQL — pre-fix `handleGetTraces` did
    /// `raw.filter { $0.status == f }` AFTER the limit, so a caller
    /// asking for `limit:25 status:open` could get fewer than 25
    /// results when more existed.
    public func listTraces(limit: Int, status: String?) async throws -> [Trace] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let baseSelect = """
        SELECT id, title, anchor_event_id, root_entity_id, severity, confidence,
               status, created_at, updated_at, summary_json, attack_json,
               evidence_bundle_status, daemon_version, ruleset_version,
               policy_id, policy_version, policy_sha256, policy_snapshot_json,
               trace_signing_key_mode, replay_scope, attribution_override_policy
          FROM traces
        """
        let sql: String
        if status != nil {
            sql = baseSelect + " WHERE status = ? ORDER BY created_at DESC LIMIT ?"
        } else {
            sql = baseSelect + " ORDER BY created_at DESC LIMIT ?"
        }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        if let status {
            sqlite3_bind_text(stmt, 1, status, -1, SQLITE_TRANSIENT)
            sqlite3_bind_int(stmt, 2, Int32(limit))
        } else {
            sqlite3_bind_int(stmt, 1, Int32(limit))
        }
        var out: [Trace] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeTraceRow(stmt!))
        }
        return out
    }

    /// v1.11.1 (audit perf LOW): SQL-side title substring search.
    /// Pre-fix `hunt_trace` listed up to 500 candidates then
    /// substring-filtered in Swift; pushing to SQL `LIKE` lets the
    /// query planner use an index when present and skips
    /// deserialization for non-matches.
    public func huntTraces(query: String, limit: Int) async throws -> [Trace] {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, title, anchor_event_id, root_entity_id, severity, confidence,
               status, created_at, updated_at, summary_json, attack_json,
               evidence_bundle_status, daemon_version, ruleset_version,
               policy_id, policy_version, policy_sha256, policy_snapshot_json,
               trace_signing_key_mode, replay_scope, attribution_override_policy
          FROM traces
         WHERE LOWER(title) LIKE ?
         ORDER BY updated_at DESC
         LIMIT ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        let pattern = "%\(query.lowercased())%"
        sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT)
        sqlite3_bind_int(stmt, 2, Int32(limit))
        var out: [Trace] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeTraceRow(stmt!))
        }
        return out
    }

    /// v1.11.1 (audit perf HIGH): O(1) member count by trace id. Pre-fix
    /// `handleGetTraces` called `loadTrace` per row just to read
    /// `members.count` — that's 2 SQL queries + full member-array
    /// deserialization for a one-line list endpoint. Up to 400 SQL
    /// queries on a 200-trace listing.
    public func memberCount(traceId: String) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = "SELECT COUNT(*) FROM trace_membership WHERE trace_id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Distinct entity and edge counts for a trace — the graph SIZE, as opposed
    /// to `memberCount`'s raw `trace_membership` ROW count. A membership row
    /// carries exactly one of `entity_id` / `edge_id` (schema CHECK), so the row
    /// count mixes the two: MCP `get_traces` reported "Nodes: 3" for a trace
    /// `maccrabctl trace graph` renders as "2 entities, 1 edges". COUNT(DISTINCT)
    /// skips NULLs, so each column counts only its own kind, matching the Set
    /// build in TraceCommands.traceGraph.
    public func graphCounts(traceId: String) async throws -> (entities: Int, edges: Int) {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = "SELECT COUNT(DISTINCT entity_id), COUNT(DISTINCT edge_id) FROM trace_membership WHERE trace_id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else { return (0, 0) }
        return (Int(sqlite3_column_int64(stmt, 0)), Int(sqlite3_column_int64(stmt, 1)))
    }

    /// v1.11.1 (audit perf HIGH): "which trace contains this entity"
    /// in O(1) instead of O(traces × members). Used by MCP
    /// `trace_from_event` which previously listed 200 traces and
    /// linearly scanned each one's members.
    ///
    /// Returns the most recently-updated trace whose membership table
    /// references the entity, OR whose anchor event id matches.
    public func traceContaining(entityId: String) async throws -> Trace? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT t.id, t.title, t.anchor_event_id, t.root_entity_id, t.severity, t.confidence,
               t.status, t.created_at, t.updated_at, t.summary_json, t.attack_json,
               t.evidence_bundle_status, t.daemon_version, t.ruleset_version,
               t.policy_id, t.policy_version, t.policy_sha256, t.policy_snapshot_json,
               t.trace_signing_key_mode, t.replay_scope, t.attribution_override_policy
          FROM traces t
         WHERE t.id IN (
                 SELECT trace_id FROM trace_membership WHERE entity_id = ?
                 UNION
                 SELECT id FROM traces WHERE anchor_event_id = ?
               )
         ORDER BY t.updated_at DESC
         LIMIT 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, entityId, -1, SQLITE_TRANSIENT)
        sqlite3_bind_text(stmt, 2, entityId, -1, SQLITE_TRANSIENT)
        if sqlite3_step(stmt) == SQLITE_ROW {
            return try decodeTraceRow(stmt!)
        }
        return nil
    }

    // MARK: - Rule hits / replay / chain

    public func recordRuleHit(_ hit: TraceRuleHit) async throws {
        try await admitGrowth(payloadBytes: payloadBytes(hit), rows: 2)
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT OR REPLACE INTO trace_rule_hits (
            id, trace_id, rule_id, rule_title, rule_version, severity,
            matched_event_id, matched_entity_id, matched_edge_id, matched_at, explanation_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execTransaction(.begin, db: db)
        do {
            try execBound(db: db, sql: sql) { stmt in
                sqlite3_bind_text(stmt, 1, hit.id, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 2, hit.traceId, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 3, hit.ruleId, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 4, hit.ruleTitle, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 5, hit.ruleVersion, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 6, hit.severity, -1, SQLITE_TRANSIENT)
                Self.bindOptionalText(stmt, 7, hit.matchedEventId)
                Self.bindOptionalText(stmt, 8, hit.matchedEntityId)
                Self.bindOptionalText(stmt, 9, hit.matchedEdgeId)
                sqlite3_bind_double(stmt, 10, hit.matchedAt.timeIntervalSince1970)
                sqlite3_bind_text(stmt, 11, hit.explanationJson, -1, SQLITE_TRANSIENT)
            }
            try advanceTraceUpdatedAt(
                traceId: hit.traceId, through: hit.matchedAt, db: db)
            try execTransaction(.commit, db: db)
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    public func recordReplayRun(_ run: TraceReplayRun) async throws {
        try await admitGrowth(payloadBytes: payloadBytes(run), rows: 2)
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        INSERT OR REPLACE INTO trace_replay_runs (
            id, trace_id, bundle_id, ruleset_version, daemon_version,
            normalization_version, started_at, completed_at, deterministic, result_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execTransaction(.begin, db: db)
        do {
            try execBound(db: db, sql: sql) { stmt in
                sqlite3_bind_text(stmt, 1, run.id, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 2, run.traceId, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 3, run.bundleId, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 4, run.rulesetVersion, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 5, run.daemonVersion, -1, SQLITE_TRANSIENT)
                sqlite3_bind_text(stmt, 6, run.normalizationVersion, -1, SQLITE_TRANSIENT)
                sqlite3_bind_double(stmt, 7, run.startedAt.timeIntervalSince1970)
                if let completed = run.completedAt {
                    sqlite3_bind_double(stmt, 8, completed.timeIntervalSince1970)
                } else {
                    sqlite3_bind_null(stmt, 8)
                }
                sqlite3_bind_int(stmt, 9, run.deterministic ? 1 : 0)
                sqlite3_bind_text(stmt, 10, run.resultJson, -1, SQLITE_TRANSIENT)
            }
            let activity = max(run.startedAt, run.completedAt ?? run.startedAt)
            try advanceTraceUpdatedAt(
                traceId: run.traceId, through: activity, db: db)
            try execTransaction(.commit, db: db)
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    public func appendHashChain(_ entry: TraceHashChainEntry) async throws {
        try await admitGrowth(payloadBytes: payloadBytes(entry), rows: 2)
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        try execTransaction(.begin, db: db)
        do {
            try insertHashChainRow(entry, db: db)
            try advanceTraceUpdatedAt(
                traceId: entry.traceId, through: entry.createdAt, db: db)
            try execTransaction(.commit, db: db)
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    /// Sync INSERT of one hash-chain row. Shared by `appendHashChain` and the
    /// atomic `appendTraceContinuity` so the latter has no internal `await`
    /// (see its comment for why that matters for continuity correctness).
    private func insertHashChainRow(_ entry: TraceHashChainEntry, db: OpaquePointer) throws {
        let sql = """
        INSERT INTO trace_hash_chain (
            id, trace_id, sequence_number, previous_hash, current_hash,
            event_id, edge_id, chain_head_signature,
            chain_head_published_to_unified_log, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, entry.id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, entry.traceId, -1, SQLITE_TRANSIENT)
            // Bind as 64-bit to match the column (INTEGER) and the read-back
            // (sqlite3_column_int64). The old `Int32(entry.sequenceNumber)` was a
            // force-conversion that TRAPS once the monotonic sequence exceeds
            // Int32.max (~2.1B) — a crash on a long-lived host, not a truncation.
            sqlite3_bind_int64(stmt, 3, Int64(entry.sequenceNumber))
            Self.bindOptionalText(stmt, 4, entry.previousHash)
            sqlite3_bind_text(stmt, 5, entry.currentHash, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 6, entry.eventId)
            Self.bindOptionalText(stmt, 7, entry.edgeId)
            Self.bindOptionalText(stmt, 8, entry.chainHeadSignature)
            sqlite3_bind_int(stmt, 9, entry.chainHeadPublishedToUnifiedLog ? 1 : 0)
            sqlite3_bind_double(stmt, 10, entry.createdAt.timeIntervalSince1970)
        }
    }

    // MARK: - Continuity chain (A3-04)

    /// Sync read of the current global chain head (highest sequence_number
    /// across ALL traces). Used inside `appendTraceContinuity` without `await`.
    private func globalChainHeadRow(db: OpaquePointer) throws -> TraceHashChainEntry? {
        let sql = """
        SELECT id, trace_id, sequence_number, previous_hash, current_hash,
               event_id, edge_id, chain_head_signature,
               chain_head_published_to_unified_log, created_at
          FROM trace_hash_chain
         ORDER BY sequence_number DESC
         LIMIT 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeHashChainRow(stmt!)
    }

    /// Return the duplicated global maximum, if any, after examining at most
    /// two rows. The v3 global sequence index makes both MAX and the equality
    /// lookup seeks on upgraded as well as fresh databases.
    private func duplicatedGlobalHeadSequence(db: OpaquePointer) throws -> Int? {
        let sql = """
        SELECT sequence_number
          FROM trace_hash_chain
         WHERE sequence_number = (SELECT MAX(sequence_number) FROM trace_hash_chain)
         LIMIT 2
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        let firstRC = sqlite3_step(stmt)
        if firstRC == SQLITE_DONE { return nil }
        guard firstRC == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        let sequence = Int(sqlite3_column_int64(stmt, 0))
        let secondRC = sqlite3_step(stmt)
        if secondRC == SQLITE_ROW { return sequence }
        guard secondRC == SQLITE_DONE else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return nil
    }

    public func globalChainHead() async throws -> TraceHashChainEntry? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        return try globalChainHeadRow(db: db)
    }

    /// Append one continuity entry for a materialized trace, linked to the
    /// current global head. Actor isolation prevents interleaving on this
    /// instance, but the daemon, CLI, tests, or another process can hold a
    /// second SQLite connection. BEGIN IMMEDIATE serializes the head-read and
    /// insert across every connection; the schema trigger/native constraint is
    /// a second fail-closed guard against duplicate global sequence numbers.
    @discardableResult
    public func appendTraceContinuity(
        traceId: String,
        eventId: String?,
        edgeId: String?,
        signature: String?,
        publishedToUnifiedLog: Bool,
        createdAt: Date = Date()
    ) async throws -> TraceHashChainEntry {
        try await admitGrowth(
            payloadBytes: traceId.utf8.count
                + (eventId?.utf8.count ?? 0)
                + (edgeId?.utf8.count ?? 0)
                + (signature?.utf8.count ?? 0),
            rows: 2
        )
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        if let continuityIntegrityFailure {
            throw CausalGraphStoreError.stepFailed(continuityIntegrityFailure)
        }
        try execTransaction(.begin, db: db, immediate: true)
        do {
            if let duplicateSequence = try duplicatedGlobalHeadSequence(db: db) {
                let failure = "continuity ledger is forked at duplicated global head sequence \(duplicateSequence); refusing to extend either fork"
                continuityIntegrityFailure = failure
                throw CausalGraphStoreError.stepFailed(failure)
            }
            let head = try globalChainHeadRow(db: db)
            let nextSeq = (head?.sequenceNumber ?? 0) + 1
            let id = UUID().uuidString
            let currentHash = TraceHashChainEntry.computeCurrentHash(
                id: id, traceId: traceId, sequenceNumber: nextSeq,
                previousHash: head?.currentHash, eventId: eventId, edgeId: edgeId,
                createdAt: createdAt
            )
            let entry = TraceHashChainEntry(
                id: id, traceId: traceId, sequenceNumber: nextSeq,
                previousHash: head?.currentHash, currentHash: currentHash,
                eventId: eventId, edgeId: edgeId,
                chainHeadSignature: signature,
                chainHeadPublishedToUnifiedLog: publishedToUnifiedLog,
                createdAt: createdAt
            )
            try insertHashChainRow(entry, db: db)
            try advanceTraceUpdatedAt(
                traceId: traceId, through: createdAt, db: db)
            try execTransaction(.commit, db: db)
            return entry
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    /// Walk the whole ledger (ordered by sequence_number) and verify:
    ///   1. content — every row's current_hash recomputes from its stored
    ///      fields (catches an in-place UPDATE or a sequence-number reorder);
    ///   2. linkage — a row whose sequence_number is CONTIGUOUS with the
    ///      preceding retained row (seq == previous.seq + 1) must chain to it
    ///      (previous_hash == previous.currentHash).
    ///
    /// Linkage is enforced across contiguous rows only, NOT across gaps (audit
    /// sec-storage-crypto). The earlier implementation assumed retention
    /// deletes a clean sequence-number PREFIX, but retention prunes traces by
    /// `traces.updated_at` (see pruneTraces / pruneOldestTraces) and
    /// `sequence_number` is assigned in materialization order — the two orders
    /// diverge (a trace's updated_at is bumped on status changes), so
    /// authorized retention deletes INTERIOR chain rows and leaves gaps.
    /// Enforcing linkage across such a gap produced a FALSE `.brokenLinkage`
    /// on any host that had ever pruned. Treating a sequence gap as authorized
    /// deletion removes that false positive; the cost is that a retention-style
    /// interior deletion is (correctly) not treated as tampering. Content
    /// integrity — recomputing each surviving row's hash — is unaffected and
    /// still catches in-place edits and sequence-number reorders.
    /// See `HashChainVerification` for the full scope.
    public func verifyHashChain() async throws -> HashChainVerification {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, trace_id, sequence_number, previous_hash, current_hash,
               event_id, edge_id, chain_head_signature,
               chain_head_published_to_unified_log, created_at
          FROM trace_hash_chain
         ORDER BY sequence_number ASC
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }

        var checked = 0
        var previous: TraceHashChainEntry?
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
            }
            let entry = try decodeHashChainRow(stmt!)

            // 1. Content integrity — recompute from the row's own fields.
            if entry.recomputedCurrentHash() != entry.currentHash {
                return HashChainVerification(
                    status: .brokenContent(atSequence: entry.sequenceNumber),
                    entriesChecked: checked
                )
            }
            // 2. Ordering + linkage. Duplicate/decreasing numbers are never a
            // retention gap and prove the global ledger forked.
            if let previous,
               entry.sequenceNumber <= previous.sequenceNumber {
                return HashChainVerification(
                    status: .brokenLinkage(atSequence: entry.sequenceNumber),
                    entriesChecked: checked
                )
            }
            // Linkage is enforced only across CONTIGUOUS sequence numbers.
            // A gap (entry.seq > previous.seq + 1) is authorized retention
            // (prune-by-updated_at deletes interior rows), not tampering, so
            // its broken inbound link is not flagged. See the docstring.
            if let previous,
               entry.sequenceNumber == previous.sequenceNumber + 1,
               entry.previousHash != previous.currentHash {
                return HashChainVerification(
                    status: .brokenLinkage(atSequence: entry.sequenceNumber),
                    entriesChecked: checked
                )
            }
            previous = entry
            checked += 1
        }
        return HashChainVerification(status: .ok, entriesChecked: checked)
    }

    public func latestHashChainEntry(for traceId: String) async throws -> TraceHashChainEntry? {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = """
        SELECT id, trace_id, sequence_number, previous_hash, current_hash,
               event_id, edge_id, chain_head_signature,
               chain_head_published_to_unified_log, created_at
          FROM trace_hash_chain
         WHERE trace_id = ?
         ORDER BY sequence_number DESC
         LIMIT 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeHashChainRow(stmt!)
    }

    // MARK: - Title rewrite + cascade delete (for demo / housekeeping)

    /// Prefix the title of every trace whose id is in `ids` with the
    /// given string. Used by `maccrabctl trace demo` to mark
    /// synthetic traces as `[DEMO] ` after the materializer has emitted
    /// them with anchor-derived default titles.
    public func prefixTraceTitles(ids: [String], with prefix: String) async throws {
        guard !ids.isEmpty else { return }
        try await admitGrowth(
            payloadBytes: payloadAdd(payloadBytes(ids), prefix.utf8.count),
            rows: ids.count
        )
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let placeholders = ids.map { _ in "?" }.joined(separator: ", ")
        let sql = "UPDATE traces SET title = ? || title WHERE id IN (\(placeholders))"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, prefix, -1, SQLITE_TRANSIENT)
        for (idx, id) in ids.enumerated() {
            sqlite3_bind_text(stmt, Int32(2 + idx), id, -1, SQLITE_TRANSIENT)
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            try throwSQLiteFailure(
                rc: sqlite3_errcode(db), db: db, context: "prefixTraceTitles")
        }
    }

    /// Delete every trace whose title starts with the given prefix,
    /// plus its membership / rule-hit / replay-run / hash-chain rows.
    /// Returns the count of trace rows removed. Orphaned entities +
    /// edges are left in place — they're invisible to the dashboard
    /// (which lists by trace) and harmless storage-wise.
    @discardableResult
    public func deleteTracesWithTitlePrefix(_ prefix: String) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard checkpointAllowsMaintenance() else { return 0 }
        let pattern = prefix + "%"

        // First, gather the matching trace ids.
        var ids: [String] = []
        do {
            let sql = "SELECT id FROM traces WHERE title LIKE ?"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, pattern, -1, SQLITE_TRANSIENT)
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let cstr = sqlite3_column_text(stmt, 0) {
                    ids.append(String(cString: cstr))
                }
            }
        }
        guard !ids.isEmpty else { return 0 }
        return try await batchedCascadeDeleteTraces(ids: ids).tracesDeleted
    }

    // MARK: - Retention
    //
    // tracegraph.db lacked any prune logic in v1.10's first cut.
    // Every NOTIFY_EXEC anchor-worthy event added a trace + members +
    // rule_hits + edges, growing the file monotonically. On a busy
    // dev machine this hit several GB / month. The following two
    // methods mirror EventStore.prune / pruneOldest so the daemon's
    // daily retention sweep can apply a time-based cap and a size
    // safety net. v1.10.0 audit fix.

    /// Delete every trace older than `cutoff` (and cascade through
    /// trace_membership / trace_rule_hits / trace_replay_runs /
    /// trace_hash_chain). Returns the number of trace rows removed.
    /// Orphaned entities + edges are left in place; they're invisible
    /// to the dashboard (lists by trace) and the next anchor that
    /// references them can re-attach via upsert.
    @discardableResult
    public func pruneTraces(olderThan cutoff: Date) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard checkpointAllowsMaintenance() else { return 0 }
        let cutoffSecs = cutoff.timeIntervalSince1970

        var ids: [String] = []
        do {
            let sql = """
            SELECT id FROM traces
             WHERE \(Self.traceRecoveryEligibilityPredicateSQL)
             LIMIT 10000
            """
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_double(stmt, 1, cutoffSecs)
            while sqlite3_step(stmt) == SQLITE_ROW {
                if let cstr = sqlite3_column_text(stmt, 0) {
                    ids.append(String(cString: cstr))
                }
            }
        }
        guard !ids.isEmpty else { return 0 }
        return try await batchedCascadeDeleteTraces(
            ids: ids,
            eligibilityCutoff: cutoffSecs
        ).tracesDeleted
    }

    /// Drop the oldest `count` traces by `updated_at` ascending. Used
    /// as the size-cap escape hatch when the daemon's storage
    /// enforcer notices tracegraph.db has exceeded its budget.
    @discardableResult
    public func pruneOldestTraces(count: Int) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        guard count > 0 else { return 0 }
        guard checkpointAllowsMaintenance() else { return 0 }

        var ids: [String] = []
        let sql = "SELECT id FROM traces ORDER BY updated_at ASC LIMIT ?1"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_int(stmt, 1, Int32(count))
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cstr = sqlite3_column_text(stmt, 0) {
                ids.append(String(cString: cstr))
            }
        }
        guard !ids.isEmpty else { return 0 }
        return try await batchedCascadeDeleteTraces(ids: ids).tracesDeleted
    }

    /// Database file size in bytes — used by the storage enforcer.
    public func databaseSizeBytes() -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: databasePath)
        return (attrs?[.size] as? Int64) ?? 0
    }

    /// In-use data size = (page_count − freelist_count) × page_size.
    ///
    /// Unlike `databaseSizeBytes()` — the on-disk FILE footprint, which does
    /// NOT shrink until `incremental_vacuum`/`VACUUM` returns freelist pages to
    /// the OS — this DROPS as DELETEs move pages onto the freelist. A size-cap
    /// prune loop must measure its progress with THIS, not the file size:
    /// pruning frees pages but the file stays large until the post-loop vacuum,
    /// so a file-size break-condition never trips and the loop over-prunes the
    /// substrate ~10× past the cap (field-observed 476 MB → 36 MB at a 250 MB
    /// cap, because all 5 iterations ran before the single end-of-loop vacuum).
    public func liveDataSizeBytes() -> Int64 {
        guard let db else { return 0 }
        func pragmaInt(_ name: String) -> Int64 {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &stmt, nil) == SQLITE_OK else { return 0 }
            defer { sqlite3_finalize(stmt) }
            return sqlite3_step(stmt) == SQLITE_ROW ? sqlite3_column_int64(stmt, 0) : 0
        }
        let pages = pragmaInt("page_count")
        let free = pragmaInt("freelist_count")
        let pageSize = pragmaInt("page_size")
        return max(0, (pages - free) * pageSize)
    }

    // MARK: - Substrate (entity/edge) retention  (v1.18.0)
    //
    // trace_entities + trace_edges are the GLOBAL causal-graph substrate:
    // upserted on every ingested event (RollingCausalGraph.ingest) but,
    // prior to v1.18, NEVER deleted by any path. Trace cascade deletion only
    // removes `traces` + its membership / rule_hits / replay / hash_chain
    // children — the substrate was explicitly left orphaned ("the next
    // anchor can re-attach via upsert"). With anchors firing rarely while
    // upserts run per-event, the substrate accumulated monotonically with
    // lifetime event volume; field-observed at 17 GB on this host.
    //
    // These methods bound the substrate WITHOUT corrupting surviving
    // traces. A row is deletable only when no surviving trace references
    // it: an edge must be absent from BOTH trace_membership and
    // trace_hash_chain (which carry edge_id as plain, non-FK columns); an
    // entity must be absent from trace_membership AND not an endpoint of
    // any surviving edge. Edges are swept before entities to respect the
    // trace_edges -> trace_entities foreign keys and so freshly-orphaned
    // edges release their endpoints within the same sweep. Deletes are
    // batched, yielding the actor between batches, so a multi-GB sweep
    // can't stall the event pump that shares this actor.

    /// An edge id is a deletable orphan when no surviving trace references
    /// it via membership, the hash chain, or a rule hit. trace_rule_hits
    /// carries matched_edge_id as a plain (non-FK) column exactly like the
    /// other two; guarding it forward-proofs the sweep against silently
    /// deleting an edge a surviving rule-hit still points at, once
    /// recordRuleHit gains a production caller. (STG-1 / F5)
    private static let edgeOrphanGuardSQL = """
        id NOT IN (SELECT edge_id FROM trace_membership WHERE edge_id IS NOT NULL) \
        AND id NOT IN (SELECT edge_id FROM trace_hash_chain WHERE edge_id IS NOT NULL) \
        AND id NOT IN (SELECT matched_edge_id FROM trace_rule_hits WHERE matched_edge_id IS NOT NULL)
        """

    /// An entity id is a deletable orphan when no surviving trace
    /// references it via membership or a rule hit, and no surviving edge
    /// uses it as an endpoint. Valid only AFTER the edge sweep in the same
    /// pass. (matched_entity_id guard: see edgeOrphanGuardSQL — STG-1 / F5.)
    private static let entityOrphanGuardSQL = """
        id NOT IN (SELECT entity_id FROM trace_membership WHERE entity_id IS NOT NULL) \
        AND id NOT IN (SELECT matched_entity_id FROM trace_rule_hits WHERE matched_entity_id IS NOT NULL) \
        AND id NOT IN (SELECT root_entity_id FROM traces WHERE root_entity_id IS NOT NULL) \
        AND id NOT IN (SELECT source_entity_id FROM trace_edges) \
        AND id NOT IN (SELECT target_entity_id FROM trace_edges)
        """

    /// Delete graph substrate older than `cutoff` that no surviving trace
    /// references. Edges first, then entities. Returns counts deleted.
    @discardableResult
    public func pruneOrphanedGraph(olderThan cutoff: Date) async throws -> (edges: Int, entities: Int) {
        guard checkpointAllowsMaintenance() else { return (0, 0) }
        let cutoffSecs = cutoff.timeIntervalSince1970
        let edges = try await batchedSubstrateDelete(
            table: "trace_edges", guardSQL: Self.edgeOrphanGuardSQL, cutoff: cutoffSecs)
        let entities = try await batchedSubstrateDelete(
            table: "trace_entities", guardSQL: Self.entityOrphanGuardSQL, cutoff: cutoffSecs)
        return (edges, entities)
    }

    /// Size-cap fallback: delete the oldest unreferenced substrate (by
    /// last_seen ascending), up to `count` rows per table. Orphan-guarded
    /// exactly like `pruneOrphanedGraph` so it can never corrupt a
    /// surviving trace, even when evicting recent-ish rows under pressure.
    @discardableResult
    public func pruneOldestGraph(count: Int) async throws -> (edges: Int, entities: Int) {
        guard count > 0 else { return (0, 0) }
        guard checkpointAllowsMaintenance() else { return (0, 0) }
        let edges = try await batchedSubstrateDelete(
            table: "trace_edges", guardSQL: Self.edgeOrphanGuardSQL, cutoff: nil, oldestFirstLimit: count)
        let entities = try await batchedSubstrateDelete(
            table: "trace_entities", guardSQL: Self.entityOrphanGuardSQL, cutoff: nil, oldestFirstLimit: count)
        return (edges, entities)
    }

    private struct SubstrateDeleteSelection {
        var ids: [String] = []
        var byteLimited = false
        var exhaustedCandidates = false
    }

    /// Select only entity/edge rows whose complete conservative delete charge
    /// fits one transaction reserve. The SQL-level single-row payload filter
    /// means one inherited oversized JSON row is preserved without preventing
    /// reclaimable rows behind it from being selected.
    private func boundedSubstrateDeleteSelection(
        db: OpaquePointer,
        table: String,
        guardSQL: String,
        cutoff: Double?,
        oldestFirst: Bool,
        limit: Int
    ) throws -> SubstrateDeleteSelection {
        guard limit > 0 else {
            return SubstrateDeleteSelection(exhaustedCandidates: true)
        }
        let byteColumns: [String]
        switch table {
        case "trace_edges":
            byteColumns = [
                "id", "source_entity_id", "target_entity_id", "relation",
                "confidence_tier", "evidence_json", "event_ids_json",
            ]
        case "trace_entities":
            byteColumns = [
                "id", "entity_type", "stable_key", "display_name",
                "attributes_json", "source",
            ]
        default:
            throw CausalGraphStoreError.prepareFailed(
                "unsupported substrate recovery table \(table)")
        }
        let payloadExpression = byteColumns.map {
            "COALESCE(octet_length(\($0)), 0)"
        }.joined(separator: " + ")
        let transactionBudget = max(
            0, transactionReserveBytes ?? Self.defaultMinimumTransactionReserve)
        let fixedCharge = saturatingAdd(
            Self.mutationBaseBytes, Self.mutationBytesPerRow)
        guard transactionBudget > fixedCharge else {
            return SubstrateDeleteSelection(exhaustedCandidates: true)
        }
        let maxSinglePayloadBytes = (transactionBudget - fixedCharge) / 8
        var predicates = [guardSQL]
        if cutoff != nil {
            // Imported/inherited rows are not trusted to satisfy
            // first_seen <= last_seen. Preserve evidence if either timestamp
            // lies inside the caller's protected window.
            predicates.append("MAX(first_seen, last_seen) < ?1")
        }
        let payloadBindIndex = cutoff == nil ? 1 : 2
        predicates.append("(\(payloadExpression)) <= ?\(payloadBindIndex)")
        let order = oldestFirst ? "ORDER BY last_seen ASC, rowid ASC" : "ORDER BY rowid ASC"
        let sql = """
        SELECT id, (\(payloadExpression))
          FROM \(table)
         WHERE \(predicates.joined(separator: " AND "))
         \(order)
         LIMIT \(limit)
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(
                String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        if let cutoff { sqlite3_bind_double(stmt, 1, cutoff) }
        sqlite3_bind_int64(
            stmt, Int32(payloadBindIndex), maxSinglePayloadBytes)

        var selection = SubstrateDeleteSelection()
        var estimated = Self.mutationBaseBytes
        var candidatesRead = 0
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE {
                selection.exhaustedCandidates = candidatesRead < limit
                return selection
            }
            guard rc == SQLITE_ROW else {
                try throwSQLiteFailure(
                    rc: rc, db: db,
                    context: "size-bounded substrate selection from \(table)")
            }
            candidatesRead += 1
            let payloadBytes = max(0, sqlite3_column_int64(stmt, 1))
            let payloadCharge = payloadBytes > Int64.max / 8
                ? Int64.max
                : payloadBytes * 8
            let rowCharge = saturatingAdd(
                payloadCharge, Self.mutationBytesPerRow)
            let proposed = saturatingAdd(estimated, rowCharge)
            if proposed > transactionBudget {
                selection.byteLimited = true
                return selection
            }
            if let raw = sqlite3_column_text(stmt, 0) {
                selection.ids.append(String(cString: raw))
                estimated = proposed
            }
        }
    }

    /// Batched orphan delete. Deletes rows from `table` matching the orphan
    /// guard and optional cutoff. Both row count and conservative encoded-byte
    /// charge are bounded independently for every transaction.
    private func batchedSubstrateDelete(
        table: String,
        guardSQL: String,
        cutoff: Double?,
        oldestFirstLimit: Int? = nil,
        batchSize: Int? = nil
    ) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        var total = 0
        var remaining = oldestFirstLimit ?? Int.max
        let requestedBatchSize = batchSize ?? Self.substrateDeleteBatchSize
        let boundedBatchSize = max(1, min(requestedBatchSize, Self.substrateDeleteBatchSize))
        while remaining > 0 {
            guard checkpointAllowsMaintenance() else { break }
            guard recoveryMutationHeadroomAdmitted() else { break }
            let thisBatch = min(boundedBatchSize, remaining)
            let selection = try boundedSubstrateDeleteSelection(
                db: db,
                table: table,
                guardSQL: guardSQL,
                cutoff: cutoff,
                oldestFirst: oldestFirstLimit != nil,
                limit: thisBatch
            )
            guard !selection.ids.isEmpty else { break }
            let placeholders = selection.ids.map { _ in "?" }
                .joined(separator: ", ")
            var revalidation = [guardSQL]
            if cutoff != nil {
                revalidation.append(
                    "MAX(first_seen, last_seen) < ?\(selection.ids.count + 1)")
            }
            let sql = """
            DELETE FROM \(table)
             WHERE id IN (\(placeholders))
               AND \(revalidation.joined(separator: " AND "))
            """
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
            }
            for (index, id) in selection.ids.enumerated() {
                sqlite3_bind_text(
                    stmt, Int32(index + 1), id, -1, SQLITE_TRANSIENT)
            }
            if let cutoff {
                sqlite3_bind_double(
                    stmt, Int32(selection.ids.count + 1), cutoff)
            }
            let rc = sqlite3_step(stmt)
            sqlite3_finalize(stmt)
            guard rc == SQLITE_DONE else {
                try throwSQLiteFailure(
                    rc: rc, db: db, context: "bounded delete from \(table)")
            }
            let n = Int(sqlite3_changes(db))
            total += n
            remaining -= n
            guard checkpointAllowsMaintenance() else { break }
            if n == 0 || (selection.exhaustedCandidates && !selection.byteLimited) {
                break
            }
            await Task.yield()
            if recoveryHasForegroundPressure { break }
        }
        return total
    }

    // MARK: - Incremental vacuum (Wave 9B, v1.12.6)
    //
    // tracegraph.db is the WORST offender of the four stores, field-
    // observed at 11 GB on a daily-Claude-Code dev box before any
    // Wave 9B mitigation. Since Wave 9B.1 (v1.12.6) openDatabase sets
    // `auto_vacuum = INCREMENTAL` BEFORE journal_mode, so fresh DBs run
    // in mode 2 and this reclaims freelist pages in place exactly like
    // EventStore. Pre-Wave-9B.1 files still in mode 0 can be converted
    // once with an offline full-VACUUM conversion while the engine is stopped.
    @discardableResult
    public func incrementalVacuum(maxPages: Int) async throws -> Int {
        guard let db = db else { return 0 }
        guard maxPages > 0,
              StoragePragmas.readAutoVacuumMode(db) == 2,
              checkpointAllowsMaintenance() else { return 0 }
        let boundedPages: Int
        if maxFootprintBytes != nil || freeSpaceFloorBytes != nil {
            var stmt: OpaquePointer?
            var pageSize: Int64 = 4_096
            if sqlite3_prepare_v2(db, "PRAGMA page_size", -1, &stmt, nil) == SQLITE_OK,
               sqlite3_step(stmt) == SQLITE_ROW {
                pageSize = max(512, sqlite3_column_int64(stmt, 0))
            }
            sqlite3_finalize(stmt)
            let reserve = transactionReserveBytes
                ?? Self.defaultMinimumTransactionReserve
            // Charge four WAL/page-map pages per reclaimed DB page. This keeps
            // one public call inside the same transaction reserve as growth.
            let safeByReserve = max(1, reserve / max(1, pageSize * 4))
            boundedPages = min(maxPages, Int(min(Int64(8_192), safeByReserve)))
        } else {
            // Unconfigured stores are explicitly offline/test-compatible.
            boundedPages = maxPages
        }
        let result: StoragePragmas.IncrementalVacuumResult
        do {
            result = try StoragePragmas.runIncrementalVacuum(
                on: db, maxPages: boundedPages)
        } catch let error as StoragePragmas.IncrementalVacuumError {
            try throwSQLiteFailure(
                metadata: error.sqliteFailureMetadata,
                db: db,
                context: error.localizedDescription
            )
        }
        guard checkpointAllowsMaintenance() else {
            throw CausalGraphStoreError.stepFailed(
                "incremental VACUUM completed but its WAL could not be fully truncated"
            )
        }
        return result.pagesReclaimed
    }

    /// Best-effort VACUUM. On a 11 GB tracegraph.db this is the only
    /// path that actually shrinks the file today (mode-0 auto_vacuum
    /// means incremental_vacuum is a no-op) — and VACUUM needs
    /// ~= DB-size of scratch space, which is exactly the low-disk
    /// problem Wave 9B exists to work around. The size-cap caller
    /// pre-flights free space and skips this when too tight.
    ///
    /// One-shot auto_vacuum conversion (audit corr-storage): setting the
    /// pragma just before VACUUM rewrites a legacy mode-0 (NONE) file into
    /// INCREMENTAL, so subsequent incremental_vacuum calls actually reclaim
    /// (previously this was the ONLY reclaim path on such a file). Idempotent
    /// once already mode 2.
    public func vacuum() async throws {
        guard let db = db else { return }
        guard maxFootprintBytes == nil, freeSpaceFloorBytes == nil else {
            throw CausalGraphStoreError.stepFailed(
                "full VACUUM is disabled on an admission-configured live TraceGraph store; stop the engine and reopen the database through an explicit offline maintenance path"
            )
        }
        guard checkpointAllowsMaintenance() else { return }
        // checkpointAllowsMaintenance() above performed a fully-drained,
        // sidecar-admitted TRUNCATE checkpoint before the rewrite.
        // tracegraph.db is in WAL mode, so VACUUM writes its ENTIRE rebuild to
        // tracegraph.db-wal. Without the trailing checkpoint the caller's
        // measureDatabaseFootprintMB (the complete SQLite family)
        // reads the rebuild stacked ON TOP of the main file it has not replaced
        // yet, and reports the VACUUM as having GROWN the store (field: 138 MB
        // -> 268 MB). The cap can then never read as satisfied, so the next
        // hourly tick prunes the oldest traces plus up to 250K graph
        // edges/entities again — a self-perpetuating loop that permanently
        // destroys causal history (the substrate behind get_traces /
        // get_trace_detail / the Investigation workspace) to chase a
        // measurement artefact. The leading PASSIVE checkpoint additionally
        // lets VACUUM rebuild from a drained main DB.
        sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        try SQLitePersistentStoreAdmission.requireFullVacuumHeadroom(
            databasePath: databasePath,
            storageVolumePath: (databasePath as NSString).deletingLastPathComponent,
            freeSpaceFloorBytes: 0
        )
        let rc = sqlite3_exec(db, "VACUUM", nil, nil, nil)
        if rc != SQLITE_OK {
            let msg = String(cString: sqlite3_errmsg(db))
            throw CausalGraphStoreError.stepFailed("VACUUM failed: \(msg)")
        }
        let trailing = checkpointObservation(
            mode: Int32(SQLITE_CHECKPOINT_TRUNCATE)
        )
        guard trailing.completed && !trailing.pinned else {
            throw CausalGraphStoreError.stepFailed(
                "VACUUM completed but its WAL could not be fully truncated"
            )
        }
    }

    private struct CheckpointObservation {
        let completed: Bool
        let pinned: Bool
        let logFrames: Int32
        let checkpointedFrames: Int32
    }

    /// Fresh floor + sidecar gate for every checkpoint mode. A checkpoint can
    /// grow the main file by the complete currently allocated WAL family while
    /// those sidecars remain allocated. The normal footprint cap is omitted:
    /// draining/truncating WAL is itself the bounded route back under that cap.
    private func checkpointHeadroomAdmitted() -> Bool {
        let configured = maxFootprintBytes != nil || freeSpaceFloorBytes != nil
        func refuse(_ error: CausalGraphStorageAdmissionError) -> Bool {
            pinnedReader = false
            if configured {
                if storageBlockReason != error.blockReason {
                    logger.fault("\(error.localizedDescription, privacy: .public). WAL checkpoint deferred; existing TraceGraph evidence is retained.")
                }
                storageBlockReason = error.blockReason
            }
            return false
        }

        let main: Int64
        do {
            main = try SQLitePersistentStoreAdmission.measureMainFile(
                databasePath
            )
        } catch {
            return refuse(.probeFailed(
                "checkpoint main-file measurement: \(error.localizedDescription)"
            ))
        }
        let measuredFamily = configured
            ? footprintProbe(databasePath)
            : Self.exactSQLiteFootprintBytes(databasePath: databasePath)
        guard let family = measuredFamily, family >= main else {
            lastFootprintBytes = nil
            return refuse(.probeFailed("checkpoint SQLite-family footprint"))
        }
        lastFootprintBytes = family
        let measuredFree = configured
            ? freeSpaceProbe(storageVolumePath)
            : Self.availableFilesystemBytes(path: storageVolumePath)
        guard let free = measuredFree else {
            lastFreeSpaceBytes = nil
            return refuse(.probeFailed("checkpoint free-space"))
        }
        lastFreeSpaceBytes = free
        let floor = freeSpaceFloorBytes ?? 0
        let snapshot = SQLitePersistentStoreAdmission
            .checkpointAdmissionSnapshot(
                mainFileBytes: main,
                familyFootprintBytes: family,
                freeSpaceBytes: free,
                freeSpaceFloorBytes: floor
            )
        guard snapshot.admitted else {
            return refuse(.lowFreeSpace(
                freeBytes: free,
                floorBytes: floor,
                requiredFreeBytes: snapshot.requiredFreeBytes
            ))
        }
        return true
    }

    private func checkpointObservation(mode: Int32) -> CheckpointObservation {
        guard let db, checkpointHeadroomAdmitted() else {
            return CheckpointObservation(
                completed: false, pinned: false, logFrames: 0, checkpointedFrames: 0)
        }
        var logFrames: Int32 = 0
        var checkpointedFrames: Int32 = 0
        let rc = sqlite3_wal_checkpoint_v2(
            db, nil, mode, &logFrames, &checkpointedFrames
        )
        // Capture the connection/VFS error state before any filesystem probe or
        // log call can obscure it. BUSY/LOCKED are reader coordination, not
        // storage exhaustion; FULL and IOERR+ENOSPC/EDQUOT latch admission.
        if rc != SQLITE_OK, rc != SQLITE_BUSY, rc != SQLITE_LOCKED {
            let failure = SQLiteFailureMetadata(resultCode: rc, db: db)
            _ = latchSQLiteStorageFailure(
                failure, context: "WAL checkpoint mode \(mode)")
        }
        // Frame counts, not WAL byte size, identify a reader-pinned snapshot.
        // A perfectly valid reader can pin one 4 KiB frame; the old >64 MB
        // heuristic missed that and let DELETE maintenance amplify the WAL.
        let frameGap = logFrames >= 0
            && checkpointedFrames >= 0
            && logFrames > checkpointedFrames
        let isPinned = rc == SQLITE_BUSY || rc == SQLITE_LOCKED || frameGap
        pinnedReader = isPinned
        return CheckpointObservation(
            completed: rc == SQLITE_OK && !frameGap,
            pinned: isPinned,
            logFrames: logFrames,
            checkpointedFrames: checkpointedFrames
        )
    }

    /// Checkpoint before every maintenance write. If a reader has pinned even
    /// a small WAL snapshot, no DELETE or vacuum is issued on that tick.
    private func checkpointAllowsMaintenance() -> Bool {
        let observation = checkpointObservation(mode: Int32(SQLITE_CHECKPOINT_TRUNCATE))
        if observation.pinned {
            logger.warning("TraceGraph recovery paused: reader pins WAL (\(observation.checkpointedFrames)/\(observation.logFrames) frames checkpointed); no delete or vacuum issued")
        }
        return observation.completed && !observation.pinned
    }

    /// PASSIVE→RESTART checkpoint chain. Drains the WAL so on-disk
    /// footprint measurements include WAL content.
    @discardableResult
    public func walCheckpoint() async -> Bool {
        let passive = checkpointObservation(mode: Int32(SQLITE_CHECKPOINT_PASSIVE))
        if passive.completed { return true }
        let restart = checkpointObservation(mode: Int32(SQLITE_CHECKPOINT_RESTART))
        return restart.completed
    }

    /// TRUNCATE checkpoint — drains the WAL into the main DB AND shrinks
    /// the `-wal` sidecar back to zero bytes. RESTART (above) drains the
    /// WAL but leaves the file pinned at its high-water mark, which under
    /// `journal_size_limit = 64 MiB` means tracegraph.db-wal can sit at
    /// 64 MiB indefinitely — invisible to a file-only size check yet a
    /// real 64 MiB of footprint. The size-cap path runs this periodically
    /// so the WAL can't stay pinned at the journal_size_limit ceiling.
    /// Best-effort: degrades to RESTART semantics if a reader holds the
    /// WAL open, which is still progress.
    @discardableResult
    public func walCheckpointTruncate() async -> Bool {
        checkpointObservation(mode: Int32(SQLITE_CHECKPOINT_TRUNCATE)).completed
    }

    private func recoveryBacklogSnapshot(
        retentionCutoff: Double,
        orphanCutoff: Double
    ) -> (trace: Bool?, orphan: Bool?, eligible: Bool?) {
        let trace = try? sqliteExists(
            sql: """
            SELECT EXISTS(
                SELECT 1 FROM traces
                 WHERE traces.rowid > ?2
                   AND \(Self.traceRecoveryEligibilityPredicateSQL)
                 LIMIT 1)
            """,
            cutoff: retentionCutoff,
            afterRowID: recoveryTraceScanAfterRowID
        )
        let edges = try? sqliteExists(
            sql: "SELECT EXISTS(SELECT 1 FROM trace_edges WHERE \(Self.edgeOrphanGuardSQL) AND MAX(first_seen, last_seen) < ?1 LIMIT 1)",
            cutoff: orphanCutoff
        )
        let entities = try? sqliteExists(
            sql: "SELECT EXISTS(SELECT 1 FROM trace_entities WHERE \(Self.entityOrphanGuardSQL) AND MAX(first_seen, last_seen) < ?1 LIMIT 1)",
            cutoff: orphanCutoff
        )
        let orphan: Bool?
        if edges == true || entities == true {
            orphan = true
        } else if let edges, let entities {
            orphan = edges || entities
        } else {
            orphan = nil
        }
        let eligible: Bool?
        if trace == true || orphan == true {
            eligible = true
        } else if let trace, let orphan {
            eligible = trace || orphan
        } else {
            eligible = nil
        }
        return (trace, orphan, eligible)
    }

    private func sqliteExists(
        sql: String,
        cutoff: Double,
        afterRowID: Int64? = nil
    ) throws -> Bool {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, cutoff)
        if let afterRowID {
            sqlite3_bind_int64(stmt, 2, afterRowID)
        }
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_ROW else {
            try throwSQLiteFailure(rc: rc, db: db, context: "measure recovery backlog")
        }
        return sqlite3_column_int(stmt, 0) != 0
    }

    /// One small recovery quantum. This is intentionally the only daemon
    /// size-cap path: it detects a reader pin before the first DELETE, bounds
    /// every batch, checkpoints between batches, and uses incremental vacuum
    /// only. It never runs the full-file `VACUUM` rewrite online.
    public func recoverStorageBudget(
        retentionCutoff: Date,
        orphanCutoff: Date,
        maxTraceDeletes: Int = 256,
        maxTraceChildRows: Int = 16_384,
        maxGraphDeletesPerTable: Int = 2_000,
        maxVacuumPages: Int = 2_048
    ) async throws -> CausalGraphStorageRecoveryResult {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let traceBudget = max(0, min(maxTraceDeletes, 2_000))
        let traceChildBudget = max(
            0, min(maxTraceChildRows, Self.traceRecoveryChildRowBudget))
        let graphBudget = max(0, min(maxGraphDeletesPerTable, 10_000))
        let vacuumBudget = max(0, min(maxVacuumPages, 8_192))
        var tracesDeleted = 0
        var traceChildRowsDeleted = 0
        var edgesDeleted = 0
        var entitiesDeleted = 0
        var pagesReclaimed = 0
        refreshAdmissionMeasurementsAndLatch()
        let recoveryRequiredAtStart = storageBlockReason != nil
            || footprintAdmissionLatched
            || deferredMigrationsPending
            || (Self.recoveryDeficitBytes(
                footprintBytes: lastFootprintBytes,
                recoveryTargetBytes: resumeBelowBytes
            ) ?? 0) > 0
        let mode = Int(StoragePragmas.readAutoVacuumMode(db))
        let footprintBefore = footprintProbe(databasePath)
        let retentionCutoffSeconds = retentionCutoff.timeIntervalSince1970
        let orphanCutoffSeconds = orphanCutoff.timeIntervalSince1970
        if recoveryTraceScanCutoff != retentionCutoffSeconds {
            recoveryTraceScanCutoff = retentionCutoffSeconds
            recoveryTraceScanAfterRowID = 0
        }

        func result() -> CausalGraphStorageRecoveryResult {
            let footprintAfter = footprintProbe(databasePath)
            let backlog = recoveryBacklogSnapshot(
                retentionCutoff: retentionCutoffSeconds,
                orphanCutoff: orphanCutoffSeconds
            )
            return CausalGraphStorageRecoveryResult(
                pinnedReader: pinnedReader,
                tracesDeleted: tracesDeleted,
                traceChildRowsDeleted: traceChildRowsDeleted,
                edgesDeleted: edgesDeleted,
                entitiesDeleted: entitiesDeleted,
                vacuumPagesReclaimed: pagesReclaimed,
                footprintBeforeBytes: footprintBefore,
                footprintBytes: footprintAfter,
                autoVacuumMode: mode,
                recoveryTargetBytes: resumeBelowBytes,
                recoveryDeficitBytes: Self.recoveryDeficitBytes(
                    footprintBytes: footprintAfter,
                    recoveryTargetBytes: resumeBelowBytes
                ),
                traceBacklogRemaining: backlog.trace,
                orphanBacklogRemaining: backlog.orphan,
                eligibleBacklogRemaining: backlog.eligible
            )
        }

        func internalAdmissionReachedRecoveryTarget() -> Bool {
            let targetSatisfied = resumeBelowBytes == nil
                || Self.recoveryDeficitBytes(
                    footprintBytes: lastFootprintBytes,
                    recoveryTargetBytes: resumeBelowBytes
                ) == 0
            return targetSatisfied
                && storageBlockReason == nil
                && !footprintAdmissionLatched
                && sqliteStorageFailure == nil
                && !deferredMigrationsPending
        }

        // Actor methods are re-entrant at the bounded yields below. A second
        // timer/SIGHUP-triggered recovery must observe, not join, the active
        // run; released foreground writers also get first claim on the actor
        // before another maintenance pass can begin.
        guard !recovering,
              recoveryMutationHandoffsOutstanding == 0,
              !closeRequested else { return result() }

        let sqliteFailureGenerationAtStart = sqliteStorageFailureGeneration
        var writerPreemptionRecorded = false
        func shouldPreemptForForeground() -> Bool {
            guard recoveryHasForegroundPressure else { return false }
            if !writerPreemptionRecorded {
                recoveryWriterPreemptionsTotal &+= 1
                writerPreemptionRecorded = true
            }
            return true
        }
        recoveryRunsTotal &+= 1
        recovering = true
        defer {
            recovering = false
            refreshAdmissionMeasurementsAndLatch()
            if sqliteStorageFailure != nil,
               sqliteStorageFailureGeneration == sqliteFailureGenerationAtStart,
               sqliteStorageRetryHeadroomIsHealthy() {
                sqliteStorageFailure = nil
                refreshAdmissionMeasurementsAndLatch()
                logger.notice("TraceGraph SQLite storage backstop recovered; mutations may retry")
            }
            let footprintAfter = footprintProbe(databasePath)
            let backlog = recoveryBacklogSnapshot(
                retentionCutoff: retentionCutoffSeconds,
                orphanCutoff: orphanCutoffSeconds
            )
            lastRecoveryFootprintBeforeBytes = footprintBefore
            lastRecoveryFootprintAfterBytes = footprintAfter
            lastRecoveryEligibleBacklogRemaining = backlog.eligible
            recoveryTracesDeletedTotal &+= UInt64(max(0, tracesDeleted))
            recoveryTraceChildRowsDeletedTotal &+= UInt64(
                max(0, traceChildRowsDeleted))
            recoveryEdgesDeletedTotal &+= UInt64(max(0, edgesDeleted))
            recoveryEntitiesDeletedTotal &+= UInt64(max(0, entitiesDeleted))
            recoveryVacuumPagesReclaimedTotal &+= UInt64(
                max(0, pagesReclaimed))
            if tracesDeleted > 0 || traceChildRowsDeleted > 0
                || edgesDeleted > 0 || entitiesDeleted > 0,
               pagesReclaimed == 0,
               mode == 2 {
                recoveryNoPhysicalProgressTotal &+= 1
            }
            finishRecoverySerialization()
        }

        // This checkpoint is the admission test for maintenance. No retention
        // delete is allowed to run before it (the old timer did both deletes
        // first and only then guessed pinning from a 64 MB WAL).
        guard checkpointAllowsMaintenance() else { return result() }

        // A usable inherited v1 schema can be deferred solely because free
        // space was low at open. Once exact DDL/page-limit/scratch headroom is
        // available, complete and verify that work before deciding whether a
        // legacy auto_vacuum mode requires offline physical conversion. This
        // ordering lets a mode-0 store recover without deleting a single row
        // when schema work—not file size—is its only remaining block.
        refreshAdmissionMeasurementsAndLatch()
        if deferredMigrationsPending,
           deferredMigrationFailure == nil,
           deferredMigrationHasStorageHeadroom() {
            do {
                try completeDeferredMigrations()
                guard checkpointAllowsMaintenance() else { return result() }
                refreshAdmissionMeasurementsAndLatch()
            } catch is CausalGraphStorageAdmissionError {
                // A probe/page ceiling can change between preflight and DDL.
                // Keep the usable runtime schema deferred and retry after the
                // next bounded reclaim rather than deleting on this race.
                refreshAdmissionMeasurementsAndLatch()
            }
        }

        // A DELETE cannot recover low free space—it consumes WAL/page-map
        // scratch before any later checkpoint can return blocks. If the first
        // checkpoint (or an admitted deferred migration) already restored
        // ordinary reserve and the durable byte target, return without erasing
        // eligible evidence. Otherwise preserve every row and fail closed on
        // the low-space latch.
        refreshAdmissionMeasurementsAndLatch()
        guard recoveryMutationHeadroomAdmitted() else { return result() }
        refreshAdmissionMeasurementsAndLatch()
        if sqliteStorageFailure != nil,
           sqliteStorageFailureGeneration == sqliteFailureGenerationAtStart,
           sqliteStorageRetryHeadroomIsHealthy() {
            // This pass has re-proved the ordinary reserve/low-water after its
            // checkpoint. Clear only the latch inherited at entry; a new FULL
            // or ENOSPC raised by this pass increments the generation and must
            // remain fail-closed.
            sqliteStorageFailure = nil
            refreshAdmissionMeasurementsAndLatch()
        }
        if recoveryRequiredAtStart,
           internalAdmissionReachedRecoveryTarget() {
            return result()
        }

        // First spend the bounded physical-reclaim budget on pages already on
        // the freelist. A prior crash/timer may have completed logical pruning
        // but not its final incremental vacuum; deleting more evidence before
        // trying those pages would be unnecessary and irreversible.
        if recoveryRequiredAtStart,
           mode == 2,
           vacuumBudget > pagesReclaimed {
            pagesReclaimed += try await incrementalVacuum(
                maxPages: vacuumBudget - pagesReclaimed)
            if shouldPreemptForForeground() { return result() }
            guard checkpointAllowsMaintenance() else { return result() }
            refreshAdmissionMeasurementsAndLatch()
            if deferredMigrationsPending,
               deferredMigrationFailure == nil,
               deferredMigrationHasStorageHeadroom() {
                do {
                    try completeDeferredMigrations()
                    guard checkpointAllowsMaintenance() else { return result() }
                    refreshAdmissionMeasurementsAndLatch()
                } catch is CausalGraphStorageAdmissionError {
                    refreshAdmissionMeasurementsAndLatch()
                }
            }
            guard recoveryMutationHeadroomAdmitted() else { return result() }
            refreshAdmissionMeasurementsAndLatch()
            if internalAdmissionReachedRecoveryTarget() {
                return result()
            }
            if pagesReclaimed > 0 {
                // One quantum of pre-existing freelist pages made physical
                // progress. Give the next bounded pass first claim on the
                // remaining freelist before deleting any logical evidence.
                return result()
            }
        }

        // A legacy mode-0 database cannot return freelist pages to the
        // filesystem with incremental_vacuum. Checkpointing may itself clear
        // enough WAL/SHM footprint to restore admission, so remeasure after the
        // checkpoint. If physical pressure remains, however, DELETE would only
        // erase logical evidence while leaving the main file (and therefore the
        // admission latch) unchanged. Preserve the rows until an operator can
        // stop the engine and perform the explicit offline full-VACUUM
        // conversion to INCREMENTAL mode.
        refreshAdmissionMeasurementsAndLatch()
        let proactivePressure = {
            guard let footprint = lastFootprintBytes,
                  let threshold = Self.proactiveRecoveryThresholdBytes(
                    admissionThresholdBytes: admissionThresholdBytes,
                    transactionReserveBytes: transactionReserveBytes
                  ) else {
                return false
            }
            return footprint >= threshold
        }()
        let lowWaterDeficit = Self.recoveryDeficitBytes(
            footprintBytes: lastFootprintBytes,
            recoveryTargetBytes: resumeBelowBytes
        )
        let admissionMeasurementUnavailable =
            (maxFootprintBytes != nil && lastFootprintBytes == nil)
            || (freeSpaceFloorBytes != nil && lastFreeSpaceBytes == nil)
        let legacyStoreNeedsOfflineConversion = mode == 0
            && (deferredMigrationsPending
                || footprintAdmissionLatched
                || storageBlockReason == .lowFreeSpace
                || sqliteStorageFailure != nil
                || admissionMeasurementUnavailable
                || proactivePressure
                || (lowWaterDeficit ?? 0) > 0)
        if legacyStoreNeedsOfflineConversion {
            logger.fault("TraceGraph bounded recovery cannot reclaim a pressured auto_vacuum=\(mode) store online; preserving logical evidence until an offline full-VACUUM conversion")
            return result()
        }

        if traceBudget > 0 {
            let expired = try selectRecoveryTraceIDs(
                olderThan: retentionCutoffSeconds,
                limit: traceBudget
            )
            if !expired.ids.isEmpty {
                guard recoveryMutationHeadroomAdmitted() else {
                    return result()
                }
                let cascade = try await batchedCascadeDeleteTraces(
                    ids: expired.ids,
                    eligibilityCutoff: retentionCutoffSeconds,
                    maxChildRows: traceChildBudget - traceChildRowsDeleted)
                tracesDeleted += cascade.tracesDeleted
                traceChildRowsDeleted += cascade.childRowsDeleted
                if shouldPreemptForForeground() { return result() }
                if cascade.tracesDeleted == expired.ids.count {
                    // Every eligible parent in this bounded selection is gone;
                    // the next pass may seek directly past it. If even one
                    // parent remains (usually bounded child fanout), rescan
                    // this small window until that evidence is fully drained.
                    recoveryTraceScanAfterRowID = expired.lastRowID
                }
                guard checkpointAllowsMaintenance() else { return result() }
            }
        }

        // Trace parents and their children carry the strongest causal proof.
        // Give their freed pages a checkpoint/vacuum/reprobe before falling
        // back to graph substrate, so satisfying the deficit in this phase
        // cannot also erase eligible edges/entities unnecessarily.
        if recoveryRequiredAtStart,
           tracesDeleted > 0 || traceChildRowsDeleted > 0 {
            guard recoveryMutationHeadroomAdmitted() else { return result() }
            if mode == 2, vacuumBudget > pagesReclaimed {
                pagesReclaimed += try await incrementalVacuum(
                    maxPages: vacuumBudget - pagesReclaimed)
                if shouldPreemptForForeground() { return result() }
            }
            guard checkpointAllowsMaintenance() else { return result() }
            refreshAdmissionMeasurementsAndLatch()
            if internalAdmissionReachedRecoveryTarget() {
                return result()
            }
            // Never cross from trace evidence into graph substrate in the same
            // pressured quantum. Mode 2 may need the next pass's vacuum budget
            // to expose this phase's physical gain; mode 1 has already shrunk
            // on commit and still benefits from a fresh admission decision.
            return result()
        }

        if graphBudget > 0 {
            guard recoveryMutationHeadroomAdmitted() else { return result() }
            edgesDeleted = try await batchedSubstrateDelete(
                table: "trace_edges",
                guardSQL: Self.edgeOrphanGuardSQL,
                cutoff: orphanCutoffSeconds,
                oldestFirstLimit: graphBudget,
                batchSize: min(256, graphBudget)
            )
            if shouldPreemptForForeground() { return result() }
            guard checkpointAllowsMaintenance() else { return result() }
            if recoveryRequiredAtStart, edgesDeleted > 0 {
                if mode == 2, vacuumBudget > pagesReclaimed {
                    guard recoveryMutationHeadroomAdmitted() else {
                        return result()
                    }
                    pagesReclaimed += try await incrementalVacuum(
                        maxPages: vacuumBudget - pagesReclaimed)
                    if shouldPreemptForForeground() { return result() }
                    guard checkpointAllowsMaintenance() else { return result() }
                }
                refreshAdmissionMeasurementsAndLatch()
                // Edges precede entities because surviving edges protect both
                // endpoints. Always return after this physical phase; the next
                // pass may converge or safely decide entity fallback is still
                // required.
                return result()
            }
            guard recoveryMutationHeadroomAdmitted() else { return result() }
            entitiesDeleted = try await batchedSubstrateDelete(
                table: "trace_entities",
                guardSQL: Self.entityOrphanGuardSQL,
                cutoff: orphanCutoffSeconds,
                oldestFirstLimit: graphBudget,
                batchSize: min(256, graphBudget)
            )
            if shouldPreemptForForeground() { return result() }
            guard checkpointAllowsMaintenance() else { return result() }
        }

        // Only rows older than the caller's explicit evidence cutoffs are ever
        // deleted. A pressured store used to spend leftover budget with nil
        // cutoffs, silently evicting recent traces/substrate. Repeated bounded
        // passes and caller-controlled tightening now provide convergence
        // without crossing the one-hour evidence floor.
        guard checkpointAllowsMaintenance() else { return result() }
        guard recoveryMutationHeadroomAdmitted() else { return result() }
        if vacuumBudget > pagesReclaimed, mode == 2 {
            pagesReclaimed += try await incrementalVacuum(
                maxPages: vacuumBudget - pagesReclaimed)
            if shouldPreemptForForeground() { return result() }
            guard checkpointAllowsMaintenance() else { return result() }
        }
        refreshAdmissionMeasurementsAndLatch()
        if deferredMigrationsPending,
           deferredMigrationFailure == nil,
           deferredMigrationHasStorageHeadroom() {
            do {
                try completeDeferredMigrations()
                // Migration writes must be checkpointed and measured before
                // the recovery tick can report that normal growth may resume.
                guard checkpointAllowsMaintenance() else { return result() }
                refreshAdmissionMeasurementsAndLatch()
            } catch is CausalGraphStorageAdmissionError {
                // Free space and SQLite-family footprint are external state;
                // they can change between the exact preflight and CREATE
                // INDEX. Preserve the usable runtime schema and let the
                // bounded startup loop reclaim/retry at its next pass instead
                // of converting a retryable refusal into recoveryFailed.
                refreshAdmissionMeasurementsAndLatch()
            }
        }
        return result()
    }

    /// Drain an inherited blocked store before the daemon starts any event
    /// producer. Each pass is the same bounded recovery quantum used by the
    /// periodic lane. A cutoff is repeated until its exact post-pass backlog is
    /// empty, then tightened through the supplied rungs. The fixed orphan
    /// cutoff and the final trace rung never cross the one-hour evidence floor.
    ///
    /// This method never promises convergence by row progress alone. Success
    /// requires a fresh admission snapshot proving ordinary writes are no
    /// longer blocked; every other terminal state is a typed non-convergence.
    public func recoverStorageBeforeProducers(
        configuredRetentionHours: Int,
        cutoffRungs: [Int],
        now: Date = Date(),
        maximumPasses: Int = 64
    ) async -> CausalGraphStartupRecoveryResult {
        let evidenceFloorHours = 1
        let configuredHours = max(
            evidenceFloorHours,
            min(configuredRetentionHours, 3_650 * 24)
        )
        var normalizedRungs = Array(Set(cutoffRungs.compactMap { value in
            value >= evidenceFloorHours && value < configuredHours ? value : nil
        })).sorted(by: >)
        if configuredHours > evidenceFloorHours,
           !normalizedRungs.contains(evidenceFloorHours) {
            normalizedRungs.append(evidenceFloorHours)
        }
        let passLimit = max(0, min(maximumPasses, 256))

        refreshAdmissionMeasurementsAndLatch()
        let initialAdmission = makeStorageAdmissionStatus()
        guard initialAdmission.writableHandle else {
            return CausalGraphStartupRecoveryResult(
                disposition: .nonconverged(.writableHandleUnavailable),
                initiallyBlocked: initialAdmission.blocked,
                passes: 0,
                attemptedCutoffHours: [],
                finalAdmission: initialAdmission,
                lastRecovery: nil,
                failureDetail: db == nil
                    ? "TraceGraph SQLite handle is closed"
                    : "TraceGraph SQLite handle is read-only"
            )
        }
        let proactivePressure = {
            guard let footprint = initialAdmission.footprintBytes,
                  let threshold = initialAdmission.proactiveRecoveryThresholdBytes else {
                return false
            }
            return footprint >= threshold
        }()
        guard initialAdmission.blocked || proactivePressure else {
            do {
                if initialAdmission.maxFootprintBytes != nil {
                    try configureMaximumPageCount()
                }
            } catch {
                refreshAdmissionMeasurementsAndLatch()
                return CausalGraphStartupRecoveryResult(
                    disposition: .nonconverged(.recoveryFailed),
                    initiallyBlocked: false,
                    passes: 0,
                    attemptedCutoffHours: [],
                    finalAdmission: makeStorageAdmissionStatus(),
                    lastRecovery: nil,
                    failureDetail: "max_page_count verification failed: \(error.localizedDescription)"
                )
            }
            refreshAdmissionMeasurementsAndLatch()
            let verifiedAdmission = makeStorageAdmissionStatus()
            let result = CausalGraphStartupRecoveryResult(
                disposition: .writable,
                initiallyBlocked: false,
                passes: 0,
                attemptedCutoffHours: [],
                finalAdmission: verifiedAdmission,
                lastRecovery: nil,
                failureDetail: nil
            )
            guard result.writableBeforeProducers else {
                return CausalGraphStartupRecoveryResult(
                    disposition: .nonconverged(.admissionMeasurementUnavailable),
                    initiallyBlocked: false,
                    passes: 0,
                    attemptedCutoffHours: [],
                    finalAdmission: verifiedAdmission,
                    lastRecovery: nil,
                    failureDetail: "fresh proactive-boundary or writable-handle proof was unavailable"
                )
            }
            return result
        }

        var cutoffHours = configuredHours
        var attemptedCutoffs: [Int] = []
        var lastRecovery: CausalGraphStorageRecoveryResult?
        var consecutivePinnedPasses = 0
        let pinnedRetryPassLimit = min(8, max(1, passLimit))

        func finish(
            _ disposition: CausalGraphStartupRecoveryDisposition,
            admission: CausalGraphStorageAdmissionStatus,
            detail: String? = nil
        ) -> CausalGraphStartupRecoveryResult {
            CausalGraphStartupRecoveryResult(
                disposition: disposition,
                initiallyBlocked: initialAdmission.blocked,
                passes: attemptedCutoffs.count,
                attemptedCutoffHours: attemptedCutoffs,
                finalAdmission: admission,
                lastRecovery: lastRecovery,
                failureDetail: detail
            )
        }

        while attemptedCutoffs.count < passLimit {
            attemptedCutoffs.append(cutoffHours)
            let recovery: CausalGraphStorageRecoveryResult
            do {
                recovery = try await recoverStorageBudget(
                    retentionCutoff: now.addingTimeInterval(
                        -Double(cutoffHours) * 3_600
                    ),
                    orphanCutoff: now.addingTimeInterval(-3_600)
                )
            } catch {
                refreshAdmissionMeasurementsAndLatch()
                return finish(
                    .nonconverged(.recoveryFailed),
                    admission: makeStorageAdmissionStatus(),
                    detail: error.localizedDescription
                )
            }
            lastRecovery = recovery
            refreshAdmissionMeasurementsAndLatch()
            let admission = makeStorageAdmissionStatus()
            if recovery.pinnedReader {
                consecutivePinnedPasses += 1
                if consecutivePinnedPasses < pinnedRetryPassLimit,
                   attemptedCutoffs.count < passLimit {
                    // A dashboard snapshot can overlap boot for milliseconds.
                    // No DELETE ran on a pinned pass; give that reader a small,
                    // bounded grace window instead of crash-looping the daemon.
                    try? await Task.sleep(nanoseconds: 25_000_000)
                    continue
                }
                return finish(
                    .nonconverged(.pinnedReader),
                    admission: admission,
                    detail: "reader-pinned WAL persisted across \(consecutivePinnedPasses) bounded startup attempts"
                )
            }
            consecutivePinnedPasses = 0

            let targetConfigured = admission.resumeBelowBytes != nil
            let targetSatisfied = !targetConfigured
                || admission.recoveryDeficitBytes == 0
            if !admission.blocked && targetSatisfied {
                do {
                    if admission.maxFootprintBytes != nil {
                        // An inherited oversized file initially forces SQLite
                        // to install max_page_count at its current page count.
                        // Reissue and verify after reclaim so ordinary growth is
                        // bounded by the configured ceiling, not that old size.
                        try configureMaximumPageCount()
                    }
                } catch {
                    refreshAdmissionMeasurementsAndLatch()
                    return finish(
                        .nonconverged(.recoveryFailed),
                        admission: makeStorageAdmissionStatus(),
                        detail: "max_page_count verification failed: \(error.localizedDescription)"
                    )
                }
                refreshAdmissionMeasurementsAndLatch()
                let verifiedAdmission = makeStorageAdmissionStatus()
                let verified = finish(.writable, admission: verifiedAdmission)
                if verified.writableBeforeProducers {
                    return verified
                }
                return finish(
                    .nonconverged(.admissionMeasurementUnavailable),
                    admission: verifiedAdmission,
                    detail: "fresh low-water, proactive-boundary, or writable-handle proof was unavailable after max_page_count verification"
                )
            }
            let madeProgress = recovery.tracesDeleted > 0
                || recovery.traceChildRowsDeleted > 0
                || recovery.edgesDeleted > 0
                || recovery.entitiesDeleted > 0
                || recovery.vacuumPagesReclaimed > 0
                || {
                    guard let before = recovery.footprintBeforeBytes,
                          let after = recovery.footprintBytes else {
                        return false
                    }
                    return after < before
                }()
            if targetConfigured && admission.recoveryDeficitBytes == nil {
                return finish(
                    .nonconverged(.admissionMeasurementUnavailable),
                    admission: admission,
                    detail: "the post-pass footprint or recovery target could not be measured"
                )
            }
            let lowFreeSpaceRecovery = admission.reason == .lowFreeSpace
            if admission.recoveryDeficitBytes == 0 && !lowFreeSpaceRecovery {
                return finish(
                    .nonconverged(.admissionRemainsBlocked),
                    admission: admission,
                    detail: admission.reason?.rawValue
                )
            }
            if recovery.autoVacuumMode == 0 {
                return finish(
                    .nonconverged(.incrementalVacuumUnavailable),
                    admission: admission,
                    detail: "auto_vacuum mode 0 cannot return deleted pages online"
                )
            }

            if recovery.eligibleBacklogRemaining != false {
                if !madeProgress {
                    return finish(
                        .nonconverged(.noRecoverableProgress),
                        admission: admission,
                        detail: recovery.eligibleBacklogRemaining == nil
                            ? "eligible-backlog measurement failed without physical progress"
                            : "eligible rows remain but no bounded row or page quantum could advance"
                    )
                }
                continue
            }

            if let next = normalizedRungs.first(where: { $0 < cutoffHours }) {
                cutoffHours = next
                continue
            }
            return finish(
                .nonconverged(.protectedEvidenceFloor),
                admission: admission,
                detail: "the one-hour evidence floor is exhausted; recent graph evidence was preserved"
            )
        }

        refreshAdmissionMeasurementsAndLatch()
        return finish(
            .nonconverged(.boundedPassLimit),
            admission: makeStorageAdmissionStatus(),
            detail: "startup recovery exhausted its \(passLimit) bounded passes"
        )
    }

    private struct RecoveryTraceSelection {
        var ids: [String] = []
        var lastRowID: Int64 = 0
    }

    private func selectRecoveryTraceIDs(
        olderThan cutoff: Double,
        limit: Int
    ) throws -> RecoveryTraceSelection {
        guard let db, limit > 0 else { return RecoveryTraceSelection() }
        if recoveryTraceScanCutoff != cutoff {
            recoveryTraceScanCutoff = cutoff
            recoveryTraceScanAfterRowID = 0
        }
        let sql = """
        SELECT rowid, id FROM traces
         WHERE rowid > ?2
           AND \(Self.traceRecoveryEligibilityPredicateSQL)
         ORDER BY rowid
         LIMIT ?3
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, cutoff)
        sqlite3_bind_int64(stmt, 2, recoveryTraceScanAfterRowID)
        sqlite3_bind_int64(stmt, 3, Int64(limit))
        var selection = RecoveryTraceSelection()
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return selection }
            guard rc == SQLITE_ROW else {
                // Never treat FULL/IOERR/corruption as a short result set and
                // then delete the partial prefix selected before the fault.
                try throwSQLiteFailure(
                    rc: rc, db: db, context: "select trace IDs for recovery")
            }
            if let raw = sqlite3_column_text(stmt, 1) {
                selection.ids.append(String(cString: raw))
                selection.lastRowID = sqlite3_column_int64(stmt, 0)
            }
        }
    }

    /// Read the file's current `auto_vacuum` mode. Used by callers
    /// (DaemonTimers) to log the gap when this DB is not in
    /// INCREMENTAL mode (mode 2).
    public func autoVacuumMode() async -> Int {
        guard let db = db else { return 0 }
        return Int(StoragePragmas.readAutoVacuumMode(db))
    }

    /// Total trace row count.
    public func traceCount() async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM traces", -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    private struct TraceCascadeProgress {
        var tracesDeleted = 0
        var childRowsDeleted = 0
        var remainingTraces = 0
    }

    private struct TraceCascadeChildTable {
        let name: String
        let rowLimit: Int
        let byteColumns: [String]
    }

    private struct TraceCascadeSelection {
        var rowIDs: [Int64] = []
        var estimatedUpperBoundBytes: Int64 = 0
        var oversizedFirstRowBytes: Int64?
    }

    /// Select a child-row quantum whose conservative WAL/write upper bound fits
    /// one transaction reserve. The bundled SQLite's `octet_length` reads the
    /// encoded byte length from record metadata without loading an inherited
    /// multi-megabyte value into Swift/SQLite memory. Candidate rows remain
    /// count-bounded as a second independent ceiling.
    private func boundedCascadeSelection(
        db: OpaquePointer,
        child: TraceCascadeChildTable,
        traceIDs: [String],
        maxRows: Int,
        matchColumn: String = "trace_id",
        additionalPredicate: String = "",
        initialEstimatedUpperBoundBytes: Int64 = 0
    ) throws -> TraceCascadeSelection {
        guard maxRows > 0 else { return TraceCascadeSelection() }
        let placeholders = traceIDs.map { _ in "?" }.joined(separator: ", ")
        let byteExpressions = child.byteColumns.map {
            "COALESCE(octet_length(\($0)), 0)"
        }.joined(separator: ", ")
        let payloadExpression = child.byteColumns.map {
            "COALESCE(octet_length(\($0)), 0)"
        }.joined(separator: " + ")
        let transactionBudget = max(
            0, transactionReserveBytes ?? Self.defaultMinimumTransactionReserve)
        let initialEstimate = max(
            Self.mutationBaseBytes, initialEstimatedUpperBoundBytes)
        let fixedRowCharge = saturatingAdd(
            Self.mutationBytesPerRow, 128 * 8)
        guard transactionBudget > initialEstimate,
              transactionBudget - initialEstimate > fixedRowCharge else {
            return TraceCascadeSelection(
                estimatedUpperBoundBytes: initialEstimate,
                oversizedFirstRowBytes: Int64.max
            )
        }
        let maxSinglePayloadBytes =
            (transactionBudget - initialEstimate - fixedRowCharge) / 8
        let sql = """
        SELECT rowid, \(byteExpressions)
          FROM \(child.name)
         WHERE \(matchColumn) IN (\(placeholders))
               \(additionalPredicate)
           AND (\(payloadExpression)) <= ?
         ORDER BY rowid
         LIMIT \(maxRows)
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        for (idx, id) in traceIDs.enumerated() {
            sqlite3_bind_text(stmt, Int32(idx + 1), id, -1, SQLITE_TRANSIENT)
        }
        sqlite3_bind_int64(
            stmt, Int32(traceIDs.count + 1), maxSinglePayloadBytes)

        var selection = TraceCascadeSelection(
            estimatedUpperBoundBytes: initialEstimate)
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { break }
            guard rc == SQLITE_ROW else {
                try throwSQLiteFailure(
                    rc: rc, db: db,
                    context: "size-bounded cascade selection from \(child.name)")
            }
            var payloadBytes: Int64 = 128 // record header + fixed numeric fields
            for column in 1...child.byteColumns.count {
                payloadBytes = saturatingAdd(
                    payloadBytes,
                    max(0, sqlite3_column_int64(stmt, Int32(column)))
                )
            }
            let payloadCharge = payloadBytes > Int64.max / 8
                ? Int64.max
                : payloadBytes * 8
            let rowCharge = saturatingAdd(
                payloadCharge, Self.mutationBytesPerRow)
            let proposed = saturatingAdd(
                selection.estimatedUpperBoundBytes, rowCharge)
            if proposed > transactionBudget {
                if selection.rowIDs.isEmpty {
                    selection.oversizedFirstRowBytes = proposed
                }
                break
            }
            selection.rowIDs.append(sqlite3_column_int64(stmt, 0))
            selection.estimatedUpperBoundBytes = proposed
        }
        return selection
    }

    /// Cascade-delete trace IDs in checkpointed child-row quanta. Bounding the
    /// number of trace IDs was insufficient: one inherited trace can have
    /// hundreds of thousands of child rows. Recovery also receives a total
    /// fanout budget, so one timer tick cannot loop forever on that trace.
    private func batchedCascadeDeleteTraces(
        ids: [String],
        eligibilityCutoff: Double? = nil,
        maxChildRows: Int = .max
    ) async throws -> TraceCascadeProgress {
        guard !ids.isEmpty else { return TraceCascadeProgress() }
        var total = TraceCascadeProgress()
        var remainingChildBudget = max(0, maxChildRows)

        batchLoop: for start in stride(
            from: 0, to: ids.count, by: Self.traceCascadeBatchSize) {
            let end = min(start + Self.traceCascadeBatchSize, ids.count)
            let batch = Array(ids[start..<end])
            while true {
                guard checkpointAllowsMaintenance() else { break batchLoop }
                guard recoveryMutationHeadroomAdmitted() else {
                    break batchLoop
                }
                let progress = try cascadeDeleteTraceBatch(
                    ids: batch,
                    eligibilityCutoff: eligibilityCutoff,
                    maxChildRows: remainingChildBudget)
                total.tracesDeleted += progress.tracesDeleted
                total.childRowsDeleted += progress.childRowsDeleted
                total.remainingTraces = progress.remainingTraces
                remainingChildBudget -= progress.childRowsDeleted

                if progress.remainingTraces == 0 { break }
                // No rows changed means a constraint or an exhausted fanout
                // budget prevented forward progress. Never spin indefinitely.
                if progress.tracesDeleted == 0 && progress.childRowsDeleted == 0 {
                    // Preserve an oversized/stuck batch for offline repair,
                    // but do not let it starve later rowid-selected batches.
                    break
                }
                if remainingChildBudget == 0 { break batchLoop }
                guard checkpointAllowsMaintenance() else { break batchLoop }
                guard recoveryMutationHeadroomAdmitted() else {
                    break batchLoop
                }
                if let cascadeYieldHook {
                    try await cascadeYieldHook()
                }
                await Task.yield()
                if recoveryHasForegroundPressure { break batchLoop }
            }
        }
        return total
    }

    /// One atomic child-row quantum. Only one child table is drained per
    /// transaction, and JSON-bearing rows use a much smaller limit. Parent
    /// traces are removed only once all four child tables are empty.
    private func cascadeDeleteTraceBatch(
        ids: [String],
        eligibilityCutoff: Double?,
        maxChildRows: Int
    ) throws -> TraceCascadeProgress {
        guard let db, !ids.isEmpty else { return TraceCascadeProgress() }
        try execTransaction(.begin, db: db, immediate: true)
        do {
            // The actor yields between bounded quanta. A trace selected as old
            // can gain a recent child while this recovery task is suspended.
            // Revalidate under the same immediate transaction as every DELETE
            // so no newly protected evidence can be removed from a stale ID
            // list. There is deliberately no await until after COMMIT.
            let eligibleIDs = try revalidatedCascadeTraceIDs(
                db: db, ids: ids, olderThan: eligibilityCutoff)
            guard !eligibleIDs.isEmpty else {
                let remainingTraces = try countExistingTraces(db: db, ids: ids)
                try execTransaction(.commit, db: db)
                return TraceCascadeProgress(remainingTraces: remainingTraces)
            }
            var childRowsDeleted = 0
            var transactionEstimatedUpperBoundBytes = Self.mutationBaseBytes
            let childTables: [TraceCascadeChildTable] = [
                TraceCascadeChildTable(
                    name: "trace_membership",
                    rowLimit: Self.traceCascadeNarrowChildBatchSize,
                    byteColumns: ["trace_id", "entity_id", "edge_id", "role", "layer"]
                ),
                TraceCascadeChildTable(
                    name: "trace_rule_hits",
                    rowLimit: Self.traceCascadeWideChildBatchSize,
                    byteColumns: [
                        "id", "trace_id", "rule_id", "rule_title", "rule_version",
                        "severity", "matched_event_id", "matched_entity_id",
                        "matched_edge_id", "explanation_json",
                    ]
                ),
                TraceCascadeChildTable(
                    name: "trace_replay_runs",
                    rowLimit: Self.traceCascadeWideChildBatchSize,
                    byteColumns: [
                        "id", "trace_id", "bundle_id", "ruleset_version",
                        "daemon_version", "normalization_version", "result_json",
                    ]
                ),
                TraceCascadeChildTable(
                    name: "trace_hash_chain",
                    rowLimit: Self.traceCascadeNarrowChildBatchSize,
                    byteColumns: [
                        "id", "trace_id", "previous_hash", "current_hash",
                        "event_id", "edge_id", "chain_head_signature",
                    ]
                ),
            ]
            if maxChildRows > 0 {
                for child in childTables {
                    let selection = try boundedCascadeSelection(
                        db: db,
                        child: child,
                        traceIDs: eligibleIDs,
                        maxRows: min(child.rowLimit, maxChildRows)
                    )
                    if let oversized = selection.oversizedFirstRowBytes {
                        logger.fault("TraceGraph recovery cannot safely delete one inherited \(child.name, privacy: .public) row: conservative \(oversized)-byte write bound exceeds the \((self.transactionReserveBytes ?? Self.defaultMinimumTransactionReserve))-byte transaction reserve; preserving the trace for offline repair")
                        break
                    }
                    guard !selection.rowIDs.isEmpty else { continue }
                    let rowPlaceholders = selection.rowIDs.map { _ in "?" }
                        .joined(separator: ", ")
                    let sql = "DELETE FROM \(child.name) WHERE rowid IN (\(rowPlaceholders))"
                    var stmt: OpaquePointer?
                    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                        throw CausalGraphStoreError.prepareFailed(
                            String(cString: sqlite3_errmsg(db)))
                    }
                    for (idx, rowID) in selection.rowIDs.enumerated() {
                        sqlite3_bind_int64(stmt, Int32(idx + 1), rowID)
                    }
                    let rc = sqlite3_step(stmt)
                    sqlite3_finalize(stmt)
                    guard rc == SQLITE_DONE else {
                        try throwSQLiteFailure(
                            rc: rc, db: db,
                            context: "bounded cascade delete from \(child.name)")
                    }
                    childRowsDeleted = Int(sqlite3_changes(db))
                    if childRowsDeleted > 0 {
                        transactionEstimatedUpperBoundBytes =
                            selection.estimatedUpperBoundBytes
                        break
                    }
                }
            }

            // A trace row itself carries summary/ATT&CK/policy JSON and can be
            // larger than every child row. Size it before DELETE and start its
            // budget at this transaction's child-delete charge. This preserves
            // the final-child+parent atomic step without letting their combined
            // WAL/page upper bound exceed the reserve.
            var tracesDeleted = 0
            let parent = TraceCascadeChildTable(
                name: "traces",
                rowLimit: Self.traceCascadeBatchSize,
                byteColumns: [
                    "id", "title", "anchor_event_id", "root_entity_id",
                    "severity", "status", "summary_json", "attack_json",
                    "evidence_bundle_status", "daemon_version",
                    "ruleset_version", "policy_id", "policy_version",
                    "policy_sha256", "policy_snapshot_json",
                    "trace_signing_key_mode", "replay_scope",
                    "attribution_override_policy",
                ]
            )
            let parentSelection = try boundedCascadeSelection(
                db: db,
                child: parent,
                traceIDs: eligibleIDs,
                maxRows: min(parent.rowLimit, eligibleIDs.count),
                matchColumn: "id",
                additionalPredicate: """
                AND NOT EXISTS (
                    SELECT 1 FROM trace_membership m WHERE m.trace_id = traces.id)
                AND NOT EXISTS (
                    SELECT 1 FROM trace_rule_hits h WHERE h.trace_id = traces.id)
                AND NOT EXISTS (
                    SELECT 1 FROM trace_replay_runs r WHERE r.trace_id = traces.id)
                AND NOT EXISTS (
                    SELECT 1 FROM trace_hash_chain c WHERE c.trace_id = traces.id)
                """,
                initialEstimatedUpperBoundBytes:
                    transactionEstimatedUpperBoundBytes
            )
            if let oversized = parentSelection.oversizedFirstRowBytes {
                logger.fault("TraceGraph recovery cannot safely delete one inherited traces row: conservative \(oversized)-byte write bound exceeds the \((self.transactionReserveBytes ?? Self.defaultMinimumTransactionReserve))-byte transaction reserve; preserving the trace for offline repair")
            } else if !parentSelection.rowIDs.isEmpty {
                let rowPlaceholders = parentSelection.rowIDs.map { _ in "?" }
                    .joined(separator: ", ")
                let parentSQL = "DELETE FROM traces WHERE rowid IN (\(rowPlaceholders))"
                var parentStmt: OpaquePointer?
                guard sqlite3_prepare_v2(
                    db, parentSQL, -1, &parentStmt, nil) == SQLITE_OK else {
                    throw CausalGraphStoreError.prepareFailed(
                        String(cString: sqlite3_errmsg(db)))
                }
                for (idx, rowID) in parentSelection.rowIDs.enumerated() {
                    sqlite3_bind_int64(parentStmt, Int32(idx + 1), rowID)
                }
                let parentRC = sqlite3_step(parentStmt)
                sqlite3_finalize(parentStmt)
                guard parentRC == SQLITE_DONE else {
                    try throwSQLiteFailure(
                        rc: parentRC, db: db,
                        context: "bounded cascade parent delete")
                }
                tracesDeleted = Int(sqlite3_changes(db))
            }

            let remainingTraces = try countExistingTraces(db: db, ids: ids)

            try execTransaction(.commit, db: db)
            return TraceCascadeProgress(
                tracesDeleted: tracesDeleted,
                childRowsDeleted: childRowsDeleted,
                remainingTraces: remainingTraces
            )
        } catch {
            try rollbackAndRethrow(error, db: db)
        }
    }

    /// Filter a stale cascade candidate list against the exact retention
    /// predicate while holding the immediate write transaction. A nil cutoff
    /// preserves explicit operator deletions that are not retention based.
    private func revalidatedCascadeTraceIDs(
        db: OpaquePointer,
        ids: [String],
        olderThan cutoff: Double?
    ) throws -> [String] {
        guard let cutoff else { return ids }
        guard !ids.isEmpty else { return [] }
        let placeholders = ids.indices.map { "?\($0 + 2)" }
            .joined(separator: ", ")
        let sql = """
        SELECT id FROM traces
         WHERE id IN (\(placeholders))
           AND \(Self.traceRecoveryEligibilityPredicateSQL)
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(
                String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, cutoff)
        for (idx, id) in ids.enumerated() {
            sqlite3_bind_text(
                stmt, Int32(idx + 2), id, -1, SQLITE_TRANSIENT)
        }
        var eligible: [String] = []
        while true {
            let rc = sqlite3_step(stmt)
            if rc == SQLITE_DONE { return eligible }
            guard rc == SQLITE_ROW else {
                try throwSQLiteFailure(
                    rc: rc, db: db,
                    context: "revalidate trace cascade eligibility")
            }
            if let raw = sqlite3_column_text(stmt, 0) {
                eligible.append(String(cString: raw))
            }
        }
    }

    private func countExistingTraces(
        db: OpaquePointer,
        ids: [String]
    ) throws -> Int {
        guard !ids.isEmpty else { return 0 }
        let placeholders = ids.map { _ in "?" }.joined(separator: ", ")
        let sql = "SELECT COUNT(*) FROM traces WHERE id IN (\(placeholders))"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(
                String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        for (idx, id) in ids.enumerated() {
            sqlite3_bind_text(stmt, Int32(idx + 1), id, -1, SQLITE_TRANSIENT)
        }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(
                String(cString: sqlite3_errmsg(db)))
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    public func hashChainLength(for traceId: String) async throws -> Int {
        guard let db else { throw CausalGraphStoreError.databaseOpenFailed("closed") }
        let sql = "SELECT COUNT(*) FROM trace_hash_chain WHERE trace_id = ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Helpers

    private func insertOrReplaceTraceRow(_ trace: Trace, db: OpaquePointer) throws {
        let sql = """
        INSERT OR REPLACE INTO traces (
            id, title, anchor_event_id, root_entity_id, severity, confidence,
            status, created_at, updated_at, summary_json, attack_json,
            evidence_bundle_status, daemon_version, ruleset_version,
            policy_id, policy_version, policy_sha256, policy_snapshot_json,
            trace_signing_key_mode, replay_scope, attribution_override_policy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, trace.id, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 2, trace.title, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 3, trace.anchorEventId, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 4, trace.rootEntityId)
            sqlite3_bind_text(stmt, 5, trace.severity, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 6, trace.confidence)
            sqlite3_bind_text(stmt, 7, trace.status, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 8, trace.createdAt.timeIntervalSince1970)
            sqlite3_bind_double(stmt, 9, trace.updatedAt.timeIntervalSince1970)
            Self.bindOptionalText(stmt, 10, trace.summaryJson)
            Self.bindOptionalText(stmt, 11, trace.attackJson)
            sqlite3_bind_text(stmt, 12, trace.evidenceBundleStatus, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 13, trace.daemonVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 14, trace.rulesetVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 15, trace.policyId, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 16, trace.policyVersion, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 17, trace.policySha256, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 18, trace.policySnapshotJson, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 19, trace.traceSigningKeyMode, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 20, trace.replayScope, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 21, trace.attributionOverridePolicy, -1, SQLITE_TRANSIENT)
        }
    }

    private func insertMembership(_ member: TraceMembership, db: OpaquePointer) throws {
        let sql = """
        INSERT OR REPLACE INTO trace_membership (
            trace_id, entity_id, edge_id, role, layer, added_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """
        try execBound(db: db, sql: sql) { stmt in
            sqlite3_bind_text(stmt, 1, member.traceId, -1, SQLITE_TRANSIENT)
            Self.bindOptionalText(stmt, 2, member.entityId)
            Self.bindOptionalText(stmt, 3, member.edgeId)
            sqlite3_bind_text(stmt, 4, member.role, -1, SQLITE_TRANSIENT)
            sqlite3_bind_text(stmt, 5, member.layer, -1, SQLITE_TRANSIENT)
            sqlite3_bind_double(stmt, 6, member.addedAt.timeIntervalSince1970)
        }
    }

    /// Timed child evidence extends the parent trace's effective retention
    /// activity. Call only inside the same transaction as the child write so a
    /// crash can never expose a recent child behind a stale parent timestamp.
    private func advanceTraceUpdatedAt(
        traceId: String,
        through activity: Date,
        db: OpaquePointer
    ) throws {
        try execBound(
            db: db,
            sql: "UPDATE traces SET updated_at = MAX(updated_at, ?1) WHERE id = ?2",
            bindings: { stmt in
                sqlite3_bind_double(stmt, 1, activity.timeIntervalSince1970)
                sqlite3_bind_text(stmt, 2, traceId, -1, SQLITE_TRANSIENT)
            }
        )
    }

    private func fetchTraceRow(id: String, db: OpaquePointer) throws -> Trace? {
        let sql = """
        SELECT id, title, anchor_event_id, root_entity_id, severity, confidence,
               status, created_at, updated_at, summary_json, attack_json,
               evidence_bundle_status, daemon_version, ruleset_version,
               policy_id, policy_version, policy_sha256, policy_snapshot_json,
               trace_signing_key_mode, replay_scope, attribution_override_policy
          FROM traces WHERE id = ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, id, -1, SQLITE_TRANSIENT)
        let rc = sqlite3_step(stmt)
        if rc == SQLITE_DONE { return nil }
        guard rc == SQLITE_ROW else {
            throw CausalGraphStoreError.stepFailed(String(cString: sqlite3_errmsg(db)))
        }
        return try decodeTraceRow(stmt!)
    }

    private func fetchTraceMembership(traceId: String, db: OpaquePointer) throws -> [TraceMembership] {
        let sql = """
        SELECT trace_id, entity_id, edge_id, role, layer, added_at
          FROM trace_membership WHERE trace_id = ?
         ORDER BY added_at ASC
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_text(stmt, 1, traceId, -1, SQLITE_TRANSIENT)
        var out: [TraceMembership] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            out.append(try decodeMembershipRow(stmt!))
        }
        return out
    }

    private func execBound(
        db: OpaquePointer,
        sql: String,
        bindings: (OpaquePointer?) -> Void
    ) throws {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw CausalGraphStoreError.prepareFailed(String(cString: sqlite3_errmsg(db)))
        }
        defer { sqlite3_finalize(stmt) }
        bindings(stmt)
        let rc = sqlite3_step(stmt)
        guard rc == SQLITE_DONE else {
            try throwSQLiteFailure(rc: rc, db: db, context: "bound growth statement")
        }
    }

    private func execTransaction(
        _ operation: CausalGraphTransactionOperation,
        db: OpaquePointer,
        immediate: Bool = false
    ) throws {
        if let injected = transactionFailureProbe?(operation) {
            try throwSQLiteFailure(
                metadata: SQLiteFailureMetadata(
                    resultCode: injected.resultCode,
                    extendedResultCode: injected.extendedResultCode,
                    systemErrno: injected.systemErrno
                ),
                db: db,
                context: operation.rawValue.uppercased()
            )
        }
        let sql: String
        switch operation {
        case .begin: sql = immediate ? "BEGIN IMMEDIATE" : "BEGIN TRANSACTION"
        case .commit: sql = "COMMIT"
        case .rollback: sql = "ROLLBACK"
        }
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            try throwSQLiteFailure(rc: rc, db: db, context: sql)
        }
    }

    private func poisonDatabaseAfterRollbackFailure(
        db: OpaquePointer,
        primaryError: Error,
        rollbackError: Error
    ) {
        logger.fault("TraceGraph ROLLBACK failed after \(String(describing: primaryError), privacy: .public): \(String(describing: rollbackError), privacy: .public). Closing the connection because transaction state is uncertain.")
        if sqliteStorageFailure == nil {
            sqliteStorageFailure = .probeFailed(
                "SQLite transaction rollback failed; database handle closed")
            sqliteStorageFailureGeneration &+= 1
        }
        storageBlockReason = sqliteStorageFailure?.blockReason ?? .probeFailure
        if self.db == db { self.db = nil }
        isReadOnly = true
        checkpointController?.detach(from: db)
        checkpointController = nil
        let closeRC = sqlite3_close_v2(db)
        if closeRC != SQLITE_OK {
            logger.error("sqlite3_close_v2 after failed ROLLBACK returned rc=\(closeRC)")
        }
    }

    private func rollbackAndRethrow(
        _ primaryError: Error,
        db: OpaquePointer
    ) throws -> Never {
        do {
            try execTransaction(.rollback, db: db)
        } catch {
            let rollbackError = error
            poisonDatabaseAfterRollbackFailure(
                db: db,
                primaryError: primaryError,
                rollbackError: rollbackError
            )
            // Preserve the original typed storage failure when both failed; if
            // only rollback reports storage exhaustion, it supersedes a generic
            // statement/COMMIT error and becomes the admission signal.
            if let storage = primaryError as? CausalGraphStorageAdmissionError {
                throw storage
            }
            if let storage = rollbackError as? CausalGraphStorageAdmissionError {
                throw storage
            }
            if let sqlite = primaryError as? CausalGraphStoreError,
               sqlite.sqliteFailureMetadata != nil {
                throw sqlite
            }
            throw CausalGraphStoreError.transactionFailed(
                "\(primaryError); rollback also failed: \(rollbackError)")
        }
        throw primaryError
    }

    private func execSQLChecked(db: OpaquePointer, sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            try throwSQLiteFailure(rc: rc, db: db, context: sql)
        }
    }

    private static func bindOptionalText(_ stmt: OpaquePointer?, _ idx: Int32, _ value: String?) {
        if let value {
            sqlite3_bind_text(stmt, idx, value, -1, SQLITE_TRANSIENT)
        } else {
            sqlite3_bind_null(stmt, idx)
        }
    }

    private static func columnText(_ stmt: OpaquePointer, _ idx: Int32) -> String? {
        guard let cstr = sqlite3_column_text(stmt, idx) else { return nil }
        return String(cString: cstr)
    }

    private static func columnDate(_ stmt: OpaquePointer, _ idx: Int32) -> Date {
        Date(timeIntervalSince1970: sqlite3_column_double(stmt, idx))
    }

    private static func columnDateOptional(_ stmt: OpaquePointer, _ idx: Int32) -> Date? {
        if sqlite3_column_type(stmt, idx) == SQLITE_NULL { return nil }
        return Date(timeIntervalSince1970: sqlite3_column_double(stmt, idx))
    }

    // MARK: - Decoders

    private func decryptPresentationJSON(
        _ stored: String,
        context: String
    ) throws -> String {
        let isEnvelope = stored.hasPrefix("ENC2:") || stored.hasPrefix("ENC:")
        guard isEnvelope else { return stored }
        guard let encryption else {
            throw CausalGraphStoreError.decodeFailed(
                "\(context): encrypted value unavailable without a read key"
            )
        }
        let decrypted = encryption.decrypt(stored, expectingEncrypted: true)
        guard !decrypted.hasPrefix("ENC2:"),
              !decrypted.hasPrefix("ENC:") else {
            throw CausalGraphStoreError.decodeFailed(
                "\(context): authenticated decryption failed"
            )
        }
        return decrypted
    }

    private func decodeEntityRow(_ stmt: OpaquePointer) throws -> TraceEntity {
        guard let id = Self.columnText(stmt, 0),
              let entityType = Self.columnText(stmt, 1),
              let stableKey = Self.columnText(stmt, 2),
              let displayName = Self.columnText(stmt, 3),
              let attributesJsonRaw = Self.columnText(stmt, 6),
              let source = Self.columnText(stmt, 7) else {
            throw CausalGraphStoreError.decodeFailed("trace_entities: required column null")
        }
        let attributesJson = try decryptPresentationJSON(
            attributesJsonRaw,
            context: "trace_entities.attributes_json"
        )
        return TraceEntity(
            id: id,
            entityType: entityType,
            stableKey: stableKey,
            displayName: displayName,
            firstSeen: Self.columnDate(stmt, 4),
            lastSeen: Self.columnDate(stmt, 5),
            attributesJson: attributesJson,
            source: source,
            confidence: sqlite3_column_double(stmt, 8),
            observationCount: Int(sqlite3_column_int64(stmt, 9))
        )
    }

    private func decodeEdgeRow(_ stmt: OpaquePointer) throws -> TraceEdge {
        guard let id = Self.columnText(stmt, 0),
              let sourceId = Self.columnText(stmt, 1),
              let targetId = Self.columnText(stmt, 2),
              let relation = Self.columnText(stmt, 3),
              let confidenceTier = Self.columnText(stmt, 7),
              let evidenceJsonRaw = Self.columnText(stmt, 8),
              let eventIdsJson = Self.columnText(stmt, 9) else {
            throw CausalGraphStoreError.decodeFailed("trace_edges: required column null")
        }
        let evidenceJson = try decryptPresentationJSON(
            evidenceJsonRaw,
            context: "trace_edges.evidence_json"
        )
        return TraceEdge(
            id: id,
            sourceEntityId: sourceId,
            targetEntityId: targetId,
            relation: relation,
            firstSeen: Self.columnDate(stmt, 4),
            lastSeen: Self.columnDate(stmt, 5),
            confidence: sqlite3_column_double(stmt, 6),
            confidenceTier: confidenceTier,
            evidenceJson: evidenceJson,
            eventIdsJson: eventIdsJson
        )
    }

    private func decodeTraceRow(_ stmt: OpaquePointer) throws -> Trace {
        guard let id = Self.columnText(stmt, 0),
              let title = Self.columnText(stmt, 1),
              let anchorEventId = Self.columnText(stmt, 2),
              let severity = Self.columnText(stmt, 4),
              let status = Self.columnText(stmt, 6),
              let evidenceBundleStatus = Self.columnText(stmt, 11),
              let daemonVersion = Self.columnText(stmt, 12),
              let rulesetVersion = Self.columnText(stmt, 13),
              let policyId = Self.columnText(stmt, 14),
              let policyVersion = Self.columnText(stmt, 15),
              let policySha256 = Self.columnText(stmt, 16),
              let policySnapshotJson = Self.columnText(stmt, 17),
              let traceSigningKeyMode = Self.columnText(stmt, 18),
              let replayScope = Self.columnText(stmt, 19),
              let attributionOverridePolicy = Self.columnText(stmt, 20)
        else {
            throw CausalGraphStoreError.decodeFailed("traces: required column null")
        }
        return Trace(
            id: id,
            title: title,
            anchorEventId: anchorEventId,
            rootEntityId: Self.columnText(stmt, 3),
            severity: severity,
            confidence: sqlite3_column_double(stmt, 5),
            status: status,
            createdAt: Self.columnDate(stmt, 7),
            updatedAt: Self.columnDate(stmt, 8),
            summaryJson: Self.columnText(stmt, 9),
            attackJson: Self.columnText(stmt, 10),
            evidenceBundleStatus: evidenceBundleStatus,
            daemonVersion: daemonVersion,
            rulesetVersion: rulesetVersion,
            policyId: policyId,
            policyVersion: policyVersion,
            policySha256: policySha256,
            policySnapshotJson: policySnapshotJson,
            traceSigningKeyMode: traceSigningKeyMode,
            replayScope: replayScope,
            attributionOverridePolicy: attributionOverridePolicy
        )
    }

    private func decodeMembershipRow(_ stmt: OpaquePointer) throws -> TraceMembership {
        guard let traceId = Self.columnText(stmt, 0),
              let role = Self.columnText(stmt, 3),
              let layer = Self.columnText(stmt, 4)
        else {
            throw CausalGraphStoreError.decodeFailed("trace_membership: required column null")
        }
        return TraceMembership(
            traceId: traceId,
            entityId: Self.columnText(stmt, 1),
            edgeId: Self.columnText(stmt, 2),
            role: role,
            layer: layer,
            addedAt: Self.columnDate(stmt, 5)
        )
    }

    private func decodeHashChainRow(_ stmt: OpaquePointer) throws -> TraceHashChainEntry {
        guard let id = Self.columnText(stmt, 0),
              let traceId = Self.columnText(stmt, 1),
              let currentHash = Self.columnText(stmt, 4)
        else {
            throw CausalGraphStoreError.decodeFailed("trace_hash_chain: required column null")
        }
        return TraceHashChainEntry(
            id: id,
            traceId: traceId,
            sequenceNumber: Int(sqlite3_column_int64(stmt, 2)),
            previousHash: Self.columnText(stmt, 3),
            currentHash: currentHash,
            eventId: Self.columnText(stmt, 5),
            edgeId: Self.columnText(stmt, 6),
            chainHeadSignature: Self.columnText(stmt, 7),
            chainHeadPublishedToUnifiedLog: sqlite3_column_int(stmt, 8) != 0,
            createdAt: Self.columnDate(stmt, 9)
        )
    }

    // MARK: - Set merge helpers

    private func mergeUniqueEntities(_ entities: [TraceEntity]) -> [TraceEntity] {
        var seen: Set<String> = []
        var out: [TraceEntity] = []
        out.reserveCapacity(entities.count)
        for entity in entities where !seen.contains(entity.id) {
            seen.insert(entity.id)
            out.append(entity)
        }
        return out
    }

    private func mergeUniqueEdges(_ edges: [TraceEdge]) -> [TraceEdge] {
        var seen: Set<String> = []
        var out: [TraceEdge] = []
        out.reserveCapacity(edges.count)
        for edge in edges where !seen.contains(edge.id) {
            seen.insert(edge.id)
            out.append(edge)
        }
        return out
    }
}

// MARK: - SQLITE_TRANSIENT bridge helper

private let SQLITE_TRANSIENT = unsafeBitCast(
    OpaquePointer(bitPattern: -1)!,
    to: sqlite3_destructor_type.self
)
