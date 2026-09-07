import Foundation
import CSQLCipher
import Darwin

/// One storage-pressure policy shared by the persistent Event/Alert/Campaign/
/// Attribution stores. The daemon supplies each store's configured cap while
/// the mechanics (family accounting, f_bavail floor, page ceiling, and sticky
/// recovery) stay identical.
public struct SQLitePersistentStorePolicy: Sendable, Equatable {
    public static let bytesPerMiB: Int64 = 1_048_576
    public static let freeSpaceFloorBytes: Int64 = 1_024 * bytesPerMiB
    /// The event firehose needs a larger bounded transaction than low-volume
    /// alert/campaign stores. At the measured representative estimate this
    /// amortizes roughly 390 rows per commit while retaining a 32 MiB
    /// conservative per-transaction admission budget and reserving that same
    /// space below both cap and disk floor. This does not bound the cumulative
    /// WAL file across commits; checkpoint behaviour is measured separately.
    public static let eventTransactionReserveBytes: Int64 = 32 * bytesPerMiB

    /// Convert an operator-facing MiB cap without a trapping integer multiply.
    /// Invalid/negative input clamps to zero and is then rejected by admission's
    /// typed policy validation.
    public static func capBytes(maxSizeMiB: Int) -> Int64 {
        guard maxSizeMiB > 0 else { return 0 }
        let (bytes, overflow) = Int64(maxSizeMiB)
            .multipliedReportingOverflow(by: bytesPerMiB)
        return overflow ? Int64.max : bytes
    }

    public let maxFootprintBytes: Int64
    public let freeSpaceFloorBytes: Int64
    public let transactionReserveBytes: Int64
    public let storageVolumePath: String

    public init(
        maxFootprintBytes: Int64,
        freeSpaceFloorBytes: Int64,
        transactionReserveBytes: Int64 = 8 * 1_048_576,
        storageVolumePath: String
    ) {
        self.maxFootprintBytes = maxFootprintBytes
        self.freeSpaceFloorBytes = freeSpaceFloorBytes
        self.transactionReserveBytes = transactionReserveBytes
        self.storageVolumePath = storageVolumePath
    }
}

public enum SQLitePersistentStoreAdmissionError: Error, LocalizedError, Equatable,
    SQLiteFailureReporting {
    case invalidPolicy(maxBytes: Int64, floorBytes: Int64, reserveBytes: Int64)
    case unsafeFamilyMember(path: String)
    case partialFamily(mainPath: String)
    case familyProbeFailed(path: String, systemErrno: Int32)
    case freeSpaceProbeFailed(path: String, systemErrno: Int32)
    case footprintLimit(
        footprintBytes: Int64,
        reserveBytes: Int64,
        maxFootprintBytes: Int64
    )
    case lowFreeSpace(
        freeBytes: Int64,
        floorBytes: Int64,
        reserveBytes: Int64,
        requiredFreeBytes: Int64
    )
    case transactionEstimateExceedsReserve(
        estimatedBytes: Int64,
        reserveBytes: Int64
    )
    case schemaTransactionNotSerialized
    case pageLimitInstallationFailed(details: SQLiteFailureDetails)
    case pageLimitDeferred(currentPages: Int64, maximumPages: Int64)
    case sqliteStoragePressure(details: SQLiteFailureDetails)

    public var errorDescription: String? {
        switch self {
        case .invalidPolicy(let max, let floor, let reserve):
            return "Invalid SQLite storage policy (max=\(max), floor=\(floor), reserve=\(reserve))"
        case .unsafeFamilyMember(let path):
            return "Refusing non-regular, symlinked, or multiply-linked SQLite family member at \(path)"
        case .partialFamily(let main):
            return "Refusing partial SQLite family: sidecar exists without \(main)"
        case .familyProbeFailed(let path, let code):
            return "Could not measure SQLite family member \(path) (errno \(code))"
        case .freeSpaceProbeFailed(let path, let code):
            return "Could not measure immediately writable space at \(path) (errno \(code))"
        case .footprintLimit(let footprint, let reserve, let max):
            return "SQLite writes paused: family footprint \(footprint) plus \(reserve) reserve exceeds \(max) bytes"
        case .lowFreeSpace(let free, let floor, let reserve, let required):
            return "SQLite writes paused: \(free) bytes free is below \(required) (\(floor) floor plus \(reserve) reserve)"
        case .transactionEstimateExceedsReserve(let estimated, let reserve):
            return "SQLite transaction refused: conservative \(estimated)-byte estimate exceeds \(reserve)-byte reserve"
        case .schemaTransactionNotSerialized:
            return "SQLite schema work requires an active serialized write transaction"
        case .pageLimitInstallationFailed(let details):
            return "SQLite max_page_count installation failed (rc=\(details.resultCode), extended=\(details.extendedResultCode), errno=\(details.systemErrno))"
        case .pageLimitDeferred(let current, let maximum):
            return "SQLite writes paused: current page count \(current) exceeds lowered maximum \(maximum); maintenance must reclaim pages before retry"
        case .sqliteStoragePressure(let details):
            return "SQLite storage pressure latched (rc=\(details.resultCode), extended=\(details.extendedResultCode), errno=\(details.systemErrno))"
        }
    }

    public var sqliteFailureDetails: SQLiteFailureDetails? {
        switch self {
        case .pageLimitInstallationFailed(let details),
             .sqliteStoragePressure(let details):
            return details
        default:
            return nil
        }
    }

    public var isOperationalPressure: Bool {
        switch self {
        case .footprintLimit, .lowFreeSpace, .pageLimitDeferred,
             .sqliteStoragePressure:
            return true
        default:
            return false
        }
    }
}

public struct SQLitePersistentStoreAdmissionSnapshot: Sendable, Equatable {
    public let enabled: Bool
    public let footprintBytes: Int64?
    public let freeSpaceBytes: Int64?
    public let maxFootprintBytes: Int64?
    public let freeSpaceFloorBytes: Int64?
    public let transactionReserveBytes: Int64?
    public let latchedFailure: String?
    public let pageLimitPending: Bool
}

/// Authoritative measurements taken immediately before a whole-file VACUUM.
/// SQLite may need a temporary rebuild plus journal/WAL overwrite space, so
/// the shared boundary reserves twice the main database size while preserving
/// the configured free-space floor.
public struct SQLiteFullVacuumAdmissionSnapshot: Sendable, Equatable {
    public let mainFileBytes: Int64
    public let freeSpaceBytes: Int64
    public let scratchBytes: Int64
    public let freeSpaceFloorBytes: Int64
    public let requiredFreeBytes: Int64
    public let requirementOverflowed: Bool

    public var admitted: Bool {
        !requirementOverflowed && freeSpaceBytes >= requiredFreeBytes
    }
}

/// Fresh headroom for moving committed WAL frames into the main database.
/// A checkpoint may grow the main file by as much as the currently allocated
/// sidecars while the WAL remains allocated (pinned readers and RESTART both
/// make that transient shape possible). Unlike an ordinary maintenance write,
/// this gate therefore preserves the floor plus the complete sidecar footprint;
/// it intentionally does not enforce the normal family cap because a TRUNCATE
/// checkpoint is itself a recovery route for an already-over-cap family.
public struct SQLiteCheckpointAdmissionSnapshot: Sendable, Equatable {
    public let mainFileBytes: Int64
    public let familyFootprintBytes: Int64
    public let sidecarBytes: Int64
    public let freeSpaceBytes: Int64
    public let freeSpaceFloorBytes: Int64
    public let requiredFreeBytes: Int64
    public let requirementOverflowed: Bool

    public var admitted: Bool {
        !requirementOverflowed && freeSpaceBytes >= requiredFreeBytes
    }
}

/// Fresh measurements for a schema operation whose work scales with the
/// existing database (for example CREATE/DROP INDEX or an FTS rebuild).
/// These operations are deliberately not squeezed through the small ordinary
/// transaction reserve: SQLite can materialize a new b-tree and retain its
/// rollback/WAL image until commit.
public struct SQLiteSchemaRebuildAdmissionSnapshot: Sendable, Equatable {
    public let mainFileBytes: Int64
    public let familyFootprintBytes: Int64
    public let freeSpaceBytes: Int64
    public let rebuildOperationCount: Int
    public let projectedGrowthBytes: Int64
    public let scratchBytes: Int64
    public let projectedFootprintBytes: Int64
    public let maximumFootprintBytes: Int64
    public let freeSpaceFloorBytes: Int64
    public let requiredFreeBytes: Int64
    public let requirementOverflowed: Bool

    public var admitted: Bool {
        !requirementOverflowed
            && projectedFootprintBytes <= maximumFootprintBytes
            && freeSpaceBytes >= requiredFreeBytes
    }
}

/// Actor-owned mutable admission state. The enclosing store actor serializes
/// access; probes are injected only by focused tests.
public struct SQLitePersistentStoreAdmission {
    public typealias FootprintProbe = @Sendable (String) throws -> Int64
    public typealias FreeSpaceProbe = @Sendable (String) throws -> Int64

    /// Conservative page/index/WAL allowance for a row-level mutation when a
    /// caller has no tighter encoded-size estimate. Default 8 MiB policies
    /// therefore cap a transaction at 32 candidate rows before re-probing.
    public static let conservativeRowMutationBytes: Int64 = 256 * 1_024

    /// SQLite's compile-time maximum page size. Using the maximum rather than
    /// the current store's usual 4 KiB page makes estimates independent of a
    /// legacy database's page-size setting.
    public static let maximumSQLitePageBytes: Int64 = 65_536

    /// Conservative per-row portion of a transaction estimate.
    ///
    /// `logicalRepresentationBytes` counts the table payload, every index key,
    /// and any caller-amplified FTS representation. It is doubled for the
    /// durable representation plus WAL/rollback image. Random-key inserts can
    /// dirty one leaf per table/index even when keys are tiny, so callers also
    /// supply a leaf-touch count charged at the database's authoritative page
    /// size. Root/interior tree paths are transaction-fixed and intentionally
    /// excluded here so a useful batch does not pay the same tree slack once
    /// per row.
    public static func conservativeEncodedRowMutationBytes(
        logicalRepresentationBytes: Int64,
        pageSizeBytes: Int64,
        maximumLeafPageTouches: Int
    ) -> Int64 {
        guard logicalRepresentationBytes >= 0,
              pageSizeBytes > 0,
              pageSizeBytes <= maximumSQLitePageBytes,
              maximumLeafPageTouches >= 0 else {
            return Int64.max
        }
        let walAndPayload = saturatingMultiply(logicalRepresentationBytes, by: 2)
        let leafSlack = saturatingMultiply(
            Int64(maximumLeafPageTouches),
            by: pageSizeBytes
        )
        return saturatingAdd(walAndPayload, leafSlack)
    }

    /// One-time tree/header allowance charged once per transaction, not once
    /// per row. `maximumTreePathPageTouches` should cover the union of interior
    /// table/index/FTS paths the transaction can dirty. Four extra pages cover
    /// WAL headers, commit markers and b-tree splits.
    public static func transactionFixedOverheadBytes(
        pageSizeBytes: Int64,
        maximumTreePathPageTouches: Int
    ) -> Int64 {
        guard pageSizeBytes > 0,
              pageSizeBytes <= maximumSQLitePageBytes,
              maximumTreePathPageTouches >= 0 else {
            return Int64.max
        }
        let touches = saturatingAdd(Int64(maximumTreePathPageTouches), 4)
        return saturatingMultiply(touches, by: pageSizeBytes)
    }

    public static func conservativeTransactionBytes(
        rowMutationBytes: Int64,
        pageSizeBytes: Int64,
        maximumTreePathPageTouches: Int
    ) -> Int64 {
        saturatingAdd(
            rowMutationBytes,
            transactionFixedOverheadBytes(
                pageSizeBytes: pageSizeBytes,
                maximumTreePathPageTouches: maximumTreePathPageTouches
            )
        )
    }

    public static func estimatedTransactionBytes(
        rowCount: Int,
        bytesPerRow: Int64 = conservativeRowMutationBytes
    ) -> Int64 {
        guard rowCount >= 0, bytesPerRow >= 0 else { return Int64.max }
        let result = Int64(rowCount).multipliedReportingOverflow(by: bytesPerRow)
        return result.overflow ? Int64.max : result.partialValue
    }

    public static func maximumRowsPerTransaction(
        reserveBytes: Int64,
        bytesPerRow: Int64 = conservativeRowMutationBytes
    ) -> Int {
        guard reserveBytes > 0, bytesPerRow > 0 else { return 0 }
        return Int(clamping: reserveBytes / bytesPerRow)
    }

    /// Reserve a fixed header/tree allowance before assigning page-counted
    /// maintenance work. `overshootPages` covers APIs such as FTS5 merge where
    /// the requested page count is a minimum and SQLite may finish a work unit.
    public static func boundedPageOperationPlan(
        requestedPages: Int,
        reserveBytes: Int64,
        pageSizeBytes: Int64,
        copiesPerPage: Int64 = 2,
        fixedTreePageTouches: Int = 8,
        overshootPages: Int = 0
    ) -> (pages: Int, estimatedTransactionBytes: Int64) {
        guard requestedPages > 0,
              reserveBytes > 0,
              pageSizeBytes > 0,
              pageSizeBytes <= maximumSQLitePageBytes,
              copiesPerPage > 0,
              fixedTreePageTouches >= 0,
              overshootPages >= 0 else {
            return (0, 0)
        }
        let perPage = saturatingMultiply(pageSizeBytes, by: copiesPerPage)
        let fixed = transactionFixedOverheadBytes(
            pageSizeBytes: pageSizeBytes,
            maximumTreePathPageTouches: fixedTreePageTouches
        )
        let overshoot = saturatingMultiply(Int64(overshootPages), by: perPage)
        let unavailable = saturatingAdd(fixed, overshoot)
        guard perPage > 0, unavailable < reserveBytes else {
            return (0, Int64.max)
        }
        let pages = min(
            requestedPages,
            Int(clamping: (reserveBytes - unavailable) / perPage)
        )
        guard pages > 0 else { return (0, Int64.max) }
        let requested = saturatingMultiply(Int64(pages), by: perPage)
        return (pages, saturatingAdd(unavailable, requested))
    }

    /// Pure checkpoint-headroom calculation shared by the primary stores and
    /// the independently admitted trace stores. Callers must take fresh main,
    /// family, and f_bavail measurements at the operation boundary. Invalid or
    /// internally inconsistent measurements fail closed via `requirementOverflowed`.
    public static func checkpointAdmissionSnapshot(
        mainFileBytes: Int64,
        familyFootprintBytes: Int64,
        freeSpaceBytes: Int64,
        freeSpaceFloorBytes: Int64
    ) -> SQLiteCheckpointAdmissionSnapshot {
        guard mainFileBytes >= 0,
              familyFootprintBytes >= mainFileBytes,
              freeSpaceBytes >= 0,
              freeSpaceFloorBytes >= 0 else {
            return SQLiteCheckpointAdmissionSnapshot(
                mainFileBytes: max(0, mainFileBytes),
                familyFootprintBytes: max(0, familyFootprintBytes),
                sidecarBytes: Int64.max,
                freeSpaceBytes: max(0, freeSpaceBytes),
                freeSpaceFloorBytes: max(0, freeSpaceFloorBytes),
                requiredFreeBytes: Int64.max,
                requirementOverflowed: true
            )
        }
        let sidecars = familyFootprintBytes - mainFileBytes
        let requirement = freeSpaceFloorBytes.addingReportingOverflow(sidecars)
        return SQLiteCheckpointAdmissionSnapshot(
            mainFileBytes: mainFileBytes,
            familyFootprintBytes: familyFootprintBytes,
            sidecarBytes: sidecars,
            freeSpaceBytes: freeSpaceBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            requiredFreeBytes: requirement.overflow
                ? Int64.max : requirement.partialValue,
            requirementOverflowed: requirement.overflow
        )
    }

    public static func saturatingAdd(_ lhs: Int64, _ rhs: Int64) -> Int64 {
        guard lhs >= 0, rhs >= 0 else { return Int64.max }
        let result = lhs.addingReportingOverflow(rhs)
        return result.overflow ? Int64.max : result.partialValue
    }

    public static func saturatingMultiply(_ value: Int64, by multiplier: Int64) -> Int64 {
        guard value >= 0, multiplier >= 0 else { return Int64.max }
        let result = value.multipliedReportingOverflow(by: multiplier)
        return result.overflow ? Int64.max : result.partialValue
    }

    let databasePath: String
    public private(set) var policy: SQLitePersistentStorePolicy
    private let footprintProbe: FootprintProbe
    private let freeSpaceProbe: FreeSpaceProbe
    private(set) var latchedFailure: SQLitePersistentStoreAdmissionError?
    private(set) var lastFootprintBytes: Int64?
    private(set) var lastFreeSpaceBytes: Int64?
    private(set) var pageLimitPending: Bool

    public init(
        databasePath: String,
        policy: SQLitePersistentStorePolicy,
        maintenance: Bool = false,
        latchOperationalPressure: Bool = false,
        footprintProbe: FootprintProbe? = nil,
        freeSpaceProbe: FreeSpaceProbe? = nil
    ) throws {
        try Self.validate(policy)
        self.databasePath = databasePath
        self.policy = policy
        self.footprintProbe = footprintProbe ?? { path in
            try Self.measureFamily(path)
        }
        self.freeSpaceProbe = freeSpaceProbe ?? { path in
            try Self.measureFreeSpace(path)
        }
        self.latchedFailure = nil
        self.lastFootprintBytes = nil
        self.lastFreeSpaceBytes = nil
        self.pageLimitPending = false
        do {
            if maintenance {
                try admitMaintenanceWrite(estimatedTransactionBytes: 0)
            } else {
                try evaluateAndLatch()
            }
        } catch let error as SQLitePersistentStoreAdmissionError {
            if latchOperationalPressure, error.isOperationalPressure {
                latchedFailure = error
            } else {
                throw error
            }
        }
    }

    public mutating func installPageLimit(
        on db: OpaquePointer,
        schema: String = "main"
    ) throws {
        do {
            pageLimitPending = true
            guard !schema.isEmpty,
                  schema.unicodeScalars.allSatisfy({
                      CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_")).contains($0)
                  }) else {
                throw SQLitePersistentStoreAdmissionError.pageLimitInstallationFailed(
                    details: SQLiteFailureDetails(resultCode: SQLITE_MISUSE, db: db)
                )
            }
            let pageSize = try pragmaInt64(db, schema: schema, name: "page_size")
            guard pageSize > 0 else {
                throw SQLitePersistentStoreAdmissionError.pageLimitInstallationFailed(
                    details: SQLiteFailureDetails(resultCode: SQLITE_ERROR, db: db)
                )
            }
            let mainBudget = policy.maxFootprintBytes - policy.transactionReserveBytes
            let maximumPages = max(Int64(1), mainBudget / pageSize)
            let sql = "PRAGMA \(schema).max_page_count = \(maximumPages)"
            let rc = sqlite3_exec(db, sql, nil, nil, nil)
            guard rc == SQLITE_OK else {
                let details = SQLiteFailureDetails(resultCode: rc, db: db)
                if details.primaryResultCode == SQLITE_FULL
                    || details.systemErrno == ENOSPC
                    || details.systemErrno == EDQUOT {
                    throw SQLitePersistentStoreAdmissionError
                        .sqliteStoragePressure(details: details)
                }
                throw SQLitePersistentStoreAdmissionError.pageLimitInstallationFailed(
                    details: details
                )
            }
            let installed = try pragmaInt64(
                db,
                schema: schema,
                name: "max_page_count"
            )
            guard installed <= maximumPages else {
                throw SQLitePersistentStoreAdmissionError.pageLimitDeferred(
                    currentPages: installed,
                    maximumPages: maximumPages
                )
            }
            pageLimitPending = false
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Called immediately before every write or explicit write transaction.
    /// A prior failure remains sticky until both probes demonstrate recovery.
    public mutating func admitWrite(
        estimatedTransactionBytes: Int64,
        on db: OpaquePointer? = nil
    ) throws {
        try validateTransactionEstimate(estimatedTransactionBytes)
        try evaluateAndLatch()
        if pageLimitPending, let db {
            try installPageLimit(on: db)
        }
    }

    /// Re-probe an already-serialized SQLite writer immediately after
    /// `BEGIN IMMEDIATE` and before its first DML statement. Ordinary
    /// `admitWrite` deliberately keeps the complete transaction reserve free
    /// while an actor is waiting for the cross-process lock; repeating that
    /// full-reserve test after a preceding, successfully admitted commit would
    /// make small terminal/retention transactions unable to consume the very
    /// reserve set aside for them. Once the writer lock is held, the complete
    /// conservative estimate for this transaction is authoritative instead.
    ///
    /// Maintenance has no free-space floor (it is the route back to a healthy
    /// footprint) and, since rc.36, is admitted up to ONE TRANSACTION RESERVE
    /// above the family cap.
    ///
    /// That relaxation is deliberate. Requiring maintenance to stay under the
    /// cap sounds stricter but is self-defeating: a prune, rollup or VACUUM must
    /// append to the WAL before a checkpoint can reclaim anything, so an
    /// over-cap family refused the only writes able to shrink it. An installed
    /// host paused ingestion at 289.7 MiB of a 320 MiB cap and dropped 906,509
    /// events while unable to prune itself back under budget.
    ///
    /// Ingestion is still bounded by the cap exactly as before, and the
    /// maintenance overshoot is bounded by the single transaction it needs to
    /// make progress. No caller may perform DML between `BEGIN IMMEDIATE` and
    /// this probe.
    public mutating func admitSerializedWrite(
        estimatedTransactionBytes: Int64,
        postCommitHeadroomBytes: Int64 = 0,
        maintenance: Bool,
        on db: OpaquePointer? = nil
    ) throws {
        try validateTransactionEstimate(estimatedTransactionBytes)
        guard postCommitHeadroomBytes >= 0,
              postCommitHeadroomBytes <= policy.transactionReserveBytes else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: max(0, postCommitHeadroomBytes),
                    reserveBytes: policy.transactionReserveBytes
                )
        }
        do {
            let footprint = try footprintProbe(databasePath)
            let free = try freeSpaceProbe(policy.storageVolumePath)
            lastFootprintBytes = footprint
            lastFreeSpaceBytes = free

            let afterTransaction = footprint.addingReportingOverflow(
                estimatedTransactionBytes
            )
            let requiredFootprint = afterTransaction.partialValue
                .addingReportingOverflow(postCommitHeadroomBytes)
            // v1.21.6-rc.36: maintenance gets BOUNDED headroom above the cap.
            //
            // Retention, rollup, prune and VACUUM are the operations that make
            // the family smaller — but each must WRITE before it can shrink
            // anything (a delete appends to the WAL before a checkpoint reclaims
            // it). Enforcing the family cap against them meant that once the
            // family exceeded its cap, the only work able to fix that was the
            // first thing refused. Observed on an installed host: ingestion
            // paused at 289.7 MiB of a 320 MiB cap, "Adaptive rollup at cutoff
            // 15m failed: SQLite writes paused", and 906,509 events dropped
            // while the store sat unable to prune itself back under budget.
            //
            // The headroom is one transaction reserve, not a blank cheque: a
            // maintenance pass may overshoot by the size of the single
            // transaction it needs to make progress, and no more. Ingestion
            // remains capped exactly as before.
            let admissionCeiling = maintenance
                ? Self.saturatingAdd(
                    policy.maxFootprintBytes,
                    policy.transactionReserveBytes
                )
                : policy.maxFootprintBytes
            guard !afterTransaction.overflow,
                  !requiredFootprint.overflow,
                  requiredFootprint.partialValue <= admissionCeiling
            else {
                throw SQLitePersistentStoreAdmissionError.footprintLimit(
                    footprintBytes: footprint,
                    reserveBytes: Self.saturatingAdd(
                        estimatedTransactionBytes,
                        postCommitHeadroomBytes
                    ),
                    maxFootprintBytes: admissionCeiling
                )
            }

            let floor = maintenance ? 0 : policy.freeSpaceFloorBytes
            let afterFloor = floor.addingReportingOverflow(
                estimatedTransactionBytes
            )
            let requiredFree = afterFloor.partialValue
                .addingReportingOverflow(postCommitHeadroomBytes)
            guard !afterFloor.overflow,
                  !requiredFree.overflow,
                  free >= requiredFree.partialValue else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: floor,
                    reserveBytes: Self.saturatingAdd(
                        estimatedTransactionBytes,
                        postCommitHeadroomBytes
                    ),
                    requiredFreeBytes: requiredFree.overflow
                        ? Int64.max : requiredFree.partialValue
                )
            }

            if pageLimitPending, let db {
                try installPageLimit(on: db)
            }
            if !maintenance {
                latchedFailure = nil
            }
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Admit one explicitly sized schema transaction after BEGIN IMMEDIATE.
    /// Index retirement can exceed the ordinary row-write reserve even though
    /// the whole operation fits the store and volume budgets. Its estimate must
    /// include all affected b-tree pages, their WAL image, and metadata/tree
    /// overhead, measured while this connection holds the writer lock.
    ///
    /// This is intentionally separate from row/maintenance admission: it does
    /// not enlarge their reserve, borrow the free-space floor, or allow an
    /// over-cap schema transition. Call before the first schema mutation.
    mutating func admitSerializedSchemaWrite(
        estimatedTransactionBytes: Int64,
        on db: OpaquePointer
    ) throws {
        guard sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE else {
            throw SQLitePersistentStoreAdmissionError.schemaTransactionNotSerialized
        }
        guard estimatedTransactionBytes >= 0 else {
            throw SQLitePersistentStoreAdmissionError.transactionEstimateExceedsReserve(
                estimatedBytes: Int64.max,
                reserveBytes: policy.maxFootprintBytes
            )
        }
        do {
            let footprint = try footprintProbe(databasePath)
            let free = try freeSpaceProbe(policy.storageVolumePath)
            lastFootprintBytes = footprint
            lastFreeSpaceBytes = free
            let projected = footprint.addingReportingOverflow(estimatedTransactionBytes)
            guard !projected.overflow,
                  projected.partialValue <= policy.maxFootprintBytes else {
                throw SQLitePersistentStoreAdmissionError.footprintLimit(
                    footprintBytes: footprint,
                    reserveBytes: estimatedTransactionBytes,
                    maxFootprintBytes: policy.maxFootprintBytes
                )
            }
            let requiredFree = policy.freeSpaceFloorBytes
                .addingReportingOverflow(estimatedTransactionBytes)
            guard !requiredFree.overflow, free >= requiredFree.partialValue else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: policy.freeSpaceFloorBytes,
                    reserveBytes: estimatedTransactionBytes,
                    requiredFreeBytes: requiredFree.overflow ? Int64.max : requiredFree.partialValue
                )
            }
            if pageLimitPending { try installPageLimit(on: db) }
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Atomically adopts a valid live-reload policy. Operational pressure under
    /// a newly lowered cap is reported in the returned sticky snapshot rather
    /// than rolling the policy back to its stale, more-permissive value. Once
    /// maintenance shrinks the family, the next estimated `admitWrite` retries
    /// the pending page ceiling before allowing growth.
    public mutating func updatePolicy(
        _ updated: SQLitePersistentStorePolicy,
        on db: OpaquePointer
    ) throws -> SQLitePersistentStoreAdmissionSnapshot {
        try Self.validate(updated)
        policy = updated
        pageLimitPending = true
        do {
            try evaluateAndLatch()
            try installPageLimit(on: db)
        } catch let error as SQLitePersistentStoreAdmissionError
            where error.isOperationalPressure {
            // The valid policy remains authoritative and the typed failure is
            // retained in `latchedFailure` for status + the next writer.
        }
        return snapshot(reprobe: false)
    }

    public var growthBlocked: Bool {
        latchedFailure != nil || pageLimitPending
    }

    public var transactionReserveBytes: Int64 {
        policy.transactionReserveBytes
    }

    /// Retention and incremental-reclaim operations are the route back under a
    /// footprint ceiling. They still require a bounded amount of immediately
    /// writable space, but deliberately do not require the already-violated
    /// footprint ceiling or free-space floor. A successful maintenance probe
    /// does not clear the sticky failure; only a subsequent normal admission
    /// proving full policy recovery does that.
    public mutating func admitMaintenanceWrite(
        estimatedTransactionBytes: Int64
    ) throws {
        try validateTransactionEstimate(estimatedTransactionBytes)
        do {
            lastFootprintBytes = try footprintProbe(databasePath)
            let free = try freeSpaceProbe(policy.storageVolumePath)
            lastFreeSpaceBytes = free
            guard free >= policy.transactionReserveBytes else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: 0,
                    reserveBytes: policy.transactionReserveBytes,
                    requiredFreeBytes: policy.transactionReserveBytes
                )
            }
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Admit a WAL checkpoint from fresh main/family/free-space measurements.
    /// The entire non-main family is charged as possible main-file growth. This
    /// safely over-counts SHM and a stale rollback journal, and avoids parsing
    /// WAL headers that may be changing on another connection.
    @discardableResult
    public mutating func admitCheckpoint() throws
        -> SQLiteCheckpointAdmissionSnapshot {
        do {
            let main = try Self.measureMainFile(databasePath)
            let family = try footprintProbe(databasePath)
            let free = try freeSpaceProbe(policy.storageVolumePath)
            lastFootprintBytes = family
            lastFreeSpaceBytes = free

            let snapshot = Self.checkpointAdmissionSnapshot(
                mainFileBytes: main,
                familyFootprintBytes: family,
                freeSpaceBytes: free,
                freeSpaceFloorBytes: policy.freeSpaceFloorBytes
            )
            guard snapshot.admitted else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: policy.freeSpaceFloorBytes,
                    reserveBytes: snapshot.sidecarBytes,
                    requiredFreeBytes: snapshot.requiredFreeBytes
                )
            }
            return snapshot
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Admit a whole-file `VACUUM` using a fresh main-file stat and free-block
    /// probe at the operation boundary. This is deliberately stricter than
    /// ordinary `admitMaintenanceWrite`: incremental vacuum and DELETE need
    /// only the small maintenance reserve, while full VACUUM may transiently need two
    /// copies of the authoritative main database in free space.
    @discardableResult
    public mutating func admitFullVacuum() throws
        -> SQLiteFullVacuumAdmissionSnapshot {
        do {
            lastFootprintBytes = try footprintProbe(databasePath)
            let result = try Self.requireFullVacuumHeadroom(
                databasePath: databasePath,
                storageVolumePath: policy.storageVolumePath,
                freeSpaceFloorBytes: policy.freeSpaceFloorBytes,
                freeSpaceProbe: freeSpaceProbe
            )
            lastFreeSpaceBytes = result.freeSpaceBytes
            return result
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Admit schema/index/FTS work that can scale with the full existing DB.
    /// For `N` rebuild-class statements we conservatively budget `N * main`
    /// for durable family growth and `(N + 1) * main` as immediately writable
    /// scratch (all new b-trees plus a rollback/WAL image). This deliberately
    /// overestimates DROP INDEX and serial CREATE INDEX statements; refusing a
    /// migration under uncertain headroom is safer than exhausting the boot
    /// volume midway through a daemon startup transaction.
    @discardableResult
    public mutating func admitSchemaRebuild(
        operationCount: Int,
        minimumProjectedGrowthBytes: Int64 = 0
    ) throws -> SQLiteSchemaRebuildAdmissionSnapshot {
        guard operationCount >= 0, minimumProjectedGrowthBytes >= 0 else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: Int64.max,
                    reserveBytes: policy.transactionReserveBytes
                )
        }
        guard operationCount > 0 || minimumProjectedGrowthBytes > 0 else {
            let family = try footprintProbe(databasePath)
            let main = try Self.measureMainFile(databasePath)
            let free = try freeSpaceProbe(policy.storageVolumePath)
            return SQLiteSchemaRebuildAdmissionSnapshot(
                mainFileBytes: main,
                familyFootprintBytes: family,
                freeSpaceBytes: free,
                rebuildOperationCount: 0,
                projectedGrowthBytes: 0,
                scratchBytes: 0,
                projectedFootprintBytes: family,
                maximumFootprintBytes: policy.maxFootprintBytes,
                freeSpaceFloorBytes: policy.freeSpaceFloorBytes,
                requiredFreeBytes: policy.freeSpaceFloorBytes,
                requirementOverflowed: false
            )
        }

        do {
            let family = try footprintProbe(databasePath)
            let main = try Self.measureMainFile(databasePath)
            let free = try freeSpaceProbe(policy.storageVolumePath)
            lastFootprintBytes = family
            lastFreeSpaceBytes = free

            let operations = Int64(operationCount)
            let scaledGrowth = Self.saturatingMultiply(main, by: operations)
            let projectedGrowth = max(
                scaledGrowth,
                minimumProjectedGrowthBytes
            )
            // Retain one authoritative main-file copy alongside the maximum
            // projected new b-tree/bulk-copy representation.
            let scratch = Self.saturatingAdd(main, projectedGrowth)
            let projectedFootprint = Self.saturatingAdd(family, projectedGrowth)
            let requiredFree = Self.saturatingAdd(
                policy.freeSpaceFloorBytes,
                scratch
            )
            let overflowed = projectedGrowth == Int64.max
                || scratch == Int64.max
                || projectedFootprint == Int64.max
                || requiredFree == Int64.max
            let snapshot = SQLiteSchemaRebuildAdmissionSnapshot(
                mainFileBytes: main,
                familyFootprintBytes: family,
                freeSpaceBytes: free,
                rebuildOperationCount: operationCount,
                projectedGrowthBytes: projectedGrowth,
                scratchBytes: scratch,
                projectedFootprintBytes: projectedFootprint,
                maximumFootprintBytes: policy.maxFootprintBytes,
                freeSpaceFloorBytes: policy.freeSpaceFloorBytes,
                requiredFreeBytes: requiredFree,
                requirementOverflowed: overflowed
            )
            guard !overflowed,
                  projectedFootprint <= policy.maxFootprintBytes else {
                throw SQLitePersistentStoreAdmissionError.footprintLimit(
                    footprintBytes: family,
                    reserveBytes: projectedGrowth,
                    maxFootprintBytes: policy.maxFootprintBytes
                )
            }
            guard free >= requiredFree else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: policy.freeSpaceFloorBytes,
                    reserveBytes: scratch,
                    requiredFreeBytes: requiredFree
                )
            }
            return snapshot
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    /// Overflow-safe source of truth for timer preflights and operation-time
    /// admission. Saturation is observable for diagnostics; the actual gate
    /// below still treats an arithmetic overflow as a hard refusal.
    public static func fullVacuumRequiredFreeBytes(
        mainFileBytes: Int64,
        freeSpaceFloorBytes: Int64
    ) -> Int64 {
        fullVacuumRequirement(
            mainFileBytes: mainFileBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes
        ).required
    }

    /// Shared external preflight. Store methods repeat this same probe
    /// immediately before `VACUUM`, because any caller-side check can race
    /// another disk consumer.
    @discardableResult
    public static func requireFullVacuumHeadroom(
        databasePath: String,
        storageVolumePath: String,
        freeSpaceFloorBytes: Int64
    ) throws -> SQLiteFullVacuumAdmissionSnapshot {
        try requireFullVacuumHeadroom(
            databasePath: databasePath,
            storageVolumePath: storageVolumePath,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            freeSpaceProbe: { try measureFreeSpace($0) }
        )
    }

    /// Non-mutating measurement for caller-side branch selection and logging.
    /// The operation itself must still call a `require`/`admit` method again.
    public static func inspectFullVacuumHeadroom(
        databasePath: String,
        storageVolumePath: String,
        freeSpaceFloorBytes: Int64
    ) throws -> SQLiteFullVacuumAdmissionSnapshot {
        try inspectFullVacuumHeadroom(
            databasePath: databasePath,
            storageVolumePath: storageVolumePath,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            freeSpaceProbe: { try measureFreeSpace($0) }
        )
    }

    private static func requireFullVacuumHeadroom(
        databasePath: String,
        storageVolumePath: String,
        freeSpaceFloorBytes: Int64,
        freeSpaceProbe: FreeSpaceProbe
    ) throws -> SQLiteFullVacuumAdmissionSnapshot {
        let result = try inspectFullVacuumHeadroom(
            databasePath: databasePath,
            storageVolumePath: storageVolumePath,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            freeSpaceProbe: freeSpaceProbe
        )
        guard result.admitted else {
            throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                freeBytes: result.freeSpaceBytes,
                floorBytes: max(0, freeSpaceFloorBytes),
                reserveBytes: result.scratchBytes,
                requiredFreeBytes: result.requiredFreeBytes
            )
        }
        return result
    }

    private static func inspectFullVacuumHeadroom(
        databasePath: String,
        storageVolumePath: String,
        freeSpaceFloorBytes: Int64,
        freeSpaceProbe: FreeSpaceProbe
    ) throws -> SQLiteFullVacuumAdmissionSnapshot {
        let mainBytes = try measureMainFile(databasePath)
        let requirement = fullVacuumRequirement(
            mainFileBytes: mainBytes,
            freeSpaceFloorBytes: freeSpaceFloorBytes
        )
        let free = try freeSpaceProbe(storageVolumePath)
        return SQLiteFullVacuumAdmissionSnapshot(
            mainFileBytes: mainBytes,
            freeSpaceBytes: free,
            scratchBytes: requirement.scratch,
            freeSpaceFloorBytes: freeSpaceFloorBytes,
            requiredFreeBytes: requirement.required,
            requirementOverflowed: requirement.overflow
        )
    }

    private static func fullVacuumRequirement(
        mainFileBytes: Int64,
        freeSpaceFloorBytes: Int64
    ) -> (scratch: Int64, required: Int64, overflow: Bool) {
        guard mainFileBytes >= 0, freeSpaceFloorBytes >= 0 else {
            return (Int64.max, Int64.max, true)
        }
        let doubled = mainFileBytes.multipliedReportingOverflow(by: 2)
        let scratch = doubled.overflow ? Int64.max : doubled.partialValue
        let total = freeSpaceFloorBytes.addingReportingOverflow(scratch)
        return (
            scratch,
            (doubled.overflow || total.overflow) ? Int64.max : total.partialValue,
            doubled.overflow || total.overflow
        )
    }

    /// Converts SQLite/VFS exhaustion into the same sticky typed error. Returns
    /// nil for non-pressure failures so the store can retain its native error.
    public mutating func latchSQLitePressure(
        resultCode: Int32,
        db: OpaquePointer?
    ) -> SQLitePersistentStoreAdmissionError? {
        latchSQLitePressure(
            details: SQLiteFailureDetails(resultCode: resultCode, db: db)
        )
    }

    public mutating func latchSQLitePressure(
        details: SQLiteFailureDetails
    ) -> SQLitePersistentStoreAdmissionError? {
        let primary = details.primaryResultCode
        let isPressure = primary == SQLITE_FULL
            || details.systemErrno == ENOSPC
            || details.systemErrno == EDQUOT
        guard isPressure else { return nil }
        let error = SQLitePersistentStoreAdmissionError.sqliteStoragePressure(
            details: details
        )
        latchedFailure = error
        return error
    }

    public mutating func snapshot() -> SQLitePersistentStoreAdmissionSnapshot {
        snapshot(reprobe: true)
    }

    private mutating func snapshot(
        reprobe: Bool
    ) -> SQLitePersistentStoreAdmissionSnapshot {
        // Measurement failures must not clear a latch; status remains useful
        // even when the underlying volume is unavailable.
        if reprobe {
            lastFootprintBytes = try? footprintProbe(databasePath)
            lastFreeSpaceBytes = try? freeSpaceProbe(policy.storageVolumePath)
        }
        return SQLitePersistentStoreAdmissionSnapshot(
            enabled: true,
            footprintBytes: lastFootprintBytes,
            freeSpaceBytes: lastFreeSpaceBytes,
            maxFootprintBytes: policy.maxFootprintBytes,
            freeSpaceFloorBytes: policy.freeSpaceFloorBytes,
            transactionReserveBytes: policy.transactionReserveBytes,
            latchedFailure: latchedFailure?.localizedDescription,
            pageLimitPending: pageLimitPending
        )
    }

    private static func validate(_ policy: SQLitePersistentStorePolicy) throws {
        guard policy.maxFootprintBytes > 0,
              policy.freeSpaceFloorBytes >= 0,
              policy.transactionReserveBytes > 0,
              policy.transactionReserveBytes < policy.maxFootprintBytes else {
            throw SQLitePersistentStoreAdmissionError.invalidPolicy(
                maxBytes: policy.maxFootprintBytes,
                floorBytes: policy.freeSpaceFloorBytes,
                reserveBytes: policy.transactionReserveBytes
            )
        }
    }

    private func validateTransactionEstimate(_ estimatedBytes: Int64) throws {
        guard estimatedBytes >= 0,
              estimatedBytes <= policy.transactionReserveBytes else {
            throw SQLitePersistentStoreAdmissionError
                .transactionEstimateExceedsReserve(
                    estimatedBytes: max(0, estimatedBytes),
                    reserveBytes: policy.transactionReserveBytes
                )
        }
    }

    private mutating func evaluateAndLatch() throws {
        do {
            let footprint = try footprintProbe(databasePath)
            lastFootprintBytes = footprint
            let (requiredFootprint, footprintOverflow) = footprint.addingReportingOverflow(
                policy.transactionReserveBytes
            )
            guard !footprintOverflow,
                  requiredFootprint <= policy.maxFootprintBytes else {
                throw SQLitePersistentStoreAdmissionError.footprintLimit(
                    footprintBytes: footprint,
                    reserveBytes: policy.transactionReserveBytes,
                    maxFootprintBytes: policy.maxFootprintBytes
                )
            }

            let free = try freeSpaceProbe(policy.storageVolumePath)
            lastFreeSpaceBytes = free
            let (requiredFree, freeOverflow) = policy.freeSpaceFloorBytes
                .addingReportingOverflow(policy.transactionReserveBytes)
            guard !freeOverflow, free >= requiredFree else {
                throw SQLitePersistentStoreAdmissionError.lowFreeSpace(
                    freeBytes: free,
                    floorBytes: policy.freeSpaceFloorBytes,
                    reserveBytes: policy.transactionReserveBytes,
                    requiredFreeBytes: freeOverflow ? Int64.max : requiredFree
                )
            }
            latchedFailure = nil
        } catch let error as SQLitePersistentStoreAdmissionError {
            latchedFailure = error
            throw error
        }
    }

    private func pragmaInt64(
        _ db: OpaquePointer,
        schema: String,
        name: String
    ) throws -> Int64 {
        var statement: OpaquePointer?
        let prepare = sqlite3_prepare_v2(
            db,
            "PRAGMA \(schema).\(name)",
            -1,
            &statement,
            nil
        )
        guard prepare == SQLITE_OK, let statement else {
            throw SQLitePersistentStoreAdmissionError.pageLimitInstallationFailed(
                details: SQLiteFailureDetails(resultCode: prepare, db: db)
            )
        }
        defer { sqlite3_finalize(statement) }
        let step = sqlite3_step(statement)
        guard step == SQLITE_ROW else {
            throw SQLitePersistentStoreAdmissionError.pageLimitInstallationFailed(
                details: SQLiteFailureDetails(resultCode: step, db: db)
            )
        }
        return sqlite3_column_int64(statement, 0)
    }

    public static func measureFamily(_ mainPath: String) throws -> Int64 {
        var total: Int64 = 0
        var mainExists = false
        var sidecarExists = false
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = mainPath + suffix
            var info = stat()
            if lstat(path, &info) == 0 {
                guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
                      info.st_nlink == 1,
                      info.st_size >= 0 else {
                    throw SQLitePersistentStoreAdmissionError.unsafeFamilyMember(
                        path: path
                    )
                }
                if suffix.isEmpty { mainExists = true } else { sidecarExists = true }
                let (next, overflow) = total.addingReportingOverflow(Int64(info.st_size))
                guard !overflow else {
                    throw SQLitePersistentStoreAdmissionError.footprintLimit(
                        footprintBytes: Int64.max,
                        reserveBytes: 0,
                        maxFootprintBytes: Int64.max
                    )
                }
                total = next
            } else if errno != ENOENT {
                throw SQLitePersistentStoreAdmissionError.familyProbeFailed(
                    path: path,
                    systemErrno: errno
                )
            }
        }
        if sidecarExists && !mainExists {
            throw SQLitePersistentStoreAdmissionError.partialFamily(mainPath: mainPath)
        }
        return total
    }

    public static func mainFileExists(_ path: String) throws -> Bool {
        var info = stat()
        if lstat(path, &info) == 0 {
            guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
                  info.st_nlink == 1 else {
                throw SQLitePersistentStoreAdmissionError.unsafeFamilyMember(path: path)
            }
            return true
        }
        guard errno == ENOENT else {
            throw SQLitePersistentStoreAdmissionError.familyProbeFailed(
                path: path,
                systemErrno: errno
            )
        }
        return false
    }

    public static func measureMainFile(_ path: String) throws -> Int64 {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            throw SQLitePersistentStoreAdmissionError.familyProbeFailed(
                path: path,
                systemErrno: errno
            )
        }
        guard (UInt32(info.st_mode) & UInt32(S_IFMT)) == UInt32(S_IFREG),
              info.st_nlink == 1,
              info.st_size >= 0 else {
            throw SQLitePersistentStoreAdmissionError.unsafeFamilyMember(
                path: path
            )
        }
        return Int64(info.st_size)
    }

    public static func measureFreeSpace(_ path: String) throws -> Int64 {
        var info = statfs()
        guard statfs(path, &info) == 0 else {
            throw SQLitePersistentStoreAdmissionError.freeSpaceProbeFailed(
                path: path,
                systemErrno: errno
            )
        }
        let bytes = UInt64(info.f_bavail).multipliedReportingOverflow(
            by: UInt64(info.f_bsize)
        )
        guard !bytes.overflow else {
            throw SQLitePersistentStoreAdmissionError.freeSpaceProbeFailed(
                path: path,
                systemErrno: EOVERFLOW
            )
        }
        return Int64(clamping: bytes.partialValue)
    }
}
