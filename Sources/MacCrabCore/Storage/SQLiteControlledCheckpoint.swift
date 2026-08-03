import Foundation
import CSQLCipher

public typealias SQLiteControlledCheckpointProbe = @Sendable (String) -> Int64?

/// The exact policy and probes for one SQLite schema on a writable handle.
/// `expectedDatabasePath` prevents a later ATTACH under a reused schema name
/// from inheriting another database's floor or injected probes.
public struct SQLiteControlledCheckpointFamily: Sendable {
    public let expectedDatabasePath: String
    public let storageVolumePath: String
    public let freeSpaceFloorBytes: Int64
    let footprintProbe: SQLiteControlledCheckpointProbe
    let freeSpaceProbe: SQLiteControlledCheckpointProbe

    public init(
        databasePath: String,
        storageVolumePath: String,
        freeSpaceFloorBytes: Int64,
        footprintProbe: SQLiteControlledCheckpointProbe? = nil,
        freeSpaceProbe: SQLiteControlledCheckpointProbe? = nil
    ) {
        self.expectedDatabasePath = SQLiteOpenPathPolicy.normalizedPath(
            databasePath
        )
        self.storageVolumePath = storageVolumePath
        self.freeSpaceFloorBytes = max(0, freeSpaceFloorBytes)
        self.footprintProbe = footprintProbe ?? { path in
            try? SQLitePersistentStoreAdmission.measureFamily(path)
        }
        self.freeSpaceProbe = freeSpaceProbe ?? { path in
            try? SQLitePersistentStoreAdmission.measureFreeSpace(path)
        }
    }

    public init(
        databasePath: String,
        policy: SQLitePersistentStorePolicy,
        footprintProbe: SQLiteControlledCheckpointProbe? = nil,
        freeSpaceProbe: SQLiteControlledCheckpointProbe? = nil
    ) {
        self.init(
            databasePath: databasePath,
            storageVolumePath: policy.storageVolumePath,
            freeSpaceFloorBytes: policy.freeSpaceFloorBytes,
            footprintProbe: footprintProbe,
            freeSpaceProbe: freeSpaceProbe
        )
    }
}

public enum SQLiteControlledCheckpointDisposition: String, Sendable,
    Equatable {
    case neverAttempted
    case completed
    case deferredAdmission
    case deferredPinnedReader
    case sqliteFailure
    case unknownAttachedFamily
    case databasePathMismatch
}

public struct SQLiteControlledCheckpointSnapshot: Sendable, Equatable {
    public let thresholdPages: Int32
    public let attemptCount: UInt64
    public let backoffSkipCount: UInt64
    public let completedCount: UInt64
    public let admissionDeferralCount: UInt64
    public let pinnedReaderDeferralCount: UInt64
    public let sqliteFailureCount: UInt64
    public let lastDisposition: SQLiteControlledCheckpointDisposition
    public let lastSchema: String?
    public let lastWalPages: Int32
    public let lastCheckpointedPages: Int32
    public let retryBackoffRemainingCommits: UInt32
    public let active: Bool
}

public enum SQLiteControlledCheckpointSetupError: Error, LocalizedError,
    Equatable {
    case invalidThreshold(Int32)
    case invalidSchemaName(String)
    case ownershipConfigurationFailed(Int32)

    public var errorDescription: String? {
        switch self {
        case .invalidThreshold(let pages):
            return "controlled SQLite checkpoint threshold must be positive (got \(pages))"
        case .invalidSchemaName(let schema):
            return "invalid SQLite checkpoint schema name: \(schema)"
        case .ownershipConfigurationFailed(let rc):
            return "could not disable SQLite automatic/close checkpointing (rc=\(rc))"
        }
    }
}

/// Owns the one WAL hook allowed on a SQLite connection. SQLite invokes the
/// hook synchronously after COMMIT and after releasing the writer lock. At the
/// configured page threshold this controller freshly measures the *actual*
/// schema file, complete family, and f_bavail before issuing PASSIVE.
///
/// Every hook return is SQLITE_OK. A refused, pinned, or failed checkpoint is
/// maintenance state after a durable commit; propagating it would falsely tell
/// the caller that the already-committed insert failed and invite duplicates.
public final class SQLiteControlledCheckpointController: @unchecked Sendable {
    public static let defaultThresholdPages: Int32 = 1_000
    /// A deferred family is re-probed after at most this many later commits.
    /// Commit-count backoff avoids a probe on every firehose write while still
    /// recovering after a reader/floor clears without demanding another full
    /// threshold of WAL growth.
    public static let maximumRetryBackoffCommits: UInt32 = 64

    private struct Counters {
        var attempts: UInt64 = 0
        var backoffSkips: UInt64 = 0
        var completed: UInt64 = 0
        var admissionDeferrals: UInt64 = 0
        var pinnedDeferrals: UInt64 = 0
        var sqliteFailures: UInt64 = 0
        var lastDisposition: SQLiteControlledCheckpointDisposition =
            .neverAttempted
        var lastSchema: String?
        var lastWalPages: Int32 = 0
        var lastCheckpointedPages: Int32 = 0
        var retryBackoffRemainingCommits: UInt32 = 0
    }

    private struct RetryState {
        var remainingCommits: UInt32 = 0
        var nextDelayCommits: UInt32 = 1
    }

    private struct AttemptResult {
        let disposition: SQLiteControlledCheckpointDisposition
        let logPages: Int32
        let checkpointedPages: Int32
    }

    private let condition = NSCondition()
    private let thresholdPages: Int32
    private var database: OpaquePointer?
    private var families: [String: SQLiteControlledCheckpointFamily]
    private var retryStates: [String: RetryState] = [:]
    private var counters = Counters()
    private var active = true
    private var activeCallbacks = 0

    private init(
        database: OpaquePointer,
        thresholdPages: Int32,
        families: [String: SQLiteControlledCheckpointFamily]
    ) {
        self.database = database
        self.thresholdPages = thresholdPages
        self.families = families
    }

    public static func install(
        on database: OpaquePointer,
        thresholdPages: Int32,
        families: [String: SQLiteControlledCheckpointFamily]
    ) throws -> SQLiteControlledCheckpointController {
        guard thresholdPages > 0 else {
            throw SQLiteControlledCheckpointSetupError.invalidThreshold(
                thresholdPages
            )
        }
        for schema in families.keys {
            guard validSchemaName(schema) else {
                throw SQLiteControlledCheckpointSetupError.invalidSchemaName(
                    schema
                )
            }
        }
        let rc = maccrab_sqlite_take_checkpoint_ownership(database)
        guard rc == SQLITE_OK else {
            throw SQLiteControlledCheckpointSetupError
                .ownershipConfigurationFailed(rc)
        }
        let controller = SQLiteControlledCheckpointController(
            database: database,
            thresholdPages: thresholdPages,
            families: families
        )
        // maccrab_sqlite_take_checkpoint_ownership() deliberately removes
        // SQLite's default autocheckpoint hook. SQLite exposes no supported
        // way to query an arbitrary previous callback, so production enforces
        // this controller as the sole hook owner with a source-census test.
        _ = sqlite3_wal_hook(
            database,
            sqliteControlledCheckpointWalHook,
            Unmanaged.passUnretained(controller).toOpaque()
        )
        return controller
    }

    /// Replace a policy atomically. Used when SIGHUP changes a floor and when
    /// an attached database is registered before the first write to it.
    public func updateFamily(
        schema: String,
        configuration: SQLiteControlledCheckpointFamily
    ) throws {
        guard Self.validSchemaName(schema) else {
            throw SQLiteControlledCheckpointSetupError.invalidSchemaName(schema)
        }
        condition.lock()
        families[schema] = configuration
        retryStates.removeValue(forKey: schema)
        if counters.lastSchema == schema {
            counters.retryBackoffRemainingCommits = 0
        }
        condition.unlock()
    }

    public func removeFamily(schema: String) {
        condition.lock()
        families.removeValue(forKey: schema)
        retryStates.removeValue(forKey: schema)
        if counters.lastSchema == schema {
            counters.retryBackoffRemainingCommits = 0
        }
        condition.unlock()
    }

    /// Unregister the unretained hook context and wait out any callback before
    /// the caller closes SQLite or releases this controller.
    public func detach(from database: OpaquePointer) {
        condition.lock()
        active = false
        condition.unlock()

        _ = sqlite3_wal_hook(database, nil, nil)

        condition.lock()
        while activeCallbacks > 0 {
            condition.wait()
        }
        self.database = nil
        condition.unlock()
    }

    public func snapshot() -> SQLiteControlledCheckpointSnapshot {
        condition.lock()
        defer { condition.unlock() }
        return SQLiteControlledCheckpointSnapshot(
            thresholdPages: thresholdPages,
            attemptCount: counters.attempts,
            backoffSkipCount: counters.backoffSkips,
            completedCount: counters.completed,
            admissionDeferralCount: counters.admissionDeferrals,
            pinnedReaderDeferralCount: counters.pinnedDeferrals,
            sqliteFailureCount: counters.sqliteFailures,
            lastDisposition: counters.lastDisposition,
            lastSchema: counters.lastSchema,
            lastWalPages: counters.lastWalPages,
            lastCheckpointedPages: counters.lastCheckpointedPages,
            retryBackoffRemainingCommits:
                counters.retryBackoffRemainingCommits,
            active: active
        )
    }

    fileprivate func handleCommit(
        database callbackDatabase: OpaquePointer,
        schema: String,
        walPages: Int32
    ) -> Int32 {
        condition.lock()
        guard active, database == callbackDatabase else {
            condition.unlock()
            return SQLITE_OK
        }
        guard walPages >= thresholdPages else {
            retryStates.removeValue(forKey: schema)
            condition.unlock()
            return SQLITE_OK
        }
        var retry = retryStates[schema] ?? RetryState()
        if retry.remainingCommits > 0 {
            retry.remainingCommits -= 1
            retryStates[schema] = retry
            Self.saturatingIncrement(&counters.backoffSkips)
            counters.lastSchema = schema
            counters.lastWalPages = walPages
            counters.retryBackoffRemainingCommits = retry.remainingCommits
            condition.unlock()
            return SQLITE_OK
        }
        activeCallbacks += 1
        let family = families[schema]
        condition.unlock()

        let result = attemptCheckpoint(
            database: callbackDatabase,
            schema: schema,
            walPages: walPages,
            family: family
        )

        condition.lock()
        Self.saturatingIncrement(&counters.attempts)
        counters.lastDisposition = result.disposition
        counters.lastSchema = schema
        counters.lastWalPages = result.logPages
        counters.lastCheckpointedPages = result.checkpointedPages
        switch result.disposition {
        case .completed:
            Self.saturatingIncrement(&counters.completed)
            retryStates.removeValue(forKey: schema)
            counters.retryBackoffRemainingCommits = 0
        case .deferredAdmission, .unknownAttachedFamily,
             .databasePathMismatch:
            Self.saturatingIncrement(&counters.admissionDeferrals)
            scheduleRetry(for: schema)
        case .deferredPinnedReader:
            Self.saturatingIncrement(&counters.pinnedDeferrals)
            scheduleRetry(for: schema)
        case .sqliteFailure:
            Self.saturatingIncrement(&counters.sqliteFailures)
            scheduleRetry(for: schema)
        case .neverAttempted:
            break
        }
        activeCallbacks -= 1
        if activeCallbacks == 0 { condition.broadcast() }
        condition.unlock()

        // The transaction is already durable. Never turn checkpoint
        // maintenance into a false insert/COMMIT failure.
        return SQLITE_OK
    }

    private func attemptCheckpoint(
        database: OpaquePointer,
        schema: String,
        walPages: Int32,
        family: SQLiteControlledCheckpointFamily?
    ) -> AttemptResult {
        guard let family else {
            return AttemptResult(
                disposition: .unknownAttachedFamily,
                logPages: walPages,
                checkpointedPages: 0
            )
        }
        let actualPath: String? = schema.withCString { name in
            guard let raw = sqlite3_db_filename(database, name) else {
                return nil
            }
            return String(cString: raw)
        }
        guard let actualPath else {
            return AttemptResult(
                disposition: .deferredAdmission,
                logPages: walPages,
                checkpointedPages: 0
            )
        }
        let normalizedActual = SQLiteOpenPathPolicy.normalizedPath(actualPath)
        guard normalizedActual == family.expectedDatabasePath else {
            return AttemptResult(
                disposition: .databasePathMismatch,
                logPages: walPages,
                checkpointedPages: 0
            )
        }
        guard let main = try? SQLitePersistentStoreAdmission.measureMainFile(
            normalizedActual
        ),
              let footprint = family.footprintProbe(normalizedActual),
              let free = family.freeSpaceProbe(family.storageVolumePath) else {
            return AttemptResult(
                disposition: .deferredAdmission,
                logPages: walPages,
                checkpointedPages: 0
            )
        }
        let admission = SQLitePersistentStoreAdmission
            .checkpointAdmissionSnapshot(
                mainFileBytes: main,
                familyFootprintBytes: footprint,
                freeSpaceBytes: free,
                freeSpaceFloorBytes: family.freeSpaceFloorBytes
            )
        guard admission.admitted else {
            return AttemptResult(
                disposition: .deferredAdmission,
                logPages: walPages,
                checkpointedPages: 0
            )
        }

        var logPages: Int32 = 0
        var checkpointedPages: Int32 = 0
        let rc = schema.withCString { name in
            sqlite3_wal_checkpoint_v2(
                database,
                name,
                Int32(SQLITE_CHECKPOINT_PASSIVE),
                &logPages,
                &checkpointedPages
            )
        }
        let frameGap = logPages >= 0
            && checkpointedPages >= 0
            && logPages > checkpointedPages
        if rc == SQLITE_BUSY || rc == SQLITE_LOCKED || frameGap {
            return AttemptResult(
                disposition: .deferredPinnedReader,
                logPages: logPages,
                checkpointedPages: checkpointedPages
            )
        }
        guard rc == SQLITE_OK else {
            return AttemptResult(
                disposition: .sqliteFailure,
                logPages: logPages,
                checkpointedPages: checkpointedPages
            )
        }
        return AttemptResult(
            disposition: .completed,
            logPages: logPages,
            checkpointedPages: checkpointedPages
        )
    }

    private static func validSchemaName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        return name.unicodeScalars.allSatisfy {
            CharacterSet.alphanumerics
                .union(CharacterSet(charactersIn: "_"))
                .contains($0)
        }
    }

    /// Called with `condition` held after a real attempt. Delay doubles per
    /// family but is permanently bounded, so a released pin/floor is retried
    /// on a later commit even if WAL growth since the deferral is tiny.
    private func scheduleRetry(for schema: String) {
        var retry = retryStates[schema] ?? RetryState()
        retry.remainingCommits = retry.nextDelayCommits
        if retry.nextDelayCommits < Self.maximumRetryBackoffCommits {
            retry.nextDelayCommits = min(
                Self.maximumRetryBackoffCommits,
                retry.nextDelayCommits * 2
            )
        }
        retryStates[schema] = retry
        counters.retryBackoffRemainingCommits = retry.remainingCommits
    }

    private static func saturatingIncrement(_ value: inout UInt64) {
        if value < UInt64.max { value += 1 }
    }
}

private func sqliteControlledCheckpointWalHook(
    context: UnsafeMutableRawPointer?,
    database: OpaquePointer?,
    schemaName: UnsafePointer<CChar>?,
    walPages: Int32
) -> Int32 {
    guard let context, let database, let schemaName else { return SQLITE_OK }
    let controller = Unmanaged<SQLiteControlledCheckpointController>
        .fromOpaque(context)
        .takeUnretainedValue()
    return controller.handleCommit(
        database: database,
        schema: String(cString: schemaName),
        walPages: walPages
    )
}
