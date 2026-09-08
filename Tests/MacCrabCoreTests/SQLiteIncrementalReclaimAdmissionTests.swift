import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore

@Suite("Strict pre-transition incremental reclaim admission")
struct SQLiteIncrementalReclaimAdmissionTests {
    private final class Probe: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Int64
        init(_ value: Int64) { self.value = value }
        func get() -> Int64 {
            lock.lock()
            defer { lock.unlock() }
            return value
        }
        func set(_ value: Int64) {
            lock.lock()
            defer { lock.unlock() }
            self.value = value
        }
    }

    private func execute(_ db: OpaquePointer, _ sql: String) throws {
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        guard rc == SQLITE_OK else {
            throw NSError(domain: "SQLiteIncrementalReclaimFixture", code: Int(rc))
        }
    }

    private func scalar(_ db: OpaquePointer, _ sql: String) throws -> Int64 {
        var statement: OpaquePointer?
        let rc = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard rc == SQLITE_OK, let statement else {
            sqlite3_finalize(statement)
            throw NSError(domain: "SQLiteIncrementalReclaimFixture", code: Int(rc))
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw NSError(domain: "SQLiteIncrementalReclaimFixture", code: -1)
        }
        return sqlite3_column_int64(statement, 0)
    }

    private func fixture(_ body: (OpaquePointer, String) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("strict-incremental-reclaim-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        var handle: OpaquePointer?
        let rc = sqlite3_open(path, &handle)
        guard rc == SQLITE_OK, let handle else {
            if let handle { sqlite3_close(handle) }
            throw NSError(domain: "SQLiteIncrementalReclaimFixture", code: Int(rc))
        }
        defer { sqlite3_close(handle) }
        try execute(handle, """
            PRAGMA auto_vacuum = INCREMENTAL;
            PRAGMA journal_mode = WAL;
            CREATE TABLE retained(id INTEGER PRIMARY KEY, evidence BLOB NOT NULL);
            INSERT INTO retained VALUES(1, X'010203');
            INSERT INTO retained VALUES(2, zeroblob(2097152));
            DELETE FROM retained WHERE id = 2;
            PRAGMA user_version = 6;
            PRAGMA wal_checkpoint(TRUNCATE);
            """)
        try body(handle, path)
    }

    @Test("Actual bounded reclaim preserves a row while the lower page ceiling remains deferred")
    func pendingPageLimitDoesNotBlockStrictReclaim() throws {
        try fixture { db, path in
            let original = try SQLitePersistentStoreAdmission.measureFamily(path)
            let policy = SQLitePersistentStorePolicy(
                maxFootprintBytes: original + 1_048_576,
                freeSpaceFloorBytes: 0,
                transactionReserveBytes: 1_572_864,
                storageVolumePath: (path as NSString).deletingLastPathComponent
            )
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: path, policy: policy, latchOperationalPressure: true
            )
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.installPageLimit(on: db)
            }
            #expect(admission.pageLimitPending)
            #expect(admission.growthBlocked)
            let beforePages = try scalar(db, "PRAGMA page_count")
            let beforeFreelist = try scalar(db, "PRAGMA freelist_count")
            let pageSize = try scalar(db, "PRAGMA page_size")
            let plan = SQLitePersistentStoreAdmission.boundedIncrementalReclaimPlan(
                requestedPages: 4, pageCount: beforePages, pageSizeBytes: pageSize,
                budgetBytes: 480 * 1_024,
                workspaceBytes: Int64(EventJournalCodec.maximumWorkspaceBytes)
            )
            #expect(plan.pages > 0)
            #expect(plan.estimatedTransactionBytes <= 480 * 1_024)
            var powersafe: Int32 = -1
            #expect(sqlite3_file_control(db, "main", SQLITE_FCNTL_POWERSAFE_OVERWRITE, &powersafe) == SQLITE_OK)
            #expect(powersafe == 1)
            try execute(db, "PRAGMA cache_spill = OFF")
            var currentSpills: Int32 = 0
            var highSpills: Int32 = 0
            #expect(sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_SPILL, &currentSpills, &highSpills, 1) == SQLITE_OK)
            try execute(db, "BEGIN IMMEDIATE")
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.admitSerializedSchemaWrite(
                    estimatedTransactionBytes: plan.estimatedTransactionBytes, on: db
                )
            }
            try admission.admitSerializedIncrementalReclaim(
                estimatedTransactionBytes: plan.estimatedTransactionBytes, on: db
            )
            let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: plan.pages)
            #expect(result.pagesReclaimed > 0)
            #expect(result.pagesReclaimed <= plan.pages)
            try execute(db, "COMMIT")
            #expect(sqlite3_db_status(db, SQLITE_DBSTATUS_CACHE_SPILL, &currentSpills, &highSpills, 0) == SQLITE_OK)
            #expect(currentSpills == 0)
            let withWAL = try SQLitePersistentStoreAdmission.measureFamily(path)
            #expect(withWAL <= original + plan.estimatedTransactionBytes)
            #expect(withWAL <= policy.maxFootprintBytes)
            try execute(db, "PRAGMA wal_checkpoint(TRUNCATE)")
            #expect(try scalar(db, "PRAGMA page_count") < beforePages)
            #expect(try scalar(db, "PRAGMA freelist_count") < beforeFreelist)
            #expect(try scalar(db, "SELECT COUNT(*) FROM retained WHERE id=1 AND hex(evidence)='010203'") == 1)
            #expect(try scalar(db, "PRAGMA user_version") == 6)
            #expect(try SQLitePersistentStoreAdmission.measureFamily(path) < original)
            // A small committed shrink does not pretend the still-impossible
            // lower page ceiling has already been installed.
            #expect(admission.pageLimitPending)
            #expect(admission.growthBlocked)
        }
    }

    @Test("Strict reclaim retains the full cap, free-space floor and transaction reserve")
    func strictBudgetsRemainAuthoritative() throws {
        try fixture { db, path in
            let actual = try SQLitePersistentStoreAdmission.measureFamily(path)
            let cap = actual + 1_048_576
            let floor: Int64 = 65_536
            let reserve: Int64 = 524_288
            let footprint = Probe(actual)
            let free = Probe(floor + reserve * 4)
            let policy = SQLitePersistentStorePolicy(
                maxFootprintBytes: cap, freeSpaceFloorBytes: floor,
                transactionReserveBytes: reserve,
                storageVolumePath: (path as NSString).deletingLastPathComponent
            )
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: path, policy: policy,
                footprintProbe: { _ in footprint.get() },
                freeSpaceProbe: { _ in free.get() }
            )
            #expect(throws: SQLitePersistentStoreAdmissionError.schemaTransactionNotSerialized) {
                try admission.admitSerializedIncrementalReclaim(estimatedTransactionBytes: 1, on: db)
            }
            try execute(db, "BEGIN IMMEDIATE")
            footprint.set(cap - 4_096)
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.admitSerializedIncrementalReclaim(estimatedTransactionBytes: 8_192, on: db)
            }
            footprint.set(actual)
            free.set(floor + 4_096)
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.admitSerializedIncrementalReclaim(estimatedTransactionBytes: 8_192, on: db)
            }
            free.set(floor + reserve * 4)
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.admitSerializedIncrementalReclaim(estimatedTransactionBytes: reserve + 1, on: db)
            }
            try admission.admitSerializedIncrementalReclaim(estimatedTransactionBytes: 8_192, on: db)
            try execute(db, "ROLLBACK")
            #expect(try scalar(db, "SELECT COUNT(*) FROM retained") == 1)
        }
    }

    @Test("Reclaim planning refuses unsupported occupancy and bounds pointer-map and dirty-page workspace")
    func plannerBoundsOccupancyAndMemory() {
        let workspace = Int64(EventJournalCodec.maximumWorkspaceBytes)
        let plan = SQLitePersistentStoreAdmission.boundedIncrementalReclaimPlan(
            requestedPages: 200_000, pageCount: 102_400, pageSizeBytes: 4_096,
            budgetBytes: 10 * 1_024 * 1_024, workspaceBytes: workspace
        )
        #expect(plan.pages > 0 && plan.pages <= 128)
        #expect(plan.estimatedTransactionBytes <= 10 * 1_024 * 1_024)
        #expect(plan.workspaceBytes <= workspace)
        for invalidPageSize in [Int64(0), 511, 1_000, 131_072] {
            #expect(SQLitePersistentStoreAdmission.boundedIncrementalReclaimPlan(
                requestedPages: 128, pageCount: 102_400, pageSizeBytes: invalidPageSize,
                budgetBytes: 10 * 1_024 * 1_024, workspaceBytes: workspace
            ).pages == 0)
        }
        #expect(SQLitePersistentStoreAdmission.boundedIncrementalReclaimPlan(
            requestedPages: 128, pageCount: 102_400, pageSizeBytes: 4_096,
            budgetBytes: 10 * 1_024 * 1_024, workspaceBytes: 1_024
        ).pages == 0)
        #expect(SQLitePersistentStoreAdmission.boundedIncrementalReclaimPlan(
            requestedPages: 128, pageCount: Int64.max, pageSizeBytes: 4_096,
            budgetBytes: 10 * 1_024 * 1_024, workspaceBytes: workspace
        ).pages == 0)
    }
}
