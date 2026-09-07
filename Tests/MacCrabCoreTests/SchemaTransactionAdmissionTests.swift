import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore

@Suite("Serialized schema admission")
struct SchemaTransactionAdmissionTests {
    private final class Bytes: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: Int64
        init(_ value: Int64) { storage = value }
        var value: Int64 {
            get { lock.lock(); defer { lock.unlock() }; return storage }
            set { lock.lock(); defer { lock.unlock() }; storage = newValue }
        }
    }

    private func withDatabase(_ body: (OpaquePointer) throws -> Void) throws {
        var raw: OpaquePointer?
        #expect(sqlite3_open(":memory:", &raw) == SQLITE_OK)
        let db = try #require(raw)
        defer { sqlite3_close(db) }
        try body(db)
    }

    @Test("Schema work uses its complete budget without increasing ordinary reserves")
    func separateBudget() throws {
        try withDatabase { db in
            let mib: Int64 = 1_048_576
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: ":memory:",
                policy: SQLitePersistentStorePolicy(
                    maxFootprintBytes: 128 * mib,
                    freeSpaceFloorBytes: 16 * mib,
                    transactionReserveBytes: 32 * mib,
                    storageVolumePath: NSTemporaryDirectory()
                ),
                footprintProbe: { _ in mib },
                freeSpaceProbe: { _ in 128 * mib }
            )
            #expect(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK)
            defer { sqlite3_exec(db, "ROLLBACK", nil, nil, nil) }
            try admission.admitSerializedSchemaWrite(
                estimatedTransactionBytes: 48 * mib, on: db
            )
            #expect(admission.policy.transactionReserveBytes == 32 * mib)
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.admitSerializedWrite(
                    estimatedTransactionBytes: 48 * mib, maintenance: true, on: db
                )
            }
        }
    }

    @Test("Schema admission remeasures both cap and free-space floor under the lock")
    func freshBoundaries() throws {
        try withDatabase { db in
            let footprint = Bytes(100)
            let free = Bytes(600)
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: ":memory:",
                policy: SQLitePersistentStorePolicy(
                    maxFootprintBytes: 600, freeSpaceFloorBytes: 100,
                    transactionReserveBytes: 50, storageVolumePath: NSTemporaryDirectory()
                ),
                footprintProbe: { _ in footprint.value },
                freeSpaceProbe: { _ in free.value }
            )
            #expect(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK)
            defer { sqlite3_exec(db, "ROLLBACK", nil, nil, nil) }
            try admission.admitSerializedSchemaWrite(estimatedTransactionBytes: 500, on: db)
            free.value = 599
            #expect(throws: SQLitePersistentStoreAdmissionError.lowFreeSpace(
                freeBytes: 599, floorBytes: 100, reserveBytes: 500, requiredFreeBytes: 600
            )) {
                try admission.admitSerializedSchemaWrite(estimatedTransactionBytes: 500, on: db)
            }
            free.value = 600
            footprint.value = 101
            #expect(throws: SQLitePersistentStoreAdmissionError.footprintLimit(
                footprintBytes: 101, reserveBytes: 500, maxFootprintBytes: 600
            )) {
                try admission.admitSerializedSchemaWrite(estimatedTransactionBytes: 500, on: db)
            }
            footprint.value = 100
            try admission.admitSerializedSchemaWrite(estimatedTransactionBytes: 500, on: db)
        }
    }

    @Test("Schema admission requires the writer lock and rejects unbounded estimates")
    func serializedOnly() throws {
        try withDatabase { db in
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: ":memory:",
                policy: SQLitePersistentStorePolicy(
                    maxFootprintBytes: 1_000, freeSpaceFloorBytes: 100,
                    transactionReserveBytes: 50, storageVolumePath: NSTemporaryDirectory()
                ), footprintProbe: { _ in 100 }, freeSpaceProbe: { _ in 1_000 }
            )
            #expect(throws: SQLitePersistentStoreAdmissionError.schemaTransactionNotSerialized) {
                try admission.admitSerializedSchemaWrite(estimatedTransactionBytes: 100, on: db)
            }
            #expect(sqlite3_exec(db, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK)
            defer { sqlite3_exec(db, "ROLLBACK", nil, nil, nil) }
            #expect(throws: SQLitePersistentStoreAdmissionError.self) {
                try admission.admitSerializedSchemaWrite(estimatedTransactionBytes: Int64.max, on: db)
            }
        }
    }
}
