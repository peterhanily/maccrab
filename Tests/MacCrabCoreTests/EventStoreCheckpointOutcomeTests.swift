import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

@Suite("EventStore typed startup checkpoint outcomes")
struct EventStoreCheckpointOutcomeTests {
    private enum FixtureError: Error { case sqlite(Int32) }

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw FixtureError.sqlite(result) }
    }

    private func withDatabase(_ body: (OpaquePointer, String) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-checkpoint-outcome-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        var opened: OpaquePointer?
        let rc = sqlite3_open_v2(path, &opened,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
        guard rc == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(rc)
        }
        defer { sqlite3_close(db) }
        try execute("PRAGMA journal_mode=WAL", on: db)
        // The private fixture reports contention immediately; production keeps
        // its existing SQLite busy timeout. No elapsed-time race is needed.
        sqlite3_busy_timeout(db, 0)
        try execute("CREATE TABLE ordinary_records (value INTEGER)", on: db)
        try execute("INSERT INTO ordinary_records VALUES (1)", on: db)
        try body(db, path)
    }

    @Test("An ordinary active reader reports contention; release permits a complete truncate")
    func readerContentionAndRelease() throws {
        try withDatabase { writer, path in
            let initial = try EventStore.truncateCheckpoint(on: writer, admit: {})
            try initial.requireTruncated(context: "fixture initial checkpoint")
            var opened: OpaquePointer?
            let rc = sqlite3_open_v2(path, &opened, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
            guard rc == SQLITE_OK, let reader = opened else {
                if let opened { sqlite3_close(opened) }
                throw FixtureError.sqlite(rc)
            }
            defer { sqlite3_close(reader) }
            try execute("BEGIN", on: reader)
            defer { sqlite3_exec(reader, "ROLLBACK", nil, nil, nil) }
            var statement: OpaquePointer?
            #expect(sqlite3_prepare_v2(reader, "SELECT value FROM ordinary_records", -1, &statement, nil) == SQLITE_OK)
            let read = try #require(statement)
            defer { if let statement { sqlite3_finalize(statement) } }
            #expect(sqlite3_step(read) == SQLITE_ROW)
            #expect(sqlite3_column_int(read, 0) == 1)
            // The active statement/transaction establishes the old snapshot
            // before the second connection commits its ordinary row.
            try execute("INSERT INTO ordinary_records VALUES (2)", on: writer)
            let blocked = try EventStore.truncateCheckpoint(on: writer, admit: {})
            #expect(blocked.retryableContention)
            #expect(!blocked.truncated)
            #expect(blocked.failure.resultCode & 0xff == SQLITE_BUSY)
            #expect(!blocked.connectionInTransaction)
            #expect(blocked.duration >= .zero)
            do {
                try blocked.requireTruncated(context: "fixture recovery boundary")
                Issue.record("active reader checkpoint unexpectedly accepted")
            } catch let error as EventStoreError {
                guard case let .busy(message, failure) = error else { throw error }
                #expect(failure == blocked.failure)
                #expect(message.contains("checkpoint contention"))
                #expect(!message.contains("reader-pinned"))
            }
            sqlite3_finalize(read)
            statement = nil
            try execute("ROLLBACK", on: reader)
            let completed = try EventStore.truncateCheckpoint(on: writer, admit: {})
            try completed.requireTruncated(context: "fixture released reader")
            #expect(completed.failure.resultCode == SQLITE_OK)
            #expect(completed.logFrames == 0)
            #expect(completed.checkpointedFrames == 0)
            var count: OpaquePointer?
            #expect(sqlite3_prepare_v2(writer, "SELECT COUNT(*), SUM(value) FROM ordinary_records", -1, &count, nil) == SQLITE_OK)
            let countStatement = try #require(count)
            defer { sqlite3_finalize(countStatement) }
            #expect(sqlite3_step(countStatement) == SQLITE_ROW)
            #expect(sqlite3_column_int(countStatement, 0) == 2)
            #expect(sqlite3_column_int(countStatement, 1) == 3)
        }
    }

    @Test("Checkpoint admission refusal and probe failure preserve their original category")
    func admissionFailurePreserved() throws {
        try withDatabase { writer, path in
            let policy = SQLitePersistentStorePolicy(
                maxFootprintBytes: 64 * 1_048_576, freeSpaceFloorBytes: 128,
                transactionReserveBytes: 1_048_576,
                storageVolumePath: (path as NSString).deletingLastPathComponent)
            var admission = try SQLitePersistentStoreAdmission(
                databasePath: path, policy: policy, latchOperationalPressure: true,
                freeSpaceProbe: { _ in 0 })
            let walPath = path + "-wal"
            let before = try Data(contentsOf: URL(fileURLWithPath: walPath))
            do {
                _ = try EventStore.truncateCheckpoint(on: writer) { _ = try admission.admitCheckpoint() }
                Issue.record("checkpoint ran despite refused headroom")
            } catch let error as SQLitePersistentStoreAdmissionError {
                guard case let .lowFreeSpace(free, floor, _, _) = error else { throw error }
                #expect(free == 0)
                #expect(floor == 128)
                #expect(!error.localizedDescription.contains("reader"))
            }
            let probeError = SQLitePersistentStoreAdmissionError.freeSpaceProbeFailed(
                path: "fixture-volume", systemErrno: EIO)
            do {
                _ = try EventStore.truncateCheckpoint(on: writer) { throw probeError }
                Issue.record("checkpoint ran after a failed admission probe")
            } catch let error as SQLitePersistentStoreAdmissionError {
                #expect(error == probeError)
            }
            #expect(try Data(contentsOf: URL(fileURLWithPath: walPath)) == before)
        }
    }

    @Test("Checkpoint classification preserves non-contention SQLite failures and unknown frame state")
    func typedClassification() throws {
        func observation(_ rc: Int32, log: Int32 = -1, copied: Int32 = -1) -> EventStore.WALCheckpointObservation {
            .init(failure: .init(resultCode: rc, extendedResultCode: rc, systemErrno: 0),
                  logFrames: log, checkpointedFrames: copied, duration: .zero,
                  connectionInTransaction: false)
        }
        for rc in [SQLITE_BUSY, SQLITE_LOCKED] {
            #expect(observation(rc).retryableContention)
        }
        let undrained = observation(SQLITE_OK, log: 5, copied: 3)
        #expect(undrained.retryableContention)
        #expect(!undrained.truncated)
        // Copied frames do not establish a successful TRUNCATE when SQLite
        // explicitly reports BUSY; the existing boundary remains strict.
        #expect(!observation(SQLITE_BUSY, log: 5, copied: 5).truncated)
        let io = observation(SQLITE_IOERR)
        #expect(!io.retryableContention)
        do {
            try io.requireTruncated(context: "fixture IO result")
            Issue.record("SQLite IO failure was accepted")
        } catch let error as EventStoreError {
            guard case let .sqliteFailure(_, _, rc, extended, _) = error else { throw error }
            #expect(rc == SQLITE_IOERR)
            #expect(extended == SQLITE_IOERR)
        }
        do {
            try observation(SQLITE_OK).requireTruncated(context: "fixture unknown frame state")
            Issue.record("unknown checkpoint frame state was accepted")
        } catch let error as EventStoreError {
            guard case .storageNotReady = error else { throw error }
        }
    }
}
