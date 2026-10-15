import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore

@Suite("Idle read-only SQLite certificate", .serialized)
struct SQLiteIdleReadCertificateTests {
    private func withReader(_ body: (OpaquePointer) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-idle-certificate-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("fixture.sqlite").path
        var writer: OpaquePointer?
        #expect(sqlite3_open(path, &writer) == SQLITE_OK)
        let writable = try #require(writer)
        #expect(sqlite3_exec(writable, "CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES(1),(2);",
                             nil, nil, nil) == SQLITE_OK)
        #expect(!SQLiteIdleReadCertificate.permitsRetention(writable, readOnly: false))
        #expect(!SQLiteIdleReadCertificate.permitsRetention(writable, readOnly: true),
                "A claimed read-only owner cannot certify a writable SQLite handle")
        #expect(sqlite3_close(writable) == SQLITE_OK)
        var reader: OpaquePointer?
        #expect(sqlite3_open_v2(path, &reader, SQLITE_OPEN_READONLY, nil) == SQLITE_OK)
        let readOnly = try #require(reader)
        defer { #expect(sqlite3_close(readOnly) == SQLITE_OK) }
        try body(readOnly)
    }

    @Test("An explicit transaction or busy implicit statement refuses retention")
    func transactionAndBusyStatement() throws {
        try withReader { db in
            #expect(SQLiteIdleReadCertificate.permitsRetention(db, readOnly: true))
            #expect(sqlite3_exec(db, "BEGIN DEFERRED; SELECT * FROM fixture;", nil, nil, nil) == SQLITE_OK)
            #expect(!SQLiteIdleReadCertificate.permitsRetention(db, readOnly: true))
            #expect(sqlite3_exec(db, "ROLLBACK", nil, nil, nil) == SQLITE_OK)
            var statement: OpaquePointer?
            #expect(sqlite3_prepare_v2(db, "SELECT value FROM fixture", -1, &statement, nil) == SQLITE_OK)
            let query = try #require(statement)
            defer { sqlite3_finalize(query) }
            #expect(sqlite3_step(query) == SQLITE_ROW)
            #expect(sqlite3_get_autocommit(db) != 0, "Autocommit alone cannot certify an implicit reader")
            #expect(!SQLiteIdleReadCertificate.permitsRetention(db, readOnly: true))
            #expect(sqlite3_step(query) == SQLITE_ROW)
            #expect(sqlite3_step(query) == SQLITE_DONE)
            #expect(SQLiteIdleReadCertificate.permitsRetention(db, readOnly: true))
        }
    }

    @Test("Missing handles and failed rollback leaving a transaction fail closed")
    func missingAndFailedCleanup() throws {
        #expect(!SQLiteIdleReadCertificate.permitsRetention(nil, readOnly: true))
        try withReader { db in
            #expect(sqlite3_exec(db, "BEGIN DEFERRED", nil, nil, nil) == SQLITE_OK)
            #expect(sqlite3_exec(db, "ROLLBACK invalid_syntax", nil, nil, nil) != SQLITE_OK)
            #expect(!SQLiteIdleReadCertificate.permitsRetention(db, readOnly: true))
            #expect(sqlite3_exec(db, "ROLLBACK", nil, nil, nil) == SQLITE_OK)
            #expect(SQLiteIdleReadCertificate.permitsRetention(db, readOnly: true))
        }
    }

    @Test("EventStore certifies only a nonretired reader and never changes retirement")
    func realEventStoreOwnership() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-idle-eventstore-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        let writer = try EventStore(directory: directory.path)
        #expect(await writer.permitsIdleReadOnlyRetention() == false)
        let reader = try EventStore(directory: directory.path, forceReadOnly: true)
        #expect(await reader.permitsIdleReadOnlyRetention())
        let snapshot = try await reader.exactEventsSnapshot(since: .distantPast, limit: 1)
        #expect(snapshot.isComplete)
        #expect(await reader.permitsIdleReadOnlyRetention())
        #expect(await writer.walCheckpointTruncate())
        reader.retireReadOnlyReads()
        #expect(await reader.permitsIdleReadOnlyRetention() == false)
        do {
            _ = try await reader.exactEventsSnapshot(since: .distantPast, limit: 1)
            Issue.record("A certificate unretired the reader")
        } catch is CancellationError { }
    }

    @Test("A moved SQLite backing file is not eligible even while its handle is idle")
    func movedBackingFile() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-idle-moved-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        do { _ = try EventStore(directory: directory.path) }
        let reader = try EventStore(directory: directory.path, forceReadOnly: true)
        defer { reader.retireReadOnlyReads() }
        #expect(await reader.permitsIdleReadOnlyRetention())
        let path = directory.appendingPathComponent("events.db")
        try FileManager.default.moveItem(at: path, to: directory.appendingPathComponent("original.sqlite"))
        #expect(await reader.permitsIdleReadOnlyRetention() == false)
        // The replacement is inert test data, never queried as a database.
        try Data("replacement fixture".utf8).write(to: path)
        #expect(await reader.permitsIdleReadOnlyRetention() == false)
    }
}
