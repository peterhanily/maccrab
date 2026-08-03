import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore

@Suite("Controlled SQLite checkpoints")
struct SQLiteControlledCheckpointTests {
    private final class Int64Box: @unchecked Sendable {
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
            self.value = value
            lock.unlock()
        }
    }

    private enum ProbeError: Error {
        case sqlite(code: Int32, message: String)
        case missingFile(String)
        case noRow(String)
    }

    private func tempDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(
            "controlled-checkpoint-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    private func openWriter(_ path: String) throws -> OpaquePointer {
        var database: OpaquePointer?
        let rc = SQLiteOpenPathPolicy.open(
            path,
            database: &database,
            flags: SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                | SQLITE_OPEN_FULLMUTEX
        )
        guard rc == SQLITE_OK, let database else {
            if let database { sqlite3_close(database) }
            throw ProbeError.sqlite(code: rc, message: "open writer")
        }
        return database
    }

    private func openReader(_ path: String) throws -> OpaquePointer {
        var database: OpaquePointer?
        let rc = SQLiteOpenPathPolicy.open(
            path,
            database: &database,
            flags: SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX
        )
        guard rc == SQLITE_OK, let database else {
            if let database { sqlite3_close(database) }
            throw ProbeError.sqlite(code: rc, message: "open reader")
        }
        return database
    }

    private func execute(_ sql: String, on database: OpaquePointer) throws {
        var message: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(database, sql, nil, nil, &message)
        let detail = message.map { String(cString: $0) }
            ?? String(cString: sqlite3_errmsg(database))
        sqlite3_free(message)
        guard rc == SQLITE_OK else {
            throw ProbeError.sqlite(code: rc, message: detail)
        }
    }

    private func scalar(
        _ sql: String,
        on database: OpaquePointer
    ) throws -> Int64 {
        var statement: OpaquePointer?
        let prepare = sqlite3_prepare_v2(database, sql, -1, &statement, nil)
        guard prepare == SQLITE_OK, let statement else {
            throw ProbeError.sqlite(
                code: prepare,
                message: String(cString: sqlite3_errmsg(database))
            )
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw ProbeError.noRow(sql)
        }
        return sqlite3_column_int64(statement, 0)
    }

    private func fileSize(_ path: String) throws -> Int64 {
        var metadata = stat()
        guard lstat(path, &metadata) == 0 else {
            throw ProbeError.missingFile(path)
        }
        return Int64(metadata.st_size)
    }

    private func install(
        on database: OpaquePointer,
        path: String,
        directory: URL,
        thresholdPages: Int32 = 1,
        free: Int64Box
    ) throws -> SQLiteControlledCheckpointController {
        try SQLiteControlledCheckpointController.install(
            on: database,
            thresholdPages: thresholdPages,
            families: [
                "main": SQLiteControlledCheckpointFamily(
                    databasePath: path,
                    storageVolumePath: directory.path,
                    freeSpaceFloorBytes: 1,
                    freeSpaceProbe: { _ in free.get() }
                ),
            ]
        )
    }

    @Test("Low-free deferral preserves COMMIT and final writer close preserves WAL")
    func lowFreeCommitAndWriterClose() throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("store.db").path
        var writer: OpaquePointer? = try openWriter(path)
        let handle = try #require(writer)
        let free = Int64Box(0)
        let controller = try install(
            on: handle,
            path: path,
            directory: directory,
            free: free
        )
        defer {
            if let writer {
                controller.detach(from: writer)
                sqlite3_close(writer)
            }
        }

        var closeCheckpointDisabled: Int32 = 0
        #expect(maccrab_sqlite_no_checkpoint_on_close(
            handle,
            &closeCheckpointDisabled
        ) == SQLITE_OK)
        #expect(closeCheckpointDisabled == 1)
        #expect(try scalar("PRAGMA wal_autocheckpoint", on: handle) == 0)

        try execute("PRAGMA journal_mode = WAL", on: handle)
        try execute(
            "CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)",
            on: handle
        )
        // The preceding DDL attempt arms one-commit backoff. This insert is
        // deliberately allowed to commit while checkpoint maintenance skips.
        try execute(
            "INSERT INTO records(value) VALUES ('durable')",
            on: handle
        )
        #expect(try scalar("SELECT COUNT(*) FROM records", on: handle) == 1)
        let snapshot = controller.snapshot()
        #expect(snapshot.admissionDeferralCount >= 1)
        #expect(snapshot.backoffSkipCount >= 1)
        #expect(snapshot.sqliteFailureCount == 0)

        let mainBeforeClose = try fileSize(path)
        let walBeforeClose = try fileSize(path + "-wal")
        #expect(walBeforeClose > 0)
        controller.detach(from: handle)
        #expect(controller.snapshot().active == false)
        #expect(sqlite3_close(handle) == SQLITE_OK)
        writer = nil

        #expect(try fileSize(path) == mainBeforeClose,
                "last controlled RW close must not move WAL frames to main")
        #expect(try fileSize(path + "-wal") == walBeforeClose,
                "last controlled RW close must not truncate/delete the WAL")

        let reader = try openReader(path)
        defer { sqlite3_close(reader) }
        #expect(try scalar("SELECT COUNT(*) FROM records", on: reader) == 1,
                "the successful insert must remain readable from retained WAL")
    }

    @Test("A read-only final connection cannot trigger the deferred close checkpoint")
    func readOnlyFinalClose() throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("store.db").path
        var writer: OpaquePointer? = try openWriter(path)
        let handle = try #require(writer)
        let free = Int64Box(0)
        let controller = try install(
            on: handle,
            path: path,
            directory: directory,
            free: free
        )
        defer {
            if let writer {
                controller.detach(from: writer)
                sqlite3_close(writer)
            }
        }

        try execute("PRAGMA journal_mode = WAL", on: handle)
        try execute("CREATE TABLE records(id INTEGER PRIMARY KEY)", on: handle)
        try execute("INSERT INTO records VALUES (1)", on: handle)

        var reader: OpaquePointer? = try openReader(path)
        defer { if let reader { sqlite3_close(reader) } }
        let readHandle = try #require(reader)
        #expect(try scalar("SELECT COUNT(*) FROM records", on: readHandle) == 1)

        let mainBeforeWriterClose = try fileSize(path)
        let walBeforeWriterClose = try fileSize(path + "-wal")
        controller.detach(from: handle)
        #expect(sqlite3_close(handle) == SQLITE_OK)
        writer = nil
        #expect(try fileSize(path) == mainBeforeWriterClose)
        #expect(try fileSize(path + "-wal") == walBeforeWriterClose)

        let mainBeforeReaderClose = try fileSize(path)
        let walBeforeReaderClose = try fileSize(path + "-wal")
        #expect(sqlite3_close(readHandle) == SQLITE_OK)
        reader = nil
        #expect(try fileSize(path) == mainBeforeReaderClose,
                "a read-only last connection must not checkpoint on close")
        #expect(try fileSize(path + "-wal") == walBeforeReaderClose,
                "a read-only last connection must leave deferred WAL intact")
    }

    @Test("Pinned-reader retry uses bounded commit backoff and recovers below a new threshold")
    func pinnedReaderBackoffRecovery() throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("store.db").path
        let writer = try openWriter(path)
        let free = Int64Box(Int64.max)
        let controller = try install(
            on: writer,
            path: path,
            directory: directory,
            thresholdPages: 4,
            free: free
        )
        defer {
            controller.detach(from: writer)
            sqlite3_close(writer)
        }

        try execute("PRAGMA journal_mode = WAL", on: writer)
        try execute(
            "CREATE TABLE records(id INTEGER PRIMARY KEY, value TEXT)",
            on: writer
        )
        try execute("INSERT INTO records VALUES (1, 'anchor')", on: writer)
        var logPages: Int32 = 0
        var checkpointedPages: Int32 = 0
        #expect(sqlite3_wal_checkpoint_v2(
            writer,
            nil,
            Int32(SQLITE_CHECKPOINT_TRUNCATE),
            &logPages,
            &checkpointedPages
        ) == SQLITE_OK)
        let attemptsBeforePin = controller.snapshot().attemptCount

        let reader = try openReader(path)
        defer { sqlite3_close(reader) }
        try execute("BEGIN", on: reader)
        #expect(try scalar("SELECT value = 'anchor' FROM records", on: reader) == 1)

        for value in 1...4 {
            try execute(
                "UPDATE records SET value = 'pinned-\(value)' WHERE id = 1",
                on: writer
            )
        }
        let pinned = controller.snapshot()
        #expect(pinned.attemptCount == attemptsBeforePin + 1)
        #expect(pinned.lastDisposition == .deferredPinnedReader)
        #expect(pinned.retryBackoffRemainingCommits == 1)

        try execute(
            "UPDATE records SET value = 'backoff-skip' WHERE id = 1",
            on: writer
        )
        let skipped = controller.snapshot()
        #expect(skipped.attemptCount == pinned.attemptCount)
        #expect(skipped.backoffSkipCount == pinned.backoffSkipCount + 1)
        #expect(skipped.retryBackoffRemainingCommits == 0)

        try execute("COMMIT", on: reader)
        try execute(
            "UPDATE records SET value = 'recovered' WHERE id = 1",
            on: writer
        )
        let recovered = controller.snapshot()
        #expect(recovered.attemptCount == pinned.attemptCount + 1)
        #expect(recovered.lastDisposition == .completed)
        #expect(recovered.retryBackoffRemainingCommits == 0)
        #expect(recovered.lastWalPages < 8,
                "recovery must not require another four-page threshold of growth")
    }

    @Test("Sustained low-free writes use saturating bounded retry and then recover")
    func sustainedLowFreeBackoff() throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("store.db").path
        let writer = try openWriter(path)
        let free = Int64Box(0)
        let controller = try install(
            on: writer,
            path: path,
            directory: directory,
            free: free
        )
        defer {
            controller.detach(from: writer)
            sqlite3_close(writer)
        }

        try execute("PRAGMA journal_mode = WAL", on: writer)
        try execute("CREATE TABLE records(id INTEGER PRIMARY KEY)", on: writer)
        let before = controller.snapshot()
        for id in 1...150 {
            try execute("INSERT INTO records VALUES (\(id))", on: writer)
        }
        let deferred = controller.snapshot()
        #expect(try scalar("SELECT COUNT(*) FROM records", on: writer) == 150,
                "checkpoint refusal must never false-fail a committed write")
        #expect(deferred.admissionDeferralCount > before.admissionDeferralCount)
        #expect(deferred.attemptCount - before.attemptCount < 12,
                "low free space must not run expensive probes on every commit")
        #expect(deferred.backoffSkipCount > 100)
        #expect(deferred.retryBackoffRemainingCommits
            <= SQLiteControlledCheckpointController.maximumRetryBackoffCommits)

        free.set(Int64.max)
        var recoveryCommits = 0
        while controller.snapshot().lastDisposition != .completed,
              recoveryCommits
                <= Int(SQLiteControlledCheckpointController
                    .maximumRetryBackoffCommits) {
            recoveryCommits += 1
            try execute(
                "INSERT INTO records VALUES (\(150 + recoveryCommits))",
                on: writer
            )
        }
        #expect(controller.snapshot().lastDisposition == .completed)
        #expect(recoveryCommits
            <= Int(SQLiteControlledCheckpointController
                .maximumRetryBackoffCommits) + 1)
    }

    @Test("Attached schemas use exact independent family gates")
    func attachedFamilyOwnership() throws {
        let directory = try tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let mainPath = directory.appendingPathComponent("main.db").path
        let auxiliaryPath = directory.appendingPathComponent("auxiliary.db").path
        let writer = try openWriter(mainPath)
        let mainFree = Int64Box(Int64.max)
        let auxiliaryFree = Int64Box(0)
        let controller = try install(
            on: writer,
            path: mainPath,
            directory: directory,
            free: mainFree
        )
        defer {
            controller.detach(from: writer)
            sqlite3_close(writer)
        }

        let escaped = SQLiteOpenPathPolicy.normalizedPath(auxiliaryPath)
            .replacingOccurrences(of: "'", with: "''")
        try execute("ATTACH DATABASE '\(escaped)' AS auxiliary", on: writer)
        try controller.updateFamily(
            schema: "auxiliary",
            configuration: SQLiteControlledCheckpointFamily(
                databasePath: auxiliaryPath,
                storageVolumePath: directory.path,
                freeSpaceFloorBytes: 1,
                freeSpaceProbe: { _ in auxiliaryFree.get() }
            )
        )
        try execute("PRAGMA auxiliary.journal_mode = WAL", on: writer)
        try execute(
            "CREATE TABLE auxiliary.records(id INTEGER PRIMARY KEY)",
            on: writer
        )
        let refused = controller.snapshot()
        #expect(refused.lastSchema == "auxiliary")
        #expect(refused.lastDisposition == .deferredAdmission)

        // Replacing the schema policy clears its old backoff and the actual
        // sqlite3_db_filename path must match before a PASSIVE checkpoint.
        try controller.updateFamily(
            schema: "auxiliary",
            configuration: SQLiteControlledCheckpointFamily(
                databasePath: mainPath,
                storageVolumePath: directory.path,
                freeSpaceFloorBytes: 0,
                freeSpaceProbe: { _ in Int64.max }
            )
        )
        try execute("INSERT INTO auxiliary.records VALUES (1)", on: writer)
        let mismatch = controller.snapshot()
        #expect(mismatch.lastSchema == "auxiliary")
        #expect(mismatch.lastDisposition == .databasePathMismatch)
        #expect(try scalar(
            "SELECT COUNT(*) FROM auxiliary.records",
            on: writer
        ) == 1, "path mismatch refusal must not roll back the committed row")

        auxiliaryFree.set(Int64.max)
        try controller.updateFamily(
            schema: "auxiliary",
            configuration: SQLiteControlledCheckpointFamily(
                databasePath: auxiliaryPath,
                storageVolumePath: directory.path,
                freeSpaceFloorBytes: 1,
                freeSpaceProbe: { _ in auxiliaryFree.get() }
            )
        )
        try execute("INSERT INTO auxiliary.records VALUES (2)", on: writer)
        let recovered = controller.snapshot()
        #expect(recovered.lastSchema == "auxiliary")
        #expect(recovered.lastDisposition == .completed)

        controller.removeFamily(schema: "auxiliary")
        try execute("INSERT INTO auxiliary.records VALUES (3)", on: writer)
        let unknown = controller.snapshot()
        #expect(unknown.lastSchema == "auxiliary")
        #expect(unknown.lastDisposition == .unknownAttachedFamily)
        #expect(try scalar(
            "SELECT COUNT(*) FROM auxiliary.records",
            on: writer
        ) == 3)
    }
}
