// EventStoreMaintenanceCheckpointTests.swift
// v1.22.1: pins the non-waiting maintenance checkpoint.
//
// An installed upgrade rehearsal recorded two WAL TRUNCATE checkpoints
// returning SQLITE_BUSY after ~5.4 s each — the writer actor's full
// `PRAGMA busy_timeout = 5000` — while the `-wal` sidecar was well under its
// 64 MiB limit. The previous gate asked `walBytes > 64 MiB`, which
// cannot see a pinned WAL that is still small, so it discarded the checkpoint's
// actual result and went on to more reclaim and a second blocked checkpoint.
//
// These tests pin both halves of the repair: an OPTIONAL maintenance checkpoint
// must not spend the writer's busy timeout on a reader, and its contention must
// surface as a deferral rather than a throw. A small WAL is deliberate — that is
// the case the size heuristic missed.

import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

@Suite("EventStore maintenance checkpoint deferral")
struct EventStoreMaintenanceCheckpointTests {
    private enum FixtureError: Error { case sqlite(Int32) }

    /// A deliberately shortened stand-in for production's `busy_timeout = 5000`
    /// (EventStore.openDatabase). Short enough to keep the waiting comparison
    /// under two seconds, long enough that a checkpoint which honours it is
    /// unmistakable next to one that does not. The RATIO is what these tests
    /// assert, so the shorter fixture value proves the same property.
    private static let fixtureBusyTimeoutMilliseconds: Int32 = 1_500

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw FixtureError.sqlite(result) }
    }

    private func openReader(at path: String) throws -> OpaquePointer {
        var opened: OpaquePointer?
        let rc = sqlite3_open_v2(
            path, &opened, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        )
        guard rc == SQLITE_OK, let reader = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(rc)
        }
        return reader
    }

    private func walBytes(for databasePath: String) -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(
            atPath: databasePath + "-wal"
        )
        return (attrs?[.size] as? UInt64).map(Int64.init) ?? 0
    }

    private func fixtureEvent(at timestamp: Date, action: String) -> Event {
        Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .creation,
            eventAction: action,
            process: ProcessInfo(
                pid: 123, ppid: 1, rpid: 1,
                name: "tool", executable: "/usr/bin/tool",
                commandLine: "/usr/bin/tool", args: ["/usr/bin/tool"],
                workingDirectory: "/tmp",
                userId: 501, userName: "tester", groupId: 20,
                startTime: timestamp, exitCode: nil, codeSignature: nil,
                ancestors: [], architecture: "arm64", isPlatformBinary: false
            ),
            severity: .informational
        )
    }

    private func currentBusyTimeout(on db: OpaquePointer) throws -> Int32 {
        var raw: OpaquePointer?
        defer { sqlite3_finalize(raw) }
        guard sqlite3_prepare_v2(db, "PRAGMA busy_timeout", -1, &raw, nil) == SQLITE_OK,
              let statement = raw,
              sqlite3_step(statement) == SQLITE_ROW else {
            throw FixtureError.sqlite(sqlite3_errcode(db))
        }
        return Int32(sqlite3_column_int64(statement, 0))
    }

    private func withDatabase(
        _ body: (OpaquePointer, String) throws -> Void
    ) throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-maintenance-checkpoint-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        var opened: OpaquePointer?
        let rc = sqlite3_open_v2(
            path, &opened,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil
        )
        guard rc == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(rc)
        }
        defer { sqlite3_close(db) }
        try execute("PRAGMA journal_mode=WAL", on: db)
        // Unlike EventStoreCheckpointOutcomeTests, this fixture keeps a REAL
        // busy timeout. The regression is precisely that an optional checkpoint
        // used to spend it.
        sqlite3_busy_timeout(db, Self.fixtureBusyTimeoutMilliseconds)
        try execute("CREATE TABLE ordinary_records (value INTEGER)", on: db)
        try execute("INSERT INTO ordinary_records VALUES (1)", on: db)
        try body(db, path)
    }

    @Test("A reader with a small WAL defers a maintenance checkpoint without spending the busy timeout")
    func nonWaitingCheckpointDefersPromptly() throws {
        try withDatabase { writer, path in
            try EventStore.truncateCheckpoint(on: writer, admit: {})
                .requireTruncated(context: "fixture initial checkpoint")

            let reader = try openReader(at: path)
            defer { sqlite3_close(reader) }
            try execute("BEGIN", on: reader)
            var released = false
            defer { if !released { sqlite3_exec(reader, "ROLLBACK", nil, nil, nil) } }
            var statement: OpaquePointer?
            #expect(sqlite3_prepare_v2(
                reader, "SELECT value FROM ordinary_records", -1, &statement, nil
            ) == SQLITE_OK)
            let read = try #require(statement)
            defer { if statement != nil { sqlite3_finalize(read) } }
            #expect(sqlite3_step(read) == SQLITE_ROW)

            // The reader's snapshot now predates this commit, so the WAL cannot
            // be truncated — while staying a few KB, far below the 64 MiB limit
            // the old gate compared against.
            try execute("INSERT INTO ordinary_records VALUES (2)", on: writer)
            let sidecar = walBytes(for: path)
            #expect(sidecar > 0, "the fixture must actually hold WAL frames")
            #expect(sidecar < 64 * 1_024 * 1_024,
                    "the regression is a PINNED WAL that is still SMALL")

            let deferred = try EventStore.truncateCheckpoint(
                on: writer, waitForReaders: false, admit: {}
            )
            #expect(!deferred.truncated)
            #expect(deferred.retryableContention)
            #expect(deferred.failure.resultCode & 0xff == SQLITE_BUSY)
            // The whole point: SQLITE_BUSY arrived without burning the writer's
            // busy timeout. The installed rehearsal spent ~5.4 s here, twice.
            #expect(deferred.duration < .milliseconds(
                Int(Self.fixtureBusyTimeoutMilliseconds) / 3
            ), "an optional checkpoint must not wait for a reader")
            // A non-waiting checkpoint is a DEFERRAL, not a fault: the value
            // `walCheckpointTruncateForMaintenance` maps to `.deferredContention`
            // has to pass the shared validity check without throwing.
            try deferred.requireValidOutcome(context: "fixture maintenance checkpoint")
            // The connection must be handed back at its configured timeout, or
            // every ordinary write after this one silently stops waiting.
            #expect(try currentBusyTimeout(on: writer)
                    == Self.fixtureBusyTimeoutMilliseconds)

            sqlite3_finalize(read)
            statement = nil
            try execute("ROLLBACK", on: reader)
            released = true

            // Once the reader releases, the same non-waiting call completes.
            let completed = try EventStore.truncateCheckpoint(
                on: writer, waitForReaders: false, admit: {}
            )
            try completed.requireTruncated(context: "fixture released reader")
            #expect(completed.failure.resultCode == SQLITE_OK)
            #expect(try currentBusyTimeout(on: writer)
                    == Self.fixtureBusyTimeoutMilliseconds)
        }
    }

    @Test("A required checkpoint still honours the configured busy timeout")
    func waitingCheckpointStillWaits() throws {
        try withDatabase { writer, path in
            try EventStore.truncateCheckpoint(on: writer, admit: {})
                .requireTruncated(context: "fixture initial checkpoint")

            let reader = try openReader(at: path)
            defer { sqlite3_close(reader) }
            try execute("BEGIN", on: reader)
            defer { sqlite3_exec(reader, "ROLLBACK", nil, nil, nil) }
            var statement: OpaquePointer?
            #expect(sqlite3_prepare_v2(
                reader, "SELECT value FROM ordinary_records", -1, &statement, nil
            ) == SQLITE_OK)
            let read = try #require(statement)
            defer { sqlite3_finalize(read) }
            #expect(sqlite3_step(read) == SQLITE_ROW)
            try execute("INSERT INTO ordinary_records VALUES (2)", on: writer)

            // Startup and recovery boundaries are REQUIRED to drain, so they
            // keep the retry policy the fix deliberately did not touch.
            let waited = try EventStore.truncateCheckpoint(on: writer, admit: {})
            #expect(!waited.truncated)
            #expect(waited.retryableContention)
            #expect(waited.duration >= .milliseconds(
                Int(Self.fixtureBusyTimeoutMilliseconds) / 2
            ), "a required checkpoint must still retry for its busy timeout")
        }
    }

    @Test("The sweep's maintenance API reports contention as a deferral, not a throw")
    func maintenanceAPIDefersOnContention() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-maintenance-api-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let store = try EventStore(directory: directory.path)
        let databasePath = directory.appendingPathComponent("events.db").path
        for index in 0..<32 {
            try await store.insert(event: fixtureEvent(
                at: Date(timeIntervalSince1970: 1_000 + Double(index)),
                action: "maintenance-checkpoint-fixture"
            ))
        }
        #expect(try await store.walCheckpointTruncateForMaintenance() == .truncated)

        let reader = try openReader(at: databasePath)
        defer { sqlite3_close(reader) }
        try execute("BEGIN", on: reader)
        var released = false
        defer { if !released { sqlite3_exec(reader, "ROLLBACK", nil, nil, nil) } }
        var statement: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            reader, "SELECT COUNT(*) FROM events", -1, &statement, nil
        ) == SQLITE_OK)
        let read = try #require(statement)
        defer { if statement != nil { sqlite3_finalize(read) } }
        #expect(sqlite3_step(read) == SQLITE_ROW)

        // Commit behind the reader's snapshot so the WAL is genuinely pinned.
        try await store.insert(event: fixtureEvent(
            at: Date(timeIntervalSince1970: 2_000),
            action: "maintenance-checkpoint-pin"
        ))
        #expect(walBytes(for: databasePath) < 64 * 1_024 * 1_024)

        // `.deferredContention` is what makes the sweep return early instead of
        // reclaiming into a WAL it cannot drain.
        #expect(try await store.walCheckpointTruncateForMaintenance()
                == .deferredContention)

        sqlite3_finalize(read)
        statement = nil
        try execute("ROLLBACK", on: reader)
        released = true
        #expect(try await store.walCheckpointTruncateForMaintenance() == .truncated)
    }
}
