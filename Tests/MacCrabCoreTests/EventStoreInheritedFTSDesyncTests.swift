import Foundation
import CSQLCipher
import Testing
@testable import MacCrabCore

/// Up to and including v1.21.5, `prune` and `pruneOldest` deleted FTS postings
/// and their content rows as two separate autocommit statements, in batches of
/// up to 100,000. Any interruption between them left the search index durably
/// disagreeing with `events`, and that release shipped no check that would ever
/// have noticed. v1.22.0 added an external-content integrity check on the
/// pre-producer boot path, which turned that inherited, previously-tolerated
/// state into a permanent refusal to start: the daemon exits, sysextd relaunches
/// it, it measures the same store, and nothing repairs it in between.
///
/// Measured before the fix, on a real 2,339-row v7 store with exactly one
/// posting removed: "event projection FTS external-content integrity check
/// failed", on every boot.
@Suite("Inherited FTS desync degrades search, never the boot")
struct EventStoreInheritedFTSDesyncTests {
    private func makeStore(at directory: URL) throws -> EventStore {
        try EventStore(path: directory.appendingPathComponent("events.db").path)
    }

    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("inherited-fts-desync-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false
        )
        return directory
    }

    private func event(_ name: String, at timestamp: Date) -> Event {
        Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: MacCrabCore.ProcessInfo(
                pid: 4242, ppid: 1, rpid: 1, name: name,
                executable: "/usr/bin/\(name)",
                commandLine: "/usr/bin/\(name) --desync-fixture",
                args: ["/usr/bin/\(name)", "--desync-fixture"],
                workingDirectory: "/", userId: 501, userName: "fixture",
                groupId: 20, startTime: timestamp, ancestors: [],
                isPlatformBinary: true
            ),
            severity: .informational
        )
    }

    /// Reproduces the interrupted-prune shape: postings removed, content rows
    /// retained. Uses its own handle, exactly as an external interruption would
    /// have left the file.
    private func orphanOnePosting(at path: String) throws {
        var handle: OpaquePointer?
        try #require(sqlite3_open_v2(
            path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK)
        let db = try #require(handle)
        defer { sqlite3_close(db) }
        try #require(sqlite3_exec(
            db,
            "DELETE FROM events_fts WHERE rowid IN (SELECT MIN(rowid) FROM events)",
            nil, nil, nil
        ) == SQLITE_OK)
    }

    private func integrityResultCode(at path: String) throws -> Int32 {
        var handle: OpaquePointer?
        try #require(sqlite3_open_v2(
            path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK)
        let db = try #require(handle)
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        try #require(sqlite3_prepare_v2(
            db,
            "INSERT INTO events_fts(events_fts, rank) VALUES('integrity-check', 1)",
            -1, &statement, nil
        ) == SQLITE_OK)
        let prepared = try #require(statement)
        defer { sqlite3_finalize(prepared) }
        return sqlite3_step(prepared)
    }

    @Test("A store whose search index disagrees with its events still starts")
    func inheritedDesyncDoesNotRefuseTheBoot() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let now = Date()

        let store = try makeStore(at: directory)
        for (index, name) in ["launchd", "sshd", "curl", "bash"].enumerated() {
            _ = try await store.insert(
                event: event(name, at: now.addingTimeInterval(Double(-index)))
            )
        }

        try orphanOnePosting(at: path)
        try #require(try integrityResultCode(at: path) == SQLITE_CORRUPT,
                     "fixture must actually desync the index")

        // Before the fix this threw decodingFailed and the daemon exited.
        let reopened = try makeStore(at: directory)
        let recovery = try await reopened.recoverJournalBeforeProducers()
        #expect(recovery.complete)
        // The repair ran, so the index agrees again and later FTS mutations on
        // this same boot (journal expiry's projection delete is the next one)
        // no longer fail.
        #expect(await reopened.projectionSearchIndexDegraded == false)
        #expect(try integrityResultCode(at: path) == SQLITE_DONE)
    }

    @Test("Search still finds the retained rows after the repair")
    func repairedIndexStillAnswersSearch() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let now = Date()

        let store = try makeStore(at: directory)
        for (index, name) in ["launchd", "sshd", "curl", "bash"].enumerated() {
            _ = try await store.insert(
                event: event(name, at: now.addingTimeInterval(Double(-index)))
            )
        }
        try orphanOnePosting(at: path)

        let reopened = try makeStore(at: directory)
        _ = try await reopened.recoverJournalBeforeProducers()
        // The orphaned posting belonged to the oldest row; a rebuild restores
        // it, so an interrupted prune does not silently cost a hunt result.
        let hits = try await reopened.searchSnapshot(text: "desync-fixture", limit: 50)
        #expect(hits.events.count == 4)
    }

    @Test("A healthy store is untouched and reports no degradation")
    func healthyStoreIsUnchanged() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path

        let store = try makeStore(at: directory)
        _ = try await store.insert(event: event("launchd", at: Date()))

        let reopened = try makeStore(at: directory)
        let recovery = try await reopened.recoverJournalBeforeProducers()
        #expect(recovery.complete)
        #expect(await reopened.projectionSearchIndexDegraded == false)
        #expect(try integrityResultCode(at: path) == SQLITE_DONE)
    }
}
