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
@Suite("Inherited FTS repair and durable search degradation")
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

    private func refuseRepair(on store: EventStore, freeBytes: Int64 = 16 * 1_048_576) async throws {
        try await store.setStorageAdmissionProbesForTesting(
            footprint: { _ in 1_048_576 }, freeSpace: { _ in freeBytes }
        )
    }

    private func restoreCapacity(on store: EventStore) async throws {
        try await store.setStorageAdmissionProbesForTesting(
            footprint: { try SQLitePersistentStoreAdmission.measureFamily($0) },
            freeSpace: { try SQLitePersistentStoreAdmission.measureFreeSpace($0) }
        )
    }

    private func scalar(at path: String, sql: String) throws -> String? {
        var handle: OpaquePointer?
        try #require(sqlite3_open_v2(
            path, &handle, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK)
        let db = try #require(handle)
        defer { sqlite3_close(db) }
        var rawStatement: OpaquePointer?
        try #require(sqlite3_prepare_v2(db, sql, -1, &rawStatement, nil) == SQLITE_OK)
        let statement = try #require(rawStatement)
        defer { sqlite3_finalize(statement) }
        let rc = sqlite3_step(statement)
        guard rc != SQLITE_DONE else { return nil }
        try #require(rc == SQLITE_ROW)
        return sqlite3_column_text(statement, 0).map { String(cString: $0) }
    }

    @Test("Refused repair preserves all typed matches and marks both old and new readers incomplete")
    func refusedRepairIsVisibleAcrossReaders() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try makeStore(at: directory)
        _ = try await store.recoverJournalBeforeProducers()
        let now = Date()
        for name in ["launchd", "sshd", "curl", "bash"] {
            _ = try await store.insert(event: event(name, at: now))
        }
        let oldReader = try EventStore(path: path, forceReadOnly: true)
        #expect(try await oldReader.searchSnapshot(
            text: "desync-fixture", since: now, until: Date()
        ).isComplete)
        try orphanOnePosting(at: path)
        try await refuseRepair(on: store)
        #expect(try await store.recoverJournalBeforeProducers().complete)
        try await restoreCapacity(on: store)

        #expect(try integrityResultCode(at: path) == SQLITE_CORRUPT)
        let reason = try #require(try scalar(at: path,
            sql: "SELECT reason FROM event_projection_search_degradation"))
        #expect(!reason.isEmpty)
        #expect(reason.contains("bytes free"))
        #expect(try scalar(at: path,
            sql: "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('events_ai','events_au')") == "0")
        let newReader = try EventStore(path: path, forceReadOnly: true)
        for reader in [store, oldReader, newReader] {
            let snapshot = try await reader.searchSnapshot(
                text: "desync-fixture", since: now, until: Date()
            )
            #expect(snapshot.events.count == 4)
            #expect(snapshot.searchIndexDegraded)
            #expect(!snapshot.isComplete)
            #expect(snapshot.projectionOmitted == 0)
            #expect(snapshot.gaps.total == 0)
            await #expect(throws: EventStoreError.self) {
                _ = try await reader.containsProjectedFTSMatch(
                    text: "desync-fixture", since: now, until: Date()
                )
            }
            await #expect(throws: EventStoreError.self) {
                _ = try await reader.search(text: "missing", since: now, until: Date())
            }
        }
    }

    @Test("Degraded FTS cannot break expiry or subsequent journal ingestion")
    func refusedRepairAllowsExpiryAndIngestion() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try makeStore(at: directory)
        _ = try await store.recoverJournalBeforeProducers()
        let original = event("launchd", at: Date())
        _ = try await store.insert(event: original)
        try orphanOnePosting(at: path)
        try await refuseRepair(on: store)
        #expect(try await store.recoverJournalBeforeProducers().complete)
        try await restoreCapacity(on: store)
        #expect(await store.mergeFTS() == false)
        #expect(await store.optimizeFTS() == false)
        #expect(try await store.recoverExhaustedFTSIndexIfNeeded() == false)
        #expect(try await store.expireJournalBlocks(
            retainedThrough: Date().addingTimeInterval(3600)
        ) == 1)
        let fresh = event("sshd", at: Date())
        _ = try await store.insert(event: fresh)
        let snapshot = try await store.searchSnapshot(text: "desync-fixture")
        #expect(snapshot.events.map(\.id) == [fresh.id])
        #expect(snapshot.searchIndexDegraded)
        #expect(!snapshot.isComplete)
        #expect(try await store.exactEventSnapshot(id: fresh.id).event?.id == fresh.id)
    }

    @Test("A persisted degraded interval survives reopen and verified repair restores existing readers and triggers")
    func degradedReopenThenVerifiedRepair() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        var store: EventStore? = try makeStore(at: directory)
        _ = try await store!.recoverJournalBeforeProducers()
        _ = try await store!.insert(event: event("launchd", at: Date()))
        try orphanOnePosting(at: path)
        try await refuseRepair(on: store!)
        #expect(try await store!.recoverJournalBeforeProducers().complete)
        store = nil

        let reader = try EventStore(path: path, forceReadOnly: true)
        let reopened = try makeStore(at: directory)
        // Startup must not recreate FTS triggers before a rebuild commits.
        #expect(try scalar(at: path,
            sql: "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('events_ai','events_au')") == "0")
        try await refuseRepair(on: reopened)
        #expect(try await reopened.recoverJournalBeforeProducers().complete)
        #expect(try await reader.searchSnapshot(text: "desync-fixture").searchIndexDegraded)
        try await restoreCapacity(on: reopened)
        #expect(try await reopened.recoverJournalBeforeProducers().complete)
        #expect(try scalar(at: path,
            sql: "SELECT COUNT(*) FROM sqlite_schema WHERE name='event_projection_search_degradation'") == "0")
        #expect(try scalar(at: path,
            sql: "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('events_ai','events_au')") == "2")
        #expect(try integrityResultCode(at: path) == SQLITE_DONE)
        #expect(try await reader.searchSnapshot(text: "desync-fixture").searchIndexDegraded == false)
        // New rows prove triggers are active after recovery, not just that the
        // previously missing posting was restored by the rebuild.
        let fresh = event("sshd", at: Date())
        _ = try await reopened.insert(event: fresh)
        #expect(try await reader.containsProjectedFTSMatch(
            text: "sshd", since: .distantPast, until: Date()
        ))
        #expect(try integrityResultCode(at: path) == SQLITE_DONE)
    }

    @Test("If the durable fallback cannot be admitted, recovery preserves its original failure")
    func refusedDegradationDoesNotClaimRecovery() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("events.db").path
        let store = try makeStore(at: directory)
        _ = try await store.recoverJournalBeforeProducers()
        _ = try await store.insert(event: event("launchd", at: Date()))
        try orphanOnePosting(at: path)
        try await refuseRepair(on: store, freeBytes: 0)
        await #expect(throws: SQLitePersistentStoreAdmissionError.self) {
            _ = try await store.recoverJournalBeforeProducers()
        }
        #expect(await store.projectionSearchIndexDegraded == false)
        #expect(try scalar(at: path,
            sql: "SELECT COUNT(*) FROM sqlite_schema WHERE name='event_projection_search_degradation'") == "0")
        #expect(try scalar(at: path,
            sql: "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('events_ai','events_au')") == "2")
        try await restoreCapacity(on: store)
        #expect(try await store.recoverJournalBeforeProducers().complete)
        #expect(try integrityResultCode(at: path) == SQLITE_DONE)
    }

}
