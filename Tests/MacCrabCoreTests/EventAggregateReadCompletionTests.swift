import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Aggregate query terminal status")
struct EventAggregateReadCompletionTests {
    /// A tiny, task-owned legacy aggregate substrate: no installed database,
    /// system configuration, executable fixture or network operation is used.
    private func fixture() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-aggregate-completion-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        do {
            var rawDatabase: OpaquePointer?
            let result = sqlite3_open(directory.appendingPathComponent("events.db").path, &rawDatabase)
            defer { if let rawDatabase { sqlite3_close(rawDatabase) } }
            try #require(result == SQLITE_OK)
            let database = try #require(rawDatabase)
            let sql = """
                PRAGMA journal_mode = WAL;
                CREATE TABLE event_aggregates (
                    day TEXT NOT NULL, event_category TEXT NOT NULL,
                    process_signer TEXT NOT NULL DEFAULT '',
                    process_path TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL,
                    PRIMARY KEY (day, event_category, process_signer, process_path)
                );
                INSERT INTO event_aggregates VALUES
                    ('2026-10-15', 'process', '', '/fixture/a', 7),
                    ('2026-10-15', 'file', '', '/fixture/b', 4),
                    ('2026-10-14', 'process', '', '/fixture/c', 2),
                    ('2026-10-13', 'network', '', '/fixture/d', 9);
                """
            try #require(sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK)
            return directory
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    @Test("Only DONE publishes a complete ordered and filtered aggregate result")
    func ordinaryResults() async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path, forceReadOnly: true)
        let all = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(all.map(\.processPath) == ["/fixture/a", "/fixture/b", "/fixture/c", "/fixture/d"])
        #expect(all.map(\.count) == [7, 4, 2, 9])
        let filtered = try await store.aggregates(sinceDay: "2026-10-14", category: .process)
        #expect(filtered.map(\.processPath) == ["/fixture/a", "/fixture/c"])
        let empty = try await store.aggregates(sinceDay: "9999-01-01")
        #expect(empty.isEmpty)
        let idle = await store.permitsIdleReadOnlyRetention()
        #expect(idle)
    }

    @Test("Real SQLite interruption after a decoded row prefix throws and leaves no read pin",
          arguments: [1, 2])
    func interruptedPrefix(prefix: Int) async throws {
        let directory = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try EventStore(directory: directory.path, forceReadOnly: true)
        await store.setAggregateReadInterruptAfterRowsForTesting(prefix)
        do {
            _ = try await store.aggregates(sinceDay: "2000-01-01")
            Issue.record("Interrupted aggregate query returned a successful prefix")
        } catch let error as EventStoreError {
            let details = try #require(SQLiteFailureClassifier.details(from: error))
            #expect(details.resultCode == SQLITE_INTERRUPT)
            #expect(details.extendedResultCode == SQLITE_INTERRUPT)
            guard case .sqliteFailure(let context, _, _, _, _) = error else {
                Issue.record("Aggregate read lost its SQLite error context")
                return
            }
            #expect(context == "aggregate query step")
        }
        let observed = await store.aggregateReadRowsObservedForTesting
        #expect(observed == prefix, "The failure must occur after actual decoded rows")
        let connection = try await store.storageAdmissionConnectionStateForTesting()
        #expect(!connection.inTransaction)
        let idle = await store.permitsIdleReadOnlyRetention()
        #expect(idle, "Finalization must release every statement/read transaction")
        // The interruption is one-shot; a fresh statement can read all rows.
        let recovered = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(recovered.map(\.count) == [7, 4, 2, 9])
    }
}
