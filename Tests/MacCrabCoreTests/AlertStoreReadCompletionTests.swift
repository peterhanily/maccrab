import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

@Suite("Alert query terminal status")
struct AlertStoreReadCompletionTests {
    private func withStatement(_ body: (OpaquePointer, OpaquePointer) throws -> Void) throws {
        var database: OpaquePointer?
        try #require(sqlite3_open(":memory:", &database) == SQLITE_OK)
        let db = try #require(database)
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        try #require(sqlite3_prepare_v2(db, "SELECT 1 UNION ALL SELECT 2", -1, &statement, nil) == SQLITE_OK)
        let stmt = try #require(statement)
        defer { sqlite3_finalize(stmt) }
        try body(db, stmt)
    }

    @Test("Only DONE completes the real SQLite cursor")
    func rowThenDone() throws {
        try withStatement { db, stmt in
            var rows: [Int32] = []
            while try AlertQueryReadStep.advance(statement: stmt, database: db) {
                rows.append(sqlite3_column_int(stmt, 0))
            }
            #expect(rows == [1, 2])
        }
    }

    @Test("A failure after a row prefix cannot return partial success", arguments: [SQLITE_BUSY, SQLITE_IOERR, SQLITE_INTERRUPT, SQLITE_ERROR])
    func failureAfterPrefix(result: Int32) throws {
        try withStatement { _, stmt in
            var steps = 0
            func read() throws -> [Int32] {
                var rows: [Int32] = []
                while try AlertQueryReadStep.advance(statement: stmt, database: nil, step: { _ in
                    steps += 1
                    return steps == 1 ? SQLITE_ROW : result
                }) { rows.append(1) }
                return rows
            }
            do {
                _ = try read()
                Issue.record("A failed cursor returned a successful prefix")
            } catch let error as AlertStoreError {
                let details = try #require(SQLiteFailureClassifier.details(from: error))
                #expect(details.resultCode == result && details.extendedResultCode == result)
                #expect(details.systemErrno == 0 && steps == 2)
            }
        }
    }

    @Test("A real interrupted SQLite cursor retains failure metadata before finalization")
    func realInterruptAfterRow() throws {
        try withStatement { db, stmt in
            #expect(try AlertQueryReadStep.advance(statement: stmt, database: db))
            sqlite3_progress_handler(db, 1, { _ in 1 }, nil)
            defer { sqlite3_progress_handler(db, 0, nil, nil) }
            do {
                _ = try AlertQueryReadStep.advance(statement: stmt, database: db)
                Issue.record("Interrupted cursor was treated as completed")
            } catch let error as AlertStoreError {
                let details = try #require(SQLiteFailureClassifier.details(from: error))
                #expect(details.resultCode == SQLITE_INTERRUPT)
                #expect(details.extendedResultCode == SQLITE_INTERRUPT)
            }
        }
    }

    @Test("Cancellation is checked before issuing the next SQLite step")
    func cancellationDoesNotStep() async throws {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try withStatement { _, stmt in
                var steps = 0
                do {
                    _ = try AlertQueryReadStep.advance(statement: stmt, database: nil, step: { _ in
                        steps += 1
                        return SQLITE_DONE
                    })
                    Issue.record("Cancelled cursor produced success")
                } catch is CancellationError {
                    #expect(steps == 0)
                }
            }
        }
        try await task.value
    }

    @Test("Ordinary store queries retain empty, ordered, bounded read behavior")
    func normalStoreQueries() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("MacCrabAlertReadCompletion-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        #expect(try await store.alerts(since: .distantPast, limit: 5).isEmpty)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        for index in 0..<3 {
            try await store.insert(alert: Alert(id: "ordinary-\(index)",
                timestamp: base.addingTimeInterval(Double(index)),
                ruleId: "ordinary.fixture", ruleTitle: "ordinary metadata", severity: .low,
                eventId: UUID().uuidString))
        }
        let rows = try await store.alerts(since: base, limit: 2)
        #expect(rows.map(\.id) == ["ordinary-2", "ordinary-1"])
    }
}
