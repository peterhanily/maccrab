import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

/// Bundled SQLite only, with a fresh in-memory database per test. No EventStore
/// startup, installed database, collector, process, or network is involved.
@Suite("Projection DBSTAT ownership and bounded tree selection")
struct EventStoreProjectionDBStatTests {
    private enum FixtureError: Error { case sqlite(Int32), invalidResult, invalidPlan }

    /// Independent pre-optimization SQL, retained as a differential oracle.
    private static let originalSQL = """
        SELECT COALESCE(SUM(pgsize), 0)
        FROM dbstat
        WHERE name = 'events'
           OR name LIKE 'events_fts%'
           OR name IN (
                SELECT name FROM sqlite_master
                WHERE type = 'index' AND tbl_name = 'events'
           )
        """

    private func execute(_ sql: String, on db: OpaquePointer) throws {
        let result = sqlite3_exec(db, sql, nil, nil, nil)
        guard result == SQLITE_OK else { throw FixtureError.sqlite(result) }
    }

    private func prepared(_ sql: String, on db: OpaquePointer) throws -> OpaquePointer {
        var statement: OpaquePointer?
        let result = sqlite3_prepare_v2(db, sql, -1, &statement, nil)
        guard result == SQLITE_OK, let statement else {
            if let statement { sqlite3_finalize(statement) }
            throw FixtureError.sqlite(result)
        }
        return statement
    }

    private func scalar(_ sql: String, on db: OpaquePointer, name: String? = nil) throws -> Int64 {
        let statement = try prepared(sql, on: db)
        defer { sqlite3_finalize(statement) }
        if let name {
            let result = name.withCString {
                sqlite3_bind_text(statement, 1, $0, -1,
                    unsafeBitCast(-1, to: sqlite3_destructor_type.self))
            }
            guard result == SQLITE_OK else { throw FixtureError.sqlite(result) }
        }
        let result = sqlite3_step(statement)
        guard result == SQLITE_ROW else { throw FixtureError.sqlite(result) }
        guard sqlite3_column_type(statement, 0) == SQLITE_INTEGER else {
            throw FixtureError.invalidResult
        }
        let value = sqlite3_column_int64(statement, 0)
        let terminal = sqlite3_step(statement)
        guard terminal == SQLITE_DONE else { throw FixtureError.sqlite(terminal) }
        return value
    }

    private func bytes(_ name: String, on db: OpaquePointer) throws -> Int64 {
        try scalar("SELECT COALESCE(SUM(pgsize), 0) FROM dbstat WHERE name = ?1",
                   on: db, name: name)
    }

    private func withDatabase(_ body: (OpaquePointer) throws -> Void) throws {
        var opened: OpaquePointer?
        let result = sqlite3_open_v2(":memory:", &opened,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nil)
        guard result == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(result)
        }
        defer { sqlite3_close(db) }
        try execute("PRAGMA page_size = 4096; PRAGMA temp_store = MEMORY", on: db)
        try body(db)
    }

    private func seedProjection(on db: OpaquePointer) throws {
        try execute("""
            CREATE TABLE events (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE INDEX idx_events_payload ON events(payload);
            CREATE VIRTUAL TABLE events_fts USING fts5(payload);
            WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n + 1 FROM rows WHERE n < 32)
            INSERT INTO events SELECT printf('inert-%03d', n), printf('ordinary fixture row %d', n) FROM rows;
            INSERT INTO events_fts(payload) SELECT payload FROM events;
            """, on: db)
    }

    private func assertDifferential(on db: OpaquePointer) throws -> Int64 {
        let original = try scalar(Self.originalSQL, on: db)
        let optimized = try scalar(EventStore.projectionPhysicalBytesSQL, on: db)
        #expect(optimized == original)
        return optimized
    }

    @Test("Missing projection and unrelated trees still account for exactly zero")
    func emptyAndUnrelated() throws {
        try withDatabase { db in
            let empty = try assertDifferential(on: db)
            #expect(empty == 0)
            try execute("CREATE TABLE unrelated(payload BLOB); INSERT INTO unrelated VALUES(zeroblob(8192))", on: db)
            let unrelated = try assertDifferential(on: db)
            #expect(unrelated == 0)
        }
    }

    @Test("Every owned tree, LIKE wildcard/case behavior, and overlapping index are preserved")
    func exactMembershipAndLikeCompatibility() throws {
        try withDatabase { db in
            try seedProjection(on: db)
            try execute("""
                CREATE TABLE eventsXfts_compat(value TEXT);
                CREATE TABLE EVENTS_FTS_UPPER(value TEXT);
                CREATE TABLE eventsfts_not_a_match(value TEXT);
                CREATE TABLE unrelated(value TEXT);
                CREATE INDEX events_fts_overlap ON events(payload, id);
                CREATE VIEW events_fts_view AS SELECT payload FROM events;
                """, on: db)
            let ownedNames = [
                "events", "sqlite_autoindex_events_1", "idx_events_payload",
                "events_fts_data", "events_fts_idx", "events_fts_content",
                "events_fts_docsize", "events_fts_config", "events_fts_overlap",
                "eventsXfts_compat", "EVENTS_FTS_UPPER",
            ]
            var expected: Int64 = 0
            for name in ownedNames {
                let allocation = try bytes(name, on: db)
                #expect(allocation > 0)
                expected += allocation
            }
            let actual = try assertDifferential(on: db)
            #expect(actual == expected)
            let viewBytes = try bytes("events_fts_view", on: db)
            #expect(viewBytes == 0)
            let nonmatchingBytes = try bytes("eventsfts_not_a_match", on: db)
            #expect(nonmatchingBytes > 0)

            // Do not silently replace LIKE with a literal-prefix/GLOB rule.
            // The same configured LIKE behavior must apply to both queries.
            try execute("PRAGMA case_sensitive_like = ON", on: db)
            let uppercaseBytes = try bytes("EVENTS_FTS_UPPER", on: db)
            let caseSensitive = try assertDifferential(on: db)
            #expect(caseSensitive == expected - uppercaseBytes)
        }
    }

    @Test("Current schema inventory follows index creation/removal without duplicate charging")
    func dynamicIndexOwnership() throws {
        try withDatabase { db in
            try seedProjection(on: db)
            let initial = try assertDifferential(on: db)
            try execute("CREATE INDEX events_fts_new_index ON events(id, payload)", on: db)
            let newIndex = try bytes("events_fts_new_index", on: db)
            #expect(newIndex > 0)
            let added = try assertDifferential(on: db)
            #expect(added == initial + newIndex)
            try execute("DROP INDEX events_fts_new_index", on: db)
            let removed = try assertDifferential(on: db)
            #expect(removed == initial)
        }
    }

    private func dbstatPlanBits(_ sql: String, on db: OpaquePointer) throws -> [UInt] {
        let statement = try prepared("EXPLAIN QUERY PLAN " + sql, on: db)
        defer { sqlite3_finalize(statement) }
        var plans: [UInt] = []
        while true {
            let result = sqlite3_step(statement)
            if result == SQLITE_DONE { return plans }
            guard result == SQLITE_ROW else { throw FixtureError.sqlite(result) }
            guard let text = sqlite3_column_text(statement, 3) else {
                throw FixtureError.invalidPlan
            }
            let detail = String(cString: text)
            guard detail.contains("dbstat") else { continue }
            let prefix = "VIRTUAL TABLE INDEX "
            guard let range = detail.range(of: prefix) else { throw FixtureError.invalidPlan }
            let token = detail[range.upperBound...].prefix { $0 != ":" && !$0.isWhitespace }
            let parsed = token.hasPrefix("0x")
                ? UInt(token.dropFirst(2), radix: 16) : UInt(token, radix: 10)
            guard let bits = parsed else { throw FixtureError.invalidPlan }
            plans.append(bits)
        }
    }

    @Test("Bundled DBSTAT uses name pushdown while a larger unrelated tree stays uncharged")
    func namePushdownWithLargerUnrelatedTree() throws {
        try withDatabase { db in
            try seedProjection(on: db)
            let before = try assertDifferential(on: db)
            try execute("""
                CREATE TABLE unrelated_large(payload BLOB);
                WITH RECURSIVE rows(n) AS (VALUES(1) UNION ALL SELECT n + 1 FROM rows WHERE n < 256)
                INSERT INTO unrelated_large SELECT zeroblob(4096) FROM rows;
                """, on: db)
            let unrelated = try bytes("unrelated_large", on: db)
            #expect(unrelated > before * 16)
            let after = try assertDifferential(on: db)
            #expect(after == before)
            let originalPlans = try dbstatPlanBits(Self.originalSQL, on: db)
            let optimizedPlans = try dbstatPlanBits(EventStore.projectionPhysicalBytesSQL, on: db)
            #expect(originalPlans.count == 1)
            #expect(optimizedPlans.count == 1)
            // Bundled statBestIndex documents bit 0x02 as name equality.
            // This is a planner contract, not an elapsed-time performance gate.
            #expect(originalPlans.allSatisfy { $0 & 0x02 == 0 })
            #expect(optimizedPlans.allSatisfy { $0 & 0x02 != 0 })
        }
    }

    @Test("An interrupted ownership query does not become a successful zero allocation")
    func interruptedQueryRemainsFailure() throws {
        try withDatabase { db in
            try seedProjection(on: db)
            let statement = try prepared(EventStore.projectionPhysicalBytesSQL, on: db)
            defer { sqlite3_finalize(statement) }
            sqlite3_progress_handler(db, 1, { _ in 1 }, nil)
            defer { sqlite3_progress_handler(db, 0, nil, nil) }
            #expect(sqlite3_step(statement) == SQLITE_INTERRUPT)
        }
    }
}
