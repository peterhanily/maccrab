// CausalGraphHashChainContinuityTests.swift
// A3-04 — the on-DB append-only continuity hash chain + verifyHashChain().
//
// These tests exercise the ledger primitives directly (appendTraceContinuity /
// globalChainHead / verifyHashChain) and through TraceMaterializer, and prove
// the tamper-detection contract by mutating tracegraph.db out-of-band with a
// second SQLite connection — the realistic "a process edited the DB file"
// model — then re-verifying.

import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore

@Suite("TraceGraph: continuity hash chain (A3-04)")
struct CausalGraphHashChainContinuityTests {

    // MARK: - Helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-chain-\(UUID().uuidString).db")
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)
        return (store, path)
    }

    /// Mutate the DB out-of-band via a second read-write connection (the store
    /// is still open in WAL mode, so the store's next read sees the change).
    private func tamper(_ path: URL, _ sql: String) {
        var db: OpaquePointer?
        defer { if let db { sqlite3_close(db) } }
        #expect(sqlite3_open_v2(path.path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK)
        let rc = sqlite3_exec(db, sql, nil, nil, nil)
        #expect(rc == SQLITE_OK)
    }

    private func appendN(_ store: SQLiteCausalGraphStore, _ n: Int) async throws -> [TraceHashChainEntry] {
        var out: [TraceHashChainEntry] = []
        for i in 0..<n {
            let e = try await store.appendTraceContinuity(
                traceId: "trace-\(i)",
                eventId: "ev-\(i)",
                edgeId: nil,
                signature: nil,
                publishedToUnifiedLog: false,
                createdAt: Date(timeIntervalSince1970: 1_700_000_000 + Double(i))
            )
            out.append(e)
        }
        return out
    }

    private func createLegacyContinuityDatabase(
        at path: URL,
        duplicateHead: Bool
    ) async throws {
        // Start from the complete production schema. SchemaMigrator
        // intentionally replays every idempotent migration even when
        // user_version is current, so a partial hand-written fixture would
        // test an impossible database rather than the v2 continuity shape.
        let bootstrap = try await SQLiteCausalGraphStore(databasePath: path.path)
        await bootstrap.close()

        var db: OpaquePointer?
        defer { if let db { sqlite3_close(db) } }
        try #require(sqlite3_open_v2(
            path.path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil
        ) == SQLITE_OK)
        let duplicateSQL = duplicateHead ? """
        INSERT INTO trace_hash_chain
            (id, trace_id, sequence_number, previous_hash, current_hash,
             event_id, edge_id, chain_head_signature,
             chain_head_published_to_unified_log, created_at)
        VALUES
            ('fork-a', 'trace-a', 7, NULL, 'hash-a', NULL, NULL, NULL, 0, 1),
            ('fork-b', 'trace-b', 7, NULL, 'hash-b', NULL, NULL, NULL, 0, 2);
        """ : ""
        let sql = """
        DROP TRIGGER IF EXISTS trg_hash_chain_global_sequence_unique;
        DROP INDEX IF EXISTS idx_hash_chain_global_seq;
        DROP INDEX IF EXISTS idx_hash_chain_trace_seq;
        ALTER TABLE trace_hash_chain RENAME TO trace_hash_chain_v3_fixture;
        CREATE TABLE trace_hash_chain (
            id TEXT PRIMARY KEY,
            trace_id TEXT NOT NULL,
            sequence_number INTEGER NOT NULL,
            previous_hash TEXT,
            current_hash TEXT NOT NULL,
            event_id TEXT,
            edge_id TEXT,
            chain_head_signature TEXT,
            chain_head_published_to_unified_log INTEGER DEFAULT 0,
            created_at REAL NOT NULL,
            UNIQUE(trace_id, sequence_number)
        );
        CREATE INDEX idx_hash_chain_trace_seq
            ON trace_hash_chain(trace_id, sequence_number);
        \(duplicateSQL)
        DROP TABLE trace_hash_chain_v3_fixture;
        PRAGMA user_version = 2;
        """
        var errmsg: UnsafeMutablePointer<CChar>?
        let rc = sqlite3_exec(db, sql, nil, nil, &errmsg)
        if rc != SQLITE_OK {
            let message = errmsg.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(errmsg)
            throw CausalGraphStoreError.schemaFailed(
                "legacy continuity fixture failed: \(message)")
        }
        if let db {
            sqlite3_close(db)
        }
        db = nil
        #expect(chmod(path.path, 0o600) == 0)
    }

    private func queryPlan(at path: URL, sql: String) -> [String] {
        var db: OpaquePointer?
        defer { if let db { sqlite3_close(db) } }
        #expect(sqlite3_open_v2(
            path.path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil
        ) == SQLITE_OK)
        var stmt: OpaquePointer?
        #expect(sqlite3_prepare_v2(
            db, "EXPLAIN QUERY PLAN \(sql)", -1, &stmt, nil
        ) == SQLITE_OK)
        defer { sqlite3_finalize(stmt) }
        var details: [String] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let raw = sqlite3_column_text(stmt, 3) {
                details.append(String(cString: raw))
            }
        }
        return details
    }

    // MARK: - Clean chain

    @Test("A clean continuity chain verifies; entries are linked in append order")
    func cleanChainVerifies() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let entries = try await appendN(store, 3)

        // Genesis has no predecessor; each later entry links to the prior head.
        #expect(entries[0].previousHash == nil)
        #expect(entries[0].sequenceNumber == 1)
        #expect(entries[1].previousHash == entries[0].currentHash)
        #expect(entries[2].previousHash == entries[1].currentHash)
        #expect(entries[2].sequenceNumber == 3)

        let head = try await store.globalChainHead()
        #expect(head?.sequenceNumber == 3)
        #expect(head?.currentHash == entries[2].currentHash)

        let result = try await store.verifyHashChain()
        #expect(result.status == .ok)
        #expect(result.isIntact)
        #expect(result.entriesChecked == 3)
        await store.close()
    }

    @Test("An empty continuity chain is a clean no-op")
    func emptyChainIsClean() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        #expect(try await store.globalChainHead() == nil)
        let result = try await store.verifyHashChain()
        #expect(result.status == .ok)
        #expect(result.entriesChecked == 0)
        await store.close()
    }

    @Test("Two store connections cannot fork the global continuity sequence")
    func concurrentConnectionsSerializeHeadAndInsert() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-chain-race-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: path.path + suffix)
            }
        }
        let first = try await SQLiteCausalGraphStore(databasePath: path.path)
        let second = try await SQLiteCausalGraphStore(databasePath: path.path)

        @Sendable func appendRange(
            _ store: SQLiteCausalGraphStore,
            prefix: String
        ) async throws -> [TraceHashChainEntry] {
            var entries: [TraceHashChainEntry] = []
            for index in 0..<25 {
                entries.append(try await store.appendTraceContinuity(
                    traceId: "\(prefix)-\(index)",
                    eventId: "event-\(prefix)-\(index)",
                    edgeId: nil,
                    signature: nil,
                    publishedToUnifiedLog: false,
                    createdAt: Date(timeIntervalSince1970: 1_700_100_000 + Double(index))
                ))
            }
            return entries
        }

        async let left = appendRange(first, prefix: "left")
        async let right = appendRange(second, prefix: "right")
        let (leftEntries, rightEntries) = try await (left, right)
        let all = leftEntries + rightEntries
        let sequences = all.map(\.sequenceNumber).sorted()
        #expect(sequences == Array(1...50))
        #expect(Set(sequences).count == 50)
        let verification = try await first.verifyHashChain()
        #expect(verification.status == .ok)
        #expect(verification.entriesChecked == 50)
        await first.close()
        await second.close()
    }

    @Test("Legacy v2 continuity queries gain a global sequence seek index")
    func legacyMigrationIndexesGlobalSequenceQueries() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-chain-legacy-plan-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: path.path + suffix)
            }
        }
        try await createLegacyContinuityDatabase(at: path, duplicateHead: false)
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)

        let duplicateLookup = queryPlan(
            at: path,
            sql: "SELECT 1 FROM trace_hash_chain WHERE sequence_number = 42 LIMIT 1"
        ).joined(separator: " | ")
        let globalHead = queryPlan(
            at: path,
            sql: "SELECT id FROM trace_hash_chain ORDER BY sequence_number DESC LIMIT 1"
        ).joined(separator: " | ")
        #expect(duplicateLookup.contains("idx_hash_chain_global_seq"),
                "legacy duplicate guard still scans: \(duplicateLookup)")
        #expect(globalHead.contains("idx_hash_chain_global_seq"),
                "legacy global-head lookup still scans: \(globalHead)")
        #expect(!globalHead.lowercased().contains("temp b-tree"))
        await store.close()
    }

    @Test("A duplicated inherited global head latches continuity appends fail-closed")
    func duplicateGlobalHeadLatchesAppend() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-chain-duplicate-head-\(UUID().uuidString).db")
        defer {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                try? FileManager.default.removeItem(atPath: path.path + suffix)
            }
        }
        try await createLegacyContinuityDatabase(at: path, duplicateHead: true)
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)

        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await store.appendTraceContinuity(
                traceId: "new", eventId: "event", edgeId: nil,
                signature: nil, publishedToUnifiedLog: false
            )
        }
        // Remove one fork out-of-band. This handle must remain latched rather
        // than silently resuming after an integrity failure it already saw.
        tamper(path, "DELETE FROM trace_hash_chain WHERE id = 'fork-b'")
        await #expect(throws: CausalGraphStoreError.self) {
            _ = try await store.appendTraceContinuity(
                traceId: "still-blocked", eventId: "event-2", edgeId: nil,
                signature: nil, publishedToUnifiedLog: false
            )
        }
        #expect(try await store.globalChainHead()?.sequenceNumber == 7)
        await store.close()
    }

    // MARK: - Tamper detection

    @Test("A mutated row (UPDATE of a bound field) is detected as a content break")
    func mutatedRowDetected() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        _ = try await appendN(store, 3)

        // Change a bound field on the middle row without fixing current_hash —
        // exactly what an in-place UPDATE leaves behind.
        tamper(path, "UPDATE trace_hash_chain SET trace_id = 'TAMPERED' WHERE sequence_number = 2")

        let result = try await store.verifyHashChain()
        #expect(result.status == .brokenContent(atSequence: 2))
        #expect(!result.isIntact)
        #expect(result.entriesChecked == 1)   // seq 1 verified before the break
        await store.close()
    }

    @Test("Mutating current_hash itself is detected as a content break")
    func mutatedHashDetected() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        _ = try await appendN(store, 3)

        tamper(path, "UPDATE trace_hash_chain SET current_hash = 'deadbeef' WHERE sequence_number = 3")

        let result = try await store.verifyHashChain()
        #expect(result.status == .brokenContent(atSequence: 3))
        await store.close()
    }

    @Test("A deleted interior row (retention gap) is TOLERATED, not a false linkage break")
    func interiorGapToleratedAsRetention() async throws {
        // audit sec-storage-crypto: retention prunes traces by updated_at,
        // which does not track sequence_number order, so authorized retention
        // deletes INTERIOR chain rows and leaves a sequence gap. Deleting seq 2
        // leaves [1, 3] — a gap (3 != 1+1). verifyHashChain must NOT flag the
        // broken link across that gap (the old behaviour false-flagged every
        // host that had ever pruned). Content integrity of the survivors is
        // untouched, so the chain verifies clean.
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        _ = try await appendN(store, 3)

        tamper(path, "DELETE FROM trace_hash_chain WHERE sequence_number = 2")

        let result = try await store.verifyHashChain()
        #expect(result.status == .ok)
        #expect(result.entriesChecked == 2)   // seq 1 and seq 3 both verified
        await store.close()
    }

    @Test("A contiguous linkage break (spliced self-consistent row) is still detected")
    func contiguousLinkageBreakStillDetected() async throws {
        // Linkage enforcement survives for CONTIGUOUS rows: splice a forged row
        // whose own current_hash recomputes (content passes) but whose
        // previous_hash does not match its immediate predecessor. Because
        // seq 2 stays contiguous with seq 1, the broken inbound link is flagged.
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let entries = try await appendN(store, 3)

        let forgedPrev = "0000000000000000000000000000000000000000000000000000000000000000"
        // Recompute a SELF-CONSISTENT current_hash for the tampered previous_hash
        // so the content check passes and only linkage can catch it.
        let forgedHash = TraceHashChainEntry.computeCurrentHash(
            id: entries[1].id,
            traceId: entries[1].traceId,
            sequenceNumber: entries[1].sequenceNumber,
            previousHash: forgedPrev,
            eventId: entries[1].eventId,
            edgeId: entries[1].edgeId,
            createdAt: entries[1].createdAt
        )
        tamper(path, "UPDATE trace_hash_chain SET previous_hash = '\(forgedPrev)', current_hash = '\(forgedHash)' WHERE sequence_number = 2")

        let result = try await store.verifyHashChain()
        #expect(result.status == .brokenLinkage(atSequence: 2))
        #expect(result.entriesChecked == 1)   // seq 1 verified before the break
        await store.close()
    }

    @Test("Reordering rows (swapped sequence numbers) is detected")
    func reorderDetected() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        _ = try await appendN(store, 3)

        // Swap the sequence numbers of rows 2 and 3 (via a temporary value).
        tamper(path, """
        UPDATE trace_hash_chain SET sequence_number = 99 WHERE sequence_number = 2;
        UPDATE trace_hash_chain SET sequence_number = 2  WHERE sequence_number = 3;
        UPDATE trace_hash_chain SET sequence_number = 3  WHERE sequence_number = 99;
        """)

        // sequence_number is a hashed field, so the row now labelled seq 2 no
        // longer recomputes to its stored current_hash.
        let result = try await store.verifyHashChain()
        #expect(result.status == .brokenContent(atSequence: 2))
        await store.close()
    }

    @Test("Prefix pruning (deleting the oldest entries) is tolerated — shifted start still verifies")
    func prefixPruneTolerated() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        _ = try await appendN(store, 4)

        // Retention prunes the oldest entries. Deleting seq 1 (and 2) leaves a
        // contiguous suffix whose first row's back-link is allowed to dangle.
        tamper(path, "DELETE FROM trace_hash_chain WHERE sequence_number IN (1, 2)")

        let result = try await store.verifyHashChain()
        #expect(result.status == .ok)
        #expect(result.entriesChecked == 2)
        await store.close()
    }

    // MARK: - Recompute stability across a DB round-trip

    @Test("current_hash recomputes identically after a SQLite REAL round-trip of created_at")
    func recomputeSurvivesRoundTrip() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        // A createdAt with sub-second precision stresses the double round-trip.
        let e = try await store.appendTraceContinuity(
            traceId: "t", eventId: "ev", edgeId: nil, signature: nil,
            publishedToUnifiedLog: false,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000.123456)
        )
        let head = try await store.globalChainHead()
        #expect(head?.currentHash == e.currentHash)
        #expect(head?.recomputedCurrentHash() == e.currentHash)
        // And the full chain verifies (recompute matched on read-back).
        #expect(try await store.verifyHashChain().status == .ok)
        await store.close()
    }

    // MARK: - 64-bit sequence-number bind (trap avoidance)

    @Test("A sequence_number beyond Int32.max round-trips (64-bit bind — no trap)")
    func sequenceNumberBeyondInt32MaxRoundTrips() async throws {
        // Pre-GA audit (LOW): the INSERT bound sequence_number as a 32-bit int via
        // `Int32(entry.sequenceNumber)` — a force-conversion that TRAPS once the
        // monotonic sequence exceeds Int32.max (~2.1B), while the column and the
        // read-back (sqlite3_column_int64) are 64-bit. The fix binds 64-bit. This
        // exercises a value past Int32.max: on the old code the bind would trap
        // (crash the process); on the fix it round-trips.
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let bigSeq = Int(Int32.max) + 1000
        let id = UUID().uuidString
        let createdAt = Date(timeIntervalSince1970: 1_700_000_000)
        let currentHash = TraceHashChainEntry.computeCurrentHash(
            id: id, traceId: "t-big", sequenceNumber: bigSeq,
            previousHash: nil, eventId: nil, edgeId: nil, createdAt: createdAt)
        let entry = TraceHashChainEntry(
            id: id, traceId: "t-big", sequenceNumber: bigSeq,
            previousHash: nil, currentHash: currentHash, createdAt: createdAt)

        // Must not trap on the bind, and the 64-bit value must survive the column.
        try await store.appendHashChain(entry)
        let head = try await store.globalChainHead()
        #expect(head?.sequenceNumber == bigSeq)
        // Content still recomputes (String(sequenceNumber) is width-agnostic).
        #expect(try await store.verifyHashChain().status == .ok)
        await store.close()
    }

    // MARK: - Integration through the materializer

    @Test("TraceMaterializer extends the continuity chain (one entry per materialized trace)")
    func materializerExtendsChain() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let now = Date(timeIntervalSince1970: 1_700_000_000)
        func materialize(_ tag: String, at t: Date) async throws {
            let proc = ProcessNode(
                processKey: "k-\(tag)", pid: 100, ppid: 1,
                executablePath: "/bin/zsh",
                isAppleSigned: true, isNotarized: true,
                startTime: t
            )
            let entity = try proc.toEntity(source: "test")
            try await store.upsertEntity(entity)
            let materializer = TraceMaterializer(store: store)
            _ = try await materializer.materialize(
                anchorEntityId: entity.id,
                anchorEventId: "ev-\(tag)",
                title: "trace-\(tag)",
                severity: "high",
                confidence: 0.9,
                now: t.addingTimeInterval(1)
            )
        }

        // Empty before any trace.
        #expect(try await store.globalChainHead() == nil)

        try await materialize("a", at: now)
        let afterFirst = try await store.globalChainHead()
        #expect(afterFirst != nil)
        #expect(afterFirst?.sequenceNumber == 1)
        #expect(afterFirst?.previousHash == nil)

        try await materialize("b", at: now.addingTimeInterval(60))
        let afterSecond = try await store.globalChainHead()
        #expect(afterSecond?.sequenceNumber == 2)
        #expect(afterSecond?.previousHash == afterFirst?.currentHash)

        let result = try await store.verifyHashChain()
        #expect(result.status == .ok)
        #expect(result.entriesChecked == 2)
        await store.close()
    }
}
