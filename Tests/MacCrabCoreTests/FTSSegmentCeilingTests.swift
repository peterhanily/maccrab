// FTSSegmentCeilingTests.swift
//
// v1.21.6-rc.34. FTS5 has a hard compile-time ceiling of 2000 live segments
// (`FTS5_MAX_SEGMENT`). At the ceiling every operation needing a segid fails
// with SQLITE_FULL — including `optimize`, so the index cannot compact out of
// it. Only `rebuild` escapes.
//
// This store drives itself into that wall. Writes run with `automerge=0`, and
// each expired journal block issues a `DELETE FROM events_fts` that writes a
// tombstone segment. An installed host reached 2000 segments holding only 635
// events, after which:
//
//   boot expiry fails SQLITE_FULL -> engine never reaches ready -> the
//   background sweep that calls mergeFTS/optimizeFTS never runs -> the ceiling
//   is never relieved -> the engine can never boot again.
//
// Ten release candidates and 4,327 green tests did not catch that, because no
// test drove events_fts anywhere near its ceiling and none executed the boot
// readiness path. These do both.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("FTS5 segment ceiling", .serialized)
struct FTSSegmentCeilingTests {

    private func makeTempDirectory() throws -> URL {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-fts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: tmp, withIntermediateDirectories: true
        )
        return tmp
    }

    /// Drive `events_fts` toward its segment ceiling the same way production
    /// does: many small per-block FTS deletes against an index whose automerge
    /// is disabled. Entirely synthetic — no host data.
    ///
    /// Returns the live segment count reached.
    @discardableResult
    private func exhaustFTSSegments(
        databasePath: String,
        targetSegments: Int
    ) throws -> (segments: Int, hitCeiling: Bool) {
        var handle: OpaquePointer?
        guard sqlite3_open(databasePath, &handle) == SQLITE_OK,
              let db = handle else {
            throw EventStoreError.databaseOpenFailed(databasePath)
        }
        defer { sqlite3_close(db) }

        // `events` and friends carry rc.13 BEFORE-triggers that abort any write
        // unless `maccrab_event_journal_writer_v8()` returns 1 — only the
        // authorized journal writer registers it. The fixture registers the same
        // function on ITS OWN connection so it can build a saturated index. This
        // does not weaken the guard: production code is untouched, the guard
        // still aborts unregistered writers, and its behaviour is covered by the
        // rc.13 write-guard tests.
        let writerAssertion: @convention(c) (
            OpaquePointer?, Int32, UnsafeMutablePointer<OpaquePointer?>?
        ) -> Void = { context, _, _ in
            sqlite3_result_int(context, 1)
        }
        guard sqlite3_create_function_v2(
            db, "maccrab_event_journal_writer_v8", 0,
            SQLITE_UTF8, nil, writerAssertion, nil, nil, nil
        ) == SQLITE_OK else {
            throw EventStoreError.stepFailed(
                "fixture could not register the journal-writer assertion"
            )
        }

        func exec(_ sql: String) throws {
            guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
                throw EventStoreError.stepFailed(
                    "fixture sql failed: \(String(cString: sqlite3_errmsg(db)))"
                )
            }
        }

        func segmentCount() -> Int {
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(
                db,
                "SELECT count(DISTINCT (id >> 37)) FROM events_fts_data WHERE id > 10",
                -1, &stmt, nil
            ) == SQLITE_OK else { return -1 }
            defer { sqlite3_finalize(stmt) }
            guard sqlite3_step(stmt) == SQLITE_ROW else { return -1 }
            return Int(sqlite3_column_int64(stmt, 0))
        }

        // `events_fts` is an EXTERNAL-CONTENT index over `events`, so rows are
        // written through the content table and the `events_ai` trigger indexes
        // them. With `automerge=0` those segments are never merged inline, so
        // ordinary batched ingestion walks the index straight at the 2000-segid
        // ceiling — measured at roughly one segment per two rows against the
        // real schema. No expiry is required to reach it, which is why an
        // installed host got there holding only 635 live events.
        var seeded = 0
        var batchStart = 0
        var hitCeiling = false
        // Shrink the batch on contact rather than stopping. A 200-row batch
        // fails while there is still room for a smaller one, so giving up on
        // the first SQLITE_FULL leaves the index short of true saturation —
        // and expiry keeps working, which makes the test prove nothing.
        var batchSize = 200
        while segmentCount() < targetSegments, seeded < targetSegments * 8 {
            do {
                try exec("BEGIN")
                batchStart = seeded
                while seeded < batchStart + batchSize {
                    let suffix = "fixture-\(seeded)"
                    try exec("""
                        INSERT INTO events (
                            id, timestamp, event_category, event_type,
                            event_action, severity, raw_json, projection_reason,
                            projection_estimated_bytes, projection_rank,
                            journal_block_id, process_name, process_path
                        ) VALUES (
                            'evt-\(suffix)', \(1_700_000_000 + seeded), 'process',
                            'start', 'exec', 'low', '{}', 0, 0, 100,
                            \(seeded / 3), 'p\(suffix)', '/bin/\(suffix)'
                        )
                        """)
                    seeded += 1
                }
                try exec("COMMIT")
            } catch {
                // SQLITE_FULL here IS the condition under test: the index ran
                // out of segment ids for a batch this size.
                _ = sqlite3_exec(db, "ROLLBACK", nil, nil, nil)
                seeded = batchStart
                hitCeiling = true
                guard batchSize > 1 else { break }
                batchSize = max(1, batchSize / 4)
            }
        }
        return (segmentCount(), hitCeiling)
    }

    @Test("The store reports its live FTS segment count")
    func reportsSegmentCount() async throws {
        let dir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try EventStore(directory: dir.path)

        let count = await store.liveFTSSegmentCount()
        #expect(count != nil, "segment count must be observable to be governable")
        #expect((count ?? -1) >= 0)
    }

    @Test("Recovery threshold sits below the hard ceiling")
    func thresholdIsBelowCeiling() {
        // At the ceiling `optimize` itself fails, so recovery MUST trigger with
        // headroom to spare. A threshold at or above the ceiling is unusable.
        #expect(EventStore.ftsSegmentRecoveryThreshold < EventStore.ftsSegmentCeiling)
        #expect(EventStore.ftsSegmentCeiling == 2_000)
        #expect(EventStore.ftsSegmentRecoveryThreshold > 0)
    }

    @Test("A segment-saturated index is rebuilt instead of wedging the boot path")
    func saturatedIndexIsRecovered() async throws {
        let dir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let databasePath = dir.appendingPathComponent("events.db").path

        // Open once so the schema, triggers and automerge=0 config exist, then
        // release the handle before the fixture writes through its own.
        do { _ = try EventStore(directory: dir.path) }

        let fixture = try exhaustFTSSegments(
            databasePath: databasePath,
            targetSegments: EventStore.ftsSegmentRecoveryThreshold + 50
        )
        #expect(
            fixture.segments >= EventStore.ftsSegmentRecoveryThreshold,
            "fixture failed to reproduce segment pressure (reached \(fixture.segments))"
        )

        let store = try EventStore(directory: dir.path)
        let before = await store.liveFTSSegmentCount() ?? -1
        #expect(before >= EventStore.ftsSegmentRecoveryThreshold)

        let recovered = try await store.recoverExhaustedFTSIndexIfNeeded()
        #expect(recovered, "saturated index should have been rebuilt")

        let after = await store.liveFTSSegmentCount() ?? -1
        #expect(
            after < EventStore.ftsSegmentRecoveryThreshold,
            "rebuild left \(after) segments, still at/over the recovery threshold"
        )
    }

    @Test("A healthy index is left alone")
    func healthyIndexIsNotRebuilt() async throws {
        let dir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = try EventStore(directory: dir.path)

        // Recovery is not free; it must not fire on every boot.
        #expect(try await store.recoverExhaustedFTSIndexIfNeeded() == false)
    }

    @Test("Journal expiry survives a segment-saturated index")
    func expirySurvivesSaturatedIndex() async throws {
        let dir = try makeTempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let databasePath = dir.appendingPathComponent("events.db").path

        do { _ = try EventStore(directory: dir.path) }
        // Drive all the way to the HARD ceiling, not merely past the recovery
        // threshold. Below the ceiling expiry still succeeds, so a fixture that
        // stops early passes with or without the fix and proves nothing.
        let fixture = try exhaustFTSSegments(
            databasePath: databasePath,
            targetSegments: EventStore.ftsSegmentCeiling
        )
        // The meaningful signal is that a write actually failed with
        // SQLITE_FULL, not the raw segment number: FTS5 flushes on batch
        // boundaries, so the exact count where the wall is met varies.
        #expect(
            fixture.hitCeiling,
            "fixture never hit the segment ceiling (reached \(fixture.segments))"
        )

        // `expireJournalBlocks` is the call that failed on the installed host,
        // reported as "journal expiry projection count disagrees with coverage"
        // when the real cause was a SQLITE_FULL step failure.
        //
        // This asserts the WIRING rather than an end-to-end expiry failure:
        // reproducing the latter needs authenticated, hash-chained
        // `event_journal_blocks` past their retention deadline, which is
        // disproportionate to build here. What matters for the boot loop is
        // that entering the expiry path relieves segment pressure BEFORE any
        // delete needs a segid — so the index must come back compacted.
        let store = try EventStore(directory: dir.path)
        _ = try await store.expireJournalBlocks(retainedThrough: Date())

        let after = await store.liveFTSSegmentCount() ?? -1
        #expect(
            after < EventStore.ftsSegmentRecoveryThreshold,
            "expiry left events_fts at \(after) segments; the boot path did not relieve segment pressure"
        )
    }
}
