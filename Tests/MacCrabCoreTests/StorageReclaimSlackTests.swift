// StorageReclaimSlackTests.swift
//
// v1.21.6-rc.45: the size-cap sweep must reclaim freelist slack even when its
// instantaneous footprint sample says the store is under target.
//
// THE DEFECT THIS PINS (measured on an installed rc.44 host, 2026-08-30):
//
//   events.db          350,703,616 bytes on disk
//   page_count              85,621
//   freelist_count          79,300   -> 311 MiB reclaimable, 23 MiB live
//   footprint after the sweep's own walCheckpointTruncate()
//                      350,834,688 bytes
//   targetSizeBytes    352,321,536 bytes  -> UNDER target by 1.4 MiB
//   totalPruned                  0        -> every retained row inside the
//                                            15-minute forensic floor
//
// The old gate was `(totalPruned > 0 || overCap) && !walPinned`, with `overCap`
// sampled immediately after the WAL truncate — the trough of the cycle. Both
// disjuncts were false, so the reclaim was skipped on 309 consecutive sweeps
// across 8 hours while storage admission (which judges the family at its PEAK:
// main + a regrown WAL + one transaction reserve) paused ingestion under
// `footprint_limit` and the engine shed 48,193 events. One unbounded
// `incremental_vacuum` on a byte-identical copy of that store returned all
// 311 MiB in 3.0 s (350,703,616 -> 31,264,768 bytes).
//
// FAIL-WITHOUT / PASS-WITH: delete the `reclaimableSlackBytes >= slackFloorBytes`
// clause from `StorageReclaimDecision.shouldReclaim` and
// `reclaimsTheMeasuredInstalledHostStrandedSlack` fails with exactly the
// observed numbers. The surrounding cases pin the clauses that must NOT change.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Storage reclaim slack gate (v1.21.6-rc.45)")
struct StorageReclaimSlackTests {

    /// The exact rc.44 installed-host sample. Under target, nothing pruned,
    /// 311 MiB stranded. This is the case the shipped gate got wrong.
    @Test("reclaims the measured installed-host stranded slack")
    func reclaimsTheMeasuredInstalledHostStrandedSlack() {
        let footprint: Int64 = 350_834_688
        let target: Int64 = 352_321_536
        let slack: Int64 = 79_300 * 4_096   // 324,812,800 bytes

        // Precondition: this really is the aliased case — the old gate's two
        // disjuncts are both false, so the test cannot pass for the wrong reason.
        #expect(footprint <= target, "sample must be UNDER target or it proves nothing")

        #expect(
            StorageReclaimDecision.shouldReclaim(
                totalPruned: 0,
                footprintBytes: footprint,
                targetBytes: target,
                reclaimableSlackBytes: slack
            ),
            "311 MiB of reclaimable freelist must trigger the reclaim even 1.4 MiB under target"
        )
    }

    /// The pre-fix behaviour, stated explicitly: with no slack the aliased
    /// sample legitimately declines. This is what made the defect invisible.
    @Test("declines when under target with no reclaimable slack")
    func declinesWhenUnderTargetWithNoSlack() {
        #expect(
            !StorageReclaimDecision.shouldReclaim(
                totalPruned: 0,
                footprintBytes: 350_834_688,
                targetBytes: 352_321_536,
                reclaimableSlackBytes: 0
            )
        )
    }

    /// Ordinary churn must not truncate and regrow the file every sweep.
    @Test("does not fire on sub-floor churn")
    func doesNotFireOnSubFloorChurn() {
        #expect(
            !StorageReclaimDecision.shouldReclaim(
                totalPruned: 0,
                footprintBytes: 100,
                targetBytes: 352_321_536,
                reclaimableSlackBytes: reclaimableSlackFloorBytes - 1
            )
        )
        #expect(
            StorageReclaimDecision.shouldReclaim(
                totalPruned: 0,
                footprintBytes: 100,
                targetBytes: 352_321_536,
                reclaimableSlackBytes: reclaimableSlackFloorBytes
            ),
            "the floor is inclusive"
        )
    }

    /// The two pre-existing reasons must keep working unchanged.
    @Test("preserves the original prune and over-target reasons")
    func preservesOriginalReasons() {
        #expect(
            StorageReclaimDecision.shouldReclaim(
                totalPruned: 1,
                footprintBytes: 100,
                targetBytes: 352_321_536,
                reclaimableSlackBytes: 0
            )
        )
        #expect(
            StorageReclaimDecision.shouldReclaim(
                totalPruned: 0,
                footprintBytes: 352_321_537,
                targetBytes: 352_321_536,
                reclaimableSlackBytes: 0
            )
        )
    }

    /// A zero/negative floor must not degrade into "reclaim on every sweep".
    @Test("a non-positive floor disables the slack reason rather than always firing")
    func nonPositiveFloorDisablesSlackReason() {
        #expect(
            !StorageReclaimDecision.shouldReclaim(
                totalPruned: 0,
                footprintBytes: 100,
                targetBytes: 352_321_536,
                reclaimableSlackBytes: 0,
                slackFloorBytes: 0
            )
        )
    }

    /// Contract of the new accessor on a REAL EventStore: it must report exactly
    /// `freelist_count * page_size` as an independent read-only connection sees
    /// it, and that number must RISE when retention frees pages. The pure gate
    /// above is only correct if this input is truthful — a gate that opens onto
    /// a lying accessor is the same silent no-op the old code had.
    ///
    /// (The `incremental_vacuum` primitive itself is separately pinned by
    /// IncrementalVacuumTests; this test covers the EventStore-level reporting
    /// and the end-to-end reclaim, which is what the sweep actually calls.)
    @Test("a real churned store reports and returns its freelist slack")
    func realStoreReportsAndReturnsSlack() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-reclaim-slack-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        let path = dir.path + "/events.db"

        // Fill with backdated rows, then roll up past them, so the file keeps
        // its high-water mark while the live set collapses — the shape the
        // installed rc.44 host had.
        let now = Date()
        for i in 0..<4_000 {
            let ts = now.addingTimeInterval(-3600 - Double(i))
            let proc = ProcessInfo(
                pid: Int32(2000 + i), ppid: 1, rpid: 1,
                name: "slackfx\(i)", executable: "/bin/slackfx\(i)",
                commandLine: String(repeating: "x", count: 512),
                args: [],
                workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20,
                startTime: ts,
                ancestors: [],
                isPlatformBinary: false
            )
            try await store.insert(event: Event(
                timestamp: ts,
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            ))
        }
        _ = await store.walCheckpoint()

        // The accessor is only meaningful on an INCREMENTAL-mode file; if a
        // future pragma-ordering regression drops the store back to mode 0 the
        // reclaim path silently becomes a no-op, so assert the mode explicitly
        // rather than letting a 0 slack reading look like "nothing to do".
        #expect(
            storeAutoVacuumMode(at: path) == 2,
            "EventStore must open events.db in auto_vacuum = INCREMENTAL; at mode 0 the whole reclaim path is inert"
        )

        let expectedBefore = Int64(storeFreelistCount(at: path))
            * Int64(storePageSize(at: path))
        let slackBefore = await store.reclaimableFreelistBytes()
        #expect(
            slackBefore == expectedBefore,
            "accessor must report freelist_count * page_size (reported \(slackBefore), independent read \(expectedBefore))"
        )

        // Journal-owned rows are freed by block expiry, not by pruneOldest /
        // rollUpAndPrune (both require `journal_block_id IS NULL`). Expiry is
        // the path the engine actually runs, so it is the honest fixture.
        let pruned = try await store.expireJournalBlocks(
            // Blocks expire on their own `retainedUntil`, not on the event
            // timestamps they carry, so the cutoff has to be past that window.
            retainedThrough: now.addingTimeInterval(30 * 24 * 3600),
            maximumBlocks: 8_192
        )
        #expect(pruned > 0, "fixture must actually expire backdated journal blocks")
        _ = await store.walCheckpoint()

        let slackAfter = await store.reclaimableFreelistBytes()
        #expect(
            slackAfter > slackBefore,
            "rolling up \(pruned) rows must leave reclaimable freelist slack (before \(slackBefore), after \(slackAfter))"
        )
        #expect(
            slackAfter == Int64(storeFreelistCount(at: path))
                * Int64(storePageSize(at: path)),
            "accessor must still agree with an independent pragma read after churn"
        )

        let reclaimed = try await store.incrementalVacuum(maxPages: 200_000)
        #expect(
            reclaimed > 0,
            "incremental_vacuum must return pages the store reported as reclaimable"
        )
        let slackFinal = await store.reclaimableFreelistBytes()
        #expect(slackFinal < slackAfter, "the reported slack must fall after the reclaim")
    }
}

// MARK: - Independent pragma reads (separate read-only connection)

private func storePragmaInt(_ path: String, _ sql: String) -> Int {
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
          let db else { return -1 }
    defer { sqlite3_close(db) }
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
          let stmt else { return -1 }
    defer { sqlite3_finalize(stmt) }
    guard sqlite3_step(stmt) == SQLITE_ROW else { return -1 }
    return Int(sqlite3_column_int(stmt, 0))
}

private func storeFreelistCount(at path: String) -> Int {
    storePragmaInt(path, "PRAGMA freelist_count")
}

private func storePageSize(at path: String) -> Int {
    storePragmaInt(path, "PRAGMA page_size")
}

private func storeAutoVacuumMode(at path: String) -> Int {
    storePragmaInt(path, "PRAGMA auto_vacuum")
}
