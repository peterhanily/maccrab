// EventStoreWALCheckpointTests.swift
// v1.21.4 per-event perf (#23): events.db WAL autocheckpoint raised to 16 MB
// (`StoragePragmas.eventWalAutocheckpointPages`) to cut per-write PASSIVE-
// checkpoint frequency during a file-write flood, plus an explicit TRUNCATE
// checkpoint (`EventStore.walCheckpointTruncate`) driven from the background
// size-cap sweep to reclaim the raised WAL high-water mark.
//
// These pin the WAL-BOUND SAFETY contract of the change — it tensions the
// v1.18 WAL-bloat fix (field-observed 251 MB WAL), so the tests prove:
//   - Under a sustained write burst whose total churn far exceeds the 64 MB
//     `journalSizeLimitBytes`, the .db-wal sidecar NEVER exceeds that limit —
//     i.e. SQLite's own auto-checkpoint (now at 16 MB) still owns the bound,
//     independent of any background timer. A broken/disabled auto-checkpoint
//     would let the WAL grow to the full churn size (> 64 MB) and fail this.
//   - `walCheckpointTruncate()` drains the WAL and shrinks the sidecar FILE
//     back to zero — the "background checkpoint truncates it" property that a
//     plain PASSIVE→RESTART `walCheckpoint()` does NOT provide (it leaves the
//     file pinned at its high-water mark).

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("EventStore: WAL autocheckpoint bound + TRUNCATE reclaim (v1.21.4 #23)")
struct EventStoreWALCheckpointTests {

    // MARK: - Helpers (mirror EventStoreFTSMergeTests)

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("wal-ckpt-\(UUID().uuidString).db").path
    }

    private static func cleanup(_ path: String) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path + suffix)
        }
    }

    /// Size in bytes of the `-wal` sidecar, or 0 if absent.
    private static func walSize(_ path: String) -> Int64 {
        let attrs = try? FileManager.default.attributesOfItem(atPath: path + "-wal")
        return (attrs?[.size] as? NSNumber)?.int64Value ?? 0
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
            args: [commandLine],
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

    private static func makeEvent(index: Int, commandLine: String) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(
                name: "proc\(index)",
                path: "/usr/bin/proc\(index)",
                commandLine: commandLine
            )
        )
    }

    // MARK: - Tests

    /// A sustained burst whose cumulative WAL churn is far larger than the
    /// 64 MB journal_size_limit must never leave the WAL sidecar over that
    /// limit — the 16 MB auto-checkpoint keeps draining it.
    @Test("WAL sidecar stays under journal_size_limit across a burst >> 64 MB churn")
    func walStaysBoundedUnderBurst() async throws {
        let path = Self.tempPath()
        defer { Self.cleanup(path) }
        let store = try EventStore(path: path)

        // ~32 KB per row, stored in the process_commandline column AND twice in
        // the raw_json blob (commandLine + args), so ~96 KB churn/row. 1500 rows
        // ≈ ~140 MB of raw churn (plus indexes) — ~2× over the 64 MB limit — so a
        // WAL that failed to checkpoint would blow well past journalSizeLimitBytes.
        // A single long token keeps FTS tokenization cheap; the bytes drive the WAL.
        let bigCmd = String(repeating: "x", count: 32_768)
        let total = 1500
        // Each batch is one transaction (mirrors BatchedEventWriter). Kept far
        // below 64 MB so no *single* transaction can overrun the WAL before its
        // post-commit auto-checkpoint (a mid-transaction WAL can't be
        // checkpointed). 200 rows ≈ ~20 MB/batch — above the 16 MB checkpoint
        // threshold, so the auto-checkpoint fires every batch and the file
        // settles near that mark instead of growing toward the churn total.
        let batchSize = 200

        let limit = StoragePragmas.journalSizeLimitBytes
        var peakWal: Int64 = 0
        var index = 0
        while index < total {
            let upper = min(index + batchSize, total)
            let batch = (index..<upper).map { Self.makeEvent(index: $0, commandLine: bigCmd) }
            try await store.insert(events: batch)
            index = upper
            // Measure AFTER each batch commit — the post-commit auto-checkpoint
            // has already run, so this is the true high-water mark.
            peakWal = max(peakWal, Self.walSize(path))
            #expect(Self.walSize(path) < limit,
                    "events.db-wal exceeded journal_size_limit mid-burst")
        }

        // The WAL was actually exercised (non-vacuous test) yet stayed bounded:
        // well under the 64 MB limit despite ~2× that in churn.
        #expect(peakWal > 0, "burst produced no WAL activity — test is vacuous")
        #expect(peakWal < limit,
                "peak WAL \(peakWal) reached/exceeded journal_size_limit \(limit)")

        // Sanity: all rows landed.
        let stored = try await store.events(since: .distantPast, limit: total + 10)
        #expect(stored.count == total)
    }

    /// The TRUNCATE checkpoint the background sweep runs must shrink the WAL
    /// FILE to zero — RESTART (walCheckpoint) only drains content and leaves
    /// the file at its high-water mark.
    @Test("walCheckpointTruncate() reclaims the WAL sidecar to zero")
    func truncateReclaimsWal() async throws {
        let path = Self.tempPath()
        defer { Self.cleanup(path) }
        let store = try EventStore(path: path)

        // ~16 KB/row × 600 rows in one transaction ≈ ~29 MB churn — enough that
        // the sidecar is clearly non-empty after commit (its high-water mark),
        // and comfortably under the 64 MB per-transaction ceiling.
        let bigCmd = String(repeating: "y", count: 16_384)
        let batch = (0..<600).map { Self.makeEvent(index: $0, commandLine: bigCmd) }
        try await store.insert(events: batch)

        let before = Self.walSize(path)
        #expect(before > 0, "expected a non-empty WAL before truncate")

        let ok = await store.walCheckpointTruncate()
        #expect(ok)

        let after = Self.walSize(path)
        // TRUNCATE takes the sidecar to 0 bytes with no competing readers; allow
        // a small slack in case SQLite re-arms the 32-byte WAL header. The key
        // invariant: it must NOT stay pinned near its post-write high-water mark
        // (which a plain PASSIVE→RESTART walCheckpoint would leave it at).
        #expect(after < before,
                "truncate must shrink the WAL below its high-water mark (\(after) vs \(before))")
        #expect(after < 64 * 1024,
                "WAL should be reclaimed to ~0, not left pinned (\(after) bytes)")

        // Read path is intact after the checkpoint: rows still queryable.
        let stored = try await store.events(since: .distantPast, limit: 700)
        #expect(stored.count == 600)
    }
}
