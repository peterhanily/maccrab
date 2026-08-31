// JournalIndexExpiryRefreshTests.swift
//
// v1.21.6-rc.45: a journal expiry must not force a full index rebuild.
//
// THE BLOCKER THIS PINS (measured on an installed rc.44 host, 2026-08-30):
// with the dashboard window open, its 5-second poll cost MORE than five seconds
// of CPU, so the app never left the read path. All 33 microstackshots in the
// OS-generated cpu_resource.diag rooted at `EventStore.exactEventsSnapshot`,
// descending into JSONDecoder -> Event.init(from:). One `fs_usage` sample caught
// 52,188 preads in 3 seconds, touching 9,663 distinct pages at a 5.4x re-read
// factor — to serve a request for the newest 200 rows. Window closed: 0.0% CPU.
//
// CAUSE. The cheap append-only refresh required
//     blockCount > journalIndexedBlockCount        // a NET count
//  && minimumBlockID == journalIndexedMinimumBlockID
// Both fail as soon as the journal expires anything: the net count can be flat
// while the tail grows, and the minimum advances on every expiry. Under the
// 15-minute retention floor, expiry is continuous — so the fast path was
// essentially never taken and every read rebuilt the whole index.
//
// FIX. An advanced minimum now evicts the expired entries
// (`compactJournalIndex(below:)`) and the append scan continues. The writer
// already had this compaction in `expireJournalBlocks`, keyed on the tombstones
// it created; a read-only handle learns of expiry only as a raised
// `journal_min_block_id`, so it needs the threshold form.
//
// FAIL-WITHOUT / PASS-WITH: restore either clause of the old gate and
// `expiryDoesNotForceAFullRebuild` fails — the append counter stays at zero and
// full rebuilds climb with every read.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Journal index survives expiry (v1.21.6-rc.45)")
struct JournalIndexExpiryRefreshTests {

    private func makeStore() throws -> (EventStore, URL) {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-idxexpiry-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return (try EventStore(directory: dir.path), dir)
    }

    private func event(_ i: Int, at ts: Date) -> Event {
        let proc = ProcessInfo(
            pid: Int32(4000 + i), ppid: 1, rpid: 1,
            name: "idxexp\(i)", executable: "/bin/idxexp\(i)",
            commandLine: "/bin/idxexp\(i)", args: [],
            workingDirectory: "/", userId: 501, userName: "t", groupId: 20,
            startTime: ts, ancestors: [], isPlatformBinary: false
        )
        return Event(
            timestamp: ts, eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    @Test("expiry does not force a full rebuild")
    func expiryDoesNotForceAFullRebuild() async throws {
        let (writer, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        // The defect is about a SEPARATE read-only handle — the dashboard
        // observing the daemon's journal. A writer keeps its own index warm
        // inline, so its topology generation already matches and it never even
        // enters the refresh. Reproduce the real shape.
        let now = Date()
        for i in 0..<400 {
            try await writer.insert(event: event(i, at: now.addingTimeInterval(-3600 - Double(i))))
        }
        _ = await writer.walCheckpoint()

        let reader = try EventStore(directory: dir.path, forceReadOnly: true)
        _ = try await reader.exactEventsSnapshot(since: .distantPast, limit: 10)
        let base = await reader.journalIndexRefreshDiagnostics()
        #expect(base.fullRebuilds >= 1, "the reader's first read must build its index")

        // Expire a prefix AND append a tail — the exact combination the old gate
        // refused, and the one a live engine produces continuously.
        let expired = try await writer.expireJournalBlocks(
            retainedThrough: now.addingTimeInterval(30 * 24 * 3600),
            maximumBlocks: 4
        )
        #expect(expired > 0, "fixture must actually expire blocks")
        for i in 400..<460 {
            try await writer.insert(event: event(i, at: now.addingTimeInterval(Double(i))))
        }
        _ = await writer.walCheckpoint()

        _ = try await reader.exactEventsSnapshot(since: .distantPast, limit: 10)
        let after = await reader.journalIndexRefreshDiagnostics()

        #expect(
            after.appendRefreshes > base.appendRefreshes,
            "an expiry alongside appends must take the append path, not rebuild the world"
        )
        #expect(
            after.fullRebuilds == base.fullRebuilds,
            "no full rebuild should have been needed (rebuilds went \(base.fullRebuilds) -> \(after.fullRebuilds))"
        )
    }

    @Test("the surviving corpus is still exactly readable after eviction")
    func survivingCorpusStaysReadable() async throws {
        let (writer, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let now = Date()
        for i in 0..<300 {
            try await writer.insert(event: event(i, at: now.addingTimeInterval(-3600 - Double(i))))
        }
        _ = await writer.walCheckpoint()
        let store = try EventStore(directory: dir.path, forceReadOnly: true)
        _ = try await store.exactEventsSnapshot(since: .distantPast, limit: 5)

        _ = try await writer.expireJournalBlocks(
            retainedThrough: now.addingTimeInterval(30 * 24 * 3600),
            maximumBlocks: 3
        )
        for i in 300..<340 {
            try await writer.insert(event: event(i, at: now.addingTimeInterval(Double(i))))
        }
        _ = await writer.walCheckpoint()

        // The critical correctness property: the snapshot must still be a
        // COMPLETE exact corpus. Eviction that lost or duplicated a live entry
        // would surface here rather than as a silent evidence gap.
        let snapshot = try await store.exactEventsSnapshot(since: .distantPast, limit: 5_000)
        #expect(
            snapshot.isComplete,
            "the exact corpus must stay complete across an evict-then-append refresh"
        )
        #expect(!snapshot.events.isEmpty)

        // And a second pass must agree with the first — a corrupted index
        // typically diverges on the next refresh.
        let again = try await store.exactEventsSnapshot(since: .distantPast, limit: 5_000)
        #expect(again.isComplete)
        #expect(again.events.count == snapshot.events.count)
    }

    @Test("everything expiring falls back to a rebuild rather than a bad append")
    func totalExpiryRebuilds() async throws {
        let (writer, dir) = try makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }

        let now = Date()
        for i in 0..<120 {
            try await writer.insert(event: event(i, at: now.addingTimeInterval(-3600 - Double(i))))
        }
        _ = await writer.walCheckpoint()
        let store = try EventStore(directory: dir.path, forceReadOnly: true)
        _ = try await store.exactEventsSnapshot(since: .distantPast, limit: 5)
        let base = await store.journalIndexRefreshDiagnostics()

        // Expire everything, then append.
        _ = try await writer.expireJournalBlocks(
            retainedThrough: now.addingTimeInterval(30 * 24 * 3600),
            maximumBlocks: 8_192
        )
        for i in 200..<240 {
            try await writer.insert(event: event(i, at: now.addingTimeInterval(Double(i))))
        }
        _ = await writer.walCheckpoint()

        let snapshot = try await store.exactEventsSnapshot(since: .distantPast, limit: 5_000)
        #expect(snapshot.isComplete, "a total-expiry refresh must still yield a complete corpus")
        let after = await store.journalIndexRefreshDiagnostics()
        #expect(
            after.fullRebuilds > base.fullRebuilds,
            "with no surviving indexed base there is nothing to append onto; rebuild is correct"
        )
    }
}
