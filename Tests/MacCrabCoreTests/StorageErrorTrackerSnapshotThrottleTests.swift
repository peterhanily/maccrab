// StorageErrorTrackerSnapshotThrottleTests.swift
// v1.22.7: `storage_errors.json` is published at most once per second, written
// atomically through SecureFileIO (same-directory temporary + rename, O_NOFOLLOW
// at every component), and never awaited inline by a recording call. Before
// this every recorded failure rewrote the file inline with a non-atomic
// `Data.write(to:)` — ~52 writes/s observed during a storage write pause.
//
// Every test here builds its own tracker against a private temporary path, so
// the production singleton (and the `.serialized` escalation suite that drives
// it) is untouched. Clocks are injected; only the one test that proves the
// production trailing timer waits on wall time, and it is bounded.

import Testing
import Foundation
@testable import MacCrabAgentKit
@testable import MacCrabCore

@Suite("StorageErrorTracker: snapshot throttle + atomic publish (v1.22.7)")
struct StorageErrorTrackerSnapshotThrottleTests {

    private static let anchor = Date(timeIntervalSince1970: 1_790_000_000)

    private struct Fixture {
        let directory: URL
        let path: String
        let tracker: StorageErrorTracker

        func removeDirectory() {
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private func makeFixture() throws -> Fixture {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-storage-errors-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("storage_errors.json").path
        return Fixture(directory: directory, path: path, tracker: StorageErrorTracker(snapshotPath: path))
    }

    private func readSnapshot(_ path: String) throws -> [String: Any] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func diskIOError() -> Error {
        EventStoreError.stepFailed("disk I/O error")
    }

    @Test("a burst of 500 failures produces at most 2 publishes and the final counts land")
    func burstCoalescesToTwoPublishes() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        // 500 failures inside half a second: the first publishes at once, the
        // rest only mark the snapshot dirty and arm one trailing publish.
        for i in 0..<500 {
            await f.tracker.recordEventError(
                diskIOError(), now: Self.anchor.addingTimeInterval(Double(i) * 0.001))
        }
        let publishedDuringBurst = await f.tracker.snapshotPublishCount
        let coalesced = await f.tracker.snapshotPublishesCoalesced
        #expect(publishedDuringBurst == 1, "got \(publishedDuringBurst)")
        #expect(coalesced == 499, "got \(coalesced)")

        // The trailing publish (here driven as if its second had elapsed) must
        // land the burst's final counts, and nothing more.
        await f.tracker.flushTrailingSnapshotForTesting(now: Self.anchor.addingTimeInterval(1.0))
        let published = await f.tracker.snapshotPublishCount
        #expect(published == 2, "got \(published)")

        await f.tracker.awaitSnapshotWritesForTesting()
        let snapshot = try readSnapshot(f.path)
        #expect(snapshot["event_insert_errors"] as? Int == 500)
        #expect(snapshot["last_error_kind"] as? String == "event_insert")
        #expect(snapshot["last_error_at_unix"] as? Double == Self.anchor.addingTimeInterval(Double(499) * 0.001).timeIntervalSince1970)
    }

    /// Benchmark-style, deterministic, no sleeps: a synthetic failure storm at
    /// 500/s for 10 simulated seconds. The zero-loss property is that every
    /// failure is counted; the throughput property is that the file is
    /// published at most once per simulated second regardless of the storm
    /// rate. Before v1.22.7 the same storm issued 5_000 inline file writes.
    @Test("synthetic storm: 5_000 failures over 10 simulated seconds publish once per second and lose no count")
    func stormPublishesOncePerSecond() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        let count = 5_000
        let span = 10.0
        for i in 0..<count {
            await f.tracker.recordEventError(
                diskIOError(),
                now: Self.anchor.addingTimeInterval(Double(i) * span / Double(count)))
        }
        let publishedByRecordings = await f.tracker.snapshotPublishCount
        let coalesced = await f.tracker.snapshotPublishesCoalesced
        #expect(publishedByRecordings + coalesced == count,
                "every recording is either published or coalesced")
        await f.tracker.flushTrailingSnapshotForTesting(now: Self.anchor.addingTimeInterval(span + 1))
        let published = await f.tracker.snapshotPublishCount
        // One publish per simulated second (the record that crosses the due
        // time publishes on its own clock) plus the trailing publish.
        #expect(published == publishedByRecordings + 1)
        #expect(published >= Int(span), "got \(published)")
        #expect(published <= Int(span) + 2, "got \(published)")

        await f.tracker.awaitSnapshotWritesForTesting()
        let snapshot = try readSnapshot(f.path)
        #expect(snapshot["event_insert_errors"] as? Int == count)
    }

    @Test("alert-insert failures share the same throttle")
    func alertErrorsThrottled() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        for _ in 0..<100 {
            await f.tracker.recordAlertError(diskIOError())
        }
        let published = await f.tracker.snapshotPublishCount
        #expect(published == 1, "got \(published)")
        await f.tracker.flushTrailingSnapshotForTesting(now: Date().addingTimeInterval(2))
        await f.tracker.awaitSnapshotWritesForTesting()
        let snapshot = try readSnapshot(f.path)
        #expect(snapshot["alert_insert_errors"] as? Int == 100)
        #expect(snapshot["last_error_kind"] as? String == "alert_insert")
    }

    @Test("the production trailing timer lands the last write of a burst on its own")
    func trailingTimerLandsFinalWrite() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        let now = Date()
        for i in 0..<50 {
            await f.tracker.recordEventError(diskIOError(), now: now.addingTimeInterval(Double(i) * 0.001))
        }
        var published = await f.tracker.snapshotPublishCount
        #expect(published == 1)
        // Bounded wait: the trailing publish is due one second after the first
        // publish; allow generous scheduling slack but never spin forever.
        for _ in 0..<60 where published < 2 {
            try await Task.sleep(for: .milliseconds(50))
            published = await f.tracker.snapshotPublishCount
        }
        #expect(published == 2, "the trailing publish must fire without a further recording")
        await f.tracker.awaitSnapshotWritesForTesting()
        let snapshot = try readSnapshot(f.path)
        #expect(snapshot["event_insert_errors"] as? Int == 50)
    }

    @Test("the snapshot is published atomically: regular file, world-readable, no temporary left behind")
    func publishIsAtomic() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        await f.tracker.recordEventError(diskIOError(), now: Self.anchor)
        await f.tracker.recordEventError(diskIOError(), now: Self.anchor.addingTimeInterval(1.5))
        await f.tracker.awaitSnapshotWritesForTesting()

        var metadata = stat()
        #expect(lstat(f.path, &metadata) == 0)
        #expect((metadata.st_mode & S_IFMT) == S_IFREG)
        #expect(metadata.st_mode & 0o777 == 0o644, "the non-root dashboard polls this file")
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: f.directory.path)
            .filter { $0.hasPrefix(".maccrab-write-") }
        #expect(leftovers.isEmpty, "staging temporaries must be renamed or removed: \(leftovers)")
        let snapshot = try readSnapshot(f.path)
        #expect(snapshot["event_insert_errors"] as? Int == 2)
    }

    @Test("a symlink planted at the snapshot path is refused, never followed")
    func symlinkLeafRefused() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        let victim = f.directory.appendingPathComponent("victim.txt")
        try Data("untouched".utf8).write(to: victim)
        try FileManager.default.createSymbolicLink(
            atPath: f.path, withDestinationPath: victim.path)

        await f.tracker.recordEventError(diskIOError(), now: Self.anchor)
        await f.tracker.awaitSnapshotWritesForTesting()

        #expect(try String(contentsOf: victim, encoding: .utf8) == "untouched")
        var metadata = stat()
        #expect(lstat(f.path, &metadata) == 0)
        #expect((metadata.st_mode & S_IFMT) == S_IFLNK, "the symlink must still be a symlink")
    }

    @Test("refreshSnapshot publishes the rolling (empty) counters at boot")
    func refreshPublishesAtBoot() async throws {
        let f = try makeFixture()
        defer { f.removeDirectory() }

        await f.tracker.refreshSnapshot(now: Self.anchor)
        await f.tracker.awaitSnapshotWritesForTesting()
        let snapshot = try readSnapshot(f.path)
        #expect(snapshot["event_insert_errors"] as? Int == 0)
        #expect(snapshot["alert_insert_errors"] as? Int == 0)
        #expect(snapshot["window_hours"] as? Int == 24)
    }
}
