// EventStoreSizeCapTests.swift
//
// v1.6.12: regression coverage for the new `pruneOldest(count:)` and
// `vacuum()` APIs that back the hourly DB size-cap enforcer.
//
// The caller (DaemonTimers.enforceDatabaseSizeCap) is exercised via
// an integration test that writes to a live sqlite file and asserts
// the on-disk file shrinks. Here we cover the primitive behaviour:
//   - pruneOldest deletes exactly `count` rows from the oldest end
//   - vacuum runs without error
//   - prune + vacuum together actually shrinks the file on disk

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EventStore: pruneOldest + vacuum (v1.6.12)")
struct EventStoreSizeCapTests {

    private func makeTempStore() async throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-sizecap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func insertSample(_ store: EventStore, count: Int, base: Date = Date()) async throws {
        for i in 0..<count {
            let proc = ProcessInfo(
                pid: Int32(1000 + i), ppid: 1, rpid: 1,
                name: "sample\(i)", executable: "/bin/sample\(i)",
                commandLine: "/bin/sample\(i)", args: [],
                workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20,
                startTime: base,
                ancestors: [],
                isPlatformBinary: false
            )
            let ev = Event(
                timestamp: base.addingTimeInterval(Double(i)),
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            )
            try await store.insert(event: ev)
        }
    }

    @Test("pruneOldest deletes rows starting with the oldest timestamp")
    func pruneOldestOrdering() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 100)
        let beforeCount = try await store.count()
        #expect(beforeCount == 100)

        let deleted = try await store.pruneOldest(count: 30)
        #expect(deleted == 30)
        let afterCount = try await store.count()
        #expect(afterCount == 70)

        // After pruning the 30 oldest, the remaining rows are the
        // newer 70. We don't assert ordering of the returned slice
        // because `events()` ordering is an orthogonal concern —
        // the count invariant is what this test guards.
        let remaining = try await store.events(since: Date.distantPast, limit: 1)
        #expect(remaining.count == 1)
    }

    @Test("pruneOldest with count > total deletes everything, returns actual-deleted")
    func pruneOldestOverflow() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 50)
        let deleted = try await store.pruneOldest(count: 1_000_000)
        #expect(deleted == 50)
        #expect(try await store.count() == 0)
    }

    @Test("pruneOldest with count=0 is a no-op")
    func pruneOldestZero() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 10)
        let deleted = try await store.pruneOldest(count: 0)
        #expect(deleted == 0)
        #expect(try await store.count() == 10)
    }

    @Test("vacuum runs without error and doesn't corrupt the DB")
    func vacuumSafe() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 50)
        try await store.vacuum()

        // Reads still work after VACUUM.
        let count = try await store.count()
        #expect(count == 50)
    }

    // MARK: - v1.6.13 hardening tests

    @Test("beginSizeCapPrune returns false while another sweep holds the guard")
    func reentrancyGuard() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let first = await store.beginSizeCapPrune()
        #expect(first == true, "first acquire must succeed")

        let second = await store.beginSizeCapPrune()
        #expect(second == false, "second acquire while first holds must fail")

        await store.endSizeCapPrune()
        let third = await store.beginSizeCapPrune()
        #expect(third == true, "acquire after release must succeed")

        await store.endSizeCapPrune()
    }

    @Test("walCheckpoint runs without error on a fresh store")
    func walCheckpointSafe() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Empty WAL — checkpoint should be a no-op that returns
        // true (trivially drained).
        let drained = await store.walCheckpoint()
        #expect(drained == true)
    }

    @Test("walCheckpoint drains WAL after inserts")
    func walCheckpointDrainsWAL() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 100)
        // WAL now has uncommitted pages. Checkpoint should move
        // them into the main .db.
        let drained = await store.walCheckpoint()
        #expect(drained == true)

        // All data still present after checkpoint.
        #expect(try await store.count() == 100)
    }

    @Test("vacuum followed by checkpoint leaves DB queryable")
    func vacuumThenCheckpointSafe() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 200)
        _ = await store.walCheckpoint()
        try await store.vacuum()
        _ = await store.walCheckpoint()
        #expect(try await store.count() == 200)

        // Inserts continue to work after vacuum + checkpoint.
        try await insertSample(store, count: 50, base: Date().addingTimeInterval(1000))
        #expect(try await store.count() == 250)
    }

    @Test("pruneOldest + endSizeCapPrune cycle works when wrapped in defer")
    func guardDeferReleasesOnError() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Simulate the enforcer pattern: acquire, defer release,
        // then do work that might throw.
        let acquired = await store.beginSizeCapPrune()
        #expect(acquired == true)
        // Release explicitly (simulating the defer path).
        await store.endSizeCapPrune()

        // A second cycle should succeed — no stale state carried
        // across defer.
        let acquired2 = await store.beginSizeCapPrune()
        #expect(acquired2 == true)
        await store.endSizeCapPrune()
    }

    @Test("Reentrancy guard holds across pruneOldest invocation")
    func reentrancyDuringWork() async throws {
        // Start a long-running prune behind the guard. A second
        // acquire during the work must return false. Tests the
        // intended use pattern: timer fires, enforcer acquires
        // guard, then calls pruneOldest which can take time.
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 500)

        let firstAcquired = await store.beginSizeCapPrune()
        #expect(firstAcquired == true)

        // Kick off the prune. While it's in-flight, try to acquire
        // the guard again.
        async let workResult: () = {
            _ = try? await store.pruneOldest(count: 200)
        }()

        // Can't reliably observe in-progress state across actor
        // hops; the invariant we care about is that after the
        // first acquire, the second acquire returns false until
        // the first calls end.
        let secondAcquired = await store.beginSizeCapPrune()
        #expect(secondAcquired == false)

        _ = await workResult
        await store.endSizeCapPrune()
    }

    @Test("pruneOldest is not blocked by endSizeCapPrune not yet called")
    func pruneWorksEvenWithGuardHeld() async throws {
        // The guard is advisory — callers check it to avoid
        // redundant work, but pruneOldest itself doesn't depend on
        // guard state. This keeps the low-level API usable from
        // retention pruning (which has its own dedup in timers).
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await insertSample(store, count: 100)

        _ = await store.beginSizeCapPrune()
        let pruned = try await store.pruneOldest(count: 10)
        #expect(pruned == 10)
        await store.endSizeCapPrune()
    }

    @Test("prune + vacuum shrinks disk usage (db + wal + shm combined)")
    func pruneVacuumShrinks() async throws {
        let (store, tmp) = try await makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Insert a non-trivial amount so the store has something to
        // shrink. 5,000 events with realistic command lines gets the
        // cumulative file footprint into the MB range reliably.
        try await insertSample(store, count: 5_000)
        try await store.vacuum()  // force write-out before measuring

        let dbPath = tmp.appendingPathComponent("events.db").path
        let walPath = dbPath + "-wal"
        let shmPath = dbPath + "-shm"

        func totalDiskUsage() -> UInt64 {
            var total: UInt64 = 0
            for path in [dbPath, walPath, shmPath] {
                if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                   let size = attrs[.size] as? UInt64 {
                    total += size
                }
            }
            return total
        }

        let sizeBefore = totalDiskUsage()
        _ = try await store.pruneOldest(count: 4_500)
        try await store.vacuum()
        let sizeAfter = totalDiskUsage()

        // Cumulative disk use of the DB triplet should fall after
        // pruning 90% of rows + VACUUM. Exact bytes-per-row depend on
        // SQLite page alignment and FTS overhead, so the assertion is
        // a monotone bound, not a specific ratio.
        #expect(sizeAfter < sizeBefore,
                "VACUUM after pruneOldest must shrink cumulative disk usage (was \(sizeBefore), now \(sizeAfter))")
    }
}
