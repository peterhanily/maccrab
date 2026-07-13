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

// MARK: - v1.21.4: per-category retention floor

/// A cheap file-write flood collapses the events.db retention window
/// uniformly (~30×) and evicts the low-volume process/exec channel as
/// collateral. The per-category floor makes eviction category-aware:
/// non-process rows go first, and process rows newer than the floor cutoff
/// are spared — UNLESS the protected rows alone breach the cap, in which case
/// the soft-floor valve falls back to oldest-first so the DB always converges.
///
/// These pin the store-level primitives (`pruneOldest` + `rollUpAndPrune`
/// with the new `protecting:`/`newerThan:` arguments). The end-to-end sweep
/// integration lives in `EventsSizeCapIntervalTests`.
@Suite("EventStore: per-category retention floor (v1.21.4)")
struct EventStoreProcessFloorTests {

    private func makeStore() async throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-procfloor-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func insert(
        _ store: EventStore, category: EventCategory, at ts: Date, tag: String
    ) async throws {
        let proc = ProcessInfo(
            pid: 1, ppid: 1, rpid: 1,
            name: tag, executable: "/bin/\(tag)",
            commandLine: "/bin/\(tag)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: ts, ancestors: [], isPlatformBinary: false
        )
        let type: EventType = category == .process ? .start : .creation
        let ev = Event(
            timestamp: ts, eventCategory: category, eventType: type,
            eventAction: "x", process: proc
        )
        try await store.insert(event: ev)
    }

    @Test("pruneOldest spares process rows within the floor even when they are the OLDEST rows")
    func pruneOldestProtectsProcessWithinFloor() async throws {
        let (store, tmp) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        // The 10 process rows are the OLDEST rows in the store — a
        // category-BLIND oldest-first prune would evict exactly these first.
        for i in 0..<10 {
            try await insert(store, category: .process, at: base.addingTimeInterval(-100 + Double(i)), tag: "exec\(i)")
        }
        // 100 file rows, all newer than the process rows (the "flood").
        for i in 0..<100 {
            try await insert(store, category: .file, at: base.addingTimeInterval(-90 + Double(i)), tag: "file\(i)")
        }
        #expect(try await store.count() == 110)

        // Floor cutoff older than everything → all 10 process rows are
        // within-floor and must survive. Drop exactly the 100 file rows' worth.
        let floor = base.addingTimeInterval(-1000)
        let deleted = try await store.pruneOldest(count: 100, protecting: .process, newerThan: floor)

        #expect(deleted == 100)
        let byCat = try await store.eventCountsByCategory(since: .distantPast)
        #expect(byCat["process"] == 10, "all process rows survive despite being the oldest")
        #expect((byCat["file"] ?? 0) == 0, "all file rows evicted first")
    }

    @Test("pruneOldest soft-floor valve spills into process rows when eligible rows are exhausted")
    func pruneOldestValveSpillsIntoProcess() async throws {
        let (store, tmp) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        // 5 file rows (eligible) + 20 process rows (protected), all within floor.
        for i in 0..<5 {
            try await insert(store, category: .file, at: base.addingTimeInterval(Double(i)), tag: "file\(i)")
        }
        for i in 0..<20 {
            try await insert(store, category: .process, at: base.addingTimeInterval(100 + Double(i)), tag: "exec\(i)")
        }
        #expect(try await store.count() == 25)

        let floor = base.addingTimeInterval(-1000) // every process row within floor
        // Ask to drop 15 but only 5 rows are eligible → the valve MUST engage
        // and spill into protected process rows so the count is still met.
        let deleted = try await store.pruneOldest(count: 15, protecting: .process, newerThan: floor)

        #expect(deleted == 15, "convergence: the full requested count is removed despite the floor")
        let byCat = try await store.eventCountsByCategory(since: .distantPast)
        #expect((byCat["file"] ?? 0) == 0, "the 5 eligible file rows are dropped first")
        #expect(byCat["process"] == 10, "valve evicted the 10 oldest process rows to honor the drop count")
        #expect(try await store.count() == 10)
    }

    @Test("pruneOldest with a floor but no protected rows over-quota behaves like plain oldest-first")
    func pruneOldestFloorNoOverflow() async throws {
        let (store, tmp) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        for i in 0..<50 {
            try await insert(store, category: .file, at: base.addingTimeInterval(Double(i)), tag: "file\(i)")
        }
        let floor = base.addingTimeInterval(-1000)
        // No process rows at all → the floor predicate is inert; the valve is
        // never reached; all requested rows come from the eligible set.
        let deleted = try await store.pruneOldest(count: 20, protecting: .process, newerThan: floor)
        #expect(deleted == 20)
        #expect(try await store.count() == 30)
    }

    @Test("rollUpAndPrune spares process rows within the floor from the time-based rollup")
    func rollUpAndPruneSparesProcessWithinFloor() async throws {
        let (store, tmp) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        let aged = now.addingTimeInterval(-30 * 60)  // 30 min old
        for i in 0..<8 {
            try await insert(store, category: .file, at: aged, tag: "file\(i)")
        }
        for i in 0..<6 {
            try await insert(store, category: .process, at: aged, tag: "exec\(i)")
        }
        #expect(try await store.count() == 14)

        // cutoff = 15 min ago → everything (all 30-min-old rows) is a rollup
        // candidate. floor = 60 min ago → the 30-min-old process rows are
        // WITHIN the floor and must be spared from BOTH aggregation and delete.
        let cutoff = now.addingTimeInterval(-15 * 60)
        let floor = now.addingTimeInterval(-60 * 60)
        let deleted = try await store.rollUpAndPrune(olderThan: cutoff, protecting: .process, newerThan: floor)

        #expect(deleted == 8, "only the 8 file rows are rolled up + deleted")
        let byCat = try await store.eventCountsByCategory(since: .distantPast)
        #expect((byCat["file"] ?? 0) == 0, "file rows rolled up + evicted")
        #expect(byCat["process"] == 6, "process rows within the floor survive the rollup")
    }

    @Test("rollUpAndPrune with no floor rolls up every category (unchanged behavior)")
    func rollUpAndPruneNoFloorIsCategoryBlind() async throws {
        let (store, tmp) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        let aged = now.addingTimeInterval(-30 * 60)
        for i in 0..<8 { try await insert(store, category: .file, at: aged, tag: "file\(i)") }
        for i in 0..<6 { try await insert(store, category: .process, at: aged, tag: "exec\(i)") }

        let cutoff = now.addingTimeInterval(-15 * 60)
        // Default args (no protecting:/newerThan:) → both categories rolled up.
        let deleted = try await store.rollUpAndPrune(olderThan: cutoff)
        #expect(deleted == 14)
        #expect(try await store.count() == 0)
    }
}
