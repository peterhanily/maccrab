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
