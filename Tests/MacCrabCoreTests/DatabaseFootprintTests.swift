// DatabaseFootprintTests.swift
//
// v1.6.14: the size-cap enforcer now measures `db + db-wal + db-shm`
// instead of just the main `.db` file, so the on-disk cap honors
// actual SQLite footprint. Previously a 480 MB main file + 40 MB
// WAL would present as 480 MB "under cap" while consuming 520 MB.

import Testing
import Foundation
@testable import MacCrabAgentKit

@Suite("measureDatabaseFootprintMB: db + wal + shm sum (v1.6.14)")
struct DatabaseFootprintTests {

    /// Missing files are treated as zero — callers use the enforcer's
    /// `> maxSizeMB` guard as a no-op signal, and the first call during
    /// startup measurement happens before the DB is even opened.
    @Test("returns 0 when no files exist")
    func missingFiles() {
        let tmp = NSTemporaryDirectory() + "MacCrabFootprint-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let mb = measureDatabaseFootprintMB(dbPath: tmp + "/events.db")
        #expect(mb == 0)
    }

    /// Main file only — behaves like pre-v1.6.14 measurement.
    @Test("sums main .db when no sidecars present")
    func mainFileOnly() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabFootprint-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let path = tmp + "/events.db"
        let bytes = Data(count: 5 * 1_000_000) // 5 MB
        try bytes.write(to: URL(fileURLWithPath: path))

        let mb = measureDatabaseFootprintMB(dbPath: path)
        #expect(mb == 5)
    }

    /// The key regression: a big WAL must count toward the footprint
    /// so the enforcer fires when the combined on-disk size is over cap.
    @Test("sums db + wal + shm")
    func sumsAllThree() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabFootprint-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let path = tmp + "/events.db"
        try Data(count: 10 * 1_000_000).write(to: URL(fileURLWithPath: path))
        try Data(count: 4 * 1_000_000).write(to: URL(fileURLWithPath: path + "-wal"))
        try Data(count: 1 * 1_000_000).write(to: URL(fileURLWithPath: path + "-shm"))

        let mb = measureDatabaseFootprintMB(dbPath: path)
        #expect(mb == 15)
    }

    /// v1.19 (S6-1/S6-2): the tracegraph/traces over-cap TRIP gates moved
    /// from `databaseSizeBytes()` (the bare .db file) to the db+WAL footprint.
    /// Field repro: a 213 MB tracegraph.db + a 64 MiB WAL is a 277 MB on-disk
    /// footprint that a file-only check (213 MB < 250 MB cap) never tripped, so
    /// the freelist/WAL was never reclaimed. The footprint trip math must fire.
    @Test("tracegraph trip math: db-only misses cap, db+WAL footprint trips it")
    func tracegraphFootprintTripsWhereFileOnlyMissed() throws {
        let tmp = NSTemporaryDirectory() + "MacCrabFootprint-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let path = tmp + "/tracegraph.db"
        // 213 MB main file (under the 250 MB cap on its own)…
        try Data(count: 213 * 1_000_000).write(to: URL(fileURLWithPath: path))
        // …plus a 64 MiB WAL pinned at journal_size_limit.
        try Data(count: 67_108_864).write(to: URL(fileURLWithPath: path + "-wal"))

        let capMB = 250
        // Old (buggy) behaviour: trip on the bare .db file size only.
        let fileOnlyMB = Int((try FileManager.default.attributesOfItem(atPath: path)[.size] as! Int64) / 1_000_000)
        #expect(fileOnlyMB == 213)
        #expect(fileOnlyMB <= capMB, "file-only size must NOT trip — that's the bug being fixed")

        // New behaviour: trip on the footprint (db + WAL + shm).
        let footprintMB = measureDatabaseFootprintMB(dbPath: path)
        #expect(footprintMB == 213 + 67, "213 MB db + 64 MiB (≈67 MB) WAL")
        #expect(footprintMB > capMB, "footprint must trip the cap so the freelist/WAL get reclaimed")
    }
}
