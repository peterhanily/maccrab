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
}
