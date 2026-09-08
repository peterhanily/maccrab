// IncrementalVacuumTests.swift
//
// Wave 9B (v1.12.6): exercise the per-store `incrementalVacuum(maxPages:)`
// helpers that back the low-disk size-cap fallback in DaemonTimers.
//
// `PRAGMA incremental_vacuum(N)` reclaims freelist pages from the END
// of the SQLite file by truncating in place. Unlike full VACUUM it
// avoids a whole-file scratch copy. Its WAL and checkpoint still need
// temporary headroom, which persistent callers must admit separately.
//
// Contract pinned here:
//   1. When `auto_vacuum = INCREMENTAL` is active on the file, the
//      helper reclaims freelist pages and the on-disk file size
//      drops in place.
//   2. The helper short-circuits cleanly when `auto_vacuum != 2`
//      (returns 0, no thrown error). This is the gap behaviour
//      for stores whose init writes to the DB header before
//      setting auto_vacuum.
//   3. The `maxPages` parameter caps the page reclaim per call so
//      one sweep can never stall the actor for too long.
//   4. The shared `StoragePragmas.runIncrementalVacuum` correctly
//      detects the runtime auto_vacuum mode and performs no implicit
//      WAL checkpoint; persistent callers own the path/floor-aware gates.
//
// `pragmaOrderMatters` preserves the regression control: WAL first yields
// mode 0. Production now sets auto_vacuum first, and fresh-store tests
// require mode 2. Older existing files can still retain mode 0.

import Testing
import Foundation
import Darwin
import CSQLCipher
@testable import MacCrabCore

// MARK: - Helpers

/// Read `PRAGMA page_count` via a separate connection. Used by
/// tests to observe the on-disk-pages metric without poking at
/// store internals.
private func pageCount(at path: String) -> Int {
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
          let db else { return 0 }
    defer { sqlite3_close(db) }
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, "PRAGMA page_count", -1, &stmt, nil) == SQLITE_OK,
          let stmt else { return 0 }
    defer { sqlite3_finalize(stmt) }
    guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
    return Int(sqlite3_column_int(stmt, 0))
}

private func freelistCount(at path: String) -> Int {
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
          let db else { return 0 }
    defer { sqlite3_close(db) }
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, "PRAGMA freelist_count", -1, &stmt, nil) == SQLITE_OK,
          let stmt else { return 0 }
    defer { sqlite3_finalize(stmt) }
    guard sqlite3_step(stmt) == SQLITE_ROW else { return 0 }
    return Int(sqlite3_column_int(stmt, 0))
}

private func autoVacuumModeAtPath(_ path: String) -> Int {
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
          let db else { return -1 }
    defer { sqlite3_close(db) }
    return Int(StoragePragmas.readAutoVacuumMode(db))
}

private func fileSize(at path: String) -> Int64 {
    let attrs = try? FileManager.default.attributesOfItem(atPath: path)
    return (attrs?[.size] as? Int64) ?? 0
}

/// Build a sqlite file with `auto_vacuum = INCREMENTAL` correctly
/// applied (PRAGMA *before* any header write). Returns the path.
/// Caller is responsible for cleanup. Used to exercise the
/// incremental_vacuum primitive against a mode-2 DB regardless of
/// any pre-existing store-init bug.
private func makeIncrementalDB(at directory: URL, name: String) -> String {
    let path = directory.path + "/\(name).db"
    var db: OpaquePointer?
    sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
    // auto_vacuum MUST come before any other PRAGMA that dirties the
    // file header (journal_mode = WAL is the usual culprit).
    sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
    sqlite3_exec(db, "PRAGMA journal_mode = WAL", nil, nil, nil)
    sqlite3_exec(db, "CREATE TABLE blobs (id INTEGER PRIMARY KEY, payload BLOB)", nil, nil, nil)
    // Insert enough blobs to build a real freelist when we delete.
    sqlite3_exec(db, "BEGIN TRANSACTION", nil, nil, nil)
    for i in 0..<500 {
        let sql = "INSERT INTO blobs (id, payload) VALUES (\(i), zeroblob(4096))"
        sqlite3_exec(db, sql, nil, nil, nil)
    }
    sqlite3_exec(db, "COMMIT", nil, nil, nil)
    // Delete most of them so we have a substantial freelist after
    // checkpoint.
    sqlite3_exec(db, "DELETE FROM blobs WHERE id < 400", nil, nil, nil)
    // Checkpoint so the deleted pages land on the freelist of the
    // main file rather than living in the WAL.
    var log: Int32 = 0
    var ckpt: Int32 = 0
    _ = sqlite3_wal_checkpoint_v2(db, nil, Int32(SQLITE_CHECKPOINT_TRUNCATE), &log, &ckpt)
    sqlite3_close(db)
    return path
}

// MARK: - Shared helper (StoragePragmas.runIncrementalVacuum)

@Suite("StoragePragmas.runIncrementalVacuum (Wave 9B)")
struct StoragePragmasIncrementalVacuumTests {

    @Test("Hard cap of 200_000 pages is enforced")
    func enforcesHardCap() async throws {
        #expect(StoragePragmas.incrementalVacuumHardCap == 200_000)
    }

    @Test("Incremental-vacuum errors preserve SQLite rc and VFS errno")
    func errorPreservesStorageFailureMetadata() {
        for metadata in [
            SQLiteFailureMetadata(
                resultCode: SQLITE_FULL,
                extendedResultCode: SQLITE_FULL,
                systemErrno: 0
            ),
            SQLiteFailureMetadata(
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR | Int32(3 << 8),
                systemErrno: ENOSPC
            ),
            SQLiteFailureMetadata(
                resultCode: SQLITE_IOERR,
                extendedResultCode: SQLITE_IOERR | Int32(4 << 8),
                systemErrno: EDQUOT
            ),
        ] {
            let error = StoragePragmas.IncrementalVacuumError.sqliteFailure(
                context: "injected", message: "disk exhausted", metadata: metadata)
            #expect(error.sqliteFailureMetadata == metadata)
            #expect(error.sqliteFailureMetadata.isStorageExhaustion)
            #expect(error.localizedDescription.contains("system_errno="))
        }
    }

    @Test("readAutoVacuumMode returns 0 for NONE, 2 for INCREMENTAL")
    func readsAutoVacuumMode() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-shared-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let noneDB = tmp.path + "/none.db"
        let incDB = tmp.path + "/inc.db"

        var dbN: OpaquePointer?
        sqlite3_open_v2(noneDB, &dbN, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        sqlite3_exec(dbN, "PRAGMA auto_vacuum = NONE", nil, nil, nil)
        sqlite3_exec(dbN, "CREATE TABLE t (id INTEGER PRIMARY KEY)", nil, nil, nil)
        if let dbN { #expect(StoragePragmas.readAutoVacuumMode(dbN) == 0) }
        sqlite3_close(dbN)

        var dbI: OpaquePointer?
        sqlite3_open_v2(incDB, &dbI, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        sqlite3_exec(dbI, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        sqlite3_exec(dbI, "CREATE TABLE t (id INTEGER PRIMARY KEY)", nil, nil, nil)
        if let dbI { #expect(StoragePragmas.readAutoVacuumMode(dbI) == 2) }
        sqlite3_close(dbI)
    }

    @Test("Reclaims freelist pages in place when INCREMENTAL is active")
    func reclaimsPagesInPlace() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-reclaim-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let path = makeIncrementalDB(at: tmp, name: "reclaim")
        #expect(autoVacuumModeAtPath(path) == 2, "fixture must be in INCREMENTAL mode")

        let pagesBefore = pageCount(at: path)
        let freelistBefore = freelistCount(at: path)
        let sizeBefore = fileSize(at: path)
        #expect(freelistBefore > 0, "fixture should leave a populated freelist")

        var db: OpaquePointer?
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil)
        guard let db else {
            Issue.record("failed to reopen DB")
            return
        }
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: 10_000)
        sqlite3_close(db)

        #expect(result.autoVacuumActive == true)
        #expect(result.pagesReclaimed > 0)
        #expect(result.pagesReclaimed == freelistBefore - result.freelistAfter)

        let pagesAfter = pageCount(at: path)
        let sizeAfter = fileSize(at: path)
        #expect(pagesAfter < pagesBefore, "page_count must drop")
        #expect(sizeAfter < sizeBefore, "on-disk file size must shrink")
    }

    @Test("Respects maxPages parameter")
    func respectsMaxPagesCap() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-cap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let path = makeIncrementalDB(at: tmp, name: "cap")
        let freelistBefore = freelistCount(at: path)
        #expect(freelistBefore > 20, "need a freelist big enough to cap meaningfully")

        var db: OpaquePointer?
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil)
        guard let db else {
            Issue.record("failed to reopen DB")
            return
        }
        let cap = 10
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: cap)
        sqlite3_close(db)

        #expect(result.pagesReclaimed <= cap)
        #expect(result.pagesReclaimed > 0)
        // After capping at `cap`, the remainder of the freelist should
        // still be on the file.
        let freelistAfter = freelistCount(at: path)
        #expect(freelistAfter == freelistBefore - result.pagesReclaimed)
    }

    @Test("No-op when freelist is empty")
    func noopOnEmptyFreelist() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-empty-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let path = tmp.path + "/empty.db"
        var db: OpaquePointer?
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
        sqlite3_exec(db, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(db, "CREATE TABLE t (id INTEGER PRIMARY KEY)", nil, nil, nil)
        // Insert a row but don't delete — freelist stays empty.
        sqlite3_exec(db, "INSERT INTO t (id) VALUES (1)", nil, nil, nil)
        guard let db else {
            Issue.record("failed to open DB")
            return
        }
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: 10_000)
        sqlite3_close(db)

        #expect(result.autoVacuumActive == true)
        #expect(result.pagesReclaimed == 0)
    }

    @Test("Short-circuits cleanly on auto_vacuum != INCREMENTAL")
    func shortCircuitsOnGap() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-shortcircuit-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let noneDB = tmp.path + "/none.db"
        var db: OpaquePointer?
        sqlite3_open_v2(noneDB, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        sqlite3_exec(db, "PRAGMA auto_vacuum = NONE", nil, nil, nil)
        sqlite3_exec(db, "PRAGMA journal_mode = WAL", nil, nil, nil)
        sqlite3_exec(db, "CREATE TABLE t (id INTEGER PRIMARY KEY, b BLOB)", nil, nil, nil)
        // Populate then delete so there ARE free pages — the helper
        // should still skip because mode != INCREMENTAL.
        for i in 0..<100 {
            let sql = "INSERT INTO t (id, b) VALUES (\(i), zeroblob(4000))"
            sqlite3_exec(db, sql, nil, nil, nil)
        }
        sqlite3_exec(db, "DELETE FROM t WHERE id < 80", nil, nil, nil)

        guard let db else {
            Issue.record("failed to open temp DB")
            return
        }
        let result = try StoragePragmas.runIncrementalVacuum(on: db, maxPages: 1_000)
        sqlite3_close(db)
        #expect(result.autoVacuumActive == false)
        #expect(result.pagesReclaimed == 0)
    }

    /// Preserve both ordering outcomes: WAL first leaves mode 0; production's
    /// auto_vacuum-first ordering creates mode 2. Setting the pragma later
    /// cannot convert an existing populated mode-0 file without a rebuild.
    @Test("PRAGMA order pin: auto_vacuum after journal_mode yields mode 0")
    func pragmaOrderMatters() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-pragma-order-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        func openAndProbe(_ ops: (OpaquePointer) -> Void) -> Int32 {
            let path = tmp.path + "/\(UUID().uuidString).db"
            var db: OpaquePointer?
            sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
            defer { sqlite3_close(db) }
            if let db { ops(db) }
            guard let db else { return -1 }
            return StoragePragmas.readAutoVacuumMode(db)
        }

        let modeWALFirst = openAndProbe { db in
            sqlite3_exec(db, "PRAGMA journal_mode = WAL", nil, nil, nil)
            sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
            sqlite3_exec(db, "CREATE TABLE t (id INTEGER)", nil, nil, nil)
        }
        let modeAutoFirst = openAndProbe { db in
            sqlite3_exec(db, "PRAGMA auto_vacuum = INCREMENTAL", nil, nil, nil)
            sqlite3_exec(db, "PRAGMA journal_mode = WAL", nil, nil, nil)
            sqlite3_exec(db, "CREATE TABLE t (id INTEGER)", nil, nil, nil)
        }
        #expect(modeAutoFirst == 2)
        #expect(modeWALFirst == 0)
    }
}

// MARK: - EventStore

@Suite("EventStore: incrementalVacuum (Wave 9B)")
struct EventStoreIncrementalVacuumTests {

    private func makeStore() async throws -> (EventStore, URL, String) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-event-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp, tmp.path + "/events.db")
    }

    @Test("incrementalVacuum runs against mode 2 after Wave 9B.1 PRAGMA-order fix")
    func returnsZeroOnGapInit() async throws {
        // A fresh store uses INCREMENTAL but has no free pages to reclaim.
        let (store, tmp, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let mode = await store.autoVacuumMode()
        #expect(mode == 2)

        let reclaimed = try await store.incrementalVacuum(maxPages: 10_000)
        #expect(reclaimed == 0)
        #expect(FileManager.default.fileExists(atPath: path))
    }

    @Test("walCheckpoint and incrementalVacuum compose without error")
    func composesWithCheckpoint() async throws {
        let (store, tmp, _) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        await store.walCheckpoint()
        let r = try await store.incrementalVacuum(maxPages: 1_000)
        await store.walCheckpoint()
        #expect(r >= 0)
    }

    /// Generic low-disk pruning owns only unmigrated legacy rows in rc.13.
    /// Fresh canonical blocks retain an absolute 15-minute durable-admission
    /// floor and may be removed only by authenticated whole-block expiry.
    @Test("Low-disk fallback preserves fresh journal, then expires eligible whole blocks")
    func lowDiskFallbackChain() async throws {
        let (store, tmp, _) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Source timestamps do not control the retention floor. These events
        // are fresh durable admissions even though their source time spans a
        // historical-looking range.
        let base = Date()
        for i in 0..<100 {
            let proc = ProcessInfo(
                pid: Int32(2000 + i), ppid: 1, rpid: 1,
                name: "lowdisk\(i)", executable: "/bin/lowdisk\(i)",
                commandLine: "/bin/lowdisk\(i)", args: [],
                workingDirectory: "/",
                userId: 501, userName: "t", groupId: 20,
                startTime: base, ancestors: [],
                isPlatformBinary: false
            )
            let ev = Event(
                timestamp: base.addingTimeInterval(Double(i)),
                eventCategory: .process, eventType: .start,
                eventAction: "exec", process: proc
            )
            try await store.insert(event: ev)
        }
        let pruned = try await store.pruneOldest(count: 70)
        #expect(pruned == 0)
        #expect(try await store.maintenanceRetainedRecordCount() == 100)

        // The low-disk physical-reclaim chain remains safe and queryable, but
        // it cannot manufacture headroom by deleting protected evidence.
        _ = await store.walCheckpoint()
        let reclaimed = try await store.incrementalVacuum(maxPages: 200_000)
        #expect(reclaimed >= 0)
        _ = await store.walCheckpoint()
        #expect(try await store.count() == 100)

        // Once the durable floor has elapsed, the journal-owned path expires
        // complete authenticated blocks and rolls every event into aggregates.
        let expired = try await store.expireJournalBlocks(
            retainedThrough: Date().addingTimeInterval(
                EventStore.journalRetentionSeconds + 1
            ),
            maximumBlocks: 4_096
        )
        #expect(expired == 100)
        #expect(try await store.count() == 0)
        #expect(try await store.maintenanceRetainedRecordCount() == 0)
        let aggregateCount = try await store.aggregates(
            sinceDay: "0000-00-00"
        ).reduce(0) { $0 + $1.count }
        #expect(aggregateCount == 100)
    }
}

// MARK: - AlertStore

@Suite("AlertStore: incrementalVacuum (Wave 9B)")
struct AlertStoreIncrementalVacuumTests {

    private func makeStore() throws -> (AlertStore, URL, String) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-alert-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tmp.path)
        return (store, tmp, tmp.path + "/alerts.db")
    }

    @Test("incrementalVacuum runs against mode 2 after Wave 9B.1 PRAGMA-order fix")
    func returnsZeroOnGapInit() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let mode = await store.autoVacuumMode()
        #expect(mode == 2)
        let reclaimed = try await store.incrementalVacuum(maxPages: 10_000)
        #expect(reclaimed == 0)
    }

    @Test("vacuum on AlertStore succeeds and leaves the file queryable")
    func vacuumWorks() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        try await store.vacuum()
        let countAfter = try await store.count()
        #expect(countAfter == 0)
    }
}

// MARK: - CampaignStore

@Suite("CampaignStore: incrementalVacuum (Wave 9B)")
struct CampaignStoreIncrementalVacuumTests {

    private func makeStore() throws -> (CampaignStore, URL, String) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-campaign-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let path = tmp.path + "/campaigns.db"
        let store = try CampaignStore(path: path)
        return (store, tmp, path)
    }

    @Test("incrementalVacuum runs against mode 2 after Wave 9B.1 PRAGMA-order fix")
    func returnsZeroOnGapInit() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let mode = await store.autoVacuumMode()
        #expect(mode == 2)
        let reclaimed = try await store.incrementalVacuum(maxPages: 1_000)
        #expect(reclaimed == 0)
    }

    @Test("vacuum on CampaignStore succeeds")
    func vacuumWorks() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        try await store.vacuum()
    }
}

// MARK: - TraceStore

@Suite("TraceStore: incrementalVacuum (Wave 9B)")
struct TraceStoreIncrementalVacuumTests {

    private func makeStore() throws -> (TraceStore, URL, String) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-trace-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let path = tmp.path + "/traces.db"
        let store = try TraceStore(path: path)
        return (store, tmp, path)
    }

    @Test("autoVacuumMode reports mode 2 (INCREMENTAL) after Wave 9B.1")
    func autoVacuumGapIsObserved() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let mode = await store.autoVacuumMode()
        // Fresh stores must preserve the corrected initialization order.
        #expect(mode == 2, "TraceStore: auto_vacuum=INCREMENTAL after Wave 9B.1")
    }

    @Test("Returns 0 when a fresh store has no reusable pages")
    func gracefulNoOpUnderGap() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let reclaimed = try await store.incrementalVacuum(maxPages: 10_000)
        #expect(reclaimed == 0)
    }
}

// MARK: - SQLiteCausalGraphStore

@Suite("SQLiteCausalGraphStore: incrementalVacuum (Wave 9B)")
struct SQLiteCausalGraphStoreIncrementalVacuumTests {

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL, String) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-incvac-causal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let path = tmp.path + "/tracegraph.db"
        let store = try await SQLiteCausalGraphStore(databasePath: path)
        return (store, tmp, path)
    }

    @Test("autoVacuumMode reports mode 2 (INCREMENTAL) after Wave 9B.1")
    func autoVacuumGapIsObserved() async throws {
        let (store, tmp, _) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let mode = await store.autoVacuumMode()
        // Fresh stores must preserve the corrected initialization order.
        #expect(mode == 2, "SQLiteCausalGraphStore: auto_vacuum=INCREMENTAL after Wave 9B.1")
    }

    @Test("Returns 0 when a fresh store has no reusable pages")
    func gracefulNoOpUnderGap() async throws {
        let (store, tmp, _) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let reclaimed = try await store.incrementalVacuum(maxPages: 10_000)
        #expect(reclaimed == 0)
    }
}
