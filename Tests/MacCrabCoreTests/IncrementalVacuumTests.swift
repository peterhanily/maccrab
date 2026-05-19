// IncrementalVacuumTests.swift
//
// Wave 9B (v1.12.6): exercise the per-store `incrementalVacuum(maxPages:)`
// helpers that back the low-disk size-cap fallback in DaemonTimers.
//
// `PRAGMA incremental_vacuum(N)` reclaims freelist pages from the END
// of the SQLite file by truncating in place. Unlike full VACUUM it
// requires ZERO scratch disk, so the size-cap enforcer can call it
// even when the volume is too tight for a full file rewrite.
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
//      detects the runtime auto_vacuum mode and never throws on
//      a closed/read-only DB.
//
// Pre-existing observation pinned by `pragmaOrderMatters`: the
// current StoragePragmas order (journal_mode WAL FIRST, then
// auto_vacuum INCREMENTAL) yields mode 0 on this SQLite build —
// meaning all four production stores actually ship with mode 0
// auto_vacuum and the incrementalVacuum path is a no-op until
// either (a) the order is fixed on a future release with
// migrate-existing semantics, or (b) the operator runs
// `maccrabctl maintenance vacuum` to convert.

import Testing
import Foundation
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

    @Test("Reclaims freelist pages without scratch disk when INCREMENTAL is active")
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

    /// PIN the current StoragePragmas PRAGMA order so a future fix
    /// is deliberate. journal_mode WAL FIRST yields mode 0 on this
    /// SQLite build; auto_vacuum FIRST yields mode 2. Both store
    /// inits (EventStore + AlertStore + CampaignStore) currently use
    /// the WAL-first order — which means production DBs ship in
    /// mode 0 and the helper is a no-op there until a one-shot
    /// `maccrabctl maintenance vacuum` runs.
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
        // Per the StoragePragmas PRAGMA-order pin above, the fresh
        // EventStore DB ships with auto_vacuum=NONE. The helper
        // must therefore short-circuit to a clean 0 — NOT throw and
        // NOT silently report nonzero.
        let (store, tmp, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let mode = await store.autoVacuumMode()
        // Pin: fresh EventStore DB is in mode 0 (gap).
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

    /// The low-disk fallback path: pruneOldest + incrementalVacuum +
    /// walCheckpoint(TRUNCATE) is the chain that fires when full
    /// VACUUM is gated out by free-disk pre-flight. Validate that
    /// this chain runs to completion without errors and leaves the
    /// store queryable — the path is exercised inside
    /// `enforceDatabaseSizeCap` (private) but isolating it here gives
    /// us a regression target.
    @Test("Low-disk fallback chain: pruneOldest + incrementalVacuum + walCheckpoint")
    func lowDiskFallbackChain() async throws {
        let (store, tmp, _) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Build then prune so there are at least some pages to
        // touch — even though the EventStore-init gap means the
        // freelist won't actually shrink the file, the chain
        // shouldn't error or corrupt anything.
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
        #expect(pruned == 70)

        // Run the chain. The EventStore gap means reclaim==0, but
        // the chain must complete and the store must remain
        // queryable.
        _ = await store.walCheckpoint()
        let reclaimed = try await store.incrementalVacuum(maxPages: 200_000)
        #expect(reclaimed >= 0)
        _ = await store.walCheckpoint()

        // Queryable after the chain.
        let remaining = try await store.count()
        #expect(remaining == 30)
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

// MARK: - TraceStore (known gap — never opted into INCREMENTAL)

@Suite("TraceStore: incrementalVacuum (Wave 9B — known gap)")
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
        // KNOWN GAP: traces.db doesn't set INCREMENTAL on creation
        // in v1.12.6. Pinned here so a future migration is
        // deliberate.
        #expect(mode == 2, "TraceStore: auto_vacuum=INCREMENTAL after Wave 9B.1")
    }

    @Test("Returns 0 cleanly under the gap")
    func gracefulNoOpUnderGap() async throws {
        let (store, tmp, _) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let reclaimed = try await store.incrementalVacuum(maxPages: 10_000)
        #expect(reclaimed == 0)
    }
}

// MARK: - SQLiteCausalGraphStore (known gap — never opted into INCREMENTAL)

@Suite("SQLiteCausalGraphStore: incrementalVacuum (Wave 9B — known gap)")
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
        // KNOWN GAP: tracegraph.db (worst real-world offender:
        // 11 GB on a dev box) doesn't set INCREMENTAL on creation.
        #expect(mode == 2, "SQLiteCausalGraphStore: auto_vacuum=INCREMENTAL after Wave 9B.1")
    }

    @Test("Returns 0 cleanly under the gap")
    func gracefulNoOpUnderGap() async throws {
        let (store, tmp, _) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let reclaimed = try await store.incrementalVacuum(maxPages: 10_000)
        #expect(reclaimed == 0)
    }
}
