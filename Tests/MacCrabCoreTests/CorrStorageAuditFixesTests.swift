// CorrStorageAuditFixesTests.swift
//
// Regression coverage for the deep-audit (2026-07-16) `corr-storage` findings:
//   #1  auto_vacuum=NONE upgraded DBs never convert → incrementalVacuum no-op.
//        Fix: vacuum() sets PRAGMA auto_vacuum=INCREMENTAL before VACUUM, so a
//        legacy mode-0 file converts on its next full VACUUM.
//   #2  events_fts drift on re-insert. Fix: insert is an in-place UPSERT (not
//        INSERT OR REPLACE) + an AFTER UPDATE FTS trigger, so re-inserting the
//        same event id cannot orphan the old external-content FTS posting.
//   #3  alert_evidence "forward window" was never populated. Fix: capture is
//        explicitly backward-looking ([alertTs - window, alertTs]).
//   #4  delete(alertId:) orphaned the evidence copy. Fix: EventStore.deleteEvidence.
//   #5  process_commandline column (and the FTS index it feeds) was unbounded.
//        Fix: bound the stored/indexed command line to maxIndexedCommandLineBytes.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

// MARK: - Raw-SQLite probes (read store files out-of-band)

private func rawInt(at path: String, _ sql: String, bindText: String? = nil) -> Int {
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK, let db else { return -1 }
    defer { sqlite3_close(db) }
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK, let stmt else { return -1 }
    defer { sqlite3_finalize(stmt) }
    if let t = bindText {
        sqlite3_bind_text(stmt, 1, t, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
    }
    guard sqlite3_step(stmt) == SQLITE_ROW else { return -1 }
    return Int(sqlite3_column_int64(stmt, 0))
}

/// FTS5 integrity-check: verifies the events_fts index matches the events
/// content table. Returns true when consistent (an orphaned/stale posting
/// surfaces as SQLITE_CORRUPT here).
private func ftsIntegrityOK(at path: String) -> Bool {
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nil) == SQLITE_OK,
          let db else { return false }
    defer { sqlite3_close(db) }
    sqlite3_busy_timeout(db, 5000)
    return sqlite3_exec(db, "INSERT INTO events_fts(events_fts) VALUES('integrity-check')", nil, nil, nil) == SQLITE_OK
}

// MARK: - Event fixtures

private func makeEvent(
    id: UUID = UUID(),
    at timestamp: Date = Date(),
    commandLine: String,
    args: [String] = []
) -> Event {
    let proc = ProcessInfo(
        pid: 4242, ppid: 1, rpid: 1,
        name: "corrstorage-test",
        executable: "/usr/local/bin/corrstorage-test",
        commandLine: commandLine,
        args: args,
        workingDirectory: "/",
        userId: 501, userName: "tester", groupId: 20,
        startTime: timestamp,
        ancestors: [],
        isPlatformBinary: false
    )
    return Event(
        id: id,
        timestamp: timestamp,
        eventCategory: .process,
        eventType: .start,
        eventAction: "exec",
        process: proc
    )
}

private func makeEventStore() async throws -> (EventStore, URL, String) {
    let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("maccrab-corrstorage-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
    let store = try EventStore(directory: tmp.path)
    return (store, tmp, tmp.path + "/events.db")
}

// MARK: - #1 auto_vacuum conversion on vacuum()

@Suite("corr-storage #1: vacuum() converts a legacy mode-0 DB to INCREMENTAL")
struct AutoVacuumConversionTests {

    /// Pre-create a populated auto_vacuum=NONE alerts.db to simulate an
    /// install that upgraded from a build predating the INCREMENTAL default.
    private func precreateModeZeroDB(at path: String) {
        var db: OpaquePointer?
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        defer { sqlite3_close(db) }
        sqlite3_exec(db, "PRAGMA auto_vacuum = NONE", nil, nil, nil)
        sqlite3_exec(db, "CREATE TABLE legacy_blobs (id INTEGER PRIMARY KEY, b BLOB)", nil, nil, nil)
        for i in 0..<64 {
            sqlite3_exec(db, "INSERT INTO legacy_blobs (id, b) VALUES (\(i), zeroblob(2048))", nil, nil, nil)
        }
    }

    @Test("Upgraded mode-0 alerts.db stays mode 0 on open, then vacuum() converts to INCREMENTAL")
    func vacuumConvertsAlertStore() async throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-avconv-alert-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let path = tmp.path + "/alerts.db"
        precreateModeZeroDB(at: path)
        #expect(rawInt(at: path, "PRAGMA auto_vacuum") == 0, "fixture must start in mode 0 (NONE)")

        let store = try AlertStore(directory: tmp.path)
        // Opening applies `PRAGMA auto_vacuum=INCREMENTAL`, but that is a silent
        // no-op on a populated DB — the mode stays 0. This is the bug the
        // finding describes: incrementalVacuum() would be a permanent no-op.
        let modeBefore = await store.autoVacuumMode()
        #expect(modeBefore == 0, "pragma-on-open cannot flip a populated DB — mode stays 0")

        try await store.vacuum()

        let modeAfter = await store.autoVacuumMode()
        #expect(modeAfter == 2, "vacuum() performs the one-shot conversion to INCREMENTAL")
    }

    @Test("Fresh EventStore is already mode 2 and vacuum() keeps it there (idempotent)")
    func vacuumIdempotentOnFreshStore() async throws {
        let (store, tmp, _) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        #expect(await store.autoVacuumMode() == 2)
        try await store.vacuum()
        #expect(await store.autoVacuumMode() == 2, "conversion pragma is harmless when already mode 2")
    }
}

// MARK: - #2 events_fts consistency on re-insert (UPSERT + AFTER UPDATE trigger)

@Suite("corr-storage #2: re-inserting the same event id keeps events_fts consistent")
struct EventsFTSReinsertTests {

    @Test("UPSERT updates in place; old FTS token is dropped, new token present, no orphan")
    func reinsertRefreshesFTS() async throws {
        let (store, tmp, path) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let id = UUID()
        try await store.insert(event: makeEvent(id: id, commandLine: "/bin/tool zzzalphamarker"))
        // Re-insert the SAME id with a different command line (the latent
        // duplicate-id path the finding is about).
        try await store.insert(event: makeEvent(id: id, commandLine: "/bin/tool zzzbetamarker"))

        // In-place UPSERT: exactly one row, not a duplicate.
        #expect(rawInt(at: path, "SELECT count(*) FROM events") == 1)

        // FTS index: old token gone, new token present (no orphaned posting).
        #expect(rawInt(at: path, "SELECT count(*) FROM events_fts WHERE events_fts MATCH ?1",
                       bindText: "zzzalphamarker") == 0,
                "stale FTS posting for the replaced command line must be removed")
        #expect(rawInt(at: path, "SELECT count(*) FROM events_fts WHERE events_fts MATCH ?1",
                       bindText: "zzzbetamarker") == 1)

        // The definitive check: external-content FTS index matches the events table.
        #expect(ftsIntegrityOK(at: path), "events_fts integrity-check must pass (no drift)")
    }

    @Test("Normal distinct-id inserts still index correctly and pass integrity-check")
    func distinctInsertsIndexed() async throws {
        let (store, tmp, path) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(event: makeEvent(commandLine: "/bin/a zzzfirsttoken"))
        try await store.insert(event: makeEvent(commandLine: "/bin/b zzzsecondtoken"))

        #expect(rawInt(at: path, "SELECT count(*) FROM events") == 2)
        #expect(rawInt(at: path, "SELECT count(*) FROM events_fts WHERE events_fts MATCH ?1",
                       bindText: "zzzfirsttoken") == 1)
        #expect(rawInt(at: path, "SELECT count(*) FROM events_fts WHERE events_fts MATCH ?1",
                       bindText: "zzzsecondtoken") == 1)
        #expect(ftsIntegrityOK(at: path))
    }
}

// MARK: - #3 alert_evidence is backward-looking

@Suite("corr-storage #3: recordAlertEvidence captures only preceding events")
struct AlertEvidenceBackwardWindowTests {

    @Test("Events AFTER the alert timestamp are not captured; preceding events are")
    func backwardOnlyCapture() async throws {
        let (store, tmp, _) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let alertTs = Date(timeIntervalSince1970: 1_700_000_000)
        // Two events before the alert, two after — all already present in the
        // events table (proving the SQL window, not merely that the future
        // hasn't happened yet).
        try await store.insert(event: makeEvent(at: alertTs.addingTimeInterval(-20), commandLine: "/bin/before20"))
        try await store.insert(event: makeEvent(at: alertTs.addingTimeInterval(-10), commandLine: "/bin/before10"))
        try await store.insert(event: makeEvent(at: alertTs.addingTimeInterval(10), commandLine: "/bin/after10"))
        try await store.insert(event: makeEvent(at: alertTs.addingTimeInterval(20), commandLine: "/bin/after20"))

        try await store.recordAlertEvidence(alertId: "alert-1", alertTimestamp: alertTs, windowSeconds: 30)

        let evidence = try await store.evidenceFor(alertId: "alert-1")
        let cmds = Set(evidence.map { $0.process.commandLine })
        #expect(cmds.contains("/bin/before20"))
        #expect(cmds.contains("/bin/before10"))
        #expect(!cmds.contains("/bin/after10"), "post-alert events must not be captured (backward-only)")
        #expect(!cmds.contains("/bin/after20"))
        #expect(evidence.count == 2)
    }
}

// MARK: - #4 deleteEvidence purges the evidence copy

@Suite("corr-storage #4: EventStore.deleteEvidence wipes an alert's evidence rows")
struct DeleteEvidenceTests {

    @Test("deleteEvidence removes exactly the target alert's rows and is idempotent")
    func deletesEvidenceForAlert() async throws {
        let (store, tmp, path) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let ts = Date(timeIntervalSince1970: 1_700_000_500)
        try await store.insert(event: makeEvent(at: ts.addingTimeInterval(-5), commandLine: "/bin/ctx1"))
        try await store.insert(event: makeEvent(at: ts.addingTimeInterval(-3), commandLine: "/bin/ctx2"))
        try await store.recordAlertEvidence(alertId: "keep",  alertTimestamp: ts, windowSeconds: 30)
        try await store.recordAlertEvidence(alertId: "wipe",  alertTimestamp: ts, windowSeconds: 30)

        let wipeBefore = rawInt(at: path, "SELECT count(*) FROM alert_evidence WHERE alert_id = ?1", bindText: "wipe")
        #expect(wipeBefore > 0)

        let deleted = try await store.deleteEvidence(alertId: "wipe")
        #expect(deleted == wipeBefore)
        #expect(try await store.evidenceFor(alertId: "wipe").isEmpty)
        // The other alert's evidence is untouched.
        #expect(try await store.evidenceFor(alertId: "keep").isEmpty == false)

        // Idempotent: a second call removes nothing and does not throw.
        #expect(try await store.deleteEvidence(alertId: "wipe") == 0)
    }
}

// MARK: - #5 process_commandline column is bounded

@Suite("corr-storage #5: process_commandline (and its FTS entry) is length-bounded")
struct CommandLineColumnCapTests {

    @Test("maxIndexedCommandLineBytes default is 16384")
    func capConstant() {
        #expect(EventStore.maxIndexedCommandLineBytes == 16_384)
    }

    @Test("A short command line is stored unbounded (cap does not trigger)")
    func shortCommandLineUntouched() async throws {
        let (store, tmp, path) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let cmd = "/usr/bin/curl example-file.txt"
        try await store.insert(event: makeEvent(commandLine: cmd))
        let len = rawInt(at: path, "SELECT length(CAST(process_commandline AS BLOB)) FROM events LIMIT 1")
        // Mirror the exact insert pipeline (sanitize → bound) so the assertion
        // is robust regardless of sanitizer behaviour; the cap must be a no-op
        // for a tiny command line.
        let expected = EventStore.boundIndexedText(
            CommandSanitizer.sanitize(cmd),
            maxBytes: EventStore.maxIndexedCommandLineBytes
        ).utf8.count
        #expect(len == expected)
        #expect(len < 100, "short command line is not truncated to a marker")
    }

    @Test("An oversized command line is bounded in the stored/indexed column")
    func oversizedCommandLineBounded() async throws {
        let (store, tmp, path) = try await makeEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // 100 KB command line — far larger than the raw_json cap AND the column
        // cap. Pre-fix the column (and its FTS entry) took the full 100 KB.
        let huge = "/bin/payload " + String(repeating: "A", count: 100_000)
        try await store.insert(event: makeEvent(commandLine: huge))

        let len = rawInt(at: path, "SELECT length(CAST(process_commandline AS BLOB)) FROM events LIMIT 1")
        #expect(len > 0)
        #expect(len <= EventStore.maxIndexedCommandLineBytes,
                "column must be bounded to maxIndexedCommandLineBytes, was \(len)")
        #expect(len < 100_000)
        // The bound helper itself: exact byte ceiling + truncation marker.
        let bounded = EventStore.boundIndexedText(huge, maxBytes: EventStore.maxIndexedCommandLineBytes)
        #expect(bounded.utf8.count <= EventStore.maxIndexedCommandLineBytes)
        #expect(bounded.contains("<truncated:"))
    }
}
