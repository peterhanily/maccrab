// JournalIndexTearTests.swift
//
// v1.21.6-rc.43. The rc.41 chunked journal scan traded snapshot isolation
// between batches for bounded WAL read-marks. Two reader-side defects followed,
// both surfacing as "Event evidence could not be read completely: Decoding
// failed: event journal contains a duplicate UUID roster entry" in the
// dashboard under concurrent appends:
//
//   1. A writer appending mid-scan was pulled into the pass, the scanned count
//      disagreed with the topology, the pass aborted with the append-only index
//      PARTIALLY populated, and the retry re-inserted the same entries → the
//      duplicate-UUID guard fired forever until the connection recycled.
//   2. Nothing reset that partial state on a rebuild throw.
//
// rc.43: the scan is bounded to the topology's max block-id (concurrent appends
// are invisible to the pass), and ANY rebuild throw invalidates the in-memory
// index so the next call is a clean full rebuild.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("rc.43 journal index tear recovery", .serialized)
struct JournalIndexTearTests {

    private func makeEvent(_ i: Int) -> Event {
        let proc = MacCrabCore.ProcessInfo(
            pid: Int32(8000 + i), ppid: 1, rpid: 1,
            name: "tear\(i)", executable: "/usr/bin/tear\(i)",
            commandLine: "/usr/bin/tear\(i)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000 + Double(i)),
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private func makeDir() throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-tear-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true
        )
        return dir
    }

    @Test("A torn rebuild recovers on retry instead of wedging the reader")
    func tornRebuildRecovers() async throws {
        // Coverage honesty: this exercises the INVALIDATION-ON-THROW contract
        // (a torn scan must not strand partial locators that break the next
        // read). It uses a cold reader, which reliably reaches the scan loop.
        // The specific concurrent-APPEND-REFRESH race that produced the live
        // "duplicate UUID roster entry" cannot be reproduced deterministically
        // from the public test surface (it needs control over journal-block
        // materialization timing); that path is addressed by the bounded-scan
        // change (block_id <= topology max, so a mid-scan append is invisible to
        // the pass) plus this invalidation guarantee. What IS asserted here: a
        // torn rebuild leaves the reader able to recover, never permanently
        // wedged.
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        do {
            let writer = try EventStore(directory: dir.path)
            for i in 0..<60 { try await writer.insert(event: makeEvent(i)) }
        }

        let reader = try EventStore(directory: dir.path)
        await reader.setJournalRebuildFailAfterPartialForTesting(true)

        var firstThrew = false
        do {
            _ = try await reader.searchSnapshot(text: "tear", limit: 10)
        } catch {
            firstThrew = true
        }
        #expect(firstThrew, "the injected tear should have surfaced on the first read")

        // The retry must succeed — not throw duplicate-UUID from stranded state.
        let result = try await reader.searchSnapshot(text: "tear", limit: 100)
        #expect(result.events.count >= 1, "the reader did not recover after a torn rebuild")
    }

    @Test("Appends after a rebuild refresh cleanly across the bounded scan")
    func appendRefreshHasNoDuplicates() async throws {
        let dir = try makeDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = try EventStore(directory: dir.path)
        for i in 0..<40 { try await store.insert(event: makeEvent(i)) }
        // Warm the index.
        _ = try await store.searchSnapshot(text: "tear", limit: 10)
        // Append more, then read again: the append-only refresh must not
        // re-insert existing UUIDs.
        for i in 40..<90 { try await store.insert(event: makeEvent(i)) }
        let result = try await store.searchSnapshot(text: "tear", limit: 200)
        #expect(result.events.count >= 1)
    }
}
