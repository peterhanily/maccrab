import CSQLCipher
import Foundation
import Testing
@testable import MacCrabCore

#if DEBUG
/// Ordinary events through real private-store admission, overlay, expiry, and
/// authenticated reads. The existing per-instance admission-clock seam makes
/// prefix/interior expiry deterministic; no journal bytes are forged or edited.
@Suite("Expiry-only journal index refresh preserves exact survivors")
struct JournalIndexExpiryOnlyRefreshTests {
    private enum FixtureError: Error { case sqlite(Int32), invalidTopology }

    private struct Topology: Equatable {
        let count: Int64
        let minimum: Int64?
        let maximum: Int64?
    }

    private struct Fixture: Sendable {
        let writer: EventStore
        let path: String
        let budget: EventPipelineLiveMemoryBudget
        let cutoff: Date
        let blocks: [[Event]]

        func reader() throws -> EventStore {
            try EventStore(path: path, forceReadOnly: true, liveMemoryBudget: budget)
        }
    }

    private func event(_ index: Int) -> Event {
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000 + Double(index))
        let process = MacCrabCore.ProcessInfo(
            pid: Int32(20_000 + index), ppid: 1, rpid: 1,
            name: "expiry-only-fixture", executable: "/fixture/ordinary",
            commandLine: "ordinary fixture \(index)", args: [],
            workingDirectory: "/fixture", userId: 501, userName: "fixture",
            groupId: 20, startTime: timestamp, ancestors: [], isPlatformBinary: false)
        return Event(timestamp: timestamp, eventCategory: .process,
            eventType: .start, eventAction: "exec", process: process)
    }

    private func withFixture(
        offsets: [Int64], _ body: (Fixture) async throws -> Void
    ) async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("journal-expiry-only-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        // The helper's store references leave scope before private cleanup.
        try await runFixture(directory: directory, offsets: offsets, body)
    }

    private func runFixture(
        directory: URL, offsets: [Int64], _ body: (Fixture) async throws -> Void
    ) async throws {
        let path = directory.appendingPathComponent("events.db").path
        let budget = EventPipelineLiveMemoryBudget.isolatedProductionEquivalentForTesting()
        let writer = try EventStore(path: path, liveMemoryBudget: budget)
        let bucket = Int64(Date().timeIntervalSince1970.rounded(.down))
        var blocks: [[Event]] = []
        for (block, offset) in offsets.enumerated() {
            await writer.setJournalAdmissionBucketForTesting(bucket + offset)
            var events = [event(block * 2), event(block * 2 + 1)]
            let inserted = try await writer.insert(events: events, lane: .priority)
            try #require(inserted.persistedCount == events.count)
            try #require(inserted.filteredCount == 0)
            events[0].enrichments["expiry_only_fixture"] = "ordinary overlay \(block)"
            let terminal = try await writer.appendTerminalRevision(events[0], lane: .priority)
            try #require(terminal == .inserted(eventID: events[0].id))
            blocks.append(events)
        }
        await writer.setJournalAdmissionBucketForTesting(nil)
        let checkpointed = await writer.walCheckpointTruncate()
        try #require(checkpointed)
        let initial = try topology(path: path)
        try #require(initial.count == Int64(offsets.count))
        try await body(Fixture(writer: writer, path: path, budget: budget,
            cutoff: Date(timeIntervalSince1970: Double(bucket) + EventStore.journalRetentionSeconds),
            blocks: blocks))
    }

    private func topology(path: String) throws -> Topology {
        var opened: OpaquePointer?
        let result = sqlite3_open_v2(path, &opened, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        guard result == SQLITE_OK, let db = opened else {
            if let opened { sqlite3_close(opened) }
            throw FixtureError.sqlite(result)
        }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        let prepared = sqlite3_prepare_v2(db, """
            SELECT journal_block_count, journal_min_block_id, journal_max_block_id
            FROM event_storage_state WHERE singleton = 1
            """, -1, &statement, nil)
        guard prepared == SQLITE_OK, let statement else {
            if let statement { sqlite3_finalize(statement) }
            throw FixtureError.sqlite(prepared)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else { throw FixtureError.invalidTopology }
        let value = Topology(count: sqlite3_column_int64(statement, 0),
            minimum: sqlite3_column_type(statement, 1) == SQLITE_NULL ? nil : sqlite3_column_int64(statement, 1),
            maximum: sqlite3_column_type(statement, 2) == SQLITE_NULL ? nil : sqlite3_column_int64(statement, 2))
        guard sqlite3_step(statement) == SQLITE_DONE else { throw FixtureError.invalidTopology }
        return value
    }

    private func exact(_ reader: EventStore, expected: [Event]) async throws -> ExactEventQuerySnapshot {
        let snapshot = try await reader.exactEventsSnapshot(since: .distantPast, limit: 100)
        #expect(snapshot.isComplete)
        #expect(snapshot.events.map(\.id) == expected.sorted { $0.timestamp > $1.timestamp }.map(\.id))
        let identicalContent = snapshot.events == expected.sorted { $0.timestamp > $1.timestamp }
        #expect(identicalContent, "All retained event fields and terminal overlays must match")
        return snapshot
    }

    @Test("Expiry-only page and count refresh reuse the exact authenticated survivors", arguments: [false, true])
    func prefixExpiryOnly(countFirst: Bool) async throws {
        try await withFixture(offsets: [0, 0, 100, 100, 100, 100]) { fixture in
            let reader = try fixture.reader()
            defer { reader.retireReadOnlyReads() }
            _ = try await exact(reader, expected: fixture.blocks.flatMap { $0 })
            let before = await reader.journalIndexRefreshDiagnostics()
            let oldTopology = try topology(path: fixture.path)
            let expired = try await fixture.writer.expireJournalBlocks(
                retainedThrough: fixture.cutoff, maximumBlocks: 8)
            try #require(expired == 4)
            let newTopology = try topology(path: fixture.path)
            #expect(newTopology.count == oldTopology.count - 2)
            #expect(newTopology.minimum == oldTopology.minimum.map { $0 + 2 })
            #expect(newTopology.maximum == oldTopology.maximum)
            let expected = fixture.blocks.dropFirst(2).flatMap { $0 }
            if countFirst {
                let count = try await reader.count()
                #expect(count == expected.count)
            }
            let retained = try await exact(reader, expected: expected)
            let after = await reader.journalIndexRefreshDiagnostics()
            #expect(after.fullRebuilds == before.fullRebuilds)
            #expect(after.appendRefreshes == before.appendRefreshes + 1)
            #expect(after.stagesComplete)
            #expect(after.stagesNanoseconds["global_terminal_integrity"] == nil)
            #expect(after.stagesNanoseconds["global_projection_and_fts"] == nil)
            let fresh = try fixture.reader()
            defer { fresh.retireReadOnlyReads() }
            let rebuilt = try await exact(fresh, expected: expected)
            #expect(retained == rebuilt)
            let count = try await reader.count()
            #expect(count == expected.count)
            let repeated = try await exact(reader, expected: expected)
            #expect(repeated == retained)
            let final = await reader.journalIndexRefreshDiagnostics()
            #expect(final.fullRebuilds == after.fullRebuilds)
            #expect(final.appendRefreshes == after.appendRefreshes)
        }
    }

    @Test("Total expiry with no append uses the full empty-index rebuild")
    func totalExpiryFallback() async throws {
        try await withFixture(offsets: [0, 0, 0, 0]) { fixture in
            let reader = try fixture.reader()
            defer { reader.retireReadOnlyReads() }
            _ = try await exact(reader, expected: fixture.blocks.flatMap { $0 })
            let before = await reader.journalIndexRefreshDiagnostics()
            let expired = try await fixture.writer.expireJournalBlocks(
                retainedThrough: fixture.cutoff, maximumBlocks: 8)
            try #require(expired == 8)
            let emptyTopology = try topology(path: fixture.path)
            #expect(emptyTopology == Topology(count: 0, minimum: nil, maximum: nil))
            let empty = try await exact(reader, expected: [])
            let after = await reader.journalIndexRefreshDiagnostics()
            #expect(after.fullRebuilds == before.fullRebuilds + 1)
            #expect(after.appendRefreshes == before.appendRefreshes)
            #expect(after.stagesNanoseconds["global_terminal_integrity"] != nil)
            #expect(after.stagesNanoseconds["global_projection_and_fts"] != nil)
            let fresh = try fixture.reader()
            defer { fresh.retireReadOnlyReads() }
            let rebuilt = try await exact(fresh, expected: [])
            #expect(empty == rebuilt)
            let count = try await reader.count()
            #expect(count == 0)
        }
    }

    @Test("Prefix plus interior expiry fails survivor reconciliation and rebuilds")
    func interiorRemovalFallback() async throws {
        // Only blocks one and three expire. The new minimum advances, but
        // removing the prefix alone would leave the stale third-block locator.
        try await withFixture(offsets: [0, 100, 0, 100, 100, 100]) { fixture in
            let reader = try fixture.reader()
            defer { reader.retireReadOnlyReads() }
            _ = try await exact(reader, expected: fixture.blocks.flatMap { $0 })
            let before = await reader.journalIndexRefreshDiagnostics()
            let oldTopology = try topology(path: fixture.path)
            let expired = try await fixture.writer.expireJournalBlocks(
                retainedThrough: fixture.cutoff, maximumBlocks: 8)
            try #require(expired == 4)
            let newTopology = try topology(path: fixture.path)
            #expect(newTopology.count == oldTopology.count - 2)
            #expect(newTopology.minimum == oldTopology.minimum.map { $0 + 1 })
            #expect(newTopology.maximum == oldTopology.maximum)
            let expected = [1, 3, 4, 5].flatMap { fixture.blocks[$0] }
            let retained = try await exact(reader, expected: expected)
            let after = await reader.journalIndexRefreshDiagnostics()
            #expect(after.fullRebuilds == before.fullRebuilds + 1)
            #expect(after.appendRefreshes == before.appendRefreshes)
            #expect(after.stagesNanoseconds["global_terminal_integrity"] != nil)
            #expect(after.stagesNanoseconds["global_projection_and_fts"] != nil)
            let fresh = try fixture.reader()
            defer { fresh.retireReadOnlyReads() }
            let rebuilt = try await exact(fresh, expected: expected)
            #expect(retained == rebuilt)
            let count = try await reader.count()
            #expect(count == expected.count)
        }
    }
}
#endif
