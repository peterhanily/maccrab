// EventStoreSizeCapTests.swift
//
// rc.13 stores canonical evidence in authenticated, admission-time journal
// blocks. Legacy row pruning remains available for migration tails, but it
// must never delete a fresh journal row. Retention converges by expiring whole
// blocks only after their durable 15-minute floor and rolling their exact
// counts into the aggregate tier in the same transaction.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("EventStore: rc.13 journal retention and size-cap maintenance")
struct EventStoreSizeCapTests {
    private static let bytesPerMiB = SQLitePersistentStorePolicy.bytesPerMiB

    private func makeTempStore(
        capMiB: Int64 = 128
    ) throws -> (
        store: EventStore,
        directory: URL,
        databasePath: String,
        policy: SQLitePersistentStorePolicy
    ) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-sizecap-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let databasePath = directory.appendingPathComponent("events.db").path
        let policy = SQLitePersistentStorePolicy(
            maxFootprintBytes: capMiB * Self.bytesPerMiB,
            freeSpaceFloorBytes: 0,
            transactionReserveBytes:
                SQLitePersistentStorePolicy.eventTransactionReserveBytes,
            storageVolumePath: directory.path
        )
        let store = try EventStore(
            directory: directory.path,
            storagePolicy: policy
        )
        return (store, directory, databasePath, policy)
    }

    private func event(
        index: Int,
        category: EventCategory = .process,
        timestamp: Date,
        payloadBytes: Int = 0
    ) -> Event {
        let suffix = payloadBytes > 0
            ? " " + String(repeating: "a", count: payloadBytes)
            : ""
        let executable = "/usr/bin/retention-fixture"
        let process = MacCrabCore.ProcessInfo(
            pid: Int32(10_000 + index),
            ppid: 1,
            rpid: Int32(10_000 + index),
            name: "retention-fixture",
            executable: executable,
            commandLine: executable + suffix,
            args: ["--fixture", "\(index)", suffix],
            workingDirectory: "/",
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: timestamp,
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: timestamp,
            eventCategory: category,
            eventType: category == .process ? .start : .creation,
            eventAction: "fixture",
            process: process
        )
    }

    private func insertProcessBlock(
        _ store: EventStore,
        range: Range<Int>,
        sourceTime: Date,
        payloadBytes: Int = 0
    ) async throws {
        let events = range.map {
            event(
                index: $0,
                timestamp: sourceTime.addingTimeInterval(Double($0)),
                payloadBytes: payloadBytes
            )
        }
        _ = try await store.insert(events: events, lane: .priority)
    }

    private func aggregateCount(_ store: EventStore) async throws -> Int {
        try await store.aggregates(sinceDay: "0000-00-00")
            .reduce(0) { $0 + $1.count }
    }

    @Test("generic pruning cannot delete fresh journal evidence")
    func genericPrunePreservesJournal() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        // Source time is intentionally old. The retention floor is based on
        // durable admission, so attacker-controlled timestamps cannot bypass it.
        let oldSourceTime = Date().addingTimeInterval(-2 * 60 * 60)
        try await insertProcessBlock(
            fixture.store,
            range: 0..<32,
            sourceTime: oldSourceTime
        )

        #expect(try await fixture.store.count() == 32)
        #expect(try await fixture.store.maintenanceRetainedRecordCount() == 32)
        #expect(try await fixture.store.pruneOldest(count: 1_000_000) == 0)
        #expect(
            try await fixture.store.rollUpAndPrune(
                olderThan: Date().addingTimeInterval(60 * 60)
            ) == 0
        )
        #expect(try await fixture.store.count() == 32)
        #expect(try await aggregateCount(fixture.store) == 0)
    }

    @Test("whole-block expiry enforces the durable 15-minute floor")
    func retentionFloorThenWholeBlockExpiry() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let admissionStart = Date()
        try await insertProcessBlock(
            fixture.store,
            range: 0..<10,
            sourceTime: admissionStart.addingTimeInterval(-24 * 60 * 60)
        )

        let beforeFloor = admissionStart.addingTimeInterval(
            EventStore.journalRetentionSeconds - 1
        )
        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: beforeFloor,
                maximumBlocks: 8
            ) == 0
        )
        #expect(try await fixture.store.count() == 10)

        let afterFloor = Date().addingTimeInterval(
            EventStore.journalRetentionSeconds + 1
        )
        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: afterFloor,
                maximumBlocks: 8
            ) == 10
        )
        #expect(try await fixture.store.count() == 0)
        #expect(try await fixture.store.maintenanceRetainedRecordCount() == 0)
        #expect(try await aggregateCount(fixture.store) == 10)
    }

    @Test("maximumBlocks bounds expiry without splitting a journal block")
    func expiryIsWholeBlockAndBounded() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let sourceTime = Date().addingTimeInterval(-60 * 60)
        try await insertProcessBlock(
            fixture.store,
            range: 0..<8,
            sourceTime: sourceTime
        )
        try await insertProcessBlock(
            fixture.store,
            range: 8..<13,
            sourceTime: sourceTime
        )
        let cutoff = Date().addingTimeInterval(
            EventStore.journalRetentionSeconds + 1
        )

        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: cutoff,
                maximumBlocks: 1
            ) == 8
        )
        #expect(try await fixture.store.count() == 5)
        #expect(try await aggregateCount(fixture.store) == 8)

        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: cutoff,
                maximumBlocks: 1
            ) == 5
        )
        #expect(try await fixture.store.count() == 0)
        #expect(try await aggregateCount(fixture.store) == 13)
        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: cutoff,
                maximumBlocks: 1
            ) == 0
        )
    }

    @Test("size-cap guard is exclusive and releases cleanly")
    func reentrancyGuard() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        #expect(await fixture.store.beginSizeCapPrune())
        #expect(await fixture.store.beginSizeCapPrune() == false)
        await fixture.store.endSizeCapPrune()
        #expect(await fixture.store.beginSizeCapPrune())
        await fixture.store.endSizeCapPrune()
    }

    @Test("generic pruning remains retention-safe while the advisory guard is held")
    func guardCannotBypassJournalRetention() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        try await insertProcessBlock(
            fixture.store,
            range: 0..<16,
            sourceTime: Date().addingTimeInterval(-60 * 60)
        )
        #expect(await fixture.store.beginSizeCapPrune())
        let deleted = try await fixture.store.pruneOldest(count: 16)
        await fixture.store.endSizeCapPrune()

        #expect(deleted == 0)
        #expect(try await fixture.store.count() == 16)
    }

    @Test("vacuum and checkpoint preserve unexpired journal evidence")
    func vacuumAndCheckpointPreserveJournal() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        try await insertProcessBlock(
            fixture.store,
            range: 0..<40,
            sourceTime: Date()
        )
        #expect(await fixture.store.walCheckpoint())
        try await fixture.store.vacuum()
        #expect(await fixture.store.walCheckpointTruncate())
        #expect(try await fixture.store.count() == 40)

        try await insertProcessBlock(
            fixture.store,
            range: 40..<48,
            sourceTime: Date()
        )
        #expect(try await fixture.store.count() == 48)
        #expect(
            try SQLitePersistentStoreAdmission.measureFamily(
                fixture.databasePath
            ) <= fixture.policy.maxFootprintBytes
        )
    }

    @Test("bounded expiry converges under the configured SQLite family cap")
    func expiryConvergesWithinFamilyCap() async throws {
        let fixture = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let admissionStart = Date()
        try await insertProcessBlock(
            fixture.store,
            range: 0..<128,
            sourceTime: admissionStart,
            payloadBytes: 2_048
        )
        try await insertProcessBlock(
            fixture.store,
            range: 128..<256,
            sourceTime: admissionStart,
            payloadBytes: 2_048
        )
        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: admissionStart.addingTimeInterval(
                    EventStore.journalRetentionSeconds - 1
                ),
                maximumBlocks: 1
            ) == 0
        )

        let cutoff = Date().addingTimeInterval(
            EventStore.journalRetentionSeconds + 1
        )
        var expired = 0
        while true {
            let count = try await fixture.store.expireJournalBlocks(
                retainedThrough: cutoff,
                maximumBlocks: 1
            )
            guard count > 0 else { break }
            expired += count
            #expect(
                try SQLitePersistentStoreAdmission.measureFamily(
                    fixture.databasePath
                ) <= fixture.policy.maxFootprintBytes
            )
        }

        #expect(expired == 256)
        #expect(try await fixture.store.count() == 0)
        #expect(try await aggregateCount(fixture.store) == 256)
        try await fixture.store.vacuum()
        #expect(await fixture.store.walCheckpointTruncate())
        #expect(
            try SQLitePersistentStoreAdmission.measureFamily(
                fixture.databasePath
            ) <= fixture.policy.maxFootprintBytes
        )
    }
}

@Suite("EventStore: category-neutral journal retention floor")
struct EventStoreProcessFloorTests {
    private func makeStore() throws -> (store: EventStore, directory: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-procfloor-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return (
            try EventStore(directory: directory.path),
            directory
        )
    }

    private func event(
        category: EventCategory,
        index: Int,
        timestamp: Date
    ) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: Int32(20_000 + index),
            ppid: 1,
            rpid: Int32(20_000 + index),
            name: "category-\(category.rawValue)",
            executable: "/usr/bin/category-fixture",
            commandLine: "/usr/bin/category-fixture",
            args: [category.rawValue],
            workingDirectory: "/",
            userId: 501,
            userName: "tester",
            groupId: 20,
            startTime: timestamp,
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: timestamp,
            eventCategory: category,
            eventType: category == .process ? .start : .creation,
            eventAction: "fixture",
            process: process
        )
    }

    private func insertEveryCategory(
        into store: EventStore,
        timestamp: Date
    ) async throws {
        for (index, category) in EventCategory.allCases.enumerated() {
            try await store.insert(
                event: event(
                    category: category,
                    index: index,
                    timestamp: timestamp.addingTimeInterval(Double(index))
                )
            )
        }
    }

    @Test("legacy category floors cannot prune newly admitted journal blocks")
    func genericCategoryPruneCannotBypassFloor() async throws {
        let fixture = try makeStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let oldSourceTime = Date().addingTimeInterval(-2 * 60 * 60)
        try await insertEveryCategory(
            into: fixture.store,
            timestamp: oldSourceTime
        )

        #expect(
            try await fixture.store.pruneOldest(
                count: 10_000,
                protecting: .process,
                newerThan: Date().addingTimeInterval(-60 * 60),
                preservingAllNewerThan: Date().addingTimeInterval(-15 * 60)
            ) == 0
        )
        #expect(
            try await fixture.store.rollUpAndPrune(
                olderThan: Date().addingTimeInterval(60 * 60),
                protecting: .process,
                newerThan: Date().addingTimeInterval(-60 * 60)
            ) == 0
        )
        #expect(try await fixture.store.count() == EventCategory.allCases.count)

        // The typed snapshot is explicitly partial for a request before the
        // retained admission window, but its effective counts are exact.
        let snapshot = try await fixture.store.eventCategoryCountSnapshot(
            since: .distantPast
        )
        #expect(snapshot.requestedWindowComplete == false)
        #expect(snapshot.gaps.total == 0)
        for category in EventCategory.allCases {
            #expect(snapshot.counts[category.rawValue] == 1)
        }
    }

    @Test("eligible whole-block expiry rolls every category atomically")
    func expiryIsCategoryNeutral() async throws {
        let fixture = try makeStore()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }

        let admissionStart = Date()
        try await insertEveryCategory(
            into: fixture.store,
            timestamp: admissionStart.addingTimeInterval(-24 * 60 * 60)
        )
        #expect(
            try await fixture.store.expireJournalBlocks(
                retainedThrough: admissionStart.addingTimeInterval(
                    EventStore.journalRetentionSeconds - 1
                ),
                maximumBlocks: 32
            ) == 0
        )

        let expired = try await fixture.store.expireJournalBlocks(
            retainedThrough: Date().addingTimeInterval(
                EventStore.journalRetentionSeconds + 1
            ),
            maximumBlocks: 32
        )
        #expect(expired == EventCategory.allCases.count)
        #expect(try await fixture.store.count() == 0)

        let aggregates = try await fixture.store.aggregates(
            sinceDay: "0000-00-00"
        )
        let byCategory = Dictionary(
            grouping: aggregates,
            by: \.category
        ).mapValues { rows in
            rows.reduce(0) { $0 + $1.count }
        }
        for category in EventCategory.allCases {
            #expect(byCategory[category] == 1)
        }
    }
}
