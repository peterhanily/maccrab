// EventStoreCategoryQueryTests.swift
//
// v1.21.4 (Events-UI residual 1): coverage for the DB-side category
// predicate on `EventStore.events(since:category:limit:)`.
//
// This is the exact hot-tier store call `AppState.loadEvents` now forwards
// the category picker through (non-search branch). Pre-fix the dashboard
// only filtered category in-memory over the ~500-row loaded window, which
// undercounts on busy hosts; the fix threads `category` down to this query
// so the whole hot tier is filtered DB-side. The cursor variant
// (`events(before:category:)`, used by loadOlderEvents) is already covered
// by PaginationCursorTests; this closes the gap on the `since:` variant.

import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

@Suite("Storage: events(since:category:) DB-side category filter (v1.21.4)")
struct EventStoreCategoryQueryTests {

    private func makeTempEventStore() throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-category-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func event(at date: Date, category: EventCategory) -> Event {
        let proc = ProcessInfo(
            pid: 1000, ppid: 1, rpid: 1,
            name: "sample", executable: "/bin/sample",
            commandLine: "/bin/sample", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: date,
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: date,
            eventCategory: category, eventType: .info,
            eventAction: "test", process: proc
        )
    }

    private func journalBlockAdmission(
        at path: String
    ) throws -> (bucket: Int64, admission: TimeInterval) {
        var rawDatabase: OpaquePointer?
        try #require(
            sqlite3_open_v2(
                path,
                &rawDatabase,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK
        )
        defer { if let rawDatabase { sqlite3_close(rawDatabase) } }
        let database = try #require(rawDatabase)
        var statement: OpaquePointer?
        try #require(
            sqlite3_prepare_v2(
                database,
                "SELECT admission_bucket, retained_until FROM event_journal_blocks ORDER BY block_id LIMIT 1",
                -1,
                &statement,
                nil
            ) == SQLITE_OK
        )
        defer { sqlite3_finalize(statement) }
        try #require(sqlite3_step(statement) == SQLITE_ROW)
        let bucket = sqlite3_column_int64(statement, 0)
        let admission = sqlite3_column_double(statement, 1)
            - EventStore.journalRetentionSeconds
        try #require(admission.isFinite)
        return (bucket, admission)
    }

    private func journalMigrationRowCount(at path: String) throws -> Int {
        var rawDatabase: OpaquePointer?
        try #require(
            sqlite3_open_v2(
                path,
                &rawDatabase,
                SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK
        )
        defer { if let rawDatabase { sqlite3_close(rawDatabase) } }
        let database = try #require(rawDatabase)
        var statement: OpaquePointer?
        try #require(
            sqlite3_prepare_v2(
                database,
                "SELECT COUNT(*) FROM event_journal_migration",
                -1,
                &statement,
                nil
            ) == SQLITE_OK
        )
        defer { sqlite3_finalize(statement) }
        try #require(sqlite3_step(statement) == SQLITE_ROW)
        return Int(sqlite3_column_int64(statement, 0))
    }

    @Test("events(since:category:) returns only the requested category")
    func filtersByCategory() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        // 3 process + 2 network events, interleaved in time.
        for i in 0..<3 {
            try await store.insert(event: event(at: base.addingTimeInterval(Double(i)), category: .process))
        }
        for i in 0..<2 {
            try await store.insert(event: event(at: base.addingTimeInterval(Double(10 + i)), category: .network))
        }

        let processOnly = try await store.exactEventsSnapshot(
            since: .distantPast,
            category: .process,
            limit: 100
        )
        #expect(processOnly.events.count == 3)
        #expect(processOnly.events.allSatisfy { $0.eventCategory == .process })

        let networkOnly = try await store.exactEventsSnapshot(
            since: .distantPast,
            category: .network,
            limit: 100
        )
        #expect(networkOnly.events.count == 2)
        #expect(networkOnly.events.allSatisfy { $0.eventCategory == .network })

        // A category with no rows returns empty (not a fall-through to all).
        let fileOnly = try await store.exactEventsSnapshot(
            since: .distantPast,
            category: .file,
            limit: 100
        )
        #expect(fileOnly.events.isEmpty)
    }

    @Test("events(since:category:) with nil category returns all categories")
    func nilCategoryReturnsAll() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(event: event(at: base.addingTimeInterval(0), category: .process))
        try await store.insert(event: event(at: base.addingTimeInterval(1), category: .network))
        try await store.insert(event: event(at: base.addingTimeInterval(2), category: .file))

        let all = try await store.exactEventsSnapshot(
            since: .distantPast,
            category: nil,
            limit: 100
        )
        #expect(all.events.count == 3)
        #expect(Set(all.events.map { $0.eventCategory }) == Set([.process, .network, .file]))
    }

    @Test("exact Events applies both time bounds before its result limit")
    func historicalWindowBeforeLimit() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }
        let base = Date().addingTimeInterval(-600)
        let expected = [
            event(at: base, category: .process),
            event(at: base.addingTimeInterval(10), category: .process),
            event(at: base.addingTimeInterval(20), category: .process),
        ]
        for value in expected { try await store.insert(event: value) }
        try await store.insert(event: event(
            at: base.addingTimeInterval(-1), category: .process
        ))
        try await store.insert(event: event(
            at: base.addingTimeInterval(15), category: .network
        ))
        // More newer rows than the requested limit used to hide every row in
        // a centred historical window when the UI filtered `until` afterward.
        for offset in 0..<4 {
            try await store.insert(event: event(
                at: base.addingTimeInterval(Double(100 + offset)), category: .process
            ))
        }
        let snapshot = try await store.exactEventsSnapshot(
            since: base, until: base.addingTimeInterval(20),
            category: .process, limit: 3
        )
        #expect(snapshot.isComplete)
        #expect(snapshot.events == Array(expected.reversed()),
                "The inclusive range and category must be applied before LIMIT")
        let empty = try await store.exactEventsSnapshot(
            since: base.addingTimeInterval(30), until: base.addingTimeInterval(40),
            category: .process, limit: 3
        )
        #expect(empty.isComplete)
        #expect(empty.events.isEmpty)
    }

    @Test("admission category counts include the fractional activation bucket")
    func categoryCountsIncludeActivationBucket() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(event: event(at: base, category: .process))
        try await store.insert(event: event(at: base, category: .network))

        // Make the boundary deterministic: v8 activation is fractional while
        // authenticated admission metadata is intentionally integer-second.
        // The first bucket cannot contain a pre-v8 journal block and must not
        // disappear merely because its integer label precedes the fraction.
        let path = tmp.appendingPathComponent("events.db").path
        let metadata = try journalBlockAdmission(at: path)
        let activation = Double(metadata.bucket).nextUp
        try #require(activation > Double(metadata.bucket))

        var rawDatabase: OpaquePointer?
        try #require(
            sqlite3_open_v2(
                path,
                &rawDatabase,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
                nil
            ) == SQLITE_OK
        )
        defer { if let rawDatabase { sqlite3_close(rawDatabase) } }
        let database = try #require(rawDatabase)
        let sql = "INSERT INTO event_journal_migration (singleton, stage, started_at, updated_at) VALUES (1, 2, \(activation), \(activation))"
        try #require(sqlite3_exec(database, sql, nil, nil, nil) == SQLITE_OK)
        try #require(sqlite3_changes(database) == 1)

        let snapshot = try await store.eventCategoryCountSnapshot(
            since: .distantPast
        )
        #expect(snapshot.requestedWindowComplete == false)
        #expect(snapshot.counts[EventCategory.process.rawValue] == 1)
        #expect(snapshot.counts[EventCategory.network.rawValue] == 1)
    }

    @Test("absent migration state anchors counts to the earliest retained bucket")
    func categoryCountsUseStableBlockFallbackActivation() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(
            event: event(at: Date(), category: .process)
        )
        let path = tmp.appendingPathComponent("events.db").path
        let metadata = try journalBlockAdmission(at: path)
        #expect(try journalMigrationRowCount(at: path) == 0)

        // Cross the block's admission-second boundary so a fallback tied to
        // each query's moving `now` would exclude this still-retained block.
        let target = Double(metadata.bucket + 1) + 0.02
        let delay = target - Date().timeIntervalSince1970
        if delay > 0 {
            try await Task.sleep(
                nanoseconds: UInt64(delay * 1_000_000_000)
            )
        }
        try #require(
            Date().timeIntervalSince1970 >= Double(metadata.bucket + 1)
        )

        let snapshot = try await store.eventCategoryCountSnapshot(
            since: .distantPast
        )
        #expect(snapshot.requestedWindowComplete == false)
        #expect(
            snapshot.effectiveSince
                == Date(timeIntervalSince1970: Double(metadata.bucket))
        )
        #expect(snapshot.counts[EventCategory.process.rawValue] == 1)
    }

    @Test("fractional admission cutoff reports the widened bucket and incomplete coverage")
    func categoryCountsReportFractionalBucketWidening() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(
            event: event(at: Date(), category: .process)
        )
        let metadata = try journalBlockAdmission(
            at: tmp.appendingPathComponent("events.db").path
        )
        let nextBucket = Double(metadata.bucket + 1)
        let cutoff = (metadata.admission + nextBucket) / 2
        try #require(cutoff > metadata.admission)
        try #require(cutoff < nextBucket)

        let delay = cutoff + 0.01 - Date().timeIntervalSince1970
        if delay > 0 {
            try await Task.sleep(
                nanoseconds: UInt64(delay * 1_000_000_000)
            )
        }
        try #require(Date().timeIntervalSince1970 >= cutoff)

        let instant = Date(timeIntervalSince1970: cutoff)
        let snapshot = try await store.eventCategoryCountSnapshot(
            since: instant,
            until: instant
        )
        #expect(snapshot.requestedWindowComplete == false)
        #expect(
            snapshot.effectiveSince
                == Date(timeIntervalSince1970: Double(metadata.bucket))
        )
        #expect(snapshot.effectiveUntil == instant)
        #expect(snapshot.counts[EventCategory.process.rawValue] == 1)
    }

    @Test("all-future admission window has no overlap and counts nothing")
    func categoryCountsRejectAllFutureWindow() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(
            event: event(at: Date(), category: .process)
        )
        let futureSince = Date().addingTimeInterval(60 * 60)
        let futureUntil = futureSince.addingTimeInterval(60)
        let snapshot = try await store.eventCategoryCountSnapshot(
            since: futureSince,
            until: futureUntil
        )

        #expect(snapshot.counts.isEmpty)
        #expect(snapshot.requestedWindowComplete == false)
        #expect(snapshot.effectiveSince > snapshot.effectiveUntil)
    }

    @Test("wholly pre-activation admission window has no overlap and counts nothing")
    func categoryCountsRejectPreActivationWindow() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(
            event: event(at: Date(), category: .process)
        )
        let metadata = try journalBlockAdmission(
            at: tmp.appendingPathComponent("events.db").path
        )
        let retainedBoundary = Double(metadata.bucket)
        let requestedUntil = Date(
            timeIntervalSince1970: retainedBoundary.nextDown
        )
        let requestedSince = requestedUntil.addingTimeInterval(-60)
        let snapshot = try await store.eventCategoryCountSnapshot(
            since: requestedSince,
            until: requestedUntil
        )

        #expect(snapshot.counts.isEmpty)
        #expect(snapshot.requestedWindowComplete == false)
        #expect(snapshot.effectiveSince > snapshot.effectiveUntil)
    }
}
