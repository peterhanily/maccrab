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

        let processOnly = try await store.events(since: .distantPast, category: .process, limit: 100)
        #expect(processOnly.count == 3)
        #expect(processOnly.allSatisfy { $0.eventCategory == .process })

        let networkOnly = try await store.events(since: .distantPast, category: .network, limit: 100)
        #expect(networkOnly.count == 2)
        #expect(networkOnly.allSatisfy { $0.eventCategory == .network })

        // A category with no rows returns empty (not a fall-through to all).
        let fileOnly = try await store.events(since: .distantPast, category: .file, limit: 100)
        #expect(fileOnly.isEmpty)
    }

    @Test("events(since:category:) with nil category returns all categories")
    func nilCategoryReturnsAll() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(event: event(at: base.addingTimeInterval(0), category: .process))
        try await store.insert(event: event(at: base.addingTimeInterval(1), category: .network))
        try await store.insert(event: event(at: base.addingTimeInterval(2), category: .file))

        let all = try await store.events(since: .distantPast, category: nil, limit: 100)
        #expect(all.count == 3)
        #expect(Set(all.map { $0.eventCategory }) == Set([.process, .network, .file]))
    }
}
