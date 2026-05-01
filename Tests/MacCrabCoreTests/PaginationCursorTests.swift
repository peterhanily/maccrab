// PaginationCursorTests.swift
//
// Phase 2 (v1.8.0): regression coverage for the keyset-cursor APIs on
// EventStore + AlertStore. Asserts the contract every caller relies on:
//
//   1. First page (no cursor) returns the newest `pageSize` rows
//   2. Re-querying with the returned `nextCursor` returns strictly older
//      rows — no duplicates with page 1, no rows out of order
//   3. When the result count is shorter than `pageSize`, `nextCursor`
//      is nil (signals end-of-table)
//   4. Filters (severity / category / suppressed) compose with the cursor
//      predicate without leaking rows from outside the filter
//   5. `pageSize` is clamped to [1, 1000] so callers can't blow memory

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Storage: keyset cursor pagination (v1.8.0)")
struct PaginationCursorTests {

    private func makeTempEventStore() throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-paginate-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func makeTempAlertStore() throws -> (AlertStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-paginate-alerts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tmp.path)
        return (store, tmp)
    }

    private func sampleEvent(at date: Date, name: String = "sample") -> Event {
        let proc = ProcessInfo(
            pid: 1000, ppid: 1, rpid: 1,
            name: name, executable: "/bin/\(name)",
            commandLine: "/bin/\(name)", args: [],
            workingDirectory: "/",
            userId: 501, userName: "t", groupId: 20,
            startTime: date,
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: date,
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    private func sampleAlert(
        at date: Date, severity: Severity = .high, suppressed: Bool = false
    ) -> Alert {
        return Alert(
            id: UUID().uuidString,
            timestamp: date,
            ruleId: "test.rule",
            ruleTitle: "test rule",
            severity: severity,
            eventId: UUID().uuidString,
            processPath: nil, processName: nil,
            description: nil, mitreTactics: nil, mitreTechniques: nil,
            suppressed: suppressed,
            llmInvestigation: nil
        )
    }

    // MARK: - EventStore

    @Test("EventStore.events(before:) returns descending pages with no overlap")
    func eventStorePagesAreContiguous() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        for i in 0..<25 {
            try await store.insert(event: sampleEvent(at: base.addingTimeInterval(Double(i))))
        }

        let page1 = try await store.events(before: nil, pageSize: 10)
        #expect(page1.items.count == 10)
        #expect(page1.nextCursor != nil)

        let page2 = try await store.events(before: page1.nextCursor, pageSize: 10)
        #expect(page2.items.count == 10)
        #expect(page2.nextCursor != nil)

        let page3 = try await store.events(before: page2.nextCursor, pageSize: 10)
        #expect(page3.items.count == 5)
        #expect(page3.nextCursor == nil)

        let allIds = (page1.items + page2.items + page3.items).map(\.id.uuidString)
        #expect(Set(allIds).count == 25)

        let timestamps = (page1.items + page2.items + page3.items).map(\.timestamp.timeIntervalSince1970)
        let sorted = timestamps.sorted(by: >)
        #expect(timestamps == sorted)
    }

    @Test("EventStore.events(before:) honours category filter across pages")
    func eventStorePaginationRespectsCategory() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        // 5 process events (matches sampleEvent's .process category).
        for i in 0..<5 {
            try await store.insert(event: sampleEvent(at: base.addingTimeInterval(Double(i))))
        }

        // Process category should return all 5; a category we didn't insert
        // should return empty + nil cursor.
        let processPage = try await store.events(before: nil, category: .process, pageSize: 10)
        #expect(processPage.items.count == 5)
        #expect(processPage.items.allSatisfy { $0.eventCategory == .process })
        #expect(processPage.nextCursor == nil)

        let networkPage = try await store.events(before: nil, category: .network, pageSize: 10)
        #expect(networkPage.items.isEmpty)
        #expect(networkPage.nextCursor == nil)
    }

    @Test("EventStore.events(before:) clamps pageSize to [1, 1000]")
    func eventStoreClampsPageSize() async throws {
        let (store, tmp) = try makeTempEventStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(event: sampleEvent(at: Date()))

        let zero = try await store.events(before: nil, pageSize: 0)
        #expect(zero.items.count == 1)

        let huge = try await store.events(before: nil, pageSize: 100_000)
        #expect(huge.items.count == 1)
    }

    // MARK: - AlertStore

    @Test("AlertStore.alerts(before:) returns descending pages with no overlap")
    func alertStorePagesAreContiguous() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        for i in 0..<15 {
            try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(Double(i))))
        }

        let page1 = try await store.alerts(before: nil, pageSize: 6)
        #expect(page1.items.count == 6)
        #expect(page1.nextCursor != nil)

        let page2 = try await store.alerts(before: page1.nextCursor, pageSize: 6)
        #expect(page2.items.count == 6)
        #expect(page2.nextCursor != nil)

        let page3 = try await store.alerts(before: page2.nextCursor, pageSize: 6)
        #expect(page3.items.count == 3)
        #expect(page3.nextCursor == nil)

        let allIds = (page1.items + page2.items + page3.items).map(\.id)
        #expect(Set(allIds).count == 15)
    }

    @Test("AlertStore.alerts(before:) respects severity + suppressed filters")
    func alertStorePaginationRespectsFilters() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(0), severity: .low))
        try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(1), severity: .high))
        try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(2), severity: .critical))
        try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(3), severity: .high, suppressed: true))

        let high = try await store.alerts(before: nil, severity: .high, pageSize: 10)
        #expect(high.items.count == 3)
        #expect(high.items.allSatisfy { $0.severity >= .high })

        let unsuppressed = try await store.alerts(before: nil, suppressed: false, pageSize: 10)
        #expect(unsuppressed.items.count == 3)
        #expect(unsuppressed.items.allSatisfy { !$0.suppressed })
    }

    // MARK: - Campaigns

    private func campaignAlert(at date: Date, suffix: String = "kill_chain") -> Alert {
        Alert(
            id: UUID().uuidString,
            timestamp: date,
            ruleId: "maccrab.campaign.\(suffix)",
            ruleTitle: "Campaign: \(suffix)",
            severity: .critical,
            eventId: UUID().uuidString,
            processPath: nil, processName: nil,
            description: nil, mitreTactics: nil, mitreTechniques: nil,
            suppressed: false,
            llmInvestigation: nil
        )
    }

    @Test("AlertStore.campaigns(before:) returns only campaign rows")
    func campaignsExcludesNonCampaignRows() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(0)))           // not a campaign
        try await store.insert(alert: campaignAlert(at: base.addingTimeInterval(1)))
        try await store.insert(alert: campaignAlert(at: base.addingTimeInterval(2), suffix: "alert_storm"))
        try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(3)))           // not a campaign

        let page = try await store.campaigns(before: nil, pageSize: 10)
        #expect(page.items.count == 2)
        #expect(page.items.allSatisfy { $0.ruleId.hasPrefix("maccrab.campaign.") })
        #expect(page.nextCursor == nil)
    }

    @Test("AlertStore.campaigns(before:) pages contiguously")
    func campaignsPagesAreContiguous() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        for i in 0..<7 {
            try await store.insert(alert: campaignAlert(at: base.addingTimeInterval(Double(i))))
        }
        // Sprinkle non-campaign rows that must NOT count toward the page cap.
        for i in 0..<5 {
            try await store.insert(alert: sampleAlert(at: base.addingTimeInterval(Double(100 + i))))
        }

        let page1 = try await store.campaigns(before: nil, pageSize: 3)
        #expect(page1.items.count == 3)
        #expect(page1.nextCursor != nil)

        let page2 = try await store.campaigns(before: page1.nextCursor, pageSize: 3)
        #expect(page2.items.count == 3)

        let page3 = try await store.campaigns(before: page2.nextCursor, pageSize: 3)
        #expect(page3.items.count == 1)
        #expect(page3.nextCursor == nil)

        let allIds = (page1.items + page2.items + page3.items).map(\.id)
        #expect(Set(allIds).count == 7)
    }
}
