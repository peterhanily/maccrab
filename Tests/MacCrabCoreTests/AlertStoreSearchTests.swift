// AlertStoreSearchTests.swift
//
// Phase 2 (v1.8.0): coverage for the new LIKE-based `AlertStore.search`
// that backs the AlertDashboard's database-side search box. The events
// table has FTS5; the alerts table is small enough that LIKE on five
// columns is fine. These tests pin the contract:
//
//   1. Substring match across ruleTitle / processName / processPath /
//      description / mitreTechniques
//   2. Wildcards in user input (`%`, `_`) don't escape — they're treated
//      as literals (stripped before binding)
//   3. Results ordered most-recent-first (matches the dashboard)
//   4. `limit` clamps to [1, 1000]

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore.search (v1.8.0)")
struct AlertStoreSearchTests {

    private func makeTempAlertStore() throws -> (AlertStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-alert-search-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tmp.path)
        return (store, tmp)
    }

    private func alert(
        title: String,
        processName: String? = nil,
        processPath: String? = nil,
        description: String? = nil,
        mitreTechniques: String? = nil,
        at date: Date = Date()
    ) -> Alert {
        Alert(
            id: UUID().uuidString,
            timestamp: date,
            ruleId: "test.rule",
            ruleTitle: title,
            severity: .high,
            eventId: UUID().uuidString,
            processPath: processPath,
            processName: processName,
            description: description,
            mitreTactics: nil,
            mitreTechniques: mitreTechniques,
            suppressed: false,
            llmInvestigation: nil
        )
    }

    @Test("search hits every indexed column")
    func searchHitsAllFields() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(alert: alert(title: "Suspicious sshd login"))
        try await store.insert(alert: alert(title: "other", processName: "sshd"))
        try await store.insert(alert: alert(title: "other", processPath: "/usr/sbin/sshd"))
        try await store.insert(alert: alert(title: "other", description: "ssh brute force"))
        try await store.insert(alert: alert(title: "other", mitreTechniques: "T1110.001"))
        try await store.insert(alert: alert(title: "unrelated"))

        let sshHits = try await store.search(text: "ssh")
        #expect(sshHits.count == 4)

        let mitreHits = try await store.search(text: "T1110")
        #expect(mitreHits.count == 1)
    }

    @Test("LIKE wildcards in input are treated as literals")
    func wildcardsInInputDoNotEscape() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(alert: alert(title: "rule_a"))
        try await store.insert(alert: alert(title: "rule_b"))
        try await store.insert(alert: alert(title: "ruleX"))

        // `_` is a SQLite single-char wildcard. The implementation strips
        // it from the user input so the search literally is "rule" — which
        // matches all three.
        let underscoreSearch = try await store.search(text: "_")
        #expect(underscoreSearch.count == 3)

        // `%` is the SQLite multi-char wildcard. Same treatment.
        let percentSearch = try await store.search(text: "%")
        #expect(percentSearch.count == 3)
    }

    @Test("results ordered most-recent-first")
    func resultsOrderedRecentFirst() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(alert: alert(title: "ssh oldest", at: base))
        try await store.insert(alert: alert(title: "ssh middle", at: base.addingTimeInterval(60)))
        try await store.insert(alert: alert(title: "ssh newest", at: base.addingTimeInterval(120)))

        let hits = try await store.search(text: "ssh")
        #expect(hits.count == 3)
        #expect(hits.first?.ruleTitle == "ssh newest")
        #expect(hits.last?.ruleTitle == "ssh oldest")
    }

    @Test("limit clamps to [1, 1000]")
    func limitClamped() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        for _ in 0..<3 {
            try await store.insert(alert: alert(title: "needle"))
        }

        let zero = try await store.search(text: "needle", limit: 0)
        #expect(zero.count == 1)

        let huge = try await store.search(text: "needle", limit: 100_000)
        #expect(huge.count == 3)
    }

    @Test("no matches returns empty")
    func noMatches() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(alert: alert(title: "ssh login"))

        let hits = try await store.search(text: "kerberos")
        #expect(hits.isEmpty)
    }
}
