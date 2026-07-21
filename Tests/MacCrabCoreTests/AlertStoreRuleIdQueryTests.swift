// AlertStoreRuleIdQueryTests.swift
//
// v1.21.5: coverage for the exact-rule-id `AlertStore.alerts(since:ruleId:)`
// added for get_intent_posterior. The generic alerts(since:) applies its
// 500-row cap BEFORE any caller-side rule filter, so a low-volume rule's
// alerts (the daemon's `maccrab.intent.bayesian-posterior` posteriors)
// could be crowded out of the window entirely on a busy box. These pin the
// SQL-layer contract:
//
//   1. Exact match only — no prefix/LIKE semantics, wildcards are literals
//   2. Noise rows can't crowd matches out of the cap (the crowd-out fix)
//   3. `since` bounds the window; results most-recent-first; `limit` honored

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore.alerts(since:ruleId:) (v1.21.5)")
struct AlertStoreRuleIdQueryTests {

    private static let posteriorRuleId = "maccrab.intent.bayesian-posterior"

    private func makeTempAlertStore() throws -> (AlertStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-alert-ruleid-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tmp.path)
        return (store, tmp)
    }

    private func alert(ruleId: String, title: String = "t", at date: Date = Date()) -> Alert {
        Alert(
            id: UUID().uuidString,
            timestamp: date,
            ruleId: ruleId,
            ruleTitle: title,
            severity: .medium,
            eventId: UUID().uuidString
        )
    }

    @Test("returns only exact rule-id matches from a mixed store")
    func exactMatchOnly() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(alert: alert(ruleId: Self.posteriorRuleId, at: base))
        try await store.insert(alert: alert(ruleId: "maccrab.intent.bayesian-posterior-x", at: base))
        try await store.insert(alert: alert(ruleId: "maccrab.intent", at: base))
        try await store.insert(alert: alert(ruleId: "exec.osascript.suspicious", at: base))

        let hits = try await store.alerts(
            since: base.addingTimeInterval(-60), ruleId: Self.posteriorRuleId)
        #expect(hits.count == 1)
        #expect(hits.first?.ruleId == Self.posteriorRuleId)
    }

    @Test("LIKE wildcards in ruleId are literals (parameterized equality, not LIKE)")
    func wildcardsAreLiterals() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(alert: alert(ruleId: "maccrab.campaign.kill-chain"))
        let hits = try await store.alerts(
            since: Date().addingTimeInterval(-60), ruleId: "maccrab.campaign.%")
        #expect(hits.isEmpty)
    }

    @Test("noise rows can't crowd matches out of the cap (the get_intent_posterior fix)")
    func noiseDoesNotCrowdOutMatches() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // One old posterior, then a NEWER pile of noise larger than the
        // limit. The pre-fix pattern (alerts(since:) then filter) would
        // fill its cap with the newest rows — all noise — and drop the
        // posterior; the SQL-layer filter must still return it.
        let base = Date()
        try await store.insert(alert: alert(ruleId: Self.posteriorRuleId, at: base))
        for i in 0..<40 {
            try await store.insert(alert: alert(
                ruleId: "noise.rule.\(i % 5)", at: base.addingTimeInterval(Double(i + 1))))
        }

        let hits = try await store.alerts(
            since: base.addingTimeInterval(-60), ruleId: Self.posteriorRuleId, limit: 10)
        #expect(hits.count == 1)
        #expect(hits.first?.ruleId == Self.posteriorRuleId)
    }

    @Test("since bounds the window; results most-recent-first; limit honored")
    func windowOrderingAndLimit() async throws {
        let (store, tmp) = try makeTempAlertStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let base = Date()
        try await store.insert(alert: alert(ruleId: Self.posteriorRuleId, title: "too old",
                                            at: base.addingTimeInterval(-120)))
        try await store.insert(alert: alert(ruleId: Self.posteriorRuleId, title: "oldest",
                                            at: base))
        try await store.insert(alert: alert(ruleId: Self.posteriorRuleId, title: "middle",
                                            at: base.addingTimeInterval(60)))
        try await store.insert(alert: alert(ruleId: Self.posteriorRuleId, title: "newest",
                                            at: base.addingTimeInterval(120)))

        let all = try await store.alerts(
            since: base.addingTimeInterval(-60), ruleId: Self.posteriorRuleId)
        #expect(all.map(\.ruleTitle) == ["newest", "middle", "oldest"])

        let limited = try await store.alerts(
            since: base.addingTimeInterval(-60), ruleId: Self.posteriorRuleId, limit: 2)
        #expect(limited.map(\.ruleTitle) == ["newest", "middle"])
    }
}
