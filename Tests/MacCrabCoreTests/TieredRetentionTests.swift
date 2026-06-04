// TieredRetentionTests.swift
//
// Phase 2a (v1.8.0): coverage for the new three-tier storage model that
// replaces the legacy size-cap-and-VACUUM dance.
//
// The contract under test:
//   1. `recordAlertEvidence` snapshots the ±60s window of events into
//      `alert_evidence`, idempotently.
//   2. `evidenceFor` reads back exactly what was captured.
//   3. `rollUpAndPrune` aggregates events older than `cutoff` into
//      `event_aggregates` (with day/category/signer/path grouping) AND
//      deletes them from the hot tier.
//   4. The aggregate rollup is idempotent — running rollUpAndPrune twice
//      with no new events between runs doesn't double-count.
//   5. `aggregates(sinceDay:category:)` returns the expected counts.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Tiered retention (v1.8.0)")
struct TieredRetentionTests {

    private func makeTempStore() throws -> (EventStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-tiers-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try EventStore(directory: tmp.path)
        return (store, tmp)
    }

    private func sampleEvent(at date: Date, name: String = "sample", path: String = "/bin/sample") -> Event {
        let proc = ProcessInfo(
            pid: 1000, ppid: 1, rpid: 1,
            name: name, executable: path,
            commandLine: path, args: [],
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

    // MARK: - Alert evidence

    @Test("recordAlertEvidence snapshots the ±60s window")
    func evidenceCapturesSurroundingEvents() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let alertTime = Date()
        let alertId = UUID().uuidString

        // 5 events: -120s, -30s, 0s, +30s, +120s. The ±60s window
        // captures the middle three.
        for offset in [-120.0, -30.0, 0.0, 30.0, 120.0] {
            try await store.insert(event: sampleEvent(at: alertTime.addingTimeInterval(offset)))
        }

        try await store.recordAlertEvidence(alertId: alertId, alertTimestamp: alertTime)
        let evidence = try await store.evidenceFor(alertId: alertId)
        #expect(evidence.count == 3)
    }

    @Test("recordAlertEvidence is idempotent")
    func evidenceRecordingIsIdempotent() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let alertTime = Date()
        let alertId = UUID().uuidString
        try await store.insert(event: sampleEvent(at: alertTime))

        try await store.recordAlertEvidence(alertId: alertId, alertTimestamp: alertTime)
        try await store.recordAlertEvidence(alertId: alertId, alertTimestamp: alertTime)
        try await store.recordAlertEvidence(alertId: alertId, alertTimestamp: alertTime)

        let evidence = try await store.evidenceFor(alertId: alertId)
        #expect(evidence.count == 1)
    }

    @Test("pruneAlertEvidenceBySize evicts oldest until under the byte cap (RC H2)")
    func evidenceSizeCapEvictsOldest() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // 30 alerts, each with one evidence row, spaced 1 min apart (oldest first).
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        var ids: [String] = []
        for i in 0..<30 {
            let t = base.addingTimeInterval(Double(i) * 60)
            try await store.insert(event: sampleEvent(at: t))
            let id = "alert-\(i)"
            ids.append(id)
            try await store.recordAlertEvidence(alertId: id, alertTimestamp: t)
        }
        // Measure one row's payload to set a cap that keeps ~10 rows.
        let oneRow = try await store.evidenceFor(alertId: ids[0]).count
        #expect(oneRow == 1)

        // Cap above current size -> no-op.
        let noop = try await store.pruneAlertEvidenceBySize(maxBytes: 100_000_000)
        #expect(noop == 0)

        // Cap of 0 / negative -> guard returns 0 (no deletion).
        #expect(try await store.pruneAlertEvidenceBySize(maxBytes: 0) == 0)

        // Tight cap with a tiny batch -> evicts the OLDEST rows, newest survive.
        let deleted = try await store.pruneAlertEvidenceBySize(maxBytes: 1500, batchSize: 3)
        #expect(deleted > 0)
        // The oldest alert's evidence must be gone; the newest must remain.
        #expect(try await store.evidenceFor(alertId: ids[0]).isEmpty)
        #expect(try await store.evidenceFor(alertId: ids[29]).count == 1)
    }

    @Test("evidenceFor returns empty for unknown alert id")
    func evidenceForUnknownAlertEmpty() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let evidence = try await store.evidenceFor(alertId: UUID().uuidString)
        #expect(evidence.isEmpty)
    }

    // MARK: - Roll-up + prune

    @Test("rollUpAndPrune deletes hot-tier rows older than cutoff and aggregates them")
    func rollUpDeletesAndAggregates() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        let oldDay = now.addingTimeInterval(-3 * 86400)   // 3 days old
        let recent = now.addingTimeInterval(-1 * 3600)    // 1 hour old

        // 5 old events (will roll up), 2 recent events (stay in hot tier).
        for _ in 0..<5 {
            try await store.insert(event: sampleEvent(at: oldDay))
        }
        for _ in 0..<2 {
            try await store.insert(event: sampleEvent(at: recent))
        }

        let cutoff = now.addingTimeInterval(-86400) // 24h ago
        let deleted = try await store.rollUpAndPrune(olderThan: cutoff)
        #expect(deleted == 5)

        // Hot tier: only the 2 recent events.
        let remaining = try await store.events(since: Date.distantPast, limit: 100)
        #expect(remaining.count == 2)

        // Aggregates: one row for the old day + category + signer + path.
        let aggCount = try await store.aggregateCount()
        #expect(aggCount >= 1)
    }

    @Test("rollUpAndPrune is idempotent — re-running with no new events doesn't double-count")
    func rollUpIsIdempotent() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let oldDay = Date().addingTimeInterval(-3 * 86400)
        for _ in 0..<10 {
            try await store.insert(event: sampleEvent(at: oldDay))
        }

        let cutoff = Date().addingTimeInterval(-86400)
        try await store.rollUpAndPrune(olderThan: cutoff)
        try await store.rollUpAndPrune(olderThan: cutoff)
        try await store.rollUpAndPrune(olderThan: cutoff)

        // The aggregate row should still report 10 events even after
        // three roll-up calls — the second + third had nothing left in
        // the hot tier to count.
        let agg = try await store.aggregates(sinceDay: "2000-01-01")
        let total = agg.reduce(0) { $0 + $1.count }
        #expect(total == 10)
    }

    @Test("aggregates(sinceDay:category:) filters by day and category")
    func aggregatesFilterCorrectly() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let oldDay = Date().addingTimeInterval(-2 * 86400)
        for _ in 0..<3 {
            try await store.insert(event: sampleEvent(at: oldDay))
        }
        let cutoff = Date().addingTimeInterval(-86400)
        try await store.rollUpAndPrune(olderThan: cutoff)

        // Future day → empty.
        let futureDay = "2099-01-01"
        let none = try await store.aggregates(sinceDay: futureDay)
        #expect(none.isEmpty)

        // Beginning of time → finds our row.
        let all = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(!all.isEmpty)

        // Wrong category → empty.
        let networkOnly = try await store.aggregates(sinceDay: "2000-01-01", category: .network)
        #expect(networkOnly.isEmpty)

        // Right category → finds our row.
        let processOnly = try await store.aggregates(sinceDay: "2000-01-01", category: .process)
        #expect(!processOnly.isEmpty)
    }

    @Test("rollUpAndPrune trims aggregate rows older than 30 days")
    func rollUpTrimsOldAggregates() async throws {
        let (store, tmp) = try makeTempStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Plant: one 60-day-old event (will be trimmed after rollup) + one
        // 5-day-old event (will survive the 30-day trim window).
        let veryOld = Date().addingTimeInterval(-60 * 86400)
        let recentlyOld = Date().addingTimeInterval(-5 * 86400)
        try await store.insert(event: sampleEvent(at: veryOld))
        try await store.insert(event: sampleEvent(at: recentlyOld, name: "recent", path: "/bin/recent"))

        // Single rollup: aggregates both → trim drops the 60-day-old → only
        // the 5-day-old aggregate row survives.
        try await store.rollUpAndPrune(olderThan: Date().addingTimeInterval(-86400))

        let agg = try await store.aggregates(sinceDay: "2000-01-01")
        #expect(agg.count == 1)
        #expect(agg.first?.processPath == "/bin/recent")
    }
}
