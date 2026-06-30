// StorePruneOldestTests.swift
//
// v1.8.0 storage redesign: AlertStore and CampaignStore now have
// pruneOldest(count:) helpers paralleling EventStore.pruneOldest. These
// back the per-store hourly size-cap timers in DaemonTimers — defense
// in depth when alerts.db / campaigns.db exceed alertsMaxSizeMB /
// campaignsMaxSizeMB despite time-based retention.
//
// Pins the contract:
//   1. Drops EXACTLY the oldest N rows by timestamp / detected_at
//   2. Returns the number actually deleted
//   3. count == 0 is a no-op
//   4. count > total drops everything

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AlertStore.pruneOldest (v1.8.0)")
struct AlertStorePruneOldestTests {

    private func makeStore() throws -> (AlertStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-alert-prune-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try AlertStore(directory: tmp.path)
        return (store, tmp)
    }

    private func mkAlert(at date: Date, id: String = UUID().uuidString) -> Alert {
        Alert(
            id: id,
            timestamp: date,
            ruleId: "test.rule",
            ruleTitle: "Test",
            severity: .high,
            eventId: UUID().uuidString,
            processPath: nil,
            processName: nil,
            description: nil,
            mitreTactics: nil,
            mitreTechniques: nil,
            suppressed: false,
            llmInvestigation: nil
        )
    }

    @Test("Drops exactly the oldest N alerts by timestamp")
    func pruneOldestN() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        for i in 0..<10 {
            try await store.insert(alert: mkAlert(at: now.addingTimeInterval(-Double(i) * 60)))
        }

        let dropped = try await store.pruneOldest(count: 3)
        #expect(dropped == 3)

        let remaining = try await store.alerts(since: Date.distantPast, limit: 100)
        #expect(remaining.count == 7)
        // Oldest of the original 10 was at -9 minutes; after dropping 3
        // oldest, the remaining oldest should be at -6 minutes.
        let oldestRemaining = remaining.min { $0.timestamp < $1.timestamp }!
        #expect(oldestRemaining.timestamp >= now.addingTimeInterval(-6.0 * 60 - 1))
    }

    @Test("count == 0 is a no-op")
    func pruneZero() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(alert: mkAlert(at: Date()))
        let dropped = try await store.pruneOldest(count: 0)
        #expect(dropped == 0)
        let remaining = try await store.alerts(since: Date.distantPast, limit: 100)
        #expect(remaining.count == 1)
    }

    @Test("count > total drops everything")
    func pruneOverflow() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        for _ in 0..<5 {
            try await store.insert(alert: mkAlert(at: Date()))
        }
        let dropped = try await store.pruneOldest(count: 100)
        #expect(dropped == 5)
        let remaining = try await store.alerts(since: Date.distantPast, limit: 100)
        #expect(remaining.isEmpty)
    }
}

@Suite("CampaignStore.pruneOldest (v1.8.0)")
struct CampaignStorePruneOldestTests {

    private func makeStore() throws -> (CampaignStore, URL) {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-campaign-prune-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        let store = try CampaignStore(directory: tmp.path)
        return (store, tmp)
    }

    private func mkCampaign(at date: Date, id: String = UUID().uuidString) -> CampaignStore.Record {
        CampaignStore.Record(
            id: id,
            type: "kill_chain",
            severity: .high,
            title: "Test Campaign",
            description: "desc",
            tactics: ["execution", "persistence"],
            timeSpanSeconds: 300,
            detectedAt: date
        )
    }

    @Test("Drops exactly the oldest N campaigns by detected_at")
    func pruneOldestN() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        let now = Date()
        for i in 0..<10 {
            try await store.insert(mkCampaign(at: now.addingTimeInterval(-Double(i) * 3600)))
        }

        let dropped = try await store.pruneOldest(count: 4)
        #expect(dropped == 4)

        let remaining = try await store.list(since: Date.distantPast, limit: 100)
        #expect(remaining.count == 6)
        let oldestRemaining = remaining.min { $0.detectedAt < $1.detectedAt }!
        // Original oldest was -9h; after dropping 4 oldest, remaining oldest
        // should be at -5h.
        #expect(oldestRemaining.detectedAt >= now.addingTimeInterval(-5.0 * 3600 - 60))
    }

    @Test("count == 0 is a no-op")
    func pruneZero() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        try await store.insert(mkCampaign(at: Date()))
        let dropped = try await store.pruneOldest(count: 0)
        #expect(dropped == 0)
        let remaining = try await store.list(since: Date.distantPast, limit: 100)
        #expect(remaining.count == 1)
    }

    @Test("count > total drops everything")
    func pruneOverflow() async throws {
        let (store, tmp) = try makeStore()
        defer { try? FileManager.default.removeItem(at: tmp) }

        for _ in 0..<3 {
            try await store.insert(mkCampaign(at: Date()))
        }
        let dropped = try await store.pruneOldest(count: 100)
        #expect(dropped == 3)
        let remaining = try await store.list(since: Date.distantPast, limit: 100)
        #expect(remaining.isEmpty)
    }
}
