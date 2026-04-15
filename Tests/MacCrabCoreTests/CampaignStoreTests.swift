// CampaignStoreTests.swift
// Unit tests for the persistent CampaignStore.

import Testing
import Foundation
import SQLite3
@testable import MacCrabCore

@Suite("Campaign Store")
struct CampaignStoreTests {

    private func makeTempPath() -> String {
        NSTemporaryDirectory() + "maccrab_campaign_\(UUID().uuidString).db"
    }

    private func cleanup(_ path: String) {
        [path, path + "-wal", path + "-shm"].forEach { try? FileManager.default.removeItem(atPath: $0) }
    }

    private func sampleRecord(id: String = UUID().uuidString, detectedAt: Date = Date()) -> CampaignStore.Record {
        CampaignStore.Record(
            id: id,
            type: "kill_chain",
            severity: .high,
            title: "Kill chain detected",
            description: "3 tactics in 90s",
            tactics: ["TA0002", "TA0003", "TA0005"],
            timeSpanSeconds: 90,
            detectedAt: detectedAt,
            alerts: [
                CampaignStore.AlertRef(
                    ruleId: "r1",
                    ruleTitle: "Suspicious exec",
                    severity: .high,
                    processPath: "/usr/bin/curl",
                    pid: 1234,
                    userId: "501",
                    timestamp: detectedAt,
                    tactics: ["TA0002"]
                )
            ]
        )
    }

    @Test("Insert and get a campaign")
    func insertAndGet() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try CampaignStore(path: path)
        let r = sampleRecord()
        try await store.insert(r)

        let fetched = try await store.get(id: r.id)
        #expect(fetched?.id == r.id)
        #expect(fetched?.title == r.title)
        #expect(fetched?.tactics == r.tactics)
        #expect(fetched?.alerts.first?.processPath == "/usr/bin/curl")
    }

    @Test("Count reflects inserts")
    func count() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try CampaignStore(path: path)
        #expect(try await store.count() == 0)

        try await store.insert(sampleRecord())
        try await store.insert(sampleRecord())
        #expect(try await store.count() == 2)
    }

    @Test("List orders newest first and honours limit")
    func listOrdering() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try CampaignStore(path: path)
        let now = Date()
        try await store.insert(sampleRecord(id: "old", detectedAt: now.addingTimeInterval(-3600)))
        try await store.insert(sampleRecord(id: "mid", detectedAt: now.addingTimeInterval(-60)))
        try await store.insert(sampleRecord(id: "new", detectedAt: now))

        let all = try await store.list()
        #expect(all.map(\.id) == ["new", "mid", "old"])

        let top2 = try await store.list(limit: 2)
        #expect(top2.count == 2)
        #expect(top2.first?.id == "new")
    }

    @Test("includeSuppressed=false filters suppressed campaigns")
    func suppressedFilter() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try CampaignStore(path: path)
        try await store.insert(sampleRecord(id: "visible"))
        try await store.insert(sampleRecord(id: "hidden"))
        try await store.setSuppressed(id: "hidden", true)

        let visible = try await store.list(includeSuppressed: false)
        #expect(visible.map(\.id) == ["visible"])

        let all = try await store.list(includeSuppressed: true)
        #expect(all.count == 2)

        // Round-trip: raw_json reflects suppression change
        let reread = try await store.get(id: "hidden")
        #expect(reread?.suppressed == true)
    }

    @Test("Notes attach and round-trip through raw_json")
    func notesRoundTrip() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try CampaignStore(path: path)
        try await store.insert(sampleRecord(id: "n1"))
        try await store.setNotes(id: "n1", notes: "Vendor update rollout — confirmed benign")

        let r = try await store.get(id: "n1")
        #expect(r?.notes == "Vendor update rollout — confirmed benign")
    }

    @Test("Prune removes old rows and returns count")
    func prune() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let store = try CampaignStore(path: path)
        let now = Date()
        try await store.insert(sampleRecord(id: "old", detectedAt: now.addingTimeInterval(-3600)))
        try await store.insert(sampleRecord(id: "new", detectedAt: now))

        let deleted = try await store.prune(olderThan: now.addingTimeInterval(-60))
        #expect(deleted == 1)
        #expect(try await store.count() == 1)
        #expect(try await store.get(id: "new")?.id == "new")
    }

    @Test("Store survives reopen at same path")
    func reopen() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        let r = sampleRecord(id: "persistent")
        do {
            let store = try CampaignStore(path: path)
            try await store.insert(r)
        }

        let store2 = try CampaignStore(path: path)
        #expect(try await store2.get(id: "persistent")?.id == "persistent")
        #expect(try await store2.count() == 1)
    }

    @Test("Schema migrates cleanly on first open")
    func migrationClean() async throws {
        let path = makeTempPath()
        defer { cleanup(path) }

        _ = try CampaignStore(path: path)
        // Open raw to verify user_version was bumped.
        var raw: OpaquePointer?
        let rc = sqlite3_open_v2(path, &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
        #expect(rc == SQLITE_OK)
        defer { if let raw { sqlite3_close(raw) } }
        let version = try #require(try? SchemaMigrator.readVersion(db: raw!))
        #expect(version >= 1)
    }
}
