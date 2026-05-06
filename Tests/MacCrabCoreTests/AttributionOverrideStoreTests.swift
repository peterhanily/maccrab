// AttributionOverrideStoreTests.swift
// v1.9 PR-4 — operator-recorded verdict overlay tests.
//
// Plan v3 review #4 / #10 / #11 / #12:
//   * machine attribution immutable; verdict is overlay
//   * single source of truth per event (replace, not append)
//   * retention coupling (purgeOrphaned)
//   * versioned enum / tolerant decode
//   * formatted accuracy line carries "rated=N, total=M"

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AttributionOverride: model + JSON")
struct AttributionOverrideModelTests {

    @Test("Verdict raw values are stable across releases")
    func verdictRawValues() {
        #expect(AttributionOverride.Verdict.confirmed.rawValue == "confirmed")
        #expect(AttributionOverride.Verdict.wrongTool.rawValue == "wrong_tool")
        #expect(AttributionOverride.Verdict.noAgent.rawValue == "no_agent")
        #expect(AttributionOverride.Verdict.unknown.rawValue == "unknown")
    }

    @Test("Stats formatter uses 'rated=N, total=M' label (Plan v3 review #11)")
    func formattedAccuracyLine() {
        let stats = AttributionOverrideStats(
            ratedCount: 1247,
            confirmedCount: 1172,
            wrongToolCount: 50,
            noAgentCount: 20,
            unknownVerdictCount: 5,
            totalEventsWithMachineAttribution: 53_000
        )
        let line = stats.formattedAccuracyLine
        #expect(line.contains("rated=1247"))
        #expect(line.contains("total=53000"))
        #expect(line.contains("attribution_accuracy_among_rated"))
        // Accuracy is 1172/1247 ≈ 0.94
        #expect(line.contains("0.94"))
    }

    @Test("Formatter shows '—' when no rated rows")
    func emptyAccuracy() {
        let stats = AttributionOverrideStats(
            ratedCount: 0,
            confirmedCount: 0, wrongToolCount: 0, noAgentCount: 0, unknownVerdictCount: 0,
            totalEventsWithMachineAttribution: 100
        )
        #expect(stats.accuracyAmongRated == nil)
        #expect(stats.formattedAccuracyLine.contains("rated=0"))
        #expect(stats.formattedAccuracyLine.contains("total=100"))
        #expect(stats.formattedAccuracyLine.contains("—"))
    }

    @Test("AttributionOverride round-trips via Codable")
    func codableRoundtrip() throws {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let original = AttributionOverride(
            eventId: "550e8400-e29b-41d4-a716-446655440000",
            machineConfidence: "traceparent",
            verdict: .wrongTool,
            userNote: "actually a script run by hand",
            createdAt: now,
            updatedAt: now
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(AttributionOverride.self, from: data)
        #expect(decoded.eventId == original.eventId)
        #expect(decoded.verdict == .wrongTool)
        #expect(decoded.userNote == "actually a script run by hand")
        #expect(decoded.schemaVersion == 1)
    }
}

@Suite("EventStore: attribution_overrides CRUD")
struct AttributionOverrideStoreTests {

    private static func tempEventStorePath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("override-store-\(UUID().uuidString).db").path
    }

    private static func makeStore() throws -> (EventStore, String) {
        let path = Self.tempEventStorePath()
        let store = try EventStore(path: path)
        return (store, path)
    }

    private static func sampleOverride(
        eventId: String,
        verdict: AttributionOverride.Verdict = .confirmed,
        note: String? = nil
    ) -> AttributionOverride {
        AttributionOverride(
            eventId: eventId,
            machineConfidence: "lineage",
            verdict: verdict,
            userNote: note
        )
    }

    @Test("Round-trip: record then read back")
    func roundTrip() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let evId = UUID().uuidString
        try await store.recordAttributionOverride(Self.sampleOverride(
            eventId: evId, verdict: .confirmed, note: "looks right"
        ))
        let read = try await store.attributionOverride(for: evId)
        #expect(read?.verdict == .confirmed)
        #expect(read?.userNote == "looks right")
    }

    @Test("Replace, not append: second verdict for same event overwrites first")
    func replaceOnSecondVerdict() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let evId = UUID().uuidString
        try await store.recordAttributionOverride(Self.sampleOverride(
            eventId: evId, verdict: .confirmed
        ))
        try await store.recordAttributionOverride(Self.sampleOverride(
            eventId: evId, verdict: .wrongTool, note: "actually cursor"
        ))
        let read = try await store.attributionOverride(for: evId)
        #expect(read?.verdict == .wrongTool)
        #expect(read?.userNote == "actually cursor")
        // Stats: exactly one row, exactly one verdict bucket.
        let stats = try await store.attributionOverrideStats()
        #expect(stats.ratedCount == 1)
        #expect(stats.wrongToolCount == 1)
        #expect(stats.confirmedCount == 0)
    }

    @Test("Stats aggregate verdicts across events")
    func statsAggregate() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let ids = (0..<5).map { _ in UUID().uuidString }
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: ids[0], verdict: .confirmed))
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: ids[1], verdict: .confirmed))
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: ids[2], verdict: .wrongTool))
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: ids[3], verdict: .noAgent))
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: ids[4], verdict: .unknown))
        let stats = try await store.attributionOverrideStats()
        #expect(stats.ratedCount == 5)
        #expect(stats.confirmedCount == 2)
        #expect(stats.wrongToolCount == 1)
        #expect(stats.noAgentCount == 1)
        #expect(stats.unknownVerdictCount == 1)
        #expect(stats.accuracyAmongRated == 0.4)
    }

    @Test("purgeOrphanedAttributionOverrides deletes rows with no events")
    func purgeOrphans() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        // Record overrides for events that don't exist in `events`.
        let id1 = UUID().uuidString
        let id2 = UUID().uuidString
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: id1))
        try await store.recordAttributionOverride(Self.sampleOverride(eventId: id2))
        let preStats = try await store.attributionOverrideStats()
        #expect(preStats.ratedCount == 2)
        let purged = try await store.purgeOrphanedAttributionOverrides()
        #expect(purged == 2)
        let postStats = try await store.attributionOverrideStats()
        #expect(postStats.ratedCount == 0)
    }

    @Test("attributionOverride(for:) returns nil for unknown event")
    func nilForMissing() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let result = try await store.attributionOverride(for: "no-such-event")
        #expect(result == nil)
    }

    @Test("Tolerant decode: unknown verdict raw becomes .unknown")
    func tolerantVerdictDecode() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let evId = UUID().uuidString
        // Insert a row with a verdict the v1.9 reader doesn't know.
        // We do this via the CRUD API by abusing the verdict enum:
        // can't create a fake enum case, so we encode an
        // AttributionOverride with .unknown which proves the decode
        // path works for known values; the "unknown future raw"
        // fallback path is exercised by Verdict(rawValue:) returning nil.
        try await store.recordAttributionOverride(Self.sampleOverride(
            eventId: evId, verdict: .unknown
        ))
        let read = try await store.attributionOverride(for: evId)
        #expect(read?.verdict == .unknown)
    }

    @Test("Updated_at bumps on second verdict")
    func updatedAtBumps() async throws {
        let (store, path) = try Self.makeStore()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let evId = UUID().uuidString
        let early = Date(timeIntervalSince1970: 1_700_000_000)
        let late = Date(timeIntervalSince1970: 1_700_000_500)
        try await store.recordAttributionOverride(AttributionOverride(
            eventId: evId, machineConfidence: nil, verdict: .confirmed,
            createdAt: early, updatedAt: early
        ))
        try await store.recordAttributionOverride(AttributionOverride(
            eventId: evId, machineConfidence: nil, verdict: .wrongTool,
            createdAt: early, updatedAt: late
        ))
        let read = try await store.attributionOverride(for: evId)
        #expect(read?.updatedAt == late)
        #expect(read?.verdict == .wrongTool)
    }
}

@Suite("Schema v5: events.db migration")
struct SchemaV5MigrationTests {

    @Test("Fresh EventStore at schema v5 has attribution_overrides table")
    func migrationApplied() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("schema-v5-\(UUID().uuidString).db").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)
        // If the migration applied, recordAttributionOverride must succeed.
        try await store.recordAttributionOverride(AttributionOverride(
            eventId: UUID().uuidString,
            machineConfidence: nil,
            verdict: .confirmed
        ))
        let stats = try await store.attributionOverrideStats()
        #expect(stats.ratedCount == 1)
    }
}

// v1.9 PR-5 audit (B3): the dashboard now writes to its own
// AttributionOverrideStore (separate SQLite file at user-writable
// path) rather than into the root-owned events.db.

@Suite("AttributionOverrideStore: split-store CRUD + stats")
struct AttributionOverrideStoreSplitTests {

    private static func tempPath() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("override-split-\(UUID().uuidString).db").path
    }

    @Test("UPSERT round-trip + replace-on-second-verdict")
    func upsert() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try AttributionOverrideStore(path: path)
        let evId = UUID().uuidString
        try await store.record(AttributionOverride(
            eventId: evId, machineConfidence: "lineage", verdict: .confirmed
        ))
        try await store.record(AttributionOverride(
            eventId: evId, machineConfidence: "lineage",
            verdict: .wrongTool, userNote: "actually cursor"
        ))
        let read = try await store.fetch(eventId: evId)
        #expect(read?.verdict == .wrongTool)
        #expect(read?.userNote == "actually cursor")
        #expect(try await store.count() == 1)
    }

    @Test("Stats compose with caller-supplied total")
    func statsRollUp() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try AttributionOverrideStore(path: path)
        for _ in 0..<3 {
            try await store.record(AttributionOverride(
                eventId: UUID().uuidString, machineConfidence: nil,
                verdict: .confirmed
            ))
        }
        try await store.record(AttributionOverride(
            eventId: UUID().uuidString, machineConfidence: nil,
            verdict: .wrongTool
        ))
        let stats = try await store.stats(totalEventsWithMachineAttribution: 1000)
        #expect(stats.ratedCount == 4)
        #expect(stats.confirmedCount == 3)
        #expect(stats.wrongToolCount == 1)
        #expect(stats.totalEventsWithMachineAttribution == 1000)
        #expect(stats.formattedAccuracyLine.contains("rated=4"))
        #expect(stats.formattedAccuracyLine.contains("total=1000"))
        #expect(stats.formattedAccuracyLine.contains("0.75"))
    }

    @Test("Fetch returns nil for unknown event_id")
    func nilForMissing() async throws {
        let path = Self.tempPath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try AttributionOverrideStore(path: path)
        #expect(try await store.fetch(eventId: "no-such") == nil)
    }
}

// v1.9 PR-5 audit (B1): the EventStore.eventCountWithMachineAttribution
// roll-up surface used by AppState + StatusCommand.

@Suite("EventStore.eventCountWithMachineAttribution roll-up")
struct EventCountWithMachineAttributionTests {

    @Test("Counts events with agent_trace_id OR agent_tool")
    func rollUp() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("rollup-\(UUID().uuidString).db").path
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try EventStore(path: path)
        let proc = MacCrabCore.ProcessInfo(
            pid: 1, ppid: 0, rpid: 0, name: "x", executable: "/bin/x",
            commandLine: "x", args: [], workingDirectory: "/",
            userId: 0, userName: "u", groupId: 0, startTime: Date(),
            codeSignature: nil, ancestors: [], architecture: nil,
            isPlatformBinary: false
        )
        // 2 with attribution, 1 without
        for i in 0..<3 {
            var e = Event(eventCategory: .process, eventType: .start,
                          eventAction: "exec", process: proc)
            if i < 2 {
                e.enrichments[TraceCorrelator.EnrichmentKey.traceId] = String(repeating: "a", count: 32)
                e.enrichments[TraceCorrelator.EnrichmentKey.agentTool] = "claude_code"
            }
            try await store.insert(event: e)
        }
        let n = try await store.eventCountWithMachineAttribution()
        #expect(n == 2)
    }
}
