// Panel171SnapshotTests.swift
//
// v1.7.1 daemon-side panel-richness snapshots:
//  - RuleEngine.writeTelemetrySnapshot / readTelemetrySnapshot
//  - TCCMonitor.writeSnapshot / readSnapshot
//  - EventStore.eventCountsByCategory query
//
// Tests cover round-trip and decoder coverage. SwiftUI rendering is
// verified manually pre-release (out-of-scope for unit suites).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Panel-richness daemon snapshots (v1.7.1)")
struct Panel171SnapshotTests {

    @Test("RuleEngine.TelemetrySnapshot round-trip")
    func ruleTelemetryRoundTrip() async throws {
        // Build a TelemetrySnapshot directly (no live RuleEngine state
        // needed — we're testing the JSON wire format, not the
        // counter-update logic).
        let stats = [
            RuleEngine.RuleStats(
                ruleId: "test.rule.alpha",
                evaluationCount: 100, fireCount: 12, totalExecNs: 5_000_000,
                lastFiredAt: Date(timeIntervalSince1970: 1_700_000_000)
            ),
            RuleEngine.RuleStats(
                ruleId: "test.rule.beta",
                evaluationCount: 50, fireCount: 0, totalExecNs: 200_000,
                lastFiredAt: nil
            ),
        ]
        let snap = RuleEngine.TelemetrySnapshot(writtenAt: Date(), stats: stats)
        let path = NSTemporaryDirectory() + "maccrab-rule-telemetry-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        let data = try JSONEncoder().encode(snap)
        try data.write(to: URL(fileURLWithPath: path))

        let loaded = RuleEngine.readTelemetrySnapshot(at: path)
        #expect(loaded != nil)
        #expect(loaded?.stats.count == 2)
        let alpha = loaded?.stats.first { $0.ruleId == "test.rule.alpha" }
        #expect(alpha?.fireCount == 12)
        #expect(alpha?.evaluationCount == 100)
        #expect(alpha?.lastFiredAt != nil)
        let beta = loaded?.stats.first { $0.ruleId == "test.rule.beta" }
        #expect(beta?.fireCount == 0)
        #expect(beta?.lastFiredAt == nil)
    }

    @Test("RuleEngine.RuleStats meanExecNs handles zero evaluations")
    func meanExecGuardsZeroDivisor() {
        let s = RuleEngine.RuleStats(ruleId: "x", evaluationCount: 0, fireCount: 0, totalExecNs: 0)
        #expect(s.meanExecNs == 0)
        let t = RuleEngine.RuleStats(ruleId: "y", evaluationCount: 4, fireCount: 1, totalExecNs: 8_000_000)
        #expect(t.meanExecNs == 2_000_000.0)
    }

    @Test("RuleEngine telemetry write through the live actor produces a readable snapshot")
    func liveTelemetryWrite() async throws {
        // Use the live RuleEngine API even though this is a unit test —
        // we want to ensure the actor-isolated writeTelemetrySnapshot
        // path works against a fresh (empty) state.
        let engine = RuleEngine()
        let path = NSTemporaryDirectory() + "maccrab-rule-telemetry-live-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        await engine.writeTelemetrySnapshot(to: path)
        let snap = RuleEngine.readTelemetrySnapshot(at: path)
        #expect(snap != nil)
        #expect(snap?.stats.isEmpty == true) // fresh engine, no evaluations
    }

    @Test("TCCMonitor.PermissionSnapshot encodes/decodes losslessly")
    func tccSnapshotRoundTrip() throws {
        let entries = [
            TCCMonitor.PublicEntry(
                service: "kTCCServiceCamera",
                client: "com.example.app",
                clientType: 0,
                authValue: 2,
                authReason: 1,
                indirectObjectIdentifier: "",
                flags: 0,
                lastModified: 1_700_000_000,
                source: "user"
            ),
            TCCMonitor.PublicEntry(
                service: "kTCCServiceMicrophone",
                client: "/Applications/Slack.app",
                clientType: 1,
                authValue: 0,
                authReason: 2,
                indirectObjectIdentifier: "",
                flags: 0,
                lastModified: 1_700_001_000,
                source: "system"
            ),
        ]
        let snap = TCCMonitor.PermissionSnapshot(writtenAt: Date(), entries: entries)
        let path = NSTemporaryDirectory() + "maccrab-tcc-snap-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try JSONEncoder().encode(snap).write(to: URL(fileURLWithPath: path))

        let loaded = TCCMonitor.readSnapshot(at: path)
        #expect(loaded != nil)
        #expect(loaded?.entries.count == 2)
        let cam = loaded?.entries.first { $0.service == "kTCCServiceCamera" }
        #expect(cam?.authValue == 2)
        #expect(cam?.client == "com.example.app")
        let mic = loaded?.entries.first { $0.service == "kTCCServiceMicrophone" }
        #expect(mic?.authValue == 0)
        #expect(mic?.source == "system")
    }

    @Test("readTelemetrySnapshot returns nil for missing path")
    func missingTelemetryFileReturnsNil() {
        let path = NSTemporaryDirectory() + "definitely-not-real-\(UUID().uuidString).json"
        #expect(RuleEngine.readTelemetrySnapshot(at: path) == nil)
    }

    @Test("readSnapshot returns nil for malformed JSON")
    func malformedJSONReturnsNil() throws {
        let path = NSTemporaryDirectory() + "maccrab-bad-tcc-\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try "not json at all".data(using: .utf8)!.write(to: URL(fileURLWithPath: path))
        #expect(TCCMonitor.readSnapshot(at: path) == nil)
        #expect(RuleEngine.readTelemetrySnapshot(at: path) == nil)
    }

    @Test("EventStore.eventCountsByCategory returns empty dict on empty store")
    func eventCountsEmpty() async throws {
        let path = NSTemporaryDirectory() + "maccrab-eventcounts-\(UUID().uuidString).db"
        defer {
            try? FileManager.default.removeItem(atPath: path)
            try? FileManager.default.removeItem(atPath: path + "-wal")
            try? FileManager.default.removeItem(atPath: path + "-shm")
        }
        let store = try EventStore(path: path)
        let counts = try await store.eventCountsByCategory(since: Date(timeIntervalSince1970: 0))
        #expect(counts.isEmpty)
    }
}
