import Foundation
import Testing
@testable import MacCrabCore

@Suite("Rule telemetry provenance and coverage")
struct RuleTelemetryContextTests {
    private let now = Date(timeIntervalSince1970: 2000)
    private let identity = EngineTelemetryIdentity(pid: 42, startedAtUnix: 1000, version: "1.22.0", build: "fixture")

    @Test("current runtime IDs distinguish disabled, unobserved, quiet and matched rules")
    func ordinaryCoverageStates() {
        let snapshot = RuleEngine.TelemetrySnapshot(writtenAt: now, stats: [
            .init(ruleId: "quiet", evaluationCount: 5),
            .init(ruleId: "matched", evaluationCount: 8, fireCount: 1),
            .init(ruleId: "disabled", evaluationCount: 4, fireCount: 1),
        ], engineIdentity: identity, loadedRuleIds: ["quiet", "matched", "disabled", "new"],
           enabledRuleIds: ["quiet", "matched", "new"])
        let context = RuleTelemetryContext(snapshot: snapshot, heartbeatIdentity: identity,
            heartbeatWrittenAt: now, ruleProfile: "stable", now: now)
        #expect(context.current)
        #expect(context.coverage(ruleID: "quiet", status: "stable", enabled: true) == .quiet)
        #expect(context.coverage(ruleID: "matched", status: "stable", enabled: true) == .matched)
        #expect(context.coverage(ruleID: "disabled", status: "stable", enabled: true) == .disabled)
        #expect(context.coverage(ruleID: "new", status: "stable", enabled: true) == .unobserved)
        #expect(context.coverage(ruleID: "addedAfterSnapshot", status: "stable", enabled: true) == .unknown)
    }

    @Test("previous boot and older snapshots retain their age without supplying current counters")
    func historicalSnapshot() {
        let snapshot = RuleEngine.TelemetrySnapshot(writtenAt: now.addingTimeInterval(-300),
            stats: [.init(ruleId: "ordinary", evaluationCount: 9)], engineIdentity: identity,
            loadedRuleIds: ["ordinary"], enabledRuleIds: ["ordinary"])
        let context = RuleTelemetryContext(snapshot: snapshot, heartbeatIdentity: identity,
            heartbeatWrittenAt: now, ruleProfile: "stable", now: now)
        #expect(context.freshness == .historical)
        #expect(context.ageSeconds == 300)
        #expect(context.statsByID.isEmpty)
        #expect(context.coverage(ruleID: "ordinary", status: "stable", enabled: true) == .unknown)
        let newer = EngineTelemetryIdentity(pid: 43, startedAtUnix: 1900, version: "1.22.0", build: "fixture")
        let otherBoot = RuleTelemetryContext(snapshot: snapshot, heartbeatIdentity: newer,
            heartbeatWrittenAt: now, ruleProfile: "stable", now: now)
        #expect(otherBoot.freshness == .historical)
    }

    @Test("legacy telemetry remains decodable with unknown identity and unavailable current coverage")
    func legacySnapshot() throws {
        let data = try JSONEncoder().encode(RuleEngine.TelemetrySnapshot(writtenAt: now, stats: []))
        let decoded = try JSONDecoder().decode(RuleEngine.TelemetrySnapshot.self, from: data)
        let context = RuleTelemetryContext(snapshot: decoded, heartbeatIdentity: identity,
            heartbeatWrittenAt: now, ruleProfile: "all", now: now)
        #expect(context.freshness == .identityUnknown)
        #expect(context.snapshotWrittenAt == now)
        #expect(context.coverage(ruleID: "ordinary", status: "experimental", enabled: true) == .unknown)
    }

    @Test("ordinary heartbeat reads preserve provenance when optional rich metadata is unavailable")
    func ordinaryHeartbeatFiles() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-context-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let heartbeat: [String: Any] = [
            "engine_pid": identity.pid,
            "engine_started_at_unix": identity.startedAtUnix,
            "engine_version": identity.version,
            "engine_build": identity.build,
            "written_at_unix": now.timeIntervalSince1970,
        ]
        let liveness = root.appendingPathComponent("heartbeat.json")
        let rich = root.appendingPathComponent("heartbeat_rich.json")
        let livenessData = try JSONSerialization.data(withJSONObject: heartbeat)
        try livenessData.write(to: liveness)
        var richHeartbeat = heartbeat
        richHeartbeat["rule_profile"] = "stable"
        try JSONSerialization.data(withJSONObject: richHeartbeat).write(to: rich)
        let snapshot = RuleEngine.TelemetrySnapshot(writtenAt: now,
            stats: [.init(ruleId: "ordinary", evaluationCount: 3)], engineIdentity: identity,
            loadedRuleIds: ["ordinary"], enabledRuleIds: ["ordinary"])
        try JSONEncoder().encode(snapshot).write(to: root.appendingPathComponent("rule_telemetry.json"))
        let observedAt = now.addingTimeInterval(1)

        let current = RuleTelemetryContext.load(directory: root.path, now: observedAt)
        #expect(current.current)
        #expect(current.ruleProfile == "stable")
        #expect(current.coverage(ruleID: "ordinary", status: "stable", enabled: true) == .quiet)

        // An interrupted rich-snapshot write must not invent a profile or
        // discard independently verified current liveness and rule counters.
        try Data("{\n".utf8).write(to: rich)
        let partialRich = RuleTelemetryContext.load(directory: root.path, now: observedAt)
        #expect(partialRich.current)
        #expect(partialRich.ruleProfile == nil)
        let retainedEvaluations = try #require(partialRich.statsByID["ordinary"]?.evaluationCount)
        #expect(retainedEvaluations == UInt64(3))

        try FileManager.default.removeItem(at: liveness)
        let absentLiveness = RuleTelemetryContext.load(directory: root.path, now: observedAt)
        #expect(absentLiveness.freshness == .identityUnknown)
        #expect(absentLiveness.statsByID.isEmpty)
        #expect(absentLiveness.ruleProfile == nil)
    }
}
