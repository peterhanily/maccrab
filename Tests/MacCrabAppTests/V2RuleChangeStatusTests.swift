import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("Rule change saved-state confirmation")
struct V2RuleChangeStatusTests {
    @Test("enqueue and unreadable settings cannot confirm a built-in rule change")
    func builtinSavedState() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-rule-change-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var tracker = V2RuleChangeTracker()
        tracker.queued(ruleID: "maccrab.fixture", title: "Fixture", builtin: true, expected: .enabled(false))
        let pending = try #require(tracker.pending.first)
        #expect(!tracker.canSubmit(ruleID: pending.ruleID))
        #expect(pending.savedStateMatches(directory: directory.path) == nil)
        try BuiltinRuleSettings(rules: [pending.ruleID: .init(enabled: true)]).save(toDir: directory.path)
        #expect(pending.savedStateMatches(directory: directory.path) == false)
        tracker.observe(id: pending.id, saved: false)
        #expect(tracker.pending.count == 1)
        try BuiltinRuleSettings(rules: [pending.ruleID: .init(enabled: false)]).save(toDir: directory.path)
        let saved = pending.savedStateMatches(directory: directory.path)
        tracker.observe(id: pending.id, saved: saved)
        #expect(tracker.entries.first?.status == .saved)
        #expect(tracker.canSubmit(ruleID: pending.ruleID))
    }

    @Test("YAML confirmation checks saved content and absent-directory reads remain unknown")
    func yamlAndRemoval() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-rule-change-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }
        var tracker = V2RuleChangeTracker()
        tracker.queued(ruleID: "fixture", title: "Fixture", builtin: false, expected: .yaml("title: Updated\n"))
        let yaml = try #require(tracker.pending.first)
        #expect(yaml.savedStateMatches(directory: directory.path) == nil)
        let overrides = directory.appendingPathComponent("user_rules")
        try FileManager.default.createDirectory(at: overrides, withIntermediateDirectories: true)
        try Data("title: Previous\n".utf8).write(to: overrides.appendingPathComponent("fixture.yml"))
        #expect(yaml.savedStateMatches(directory: directory.path) == false)
        try Data("title: Updated\n".utf8).write(to: overrides.appendingPathComponent("fixture.yml"))
        #expect(yaml.savedStateMatches(directory: directory.path) == true)
        tracker.observe(id: yaml.id, saved: true)
        tracker.queued(ruleID: "fixture", title: "Fixture", builtin: false, expected: .overrideRemoved)
        let removal = try #require(tracker.pending.first)
        try Data("{}".utf8).write(to: overrides.appendingPathComponent("fixture.json"))
        #expect(removal.savedStateMatches(directory: directory.path) == false)
        try FileManager.default.removeItem(at: overrides.appendingPathComponent("fixture.json"))
        #expect(removal.savedStateMatches(directory: directory.path) == true)
        try FileManager.default.removeItem(at: overrides)
        #expect(removal.savedStateMatches(directory: directory.path) == nil)
    }

    @Test("unconfirmed requests expire without being reported saved")
    func boundedConfirmation() throws {
        let now = Date()
        var tracker = V2RuleChangeTracker()
        tracker.queued(ruleID: "fixture", title: "Fixture", builtin: false, expected: .enabled(false), now: now)
        let request = try #require(tracker.pending.first)
        tracker.observe(id: request.id, saved: nil, now: now.addingTimeInterval(119))
        #expect(tracker.pending.count == 1)
        tracker.observe(id: request.id, saved: nil, now: now.addingTimeInterval(120))
        #expect(tracker.entries.first?.status == .unconfirmed)
        #expect(tracker.pending.isEmpty)
        tracker.dismissCompleted()
        #expect(tracker.entries.isEmpty)
    }

    @Test("unknown rule coverage hides a historical count instead of reporting current activity")
    func historicalRuleCount() {
        let unknown = V2MockRule(id: "fixture", title: "Fixture", category: "process", severity: .low,
            mitre: [], isEnabled: true, lastFired: Date(), firesLastWeek: 12, isCustom: false,
            description: "Fixture", telemetryCoverage: .unknown, telemetryWrittenAt: Date())
        #expect(unknown.recordedMatchesDisplay == "—")
    }
}
