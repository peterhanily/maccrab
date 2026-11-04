// RuleSeverityCommandTests.swift
// MacCrabCLITests
//
// `maccrabctl rule severity` for a rule that is not a built-in, through
// ruleSeverityPlan.

import Foundation
import Testing
@testable import maccrabctl

@Suite("maccrabctl rule severity")
struct RuleSeverityCommandTests {

    /// The rule JSON a plan installs, and the level it reports as previous.
    private func installed(_ plan: RuleSeverityPlan) throws -> (rule: [String: Any], previous: String) {
        guard case let .install(json, previous) = plan else {
            Issue.record("expected an install-rule request, got \(plan)")
            return ([:], "")
        }
        return (try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]), previous)
    }

    private func enabled(_ id: String, in dir: RuleFixtureDirectory) throws -> Bool? {
        try installed(ruleSeverityPlan(ruleId: id, level: "low", supportDir: dir.path)).rule["enabled"] as? Bool
    }

    @Test("a copy of a bundled rule the profile or its own file disables is installed disabled")
    func bundledRuleKeepsItsState() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        let experimental = fixtureRule("experimental-rule", status: "experimental", level: "high")
        try dir.write(experimental, to: "compiled_rules/experimental_rule.json")
        try dir.write(fixtureRule("no-status-rule", status: nil), to: "compiled_rules/no_status_rule.json")
        try dir.write(fixtureRule("stable-rule"), to: "compiled_rules/stable_rule.json")
        try dir.write(fixtureRule("deprecated-rule", status: "deprecated", enabled: false),
                      to: "compiled_rules/deprecated_rule.json")

        // No daemon config: the "stable" profile. Only the level and enabled change.
        let copy = try installed(ruleSeverityPlan(ruleId: "experimental-rule", level: "low", supportDir: dir.path))
        var expected = experimental
        expected["level"] = "low"
        expected["enabled"] = false
        #expect(NSDictionary(dictionary: copy.rule) == NSDictionary(dictionary: expected))
        #expect(copy.previous == "high")
        // The engine counts a rule with no status as experimental.
        #expect(try enabled("no-status-rule", in: dir) == false)
        #expect(try enabled("stable-rule", in: dir) == true)
        #expect(try enabled("deprecated-rule", in: dir) == false)

        // DaemonConfig maps an unknown profile to "stable".
        try dir.write(["rule_profile": "stabel"], to: "daemon_config.json")
        #expect(try enabled("experimental-rule", in: dir) == false)

        // Under "all", only the rule's own "enabled": false disables it.
        try dir.write(["rule_profile": "all"], to: "daemon_config.json")
        #expect(try enabled("experimental-rule", in: dir) == true)
        #expect(try enabled("no-status-rule", in: dir) == true)
        #expect(try enabled("deprecated-rule", in: dir) == false)

        // The profile the engine publishes in heartbeat_rich.json comes first.
        try dir.write(["rule_profile": "stable"], to: "heartbeat_rich.json")
        #expect(try enabled("experimental-rule", in: dir) == false)
    }

    @Test("a rule with a user_rules file keeps that file's enabled whatever the profile")
    func userRuleKeepsItsEnabled() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        try dir.write(fixtureRule("experimental-rule", status: "experimental"), to: "compiled_rules/experimental_rule.json")
        // The engine runs an enabled override of a rule the profile disables.
        let override = fixtureRule("experimental-rule", status: "experimental", level: "high")
        try dir.write(override, to: "user_rules/experimental-rule.json")
        try dir.write(fixtureRule("custom-rule", status: "experimental"), to: "user_rules/custom-rule.json")

        let copy = try installed(ruleSeverityPlan(ruleId: "experimental-rule", level: "low", supportDir: dir.path))
        var expected = override
        expected["level"] = "low"
        #expect(NSDictionary(dictionary: copy.rule) == NSDictionary(dictionary: expected))
        #expect(copy.previous == "high")
        #expect(try enabled("custom-rule", in: dir) == true)

        // A disabled override stays disabled under "all".
        try dir.write(["rule_profile": "all"], to: "daemon_config.json")
        try dir.write(fixtureRule("experimental-rule", status: "experimental", enabled: false),
                      to: "user_rules/experimental-rule.json")
        #expect(try enabled("experimental-rule", in: dir) == false)
    }
}
