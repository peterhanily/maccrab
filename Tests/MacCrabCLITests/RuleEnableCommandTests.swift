// RuleEnableCommandTests.swift
// MacCrabCLITests
//
// `maccrabctl rule enable|disable`, through setCompiledRuleEnabled.

import Foundation
import MacCrabCore
import Testing
@testable import maccrabctl

@Suite("maccrabctl rule enable|disable")
struct RuleEnableCommandTests {

    @Test("an id with a user_rules file is refused and no rule file is edited")
    func userRuleIsRefused() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        let bundled = try dir.write(fixtureRule("fixture-rule"), to: "compiled_rules/fixture_rule.json")
        let before = try Data(contentsOf: bundled)
        // An override of the bundled rule, a rule the user made, and the file
        // the daemon names for an id it sanitizes.
        let override = try dir.write(fixtureRule("fixture-rule", enabled: false), to: "user_rules/fixture-rule.json")
        let custom = try dir.write(fixtureRule("custom-rule"), to: "user_rules/custom-rule.json")
        let sanitized = try dir.write(fixtureRule("fixture.rule"), to: "user_rules/fixturerule.json")
        let userRules = try [override, custom, sanitized].map { try Data(contentsOf: $0) }

        for (id, file, enabled) in [("fixture-rule", "fixture-rule", true), ("custom-rule", "custom-rule", false),
                                    ("fixture.rule", "fixturerule", false)] {
            let error = #expect(throws: RuntimeConfigContractError.self) {
                _ = try MacCrabCtl.setCompiledRuleEnabled(ruleId: id, enabled: enabled, directory: dir.path)
            }
            #expect(error?.message == "user_rules/\(file).json exists for \(id), so the bundled rule file was not edited."
                + " When the engine loads that file, its rule replaces a bundled rule with the same id."
                + " Use Disable rule or Enable rule in the dashboard's Detection › Rules,"
                + " or remove the user rule with: maccrabctl rule delete \(id)")
        }
        #expect(try Data(contentsOf: bundled) == before)
        #expect(try [override, custom, sanitized].map { try Data(contentsOf: $0) } == userRules)
    }

    @Test("an edit says it lasts until the engine restarts, and a disable points to the dashboard's Disable rule")
    func editNote() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        try dir.write(fixtureRule("fixture-rule"), to: "compiled_rules/fixture_rule.json")
        let saved = { (enabled: Bool) in [
            "Saved enabled=\(enabled) for compiled rule fixture-rule. Runtime application is pending.",
            "Run maccrabctl rules reload, then inspect the returned request ID with config status.",
            "On a release install the engine replaces edited rule files with its signed copies"
                + " when it starts, so this change lasts until the engine restarts.",
        ] }
        #expect(try MacCrabCtl.setCompiledRuleEnabled(ruleId: "fixture-rule", enabled: false, directory: dir.path)
            == saved(false) + ["For a disable that lasts, use Disable rule in the dashboard's Detection › Rules"
                + " instead of this command."])
        #expect(try MacCrabCtl.setCompiledRuleEnabled(ruleId: "fixture-rule", enabled: true, directory: dir.path)
            == saved(true))
    }

    @Test("without a user_rules file the compiled rule's enabled is set and nothing else changes")
    func editPath() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        let rule = fixtureRule("fixture-rule", status: "experimental", level: "high")
        let bundled = try dir.write(rule, to: "compiled_rules/fixture_rule.json")
        // The profile that runs every status, so enabling this experimental
        // rule is an edit the engine applies.
        try dir.write(["rule_profile": "all"], to: "daemon_config.json")
        let other = try dir.write(fixtureRule("other-rule"), to: "compiled_rules/other_rule.json")
        let otherBefore = try Data(contentsOf: other)
        // A user rule with another id does not stop the edit.
        try dir.write(fixtureRule("custom-rule"), to: "user_rules/custom-rule.json")

        for enabled in [false, true] {
            _ = try MacCrabCtl.setCompiledRuleEnabled(ruleId: "fixture-rule", enabled: enabled, directory: dir.path)
            var expected = rule
            expected["enabled"] = enabled
            #expect(NSDictionary(dictionary: try dir.object(at: bundled)) == NSDictionary(dictionary: expected))
        }
        #expect(try Data(contentsOf: other) == otherBefore)

        let missing = #expect(throws: RuntimeConfigContractError.self) {
            _ = try MacCrabCtl.setCompiledRuleEnabled(ruleId: "missing-rule", enabled: false, directory: dir.path)
        }
        #expect(missing?.message == "Rule 'missing-rule' was not found in the compiled corpus")
    }

    @Test("an enable the rule profile would keep off is refused and the file is not edited")
    func profileDisabledEnableIsRefused() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        // No heartbeat and no daemon_config.json: the default stable profile.
        let experimental = try dir.write(fixtureRule("experimental-rule", status: "experimental", enabled: false),
                                         to: "compiled_rules/experimental_rule.json")
        let unlabeled = try dir.write(fixtureRule("unlabeled-rule", status: nil, enabled: false),
                                      to: "compiled_rules/unlabeled_rule.json")
        let before = try [experimental, unlabeled].map { try Data(contentsOf: $0) }

        for (id, status) in [("experimental-rule", "experimental"), ("unlabeled-rule", "experimental")] {
            let error = #expect(throws: RuntimeConfigContractError.self) {
                _ = try MacCrabCtl.setCompiledRuleEnabled(ruleId: id, enabled: true, directory: dir.path)
            }
            #expect(error?.message == "Rule \(id) has status \(status), and the rule profile \"stable\" runs only stable rules,"
                + " so the engine keeps it off whatever its file says. The bundled rule file was not edited."
                + " To run rules of other statuses, set \"rule_profile\": \"all\" in daemon_config.json.")
        }
        #expect(try [experimental, unlabeled].map { try Data(contentsOf: $0) } == before)

        // A disable is not refused, and the profile the engine publishes
        // decides before daemon_config.json does.
        _ = try MacCrabCtl.setCompiledRuleEnabled(ruleId: "experimental-rule", enabled: false, directory: dir.path)
        try dir.write(["rule_profile": "all"], to: "heartbeat_rich.json")
        _ = try MacCrabCtl.setCompiledRuleEnabled(ruleId: "experimental-rule", enabled: true, directory: dir.path)
        #expect(try dir.object(at: experimental)["enabled"] as? Bool == true)
    }
}
