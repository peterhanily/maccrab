// RuleDeleteReplyTests.swift
// MacCrabCLITests
//
// `maccrabctl rule delete` and MCP delete_rule, through ruleDeletePlan and
// deleteRulePlan. handleDeleteRule is not called: it writes the audit log and
// reads main.swift's `dataDir`, which the test runner never initialises.

import Foundation
import Testing
@testable import maccrabctl
@testable import maccrab_mcp

@Suite("maccrabctl rule delete and MCP delete_rule")
struct RuleDeleteReplyTests {

    @Test("an id with no user_rules file queues nothing, and the reply says bundled rules cannot be deleted")
    func noUserRuleQueuesNothing() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        // The bundled rule a delete used to report as removed.
        try dir.write(fixtureRule("fixture-rule"), to: "compiled_rules/fixture_rule.json")
        // A user rule for another id.
        try dir.write(fixtureRule("custom-rule"), to: "user_rules/custom-rule.json")

        for (id, file) in [("fixture-rule", " (there is no user_rules/fixture-rule.json)"),
                           ("missing-rule", " (there is no user_rules/missing-rule.json)"),
                           // No basename survives sanitizing; the daemon rejects such an id.
                           ("!!!", "")] {
            #expect(maccrabctl.ruleDeletePlan(ruleId: id, supportDir: dir.path) == .refuse([
                "No user rule has the id \(id)\(file), so nothing was queued.",
                "Bundled rules cannot be deleted. To turn one off, use Disable rule in the dashboard's"
                    + " Detection › Rules, or maccrabctl rule disable \(id), which on a release install"
                    + " lasts until the engine restarts.",
            ]))
            #expect(maccrab_mcp.deleteRulePlan(ruleId: id, supportDir: dir.path) == .refuse(
                "No user rule has the id \(id)\(file), so nothing was queued. Bundled rules cannot be deleted;"
                    + " a person can turn one off with Disable rule in the MacCrab dashboard's Detection › Rules."
                    + " Built-in maccrab.* detections are tuned with set_builtin_rule_setting."))
        }
    }

    @Test("removing an override says the engine uses the bundled rule after the reload")
    func overrideReply() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        try dir.write(fixtureRule("fixture-rule"), to: "compiled_rules/fixture_rule.json")
        try dir.write(fixtureRule("fixture-rule", enabled: false), to: "user_rules/fixture-rule.json")

        // The daemon removes user_rules/fixture-rule.json for either spelling,
        // and the engine matches that file's rule to the bundled one by its id.
        for id in ["fixture-rule", "FIXTURE-RULE"] {
            #expect(maccrabctl.ruleDeletePlan(ruleId: id, supportDir: dir.path) == .queue(
                "Queued removal of user rule \(id), which has the same id as a bundled rule."
                    + " After the next reload (~5 s) the engine uses the bundled rule instead."))
            #expect(maccrab_mcp.deleteRulePlan(ruleId: id, supportDir: dir.path) == .queue(
                "Queued removal of user rule \(id), which has the same id as a bundled rule."
                    + " After the next reload the engine uses the bundled rule instead."))
        }
    }

    @Test("removing a rule the user made keeps the earlier reply")
    func customRuleReply() throws {
        let dir = try RuleFixtureDirectory()
        defer { dir.remove() }
        try dir.write(fixtureRule("fixture-rule"), to: "compiled_rules/fixture_rule.json")
        try dir.write(fixtureRule("custom-rule"), to: "user_rules/custom-rule.json")
        // The engine overlays user rules on single-event rules only, so a
        // sequence rule with the same id is not a bundled rule it replaces.
        try FileManager.default.createDirectory(
            at: dir.root.appendingPathComponent("compiled_rules/sequences"), withIntermediateDirectories: true)
        try dir.write(fixtureRule("sequence-id"), to: "compiled_rules/sequences/sequence_rule.json")
        try dir.write(fixtureRule("sequence-id"), to: "user_rules/sequence-id.json")

        for id in ["custom-rule", "sequence-id"] {
            #expect(maccrabctl.ruleDeletePlan(ruleId: id, supportDir: dir.path) == .queue(
                "Queued removal of user rule \(id). The engine drops it on the next reload (~5 s)."))
            #expect(maccrab_mcp.deleteRulePlan(ruleId: id, supportDir: dir.path) == .queue(
                "Queued removal of user rule \(id). The engine drops it on the next reload."))
        }
    }
}
