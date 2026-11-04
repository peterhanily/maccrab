import Foundation
import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("User rule override planning")
struct V2RuleOverridePlannerTests {
    private func supportDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-override-plan-\(UUID())")
        for relative in ["compiled_rules/sequences", "compiled_rules/graph", "user_rules"] {
            try FileManager.default.createDirectory(at: root.appendingPathComponent(relative),
                                                    withIntermediateDirectories: true)
        }
        return root
    }

    private func ruleData(id: String, level: MacCrabCore.Severity, enabled: Bool = true, status: String?) throws -> Data {
        try JSONEncoder().encode(CompiledRule(
            id: id, title: "Fixture \(id)", description: "Inert fixture", level: level, tags: [],
            logsource: LogSource(category: "file_event", product: "macos"), predicates: [],
            condition: .allOf, falsepositives: [], enabled: enabled, status: status))
    }

    private func object(_ data: Data) throws -> [String: Any] {
        try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    @Test("a severity change keeps an enabled user rule enabled when the stable profile shows it disabled")
    func severityChangeKeepsRunningUserRuleEnabled() async throws {
        let root = try supportDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        // A wizard-made rule (status experimental), and an override of a
        // bundled stable rule written before compiled rules carried a status.
        let custom = "c35c7b49-0000-4000-a000-000000000001"
        let tuned = "d1a2b3c4-2031-4000-a000-000000002031"
        try ruleData(id: tuned, level: .high, status: "stable")
            .write(to: root.appendingPathComponent("compiled_rules/\(tuned).json"))
        let files = [
            custom: try ruleData(id: custom, level: .medium, status: "experimental"),
            tuned: try ruleData(id: tuned, level: .medium, status: nil),
        ]
        for (id, data) in files { try data.write(to: root.appendingPathComponent("user_rules/\(id).json")) }

        let definitions = try await V2LiveDataProvider.loadRuleDefinitions(directory: root.path, profile: "stable")
        // The engine loads compiled_rules under the profile, then user_rules
        // with its own uid as the required owner, as the daemon does at boot.
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: root.appendingPathComponent("compiled_rules"), enabledStatuses: ["stable"])
        _ = try await engine.loadRules(from: root.appendingPathComponent("user_rules"), requireOwnerUID: geteuid())
        let running = await engine.listRules()

        for (id, data) in files {
            let row = try #require(definitions.singleEvent.first { $0.id == id })
            #expect(!row.isEnabled, "the dashboard applies the profile to \(id)")
            #expect(running.first { $0.id == id }?.enabled == true, "the engine runs \(id)")
            #expect(!V2RuleOverridePlanner.severityChangeKeepsDisabled(
                override: try object(data), displayedEnabled: row.isEnabled),
                "a severity change on \(id) would write enabled:false and stop a rule the engine runs")
        }
    }

    @Test("an override's own enabled decides; without one the displayed state does")
    func severityChangeDisabledSource() throws {
        let enabled = try object(try ruleData(id: "fixture", level: .low, status: "stable"))
        let disabled = try object(try ruleData(id: "fixture", level: .low, enabled: false, status: "stable"))
        #expect(V2RuleOverridePlanner.severityChangeKeepsDisabled(override: disabled, displayedEnabled: true))
        #expect(!V2RuleOverridePlanner.severityChangeKeepsDisabled(override: enabled, displayedEnabled: false))
        #expect(V2RuleOverridePlanner.severityChangeKeepsDisabled(override: nil, displayedEnabled: false))
        #expect(!V2RuleOverridePlanner.severityChangeKeepsDisabled(override: nil, displayedEnabled: true))
    }

    // MARK: - Enable and severity revert

    /// A bundled stable rule at level high, as parsed JSON.
    private func bundledRule() throws -> [String: Any] {
        try object(try ruleData(id: "d1a2b3c4-0449-4000-a000-000000000449", level: .high, status: "stable"))
    }

    private func with(_ rule: [String: Any], _ key: String, _ value: Any) -> [String: Any] {
        var copy = rule
        copy[key] = value
        return copy
    }

    private func equal(_ lhs: [String: Any]?, _ rhs: [String: Any]) -> Bool {
        lhs.map { NSDictionary(dictionary: $0).isEqual(to: rhs) } ?? false
    }

    @Test("Enable re-installs a disabled custom rule with enabled true")
    func enableKeepsCustomRule() throws {
        let custom = try object(try ruleData(id: "c35c7b49-0000-4000-a000-000000000001", level: .medium,
                                             enabled: false, status: "experimental"))
        #expect(equal(V2RuleOverridePlanner.enabledOverride(custom, bundled: nil, hasSourceYAML: false),
                      with(custom, "enabled", true)))
    }

    @Test("Enable removes a pure disable copy of a bundled rule, and only that")
    func enableRemovesPureDisableCopy() throws {
        let bundled = try bundledRule()
        let copy = with(bundled, "enabled", false)
        #expect(V2RuleOverridePlanner.enabledOverride(copy, bundled: bundled, hasSourceYAML: false) == nil)
        // A copy that differs in any other field, such as one taken from an
        // earlier version of the bundled rule, is kept.
        let earlier = with(copy, "description", "Earlier bundled description")
        #expect(equal(V2RuleOverridePlanner.enabledOverride(earlier, bundled: bundled, hasSourceYAML: false),
                      with(earlier, "enabled", true)))
    }

    @Test("Enable on a disable over a severity change re-installs the override at its level")
    func enableKeepsSeverityOverride() throws {
        let bundled = try bundledRule()
        let override = with(with(bundled, "level", "low"), "enabled", false)
        let enabled = V2RuleOverridePlanner.enabledOverride(override, bundled: bundled, hasSourceYAML: false)
        #expect(equal(enabled, with(override, "enabled", true)))
        #expect(enabled?["level"] as? String == "low")
    }

    @Test("Enable keeps an Edit YAML override, whose .yml remove-rule would delete")
    func enableKeepsEditedYAML() throws {
        let bundled = try bundledRule()
        // Saved from Edit YAML without changes and then disabled, so only the
        // .yml beside it tells it apart from a pure disable copy.
        #expect(equal(V2RuleOverridePlanner.enabledOverride(with(bundled, "enabled", false), bundled: bundled,
                                                            hasSourceYAML: true),
                      with(bundled, "enabled", true)))
    }

    @Test("Enable compares parsed JSON, so key order and pretty-printing do not matter")
    func enableIgnoresFormatting() throws {
        let compiled = try ruleData(id: "d1a2b3c4-0449-4000-a000-000000000449", level: .high, status: "stable")
        let bundled = try object(compiled)
        // Disable writes its copy with sorted keys and pretty-printed.
        let disabledBytes = try JSONSerialization.data(withJSONObject: with(bundled, "enabled", false),
                                                       options: [.prettyPrinted, .sortedKeys])
        #expect(disabledBytes != compiled)
        let copy = try object(disabledBytes)
        #expect(V2RuleOverridePlanner.enabledOverride(copy, bundled: bundled, hasSourceYAML: false) == nil)
        // The same formatting with a nested value changed is not a copy.
        var logsource = try #require(copy["logsource"] as? [String: Any])
        logsource["category"] = "process_creation"
        #expect(V2RuleOverridePlanner.enabledOverride(with(copy, "logsource", logsource), bundled: bundled,
                                                      hasSourceYAML: false) != nil)
    }

    @Test("a severity revert of a tuned rule restores the bundled level and keeps the tuning")
    func severityRevertKeepsTuning() throws {
        let bundled = try bundledRule()
        // Differs from the bundled rule in more than its level.
        let tuned = with(with(bundled, "level", "low"), "falsepositives", ["Nightly backup agent"])
        #expect(equal(V2RuleOverridePlanner.severityRevertedOverride(
            tuned, bundled: bundled, hasSourceYAML: false, keepsDisabled: false),
            with(tuned, "level", "high")))
        // A disabled tuned rule keeps its disable and its tuning.
        #expect(equal(V2RuleOverridePlanner.severityRevertedOverride(
            with(tuned, "enabled", false), bundled: bundled, hasSourceYAML: false, keepsDisabled: true),
            with(with(tuned, "level", "high"), "enabled", false)))
    }

    @Test("a severity revert of a severity-only override removes it unless a .yml is beside it")
    func severityRevertRemovesSeverityOnlyOverride() throws {
        let bundled = try bundledRule()
        let lowered = with(bundled, "level", "low")
        #expect(V2RuleOverridePlanner.severityRevertedOverride(
            lowered, bundled: bundled, hasSourceYAML: false, keepsDisabled: false) == nil)
        // remove-rule would delete the .yml too, so the reverted JSON is
        // installed instead.
        #expect(equal(V2RuleOverridePlanner.severityRevertedOverride(
            lowered, bundled: bundled, hasSourceYAML: true, keepsDisabled: false), bundled))
        // A disabled rule keeps a disable-only override.
        #expect(equal(V2RuleOverridePlanner.severityRevertedOverride(
            with(lowered, "enabled", false), bundled: bundled, hasSourceYAML: false, keepsDisabled: true),
            with(bundled, "enabled", false)))
    }
}
