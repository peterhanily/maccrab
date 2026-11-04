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
}
