// RuleEnginePushedRulesTests.swift
// Pins the TRUST BOUNDARY of the rule-update channel: rules delivered out-of-band
// (`source == .pushed`) are DETECTION-ONLY.
//
//   1. Additive-only — a pushed rule whose id already exists (a bundled/user
//      rule) is IGNORED. This is what prevents a signed-but-hostile pushed
//      corpus from (a) silencing a built-in detection by shadowing it with a
//      disabled copy, or (b) inheriting an operator's kill/quarantine action by
//      reusing its id.
//   2. The pushed-id set is exposed and feeds the response engine's
//      detection-only gate, so a pushed rule can never arm a response action.
//   3. reloadRules clears the pushed set (it is repopulated by loadPushedRules).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("RuleEngine: pushed-rule containment (rule-update channel)")
struct RuleEnginePushedRulesTests {

    /// `count` real compiled rules copied into an isolated dir (exercises the
    /// real decoder), returned with the list of file URLs.
    private func makeBaseDir(count: Int) throws -> (dir: URL, files: [URL]) {
        ensureRulesCompiled()
        let src = URL(fileURLWithPath: "/tmp/maccrab_v3")
        let dst = FileManager.default.temporaryDirectory
            .appendingPathComponent("pushed-base-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
        let jsons = try FileManager.default
            .contentsOfDirectory(at: src, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .prefix(count)
        var out: [URL] = []
        for f in jsons {
            let d = dst.appendingPathComponent(f.lastPathComponent)
            try FileManager.default.copyItem(at: f, to: d)
            out.append(d)
        }
        return (dst, out)
    }

    /// A pushed dir containing one rule re-id'd from `sourceFile` to `newID`.
    private func makePushedDir(reIDing sourceFile: URL, to newID: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pushed-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var obj = try JSONSerialization.jsonObject(with: Data(contentsOf: sourceFile)) as! [String: Any]
        obj["id"] = newID
        let data = try JSONSerialization.data(withJSONObject: obj)
        try data.write(to: dir.appendingPathComponent("\(newID).json"))
        return dir
    }

    @Test("a pushed rule with a NEW id is added and tagged .pushed")
    func pushedNewIdAdded() async throws {
        let (base, files) = try makeBaseDir(count: 10)
        defer { try? FileManager.default.removeItem(at: base) }
        let pushed = try makePushedDir(reIDing: files[0], to: "pushed.test.brand_new_rule")
        defer { try? FileManager.default.removeItem(at: pushed) }

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base)
        let baseCount = await engine.ruleCount
        let added = try await engine.loadPushedRules(from: pushed)
        #expect(added == 1)
        #expect(await engine.ruleCount == baseCount + 1)
        let pushedIDs = await engine.pushedRuleIDs
        #expect(pushedIDs == ["pushed.test.brand_new_rule"])
    }

    @Test("a pushed rule whose id ALREADY EXISTS is ignored (additive-only)")
    func pushedShadowIgnored() async throws {
        let (base, files) = try makeBaseDir(count: 10)
        defer { try? FileManager.default.removeItem(at: base) }
        // Re-id a pushed rule to COLLIDE with an existing base rule's id.
        let existingID = (try JSONSerialization.jsonObject(with: Data(contentsOf: files[0])) as! [String: Any])["id"] as! String
        let pushed = try makePushedDir(reIDing: files[1], to: existingID)
        defer { try? FileManager.default.removeItem(at: pushed) }

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base)
        let baseCount = await engine.ruleCount
        let added = try await engine.loadPushedRules(from: pushed)
        #expect(added == 0)                       // the colliding pushed rule was refused
        #expect(await engine.ruleCount == baseCount)
        #expect(await engine.pushedRuleIDs.isEmpty)
    }

    @Test("reloadRules clears the pushed-rule set")
    func reloadClearsPushed() async throws {
        let (base, files) = try makeBaseDir(count: 10)
        defer { try? FileManager.default.removeItem(at: base) }
        let pushed = try makePushedDir(reIDing: files[0], to: "pushed.test.ephemeral")
        defer { try? FileManager.default.removeItem(at: pushed) }

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base)
        _ = try await engine.loadPushedRules(from: pushed)
        #expect(await engine.pushedRuleIDs.contains("pushed.test.ephemeral"))
        _ = try await engine.reloadRules(from: base)   // reloads base only
        #expect(await engine.pushedRuleIDs.isEmpty)     // pushed set cleared until re-applied
    }

    @Test("a missing pushed directory is a no-op, not an error")
    func missingPushedDirNoop() async throws {
        let (base, _) = try makeBaseDir(count: 5)
        defer { try? FileManager.default.removeItem(at: base) }
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base)
        let missing = FileManager.default.temporaryDirectory.appendingPathComponent("does-not-exist-\(UUID().uuidString)")
        let added = try await engine.loadPushedRules(from: missing)
        #expect(added == 0)
        #expect(await engine.pushedRuleIDs.isEmpty)
    }

    @Test("ResponseEngine never arms an action for a detection-only (pushed) rule")
    func responseEngineDetectionOnlyGate() async throws {
        let engine = ResponseEngine()
        // A confirmation-gated kill default: when execute() proceeds past the
        // detection-only gate it records a "pending" log entry but never actually
        // kills (safe for a unit test). So a log entry == "the gate let it through".
        await engine.setDefaultActions([ResponseActionConfig(action: .kill, minimumSeverity: .high, requireConfirmation: true)])
        await engine.setDetectionOnlyRuleIDs(["pushed.test.detect_only"])

        // Pushed (detection-only) rule: must be gated — no log entry at all.
        let pushedAlert = Alert(ruleId: "pushed.test.detect_only", ruleTitle: "t", severity: .high,
                                eventId: "e", processPath: "/bin/x", processName: "x",
                                description: "d", mitreTactics: nil, mitreTechniques: nil, suppressed: false)
        await engine.execute(alert: pushedAlert, event: makeEvent())
        #expect(await engine.getExecutionLog().isEmpty)

        // A normal rule with the same default DOES proceed (sanity check that the
        // gate isn't simply swallowing everything).
        let normalAlert = Alert(ruleId: "normal.rule", ruleTitle: "t", severity: .high,
                                eventId: "e2", processPath: "/bin/x", processName: "x",
                                description: "d", mitreTactics: nil, mitreTechniques: nil, suppressed: false)
        await engine.execute(alert: normalAlert, event: makeEvent())
        #expect(await engine.getExecutionLog().count == 1)
    }
}
