// RuleEngineReloadTests.swift
// v1.18 — last-known-good safety for RuleEngine.reloadRules (the on-host
// content-swap gate driven by SIGHUP / the privileged inbox IPC).
//
// loadRules is best-effort: it CATCHES + SKIPS any compiled-rule file it
// can't decode. On a RELOAD that means a single corrupt/truncated .json
// would silently shrink the live ruleset with no error — the CrowdStrike
// Channel-File-291 class of failure (content is code; a bad content file
// must not degrade a privileged detector). reloadRules now treats ANY
// decode failure as a failed atomic swap and rolls back to the prior
// known-good set. These tests pin that contract.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("RuleEngine: reload last-known-good safety (v1.18)")
struct RuleEngineReloadTests {

    /// An isolated rules directory holding `count` real compiled rules copied
    /// from the project's compiled output (so we exercise the real decoder).
    private func makeRulesDir(count: Int) throws -> URL {
        try ensureRulesCompiled()
        let src = compiledRulesDirectory
        let dst = FileManager.default.temporaryDirectory
            .appendingPathComponent("reload-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dst, withIntermediateDirectories: true)
        let jsons = try FileManager.default
            .contentsOfDirectory(at: src, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .prefix(count)
        for f in jsons {
            try FileManager.default.copyItem(at: f, to: dst.appendingPathComponent(f.lastPathComponent))
        }
        return dst
    }

    @Test("clean reload swaps rules and reports zero decode failures")
    func cleanReload() async throws {
        let dir = try makeRulesDir(count: 20)
        defer { try? FileManager.default.removeItem(at: dir) }
        let engine = RuleEngine()
        let n = try await engine.loadRules(from: dir)
        #expect(n == 20)
        let reloaded = try await engine.reloadRules(from: dir)
        #expect(reloaded == 20)
        #expect(await engine.lastLoadFailedCount == 0)
        #expect(await engine.ruleCount == 20)
    }

    @Test("override overlay per-file ownership gate skips non-daemon-owned files (v1.19.1)")
    func overlayOwnershipGate() async throws {
        // The override overlay can DISABLE bundled detections; an audit found the
        // directory was gated but not per-FILE ownership, so a legacy file owned
        // by a non-daemon uid inside a root-owned dir could shadow a rule.
        // requireOwnerUID closes that: only files owned by the daemon's uid load.
        let dir = try makeRulesDir(count: 3)
        defer { try? FileManager.default.removeItem(at: dir) }
        let mine = geteuid()                         // the test runner owns the temp files
        let notMine: uid_t = mine == 0 ? 99 : 0      // a uid that does NOT own them

        // Requiring a DIFFERENT uid → every override file is skipped AND counted
        // (so status/dashboard can surface that operator tuning was dropped).
        let skipEngine = RuleEngine()
        #expect(try await skipEngine.loadRules(from: dir, requireOwnerUID: notMine) == 0)
        #expect(await skipEngine.lastLoadSkippedByOwnerCount == 3)
        // Requiring the actual owner uid → all load.
        #expect(try await RuleEngine().loadRules(from: dir, requireOwnerUID: mine) == 3)
        // No gate (default) → all load — back-compat for the primary rules path.
        #expect(try await RuleEngine().loadRules(from: dir, requireOwnerUID: nil) == 3)
    }

    @Test("a single corrupt compiled rule rolls back to last-known-good (no silent N-1)")
    func corruptFileRollsBack() async throws {
        let dir = try makeRulesDir(count: 20)
        defer { try? FileManager.default.removeItem(at: dir) }
        let engine = RuleEngine()
        #expect(try await engine.loadRules(from: dir) == 20)

        // Corrupt ONE compiled rule into undecodable garbage.
        let victim = try FileManager.default
            .contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .first { $0.pathExtension == "json" }!
        try Data("{ this is not valid json".utf8).write(to: victim)

        // The reload must be REJECTED, not silently accepted at 19 rules.
        await #expect(throws: RuleEngineError.self) {
            _ = try await engine.reloadRules(from: dir)
        }
        // Last-known-good set is fully intact — coverage was not silently lost.
        #expect(await engine.ruleCount == 20)
    }

    @Test("missing directory rolls back; engine is never left empty")
    func missingDirRollsBack() async throws {
        let dir = try makeRulesDir(count: 15)
        defer { try? FileManager.default.removeItem(at: dir) }
        let engine = RuleEngine()
        #expect(try await engine.loadRules(from: dir) == 15)

        let gone = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-\(UUID().uuidString)")
        await #expect(throws: (any Error).self) {
            _ = try await engine.reloadRules(from: gone)
        }
        #expect(await engine.ruleCount == 15)
    }

    @Test("disabled state survives a clean reload")
    func disabledStateSurvives() async throws {
        let dir = try makeRulesDir(count: 20)
        defer { try? FileManager.default.removeItem(at: dir) }
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: dir)

        let id = await engine.listRules().first!.id
        await engine.setEnabled(id, enabled: false)
        _ = try await engine.reloadRules(from: dir)

        let after = await engine.listRules().first { $0.id == id }
        #expect(after?.enabled == false, "a rule disabled before reload must stay disabled after")
    }

    @Test("a reload that drops >30% of rules is rejected as a truncated bundle (count regression)")
    func countRegressionRollsBack() async throws {
        let big = try makeRulesDir(count: 20)
        let small = try makeRulesDir(count: 10)   // 10 < 70% of 20
        defer {
            try? FileManager.default.removeItem(at: big)
            try? FileManager.default.removeItem(at: small)
        }
        let engine = RuleEngine()
        #expect(try await engine.loadRules(from: big) == 20)
        await #expect(throws: RuleEngineError.self) {
            _ = try await engine.reloadRules(from: small)
        }
        #expect(await engine.ruleCount == 20, "last-known-good must be preserved on a count regression")
    }

    @Test("a modest reduction within the count budget is allowed")
    func modestReductionAllowed() async throws {
        let big = try makeRulesDir(count: 20)
        let slightly = try makeRulesDir(count: 18)   // 18 ≥ 70% of 20
        defer {
            try? FileManager.default.removeItem(at: big)
            try? FileManager.default.removeItem(at: slightly)
        }
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: big)
        #expect(try await engine.reloadRules(from: slightly) == 18)
        #expect(await engine.ruleCount == 18)
    }

    // v1.18.1 regression: the live compiled_rules dir ships a manifest.json
    // (build integrity metadata). It is not a CompiledRule, so decoding it
    // throws — which on RELOAD tripped the "any decode failure rolls back"
    // guard, making every SIGHUP / .reload_tick reload (and dashboard rule
    // edits) silently no-op until a daemon restart. loadRules now excludes it.
    @Test("manifest.json in the rules dir does not break reload")
    func manifestJsonIgnoredOnReload() async throws {
        let dir = try makeRulesDir(count: 20)
        defer { try? FileManager.default.removeItem(at: dir) }
        let manifest = #"{"generated":"2026-06-11","rule_count":20,"sha256":"deadbeef"}"#
        try manifest.write(to: dir.appendingPathComponent("manifest.json"),
                           atomically: true, encoding: .utf8)
        let engine = RuleEngine()
        #expect(try await engine.loadRules(from: dir) == 20, "manifest must not be counted/loaded as a rule")
        #expect(try await engine.reloadRules(from: dir) == 20, "reload must succeed with manifest.json present")
        #expect(await engine.lastLoadFailedCount == 0, "manifest must not register as a decode failure")
        #expect(await engine.ruleCount == 20)
    }

    // v1.18.1 regression: a user_rules override of a bundled rule (same id,
    // loaded by a second loadRules call) was de-duped in allRules but APPENDED
    // to the dispatch index, so both copies fired and the bundled rule shadowed
    // the override's severity/enabled — a dashboard Sigma-rule severity/disable
    // change had no runtime effect.
    @Test("same-id overlay replaces in the dispatch index instead of duplicating")
    func sameIdOverlayDeduplicates() async throws {
        let base = try makeRulesDir(count: 20)
        defer { try? FileManager.default.removeItem(at: base) }
        let baseJson = try FileManager.default
            .contentsOfDirectory(at: base, includingPropertiesForKeys: nil)
            .first { $0.pathExtension == "json" }!
        var obj = try JSONSerialization.jsonObject(with: Data(contentsOf: baseJson)) as! [String: Any]
        let id = obj["id"] as! String
        let category = (obj["logsource"] as! [String: Any])["category"] as! String
        let originalLevel = obj["level"] as! String
        let overrideLevel = originalLevel == "critical" ? "low" : "critical"
        obj["level"] = overrideLevel
        let overrideDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("override-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: overrideDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: overrideDir) }
        try JSONSerialization.data(withJSONObject: obj)
            .write(to: overrideDir.appendingPathComponent("\(id).json"))

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base)        // bundled
        _ = try await engine.loadRules(from: overrideDir) // overlay (no clear)

        let inIndex = await engine.listRules(category: category).filter { $0.id == id }
        #expect(inIndex.count == 1, "the dispatch index must hold exactly one copy of an overridden rule, got \(inIndex.count)")
        #expect(inIndex.first?.level.rawValue == overrideLevel, "the override severity must win, not the bundled default")
    }

    /// The stable iodine_dns_tunnel rule (Image|endswith '/iodine'), and an
    /// exec it matches.
    private let iodineRuleID = "d1a2b3c4-0246-4000-a000-000000000246"
    private let iodineRuleFile = "iodine_dns_tunnel.json"

    private func iodineExec() -> Event {
        let p = MacCrabCore.ProcessInfo(
            pid: 4401, ppid: 1, rpid: 1, name: "iodine",
            executable: "/usr/local/bin/iodine",
            commandLine: "iodine -f 192.0.2.1 t.example.com",
            args: ["/usr/local/bin/iodine"], workingDirectory: "/tmp",
            userId: 501, userName: "t", groupId: 20, startTime: Date(),
            codeSignature: nil,
            ancestors: [ProcessAncestor(pid: 1, executable: "/bin/bash", name: "bash")],
            architecture: "arm64", isPlatformBinary: false)
        return Event(eventCategory: .process, eventType: .start, eventAction: "exec", process: p)
    }

    /// Sets the `enabled` key of the rule file at `url`, as the dashboard's
    /// disable override and `maccrabctl rule enable|disable` do.
    private func setEnabledKey(_ enabled: Bool, in url: URL) throws {
        var obj = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        obj["enabled"] = enabled
        try JSONSerialization.data(withJSONObject: obj).write(to: url, options: .atomic)
    }

    /// Writes into `folder` an override of the iodine rule: its compiled file
    /// with `changes` applied, as the dashboard's disable and severity
    /// overrides are.
    private func writeIodineOverride(_ changes: [String: Any], into folder: URL) throws {
        var obj = try JSONSerialization.jsonObject(
            with: Data(contentsOf: compiledRulesDirectory.appendingPathComponent(iodineRuleFile))) as! [String: Any]
        obj.merge(changes) { $1 }
        try JSONSerialization.data(withJSONObject: obj)
            .write(to: folder.appendingPathComponent("\(iodineRuleID).json"))
    }

    // The dashboard's Disable installs user_rules/<id>.json with enabled:false.
    // Its Enable, MCP delete_rule and `maccrabctl rule delete` delete that file,
    // and the daemon then reloads compiled_rules and the overlay in one call.
    // The reload used to carry disabled flags across, so with the override gone
    // the bundled rule stayed disabled until the engine restarted.
    @Test("deleting a disable override re-enables the bundled rule on the next reload")
    func deletedOverrideReenablesOnReload() async throws {
        try ensureRulesCompiled()
        let base = compiledRulesDirectory
        let overlay = FileManager.default.temporaryDirectory
            .appendingPathComponent("overlay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: overlay, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: overlay) }
        let override = overlay.appendingPathComponent("\(iodineRuleID).json")
        try FileManager.default.copyItem(at: base.appendingPathComponent(iodineRuleFile), to: override)
        try setEnabledKey(false, in: override)

        // Boot order: the base under the stable profile, then the overlay.
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base, enabledStatuses: ["stable"])
        let enabledAtBoot = await engine.enabledRuleCount
        let bundled = try #require(await engine.listRules().first { $0.id == iodineRuleID })
        #expect(bundled.status == "stable")
        #expect(bundled.enabled)
        _ = try await engine.loadRules(from: overlay, requireOwnerUID: geteuid())
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == false)
        #expect(await engine.enabledRuleCount == enabledAtBoot - 1)
        #expect(!(await engine.evaluate(iodineExec()).contains { $0.ruleId == iodineRuleID }))

        // Enable deletes the override; then the daemon's reload.
        try FileManager.default.removeItem(at: override)
        _ = try await engine.reloadRules(from: base, overlay: overlay, requireOwnerUID: geteuid())

        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == true,
                "with its override deleted, the bundled rule must load enabled again")
        #expect(await engine.enabledRuleCount == enabledAtBoot)
        #expect(await engine.evaluate(iodineExec()).contains { $0.ruleId == iodineRuleID })
    }

    // `maccrabctl rule disable|enable` sets the `enabled` key in the compiled
    // rule file and asks for `rules reload`, which raises SIGHUP. The reload
    // used to keep a rule disabled after its file was set back to enabled:true.
    @Test("a reload takes a compiled rule's enabled key from its file")
    func reloadTakesEnabledFromFile() async throws {
        try ensureRulesCompiled()
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("reload-enabled-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent(iodineRuleFile)
        try FileManager.default.copyItem(at: compiledRulesDirectory.appendingPathComponent(iodineRuleFile), to: file)

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: dir, enabledStatuses: ["stable"])
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == true)

        try setEnabledKey(false, in: file)
        _ = try await engine.reloadRules(from: dir)
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == false)

        try setEnabledKey(true, in: file)
        _ = try await engine.reloadRules(from: dir)
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == true,
                "a file set back to enabled:true must load enabled")
        #expect(await engine.evaluate(iodineExec()).contains { $0.ruleId == iodineRuleID })
    }

    // The .reload_tick watcher and SIGHUP reload compiled_rules and the
    // user_rules overlay in one call. As two calls, an evaluation queued during
    // the reload could run before the overlay load, against the bundled copy
    // of each rule an override replaces: a disabled rule could fire, and a
    // rule could fire with its bundled severity.
    @Test("a reload with the overlay applies a disable override before it returns")
    func reloadWithOverlayKeepsDisableOverride() async throws {
        try ensureRulesCompiled()
        let base = compiledRulesDirectory
        let overlay = FileManager.default.temporaryDirectory
            .appendingPathComponent("overlay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: overlay, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: overlay) }
        try writeIodineOverride(["enabled": false], into: overlay)

        // Boot order: the base under the stable profile, then the overlay.
        let engine = RuleEngine()
        let baseAtBoot = try await engine.loadRules(from: base, enabledStatuses: ["stable"])
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == true)
        _ = try await engine.loadRules(from: overlay, requireOwnerUID: geteuid())
        let enabledAtBoot = await engine.enabledRuleCount
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == false)

        let reloaded = try await engine.reloadRules(from: base, overlay: overlay, requireOwnerUID: geteuid())
        #expect(reloaded.base == baseAtBoot)
        #expect(reloaded.overlay == 1)
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.enabled == false,
                "the override's disable must hold when the reload returns")
        #expect(await engine.enabledRuleCount == enabledAtBoot)
        #expect(!(await engine.evaluate(iodineExec()).contains { $0.ruleId == iodineRuleID }))
    }

    @Test("a reload with the overlay applies a severity override before it returns")
    func reloadWithOverlayKeepsSeverityOverride() async throws {
        try ensureRulesCompiled()
        let base = compiledRulesDirectory
        let overlay = FileManager.default.temporaryDirectory
            .appendingPathComponent("overlay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: overlay, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: overlay) }
        try writeIodineOverride(["level": Severity.low.rawValue], into: overlay)

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base, enabledStatuses: ["stable"])
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.level != .low)
        _ = try await engine.loadRules(from: overlay, requireOwnerUID: geteuid())

        _ = try await engine.reloadRules(from: base, overlay: overlay, requireOwnerUID: geteuid())
        #expect(await engine.listRules().first { $0.id == iodineRuleID }?.level == .low,
                "the override's severity must hold when the reload returns")
        let match = await engine.evaluate(iodineExec()).first { $0.ruleId == iodineRuleID }
        #expect(match?.severity == .low)
    }

    // A setEnabled disable that a reload keeps is applied after the overlay,
    // so it holds when an override replaces the rule.
    @Test("a reload with the overlay keeps a setEnabled disable of a rule the overlay replaces")
    func reloadWithOverlayKeepsSetEnabledDisable() async throws {
        try ensureRulesCompiled()
        let base = compiledRulesDirectory
        let overlay = FileManager.default.temporaryDirectory
            .appendingPathComponent("overlay-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: overlay, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: overlay) }
        try writeIodineOverride(["level": Severity.low.rawValue], into: overlay)

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: base, enabledStatuses: ["stable"])
        _ = try await engine.loadRules(from: overlay, requireOwnerUID: geteuid())
        await engine.setEnabled(iodineRuleID, enabled: false)

        _ = try await engine.reloadRules(from: base, overlay: overlay, requireOwnerUID: geteuid())
        let rule = try #require(await engine.listRules().first { $0.id == iodineRuleID })
        #expect(rule.level == .low, "the loaded rule is the override")
        #expect(!rule.enabled, "the setEnabled disable must hold for the override")
        #expect(!(await engine.evaluate(iodineExec()).contains { $0.ruleId == iodineRuleID }))
    }

    @Test("an overlay that fails to load neither fails nor rolls back the reload")
    func reloadWithFailedOverlayStands() async throws {
        let big = try makeRulesDir(count: 20)
        let slightly = try makeRulesDir(count: 18)
        defer {
            try? FileManager.default.removeItem(at: big)
            try? FileManager.default.removeItem(at: slightly)
        }
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-\(UUID().uuidString)")
        let engine = RuleEngine()
        _ = try await engine.loadRules(from: big)

        let reloaded = try await engine.reloadRules(from: slightly, overlay: missing, requireOwnerUID: geteuid())
        #expect(reloaded.base == 18)
        #expect(reloaded.overlay == nil)
        #expect(await engine.ruleCount == 18)
    }
}
