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
        ensureRulesCompiled()
        let src = URL(fileURLWithPath: "/tmp/maccrab_v3")
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
}
