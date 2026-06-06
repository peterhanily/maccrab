// BuiltinRuleSettingsTests.swift
// MacCrabCoreTests
//
// The catalog + settings that let operators mute / re-severity the hardcoded
// maccrab.* detections. The longest-prefix lookup is the load-bearing bit: a
// family-base setting (maccrab.git) must govern its dynamic-suffix emissions
// (maccrab.git.create) WITHOUT false-matching a sibling (maccrab.gitsomething).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Built-in rule catalog + settings")
struct BuiltinRuleSettingsTests {

    @Test("Catalog ids are unique, namespaced, and non-trivial")
    func catalogIntegrity() {
        let ids = BuiltinRuleCatalog.all.map(\.id)
        #expect(ids.count == Set(ids).count, "duplicate built-in rule ids")
        #expect(ids.allSatisfy { $0.hasPrefix("maccrab.") && !$0.isEmpty })
        #expect(BuiltinRuleCatalog.all.count >= 25)
        #expect(BuiltinRuleCatalog.byId["maccrab.clickfix.paste-and-run"] != nil)
    }

    @Test("Longest-prefix lookup: family base governs dynamic suffixes, no false match")
    func prefixMatch() {
        let s = BuiltinRuleSettings(rules: [
            "maccrab.git": BuiltinRuleSetting(enabled: false),
            "maccrab.ai-guard.credential-access": BuiltinRuleSetting(enabled: true, severityOverride: .medium),
        ])
        #expect(s.setting(forRuleId: "maccrab.ai-guard.credential-access")?.severityOverride == .medium) // exact
        #expect(s.setting(forRuleId: "maccrab.git.create")?.enabled == false)   // family
        #expect(s.setting(forRuleId: "maccrab.git.hook.delete")?.enabled == false)
        #expect(s.setting(forRuleId: "maccrab.usb.connected") == nil)           // unrelated
        #expect(s.setting(forRuleId: "maccrab.gitsomething") == nil)            // sibling, not a `.` boundary
    }

    @Test("Settings round-trip through JSON")
    func codable() throws {
        let s = BuiltinRuleSettings(rules: [
            "maccrab.clickfix.paste-and-run": BuiltinRuleSetting(enabled: false, severityOverride: .critical),
        ])
        let back = try JSONDecoder().decode(BuiltinRuleSettings.self, from: try JSONEncoder().encode(s))
        #expect(back.rules["maccrab.clickfix.paste-and-run"]?.enabled == false)
        #expect(back.rules["maccrab.clickfix.paste-and-run"]?.severityOverride == .critical)
    }

    @Test("Save then load from a temp dir is a faithful round-trip")
    func saveLoad() throws {
        let dir = NSTemporaryDirectory() + "maccrab-brs-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try BuiltinRuleSettings(rules: ["maccrab.usb": BuiltinRuleSetting(enabled: false)]).save(toDir: dir)
        #expect(BuiltinRuleSettings.load(fromDir: dir).rules["maccrab.usb"]?.enabled == false)
        // missing dir → empty defaults (backward compatible)
        #expect(BuiltinRuleSettings.load(fromDir: "/nonexistent/\(UUID().uuidString)").rules.isEmpty)
    }

    @Test("v1.17.6 SECURITY: saved settings file is NOT world-writable (0o644, not 0o666)")
    func savedFileNotWorldWritable() throws {
        let dir = NSTemporaryDirectory() + "maccrab-brs-perm-\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try BuiltinRuleSettings(rules: ["maccrab.usb": BuiltinRuleSetting(enabled: false)]).save(toDir: dir)
        let p = BuiltinRuleSettings.path(inDir: dir)
        let perms = (try FileManager.default.attributesOfItem(atPath: p)[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        // 0o002 = world-write. A world-writable settings file lets any local
        // process mute a built-in detection, bypassing the audited inbox path.
        #expect((perms & 0o002) == 0, "builtin_rules_settings.json must not be world-writable (got \(String(perms, radix: 8)))")
    }
}
