// BuiltinRuleSettings.swift
// MacCrabCore
//
// Per-built-in-rule operator overrides: enable/disable + severity. Persisted to
// `<support>/builtin_rules_settings.json`. The dashboard (user uid) WRITES it;
// the daemon (root sysext) READS it via AlertSink (mtime-cached). A missing file
// or missing key means "use the catalog default" — fully backward compatible.

import Foundation

public struct BuiltinRuleSetting: Codable, Sendable, Equatable {
    /// false = mute the alert (the detection + any protective action still run).
    public var enabled: Bool
    /// nil = use the catalog default severity.
    public var severityOverride: Severity?

    public init(enabled: Bool = true, severityOverride: Severity? = nil) {
        self.enabled = enabled
        self.severityOverride = severityOverride
    }
}

public struct BuiltinRuleSettings: Codable, Sendable, Equatable {
    public var rules: [String: BuiltinRuleSetting]

    public init(rules: [String: BuiltinRuleSetting] = [:]) { self.rules = rules }

    public static let fileName = "builtin_rules_settings.json"

    public static func path(inDir dir: String) -> String { dir + "/" + fileName }

    /// Load from `<dir>/builtin_rules_settings.json`; defaults (empty) when
    /// absent or unreadable.
    public static func load(fromDir dir: String) -> BuiltinRuleSettings {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path(inDir: dir))),
              let decoded = try? JSONDecoder().decode(BuiltinRuleSettings.self, from: data)
        else { return BuiltinRuleSettings() }
        return decoded
    }

    /// Atomic write, creating the dir if needed. v1.17.6 SECURITY: 0o644 (was
    /// 0o666) — written ONLY by the root daemon (via the builtin-rule-setting
    /// inbox verb), world-READABLE so the uid-501 dashboard can display the
    /// effective settings. The dashboard never writes this file directly (it
    /// routes through the inbox), so it must not be world-WRITABLE: at 0o666 a
    /// local process could mute a built-in detection — including a HIGH IOC
    /// match — by editing the file directly, bypassing the audited inbox path.
    public func save(toDir dir: String) throws {
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let p = Self.path(inDir: dir)
        let data = try JSONEncoder().encode(self)
        try data.write(to: URL(fileURLWithPath: p), options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: p)
    }

    /// Longest-prefix lookup so a family base id (e.g. `maccrab.git`) governs its
    /// dynamic-suffix emissions (`maccrab.git.create`).
    public func setting(forRuleId ruleId: String) -> BuiltinRuleSetting? {
        if let exact = rules[ruleId] { return exact }
        let key = rules.keys
            .filter { ruleId.hasPrefix($0 + ".") }
            .max(by: { $0.count < $1.count })
        return key.flatMap { rules[$0] }
    }
}
