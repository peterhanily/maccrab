// V2BuiltinSeveritySeedTests.swift
// v1.19 (S6-4): the built-in detection inspector's "Override severity" Picker
// showed "Default" even when an override was active, because its @State
// (severitySel) defaulted to "default" and nothing seeded it from the rule.
// The fix plumbs the live override onto V2MockRule.severityOverrideRaw and the
// inspector seeds the Picker from it in .onAppear:
//
//     severitySel = rule.severityOverrideRaw ?? "default"
//
// These tests pin the two halves of that contract:
//   1. severityOverrideRaw carries the live override (== Severity.rawValue), and
//   2. the seed expression yields the matching Picker tag for every case.

import Testing
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2 built-in severity Picker seed (S6-4)")
struct V2BuiltinSeveritySeedTests {

    /// Build a built-in row the way V2LiveDataProvider does: the override is
    /// `s?.severityOverride?.rawValue` (nil when no override is set).
    /// `MacCrabCore.Severity` is the engine enum that backs the override
    /// (MacCrabApp also declares a `Severity`, so qualify to disambiguate).
    private func builtinRule(override: MacCrabCore.Severity?) -> V2MockRule {
        V2MockRule(
            id: "maccrab.test.builtin",
            title: "Test built-in",
            category: "execution",
            severity: .medium,
            mitre: [],
            isEnabled: true,
            lastFired: nil,
            firesLastWeek: 0,
            isCustom: false,
            description: "x",
            severityOverrideRaw: override?.rawValue
        )
    }

    /// The exact expression the inspector's .onAppear uses to seed the Picker.
    private func seed(_ rule: V2MockRule) -> String {
        rule.severityOverrideRaw ?? "default"
    }

    @Test("no override → Picker seeds to \"default\"")
    func noOverrideSeedsDefault() {
        #expect(seed(builtinRule(override: nil)) == "default")
    }

    @Test("each override severity seeds to its matching Picker tag")
    func overrideSeedsMatchingTag() {
        // The Picker tags in BuiltinRuleSettingsSection are the lowercase
        // Severity raw values. Pin that mapping for every tier.
        let cases: [(MacCrabCore.Severity, String)] = [
            (.critical, "critical"),
            (.high, "high"),
            (.medium, "medium"),
            (.low, "low"),
            (.informational, "informational"),
        ]
        for (sev, expectedTag) in cases {
            #expect(seed(builtinRule(override: sev)) == expectedTag,
                    "override \(sev) should seed the \(expectedTag) tag")
        }
    }

    @Test("severityOverrideRaw always equals a real Picker tag")
    func rawMatchesPickerTags() {
        // Guard against a future Severity raw-value rename silently breaking
        // the seed (the Picker would fall back to showing nothing selected).
        let pickerTags: Set<String> = ["default", "critical", "high", "medium", "low", "informational"]
        for sev in MacCrabCore.Severity.allCases {
            #expect(pickerTags.contains(sev.rawValue),
                    "Severity.\(sev).rawValue (\(sev.rawValue)) is not a Picker tag")
        }
    }

    @Test("Sigma/composite rows carry no override (nil) → seed stays default")
    func nonBuiltinHasNoOverride() {
        // Default init (no severityOverrideRaw arg) must be nil so non-built-in
        // rows never spuriously seed an override.
        let sigma = V2MockRule(
            id: "sigma.rule", title: "Sigma", category: "execution",
            severity: .high, mitre: [], isEnabled: true, lastFired: nil,
            firesLastWeek: 0, isCustom: false, description: "x")
        #expect(sigma.severityOverrideRaw == nil)
        #expect(seed(sigma) == "default")
    }
}
