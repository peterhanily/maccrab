// V2RuleSearchHaystackTests.swift
// MacCrabAppTests
//
// Pin the searchable-field set of the Detection › Rules search box
// (V2DetectionWorkspace.ruleSearchHaystack). An operator must be able to
// find a rule by its id, its name/title (= the alert name), its MITRE
// tag, OR free text from its description — the description field being
// the v1.17.3 enhancement. The formula is the single source of truth for
// both the precomputed cache and the not-yet-built fallback, so a
// regression here silently breaks search in the dashboard.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("Detection rule search haystack")
struct V2RuleSearchHaystackTests {

    private func sampleRule() -> V2MockRule {
        V2MockRule(
            id: "d1a2b3c4-0500-4000-a000-000000000505",
            title: "AppleScript Spawned From A Non-Apple Parent",
            category: "process_creation",
            severity: .high,
            mitre: ["T1059.002", "EXECUTION"],
            isEnabled: true,
            lastFired: nil,
            firesLastWeek: 0,
            isCustom: false,
            description: "Detects osascript launched by a browser or downloaded binary — a common stealer delivery step."
        )
    }

    @Test("searchable by id, name/title, category, MITRE, and description")
    func searchableFields() {
        let h = V2DetectionWorkspace.ruleSearchHaystack(for: sampleRule())
        #expect(h == h.lowercased())                                    // always lowercased
        #expect(h.contains("d1a2b3c4-0500-4000-a000-000000000505"))     // id
        #expect(h.contains("non-apple parent"))                         // name / title (= alert name)
        #expect(h.contains("process_creation"))                         // category
        #expect(h.contains("t1059.002"))                                // MITRE technique
        #expect(h.contains("stealer delivery"))                         // description (v1.17.3 enhancement)
    }

    @Test("a query that appears ONLY in the description still matches")
    func descriptionOnlyQuery() {
        let h = V2DetectionWorkspace.ruleSearchHaystack(for: sampleRule())
        // "stealer" is present only in the description — not in id, title,
        // category, or MITRE — so this fails before the v1.17.3 change.
        #expect(h.contains("stealer"))
    }
}
