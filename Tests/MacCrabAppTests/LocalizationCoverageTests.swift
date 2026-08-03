// LocalizationCoverageTests.swift
// MacCrabAppTests
//
// UX-2 grep-lint: NO file under Sources/MacCrabApp may carry a bare
// user-facing string literal — every operator-visible string goes through
// String(localized:defaultValue:). Dynamic interpolation (Text("\(x)")),
// explicit Text(verbatim:), and non-literal Text(expr) are allowed.
//
// This used to guard a hardcoded list of 9 files out of 108, and the claim
// that "the localization floor can't erode" was only ever true for those 9:
// 268 bare literals accumulated across 33 unguarded files, including all of
// V2DocsWorkspace. The walk is now the default and the debt is recorded per
// file in bareLiteralBudget, so an unlisted (or brand new) file must sit at
// zero and the listed ones can only improve.

import Testing
import Foundation

@Suite("Localization coverage (UX-2)")
struct LocalizationCoverageTests {

    /// L10N-01 ratchet. Every `String(localized: "k", defaultValue: …)` key
    /// should have a row in en.lproj/Localizable.strings. That table — not the
    /// call sites — is what the 13 translation bundles are generated from, so a
    /// key that exists only at a call site is invisible to translators and
    /// renders English in every locale, permanently. 557 of the 1005 referenced
    /// keys are in that state today (the table defines 699).
    ///
    /// prerelease-check.sh:294 has printed this same diff as a *warning* ever
    /// since the count drifted off zero after v1.18.1 — but prerelease-check.sh
    /// is not invoked by ci-local.sh, so it only ran at release time and never
    /// blocked anything, which is how 557 accreted unnoticed. This check runs
    /// under `swift test`, which the pre-push hook does gate on.
    ///
    /// The budget only ratchets DOWN: lower it as keys are backfilled. Never
    /// raise it to make a build pass.
    static let missingEnKeyBudget = 552

    @Test("no new String(localized:) key without an en.lproj row")
    func localizedKeysHaveEnglishTableRows() throws {
        let root = Self.packageRoot().appendingPathComponent("Sources/MacCrabApp")
        let keyRef = try NSRegularExpression(pattern: #"localized:\s*"([^"]+)""#)
        let walker = try #require(FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: nil))

        var referenced = Set<String>()
        for url in walker.compactMap({ $0 as? URL }) where url.pathExtension == "swift" {
            let src = try String(contentsOf: url, encoding: .utf8)
            for line in src.components(separatedBy: "\n") {
                if line.trimmingCharacters(in: .whitespaces).hasPrefix("//") { continue }
                let ns = line as NSString
                for m in keyRef.matches(in: line, range: NSRange(location: 0, length: ns.length)) {
                    referenced.insert(ns.substring(with: m.range(at: 1)))
                }
            }
        }

        let table = root.appendingPathComponent("Resources/en.lproj/Localizable.strings")
        let rowKey = try NSRegularExpression(pattern: #"^\s*"([^"]+)"\s*="#)
        var defined = Set<String>()
        for line in try String(contentsOf: table, encoding: .utf8).components(separatedBy: "\n") {
            let ns = line as NSString
            if let m = rowKey.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)) {
                defined.insert(ns.substring(with: m.range(at: 1)))
            }
        }

        let missing = referenced.subtracting(defined).sorted()
        #expect(missing.count <= Self.missingEnKeyBudget,
                """
                \(missing.count) String(localized:) key(s) have no en.lproj row \
                (budget \(Self.missingEnKeyBudget)). Add the key and its call-site \
                defaultValue copy to Sources/MacCrabApp/Resources/en.lproj/Localizable.strings, \
                then LOWER missingEnKeyBudget. First 10: \(missing.prefix(10).joined(separator: ", "))
                """)
    }

    /// Pre-existing bare-literal debt, keyed on path relative to
    /// Sources/MacCrabApp. Any file NOT listed here must sit at zero — that is
    /// the point of inverting the old allowlist: a file added tomorrow is
    /// guarded without anyone remembering to enrol it.
    ///
    /// These budgets only ratchet DOWN. Wrap literals, then lower the number
    /// (delete the entry when it reaches zero). Never raise one to go green.
    /// The 9 formerly-enrolled surfaces are absent from this map on purpose:
    /// they are clean, and they stay gated at zero.
    ///
    /// V2/Mock/V2MockData.swift is deliberately NOT exempted — it scores zero
    /// under this regex, so it needs no carve-out.
    static let bareLiteralBudget: [String: Int] = [
        "MacCrabApp.swift": 7,
        "V2/CommandBar/V2CommandBar.swift": 2,
        "V2/CommandBar/V2CommandPalette.swift": 1,
        "V2/Components/V2DataTable.swift": 3,
        "V2/Components/V2Inspector.swift": 1,
        "V2/Components/V2StateViews.swift": 1,
        "V2/Components/V2Toast.swift": 1,
        "V2/Forensics/PluginDetailInspector.swift": 6,
        "V2/Forensics/Viewers/ArtifactBarChartView.swift": 1,
        "V2/Forensics/Viewers/ArtifactHistogramView.swift": 1,
        "V2/Forensics/Viewers/ArtifactKeyValueView.swift": 4,
        "V2/Forensics/Viewers/ArtifactLayoutView.swift": 1,
        "V2/Forensics/Viewers/ArtifactTableView.swift": 1,
        "V2/Forensics/Viewers/ArtifactTimelineView.swift": 1,
        "V2/Forensics/Viewers/ArtifactTranscriptView.swift": 1,
        "V2/Forensics/Viewers/JSONTreeView.swift": 3,
        "V2/Sidebar/V2Sidebar.swift": 3,
        "V2/Workspaces/V2AlertsWorkspace.swift": 33,
        "V2/Workspaces/V2CrabWidget.swift": 4,
        "V2/Workspaces/V2DetectionWorkspace.swift": 62,
        "V2/Workspaces/V2DocsWorkspace.swift": 2,
        "V2/Workspaces/V2EventsWorkspace.swift": 4,
        "V2/Workspaces/V2ForensicsSettingsSheet.swift": 6,
        "V2/Workspaces/V2ForensicsWorkspace.swift": 1,
        "V2/Workspaces/V2IntelligenceWorkspace.swift": 26,
        "V2/Workspaces/V2InvestigationWorkspace.swift": 51,
        "Views/AgentTracesView.swift": 3,
        "Views/Components.swift": 3,
        "Views/EventStream.swift": 7,
        "Views/ResponseActionsView.swift": 7,
        "Views/RuleWizard.swift": 14,
        "Views/SettingsView.swift": 3,
        "Views/WelcomeView.swift": 2,
    ]

    /// A bare user-facing literal: Text / Button / Label / .help /
    /// .navigationTitle / V2StatusChip / V2ActionButton opening with a
    /// double-quote whose first character is a letter (actual copy). This
    /// deliberately does NOT match `("\(` (dynamic interpolation),
    /// `(verbatim:` , or `(String(localized:` (already wrapped).
    ///
    /// `.accessibilityLabel("…")` was already caught — accidentally — because
    /// the `Label` alternative is unanchored and `Label(` is a substring of
    /// `accessibilityLabel(`. `accessibilityHint` / `accessibilityValue` were
    /// not, so VoiceOver-only copy could go in unwrapped; they are named
    /// explicitly here (3 sites at the time of writing).
    static let bareLiteral = try! NSRegularExpression(
        pattern: #"(Text|Button|Label|V2StatusChip|V2ActionButton)\("[A-Za-z]|\.(help|navigationTitle|accessibilityHint|accessibilityValue)\("[A-Za-z]"#
    )

    static func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    @Test("no new bare user-facing string literal anywhere in MacCrabApp")
    func sourcesAreLocalized() throws {
        let root = Self.packageRoot().appendingPathComponent("Sources/MacCrabApp")
        // Resolve symlinks on BOTH sides: #filePath can sit under /tmp on some
        // checkouts while the enumerator hands back /private/tmp, and a prefix
        // that fails to strip would leave every path unmatched in the budget
        // map — i.e. 33 phantom regressions.
        let rootPath = root.resolvingSymlinksInPath().path
        let walker = try #require(FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: nil))

        var regressions: [String] = []
        for url in walker.compactMap({ $0 as? URL }) where url.pathExtension == "swift" {
            let rel = url.resolvingSymlinksInPath().path
                .replacingOccurrences(of: rootPath + "/", with: "")
            let src = try String(contentsOf: url, encoding: .utf8)
            var offenders: [String] = []
            for (i, line) in src.components(separatedBy: "\n").enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") { continue }   // skip comments
                let ns = line as NSString
                if Self.bareLiteral.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)) != nil {
                    offenders.append("\(rel):\(i + 1): \(trimmed)")
                }
            }
            let budget = Self.bareLiteralBudget[rel] ?? 0
            guard offenders.count > budget else { continue }
            regressions.append(
                "\(rel): \(offenders.count) bare literal(s), budget \(budget)\n"
                + offenders.joined(separator: "\n"))
        }

        #expect(regressions.isEmpty,
                """
                bare user-facing literal(s) — wrap in String(localized:defaultValue:). \
                If you FIXED some, LOWER that file's bareLiteralBudget entry to the new count:
                \(regressions.joined(separator: "\n"))
                """)
    }
}
