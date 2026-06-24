// LocalizationCoverageTests.swift
// MacCrabAppTests
//
// UX-2 grep-lint: the 8 priority V2 workspace surfaces must carry no bare
// user-facing string literal — every operator-visible string goes through
// String(localized:defaultValue:). Dynamic interpolation (Text("\(x)")),
// explicit Text(verbatim:), and non-literal Text(expr) are allowed. A new
// bare literal in these files fails CI so the localization floor can't erode.

import Testing
import Foundation

@Suite("Localization coverage (UX-2)")
struct LocalizationCoverageTests {

    static let priorityFiles = [
        "V2OverviewWorkspace.swift",
        "V2ForensicsScansView.swift",
        "V2ForensicsFindingsView.swift",
        "V2ForensicsPastScansView.swift",
        "V2ForensicsScanDetailView.swift",
        "V2KitDetailSheet.swift",
        "V2SystemWorkspace.swift",
        "V2PreventionWorkspace.swift",
    ]

    /// A bare user-facing literal: Text / Button / Label / .help /
    /// .navigationTitle / V2StatusChip / V2ActionButton opening with a
    /// double-quote whose first character is a letter (actual copy). This
    /// deliberately does NOT match `("\(` (dynamic interpolation),
    /// `(verbatim:` , or `(String(localized:` (already wrapped).
    static let bareLiteral = try! NSRegularExpression(
        pattern: #"(Text|Button|Label|V2StatusChip|V2ActionButton)\("[A-Za-z]|\.(help|navigationTitle)\("[A-Za-z]"#
    )

    static func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    @Test("no bare user-facing string literal in the priority V2 surfaces")
    func priorityFilesAreLocalized() throws {
        let dir = Self.packageRoot().appendingPathComponent("Sources/MacCrabApp/V2/Workspaces")
        for file in Self.priorityFiles {
            let url = dir.appendingPathComponent(file)
            let src = try String(contentsOf: url, encoding: .utf8)
            var offenders: [String] = []
            for (i, line) in src.components(separatedBy: "\n").enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") { continue }   // skip comments
                let ns = line as NSString
                if Self.bareLiteral.firstMatch(in: line, range: NSRange(location: 0, length: ns.length)) != nil {
                    offenders.append("\(file):\(i + 1): \(trimmed)")
                }
            }
            let detail = offenders.joined(separator: "\n")
            #expect(offenders.isEmpty,
                    "bare user-facing literal(s) — wrap in String(localized:defaultValue:):\n\(detail)")
        }
    }
}
