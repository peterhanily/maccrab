import Foundation
import Testing

@Suite("Live localization plurals")
struct LocalizationPluralTests {
    private func bundle(_ locale: String) throws -> Bundle {
        let resources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabApp/Resources")
        return try #require(Bundle(url: resources.appendingPathComponent("\(locale).lproj")))
    }

    @Test("Counts resolve the shipped locale's grammatical form", arguments: [
        ("en", 0, "0 findings"), ("en", 1, "1 finding"), ("en", 2, "2 findings"),
        ("es", 1, "1 hallazgo"), ("es", 2, "2 hallazgos"),
        ("ru", 1, "1 результат"), ("ru", 2, "2 результата"),
        ("ru", 5, "5 результатов"), ("ru", 11, "11 результатов"), ("ru", 21, "21 результат"),
        ("pl", 1, "1 wynik"), ("pl", 2, "2 wyniki"), ("pl", 5, "5 wyników"), ("pl", 21, "21 wyników"),
        ("ja", 1, "検出結果 1 件"), ("ja", 2, "検出結果 2 件"),
    ])
    func countForms(_ locale: String, _ count: Int, _ expected: String) throws {
        let localized = String(
            localized: "findings.findingCount", defaultValue: "\(count) findings",
            bundle: try bundle(locale), locale: Locale(identifier: locale)
        )
        #expect(localized == expected)
    }

    @Test("Plural selection retains all additional format arguments", arguments: [1, 3])
    func extraArguments(_ count: Int) throws {
        let version = "1.2.3"
        let maintainer = "Example Maintainer"
        let localized = String(
            localized: "kit.footerSummary", defaultValue: "\(count) scanners · v\(version) · \(maintainer)",
            bundle: try bundle("en"), locale: Locale(identifier: "en")
        )
        let noun = count == 1 ? "scanner" : "scanners"
        #expect(localized == "\(count) \(noun) · v1.2.3 · Example Maintainer")
    }
}
