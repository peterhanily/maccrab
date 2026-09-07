// LocalizationCoverageTests.swift
// MacCrabAppTests
//
// UX-2 source lint covers explicit UI constructors and accessibility labels
// throughout Sources/MacCrabApp. Ordinary literal copy uses stable localization
// keys; exact technical values use Text(verbatim:). Dynamic expressions and
// leading-interpolation literals still need semantic review, so this syntactic
// check does not certify every rendered string. Both debt budgets are zero.

import Testing
import Foundation

@Suite("Localization coverage (UX-2)")
struct LocalizationCoverageTests {

    /// Every source localization key must have an English catalog row.
    /// The companion Python gate checks all locale keys, printf arguments,
    /// live plural resources, and source-default agreement. Keep this at zero.
    static let missingEnKeyBudget = 0

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
                keep missingEnKeyBudget at zero. First 10: \(missing.prefix(10).joined(separator: ", "))
                """)
    }

    /// Ordinary user-facing literals must use explicit localization keys.
    /// Exact commands, identifiers, brands and versions use Text(verbatim:).
    /// Dynamic Text(expression) still requires semantic review; this syntax
    /// check alone does not certify that every rendered value is localized.
    static let bareLiteralBudget: [String: Int] = [:]

    /// Constructor boundaries avoid treating SF Symbol arguments to helper
    /// functions such as deviceButton as user-visible Button titles.
    static let bareLiteral = try! NSRegularExpression(
        pattern: #"(?<![A-Za-z0-9_])(Text|Button|Label|V2StatusChip|V2ActionButton)\("[A-Za-z]|\.(help|navigationTitle|accessibilityLabel|accessibilityHint|accessibilityValue)\("[A-Za-z]"#
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
                Keep every file at zero bare literals:
                \(regressions.joined(separator: "\n"))
                """)
    }

    @Test("AI Guard empty state never becomes a safety verdict in any locale")
    func aiGuardEmptyStateTranslationParity() throws {
        let resources = Self.packageRoot()
            .appendingPathComponent("Sources/MacCrabApp/Resources")
        let oldUnsafeValues: Set<String> = [
            "Les outils IA fonctionnent dans les limites de sécurité",
            "AI 도구가 안전한 범위 내에서 작동 중입니다",
            "AI 工具在安全範圍內運作",
            "AIツールは安全な範囲内で動作しています",
            "AI工具在安全范围内运行",
            "AI-verktyg arbetar inom säkra gränser",
            "Las herramientas IA están operando dentro de límites seguros",
            "ИИ-инструменты работают в безопасных границах",
            "Gli strumenti IA operano entro limiti sicuri",
            "Narzędzia AI działają w bezpiecznych granicach",
            "AI-tools werken binnen veilige grenzen",
            "Ferramentas de IA estão operando dentro dos limites seguros",
            "KI-Tools arbeiten innerhalb sicherer Grenzen",
        ]
        let row = try NSRegularExpression(
            pattern: #"^\s*"aiGuard\.noAlertsDesc"\s*=\s*"(.*)";\s*$"#
        )
        let locales = try FileManager.default.contentsOfDirectory(
            at: resources,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "lproj" }
        #expect(locales.count >= 14)

        for locale in locales {
            let table = locale.appendingPathComponent("Localizable.strings")
            let text = try String(contentsOf: table, encoding: .utf8)
            let match = text.components(separatedBy: "\n").compactMap { line -> String? in
                let ns = line as NSString
                guard let result = row.firstMatch(
                    in: line,
                    range: NSRange(location: 0, length: ns.length)
                ) else { return nil }
                return ns.substring(with: result.range(at: 1))
            }.first
            let value = try #require(match, "Missing aiGuard.noAlertsDesc in \(locale.lastPathComponent)")
            #expect(!oldUnsafeValues.contains(value),
                    "\(locale.lastPathComponent) still turns an empty result into a safety verdict")
        }
    }
}
