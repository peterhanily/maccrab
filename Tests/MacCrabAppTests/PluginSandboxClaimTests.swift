// PluginSandboxClaimTests.swift
// MacCrabAppTests
//
// MacCrab's own (first-party) plugins run with MacCrab's access, unsandboxed;
// only plugins from other publishers run sandboxed. v1.22.5 told every user
// that installs "run fully sandboxed" (Overview prompt, bundled store news,
// all 14 translations). These checks fail if that claim, or one of the old
// translations of it, comes back.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("Plugin sandbox claim stays true")
struct PluginSandboxClaimTests {

    static func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    static let locales = [
        "en", "de", "es", "fr", "it", "ja", "ko", "nl",
        "pl", "pt-BR", "ru", "sv", "zh-Hans", "zh-Hant",
    ]

    /// The overview.storeBrowsePrompt values that shipped in v1.22.5.
    static let oldPromptValues: [String: String] = [
        "en": "Browse signed forensic plugins from the catalog. Installs run fully sandboxed.",
        "de": "Durchsuchen Sie signierte forensische Plugins aus dem Katalog. Installationen laufen vollständig isoliert.",
        "es": "Explore plugins forenses firmados desde el catálogo. Los instalados se ejecutan completamente en la zona de aislamiento.",
        "fr": "Parcourez les plugins forensiques signés du catalogue. Les installations s'exécutent entièrement isolées.",
        "it": "Sfoglia plugin forense firmati dal catalogo. Gli install vengono eseguiti completamente in sandbox.",
        "ja": "カタログから署名済みのフォレンジックプラグインを参照します。インストールは完全にサンドボックス化されて実行されます。",
        "ko": "카탈로그에서 서명된 포렌식 플러그인을 찾아보세요. 설치 후 완전히 샌드박스된 상태에서 실행됩니다.",
        "nl": "Blader door ondertekende forensische plugins uit de catalogus. Installaties worden volledig sandboxed uitgevoerd.",
        "pl": "Przeglądaj podpisane wtyczki forensyki z katalogu. Instalacje działają w pełni piaskownicy.",
        "pt-BR": "Procure plugins forenses assinados no catálogo. As instalações rodam totalmente isoladas.",
        "ru": "Просмотрите подписанные криминалистические плагины в каталоге. Установки полностью изолированы.",
        "sv": "Bläddra signerade forensikplugins från katalogen. Installationer körs helt sandlådade.",
        "zh-Hans": "浏览来自目录的已签名取证插件。安装运行于完整沙盒环境。",
        "zh-Hant": "瀏覽來自目錄的已簽署鑑識外掛模組。安裝會在完全沙盒環境中執行。",
    ]

    /// The "everything is sandboxed" wording inside those old values.
    static let oldSandboxWording = [
        "fully sandboxed",
        "vollständig isoliert",
        "completamente en la zona de aislamiento",
        "entièrement isolées",
        "completamente in sandbox",
        "完全にサンドボックス",
        "완전히 샌드박스",
        "volledig sandboxed",
        "w pełni piaskownicy",
        "totalmente isoladas",
        "полностью изолированы",
        "helt sandlådade",
        "完整沙盒",
        "完全沙盒",
    ]

    /// Phrases that claim every plugin is sandboxed. Matched case-insensitively
    /// in every scanned text file under Sources/, comments included.
    static let forbiddenSourcePhrases = [
        "fully sandboxed",
        "Tier-B plugins run sandboxed",
    ]

    /// The text files under Sources/ that the scan reads: code, every string
    /// table, docs and JSON resources. Vendored C and binary resources are
    /// skipped.
    static let scannedExtensions: Set<String> = ["swift", "strings", "stringsdict", "md", "json"]

    @Test("no text file under Sources/ claims plugins run fully sandboxed, in any language")
    func sourcesMakeNoBlanketSandboxClaim() throws {
        let root = Self.packageRoot().appendingPathComponent("Sources")
        let walker = try #require(FileManager.default.enumerator(
            at: root, includingPropertiesForKeys: nil))
        var scanned: [String: Int] = [:]
        var hits: [String] = []
        for url in walker.compactMap({ $0 as? URL })
        where Self.scannedExtensions.contains(url.pathExtension) {
            scanned[url.pathExtension, default: 0] += 1
            let src = try String(contentsOf: url, encoding: .utf8)
            // A string table is checked for the old translated wording under
            // every key, not just the Overview prompt.
            let isTable = url.pathExtension == "strings" || url.pathExtension == "stringsdict"
            let phrases = Self.forbiddenSourcePhrases + (isTable ? Self.oldSandboxWording : [])
            for (i, line) in src.components(separatedBy: "\n").enumerated() {
                for phrase in phrases
                where line.range(of: phrase, options: .caseInsensitive) != nil {
                    let name = url.deletingLastPathComponent().lastPathComponent + "/" + url.lastPathComponent
                    hits.append("\(name):\(i + 1): \(phrase)")
                }
            }
        }
        #expect(scanned["swift", default: 0] > 100,
                "expected to scan the whole Sources/ tree, scanned \(scanned)")
        #expect(scanned["strings"] == Self.locales.count, "scanned \(scanned)")
        #expect(scanned["stringsdict"] == Self.locales.count, "scanned \(scanned)")
        #expect(scanned["md", default: 0] > 0, "scanned \(scanned)")
        #expect(hits.isEmpty, "blanket sandbox claim found:\n\(hits.joined(separator: "\n"))")
    }

    @Test("the Overview store news does not repeat the store line under it")
    func storeNewsDoesNotRepeatStorePrompt() {
        let news = StoreNews.bundled(appVersion: "0.0.0")
        #expect(!news.isEmpty)
        #expect(!news.contains { $0.id == "store-catalog" })
        #expect(!news.contains { $0.summary.contains("Browse signed forensic plugins") })
        for item in news {
            for phrase in Self.forbiddenSourcePhrases {
                #expect(item.summary.range(of: phrase, options: .caseInsensitive) == nil)
            }
        }
    }

    @Test("overview.storeBrowsePrompt drops the old sandbox claim in all 14 locales")
    func storeBrowsePromptNoLongerClaimsFullSandbox() throws {
        let resources = Self.packageRoot()
            .appendingPathComponent("Sources/MacCrabApp/Resources")
        let row = try NSRegularExpression(
            pattern: #"^\s*"overview\.storeBrowsePrompt"\s*=\s*"(.*)";\s*$"#
        )
        let oldValues = Set(Self.oldPromptValues.values)
        #expect(oldValues.count == Self.locales.count)

        for locale in Self.locales {
            let table = resources.appendingPathComponent("\(locale).lproj/Localizable.strings")
            let text = try String(contentsOf: table, encoding: .utf8)
            let value = try #require(
                text.components(separatedBy: "\n").lazy.compactMap { line -> String? in
                    let ns = line as NSString
                    guard let m = row.firstMatch(
                        in: line, range: NSRange(location: 0, length: ns.length)
                    ) else { return nil }
                    return ns.substring(with: m.range(at: 1))
                }.first,
                "Missing overview.storeBrowsePrompt in \(locale).lproj")

            #expect(!oldValues.contains(value),
                    "\(locale).lproj still ships the old store prompt: \(value)")
            if locale == "en" {
                #expect(value.contains("MacCrab's own plugins run with MacCrab's access"),
                        "the English prompt must name the first-party case: \(value)")
            }
            for wording in Self.oldSandboxWording {
                #expect(value.range(of: wording, options: .caseInsensitive) == nil,
                        "\(locale).lproj store prompt still says “\(wording)”: \(value)")
            }
        }
    }

    @Test("MCP plugin tool descriptions do not call every plugin a third-party scanner")
    func mcpToolDescriptionsSayPlugin() throws {
        let main = try String(
            contentsOf: Self.packageRoot().appendingPathComponent("Sources/maccrab-mcp/main.swift"),
            encoding: .utf8)
        #expect(main.range(of: "third-party scanner", options: .caseInsensitive) == nil)
        #expect(main.contains("\"name\": \"forensics_list_installed_plugins\""))
    }
}
