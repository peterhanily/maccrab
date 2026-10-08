// RaveInstallConsentSheetTests.swift
// MacCrabAppTests
//
// The install consent sheet tells the person consenting what they are
// installing and how it will run. These pin the title choice (only a
// maccrab:// link says "Install from MacCrab link"), the order of the
// "How this plugin runs" text (a first-party plugin hears what applies to it,
// never the third-party sandbox text first), the signed short_description
// decode, and where the catalog key fingerprint comes from.

import CryptoKit
import Foundation
import Testing
@testable import MacCrabApp

@Suite("RaveInstallConsentSheet — title, disclosure order and key fingerprint")
@MainActor
struct RaveInstallConsentSheetTests {

    static func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    private final class BundleToken {}

    // MARK: - Title

    @Test("a fresh install from the store or the scans view is titled Install plugin")
    func freshInstallTitle() {
        #expect(RaveInstallConsentSheet.title(isUpdate: false, openedFromLink: false) == .install)
    }

    @Test("only a maccrab:// link gets Install from MacCrab link")
    func linkTitle() {
        #expect(RaveInstallConsentSheet.title(isUpdate: false, openedFromLink: true) == .installFromLink)
    }

    @Test("an update is titled Update plugin whatever opened it")
    func updateTitle() {
        #expect(RaveInstallConsentSheet.title(isUpdate: true, openedFromLink: false) == .update)
        #expect(RaveInstallConsentSheet.title(isUpdate: true, openedFromLink: true) == .update)
    }

    @Test("the sheet is not marked as opened from a link unless the caller says so")
    func linkOriginDefaultsOff() {
        let sheet = RaveInstallConsentSheet(
            link: RaveInstallLink(kind: .plugin, id: "com.maccrab.forensics.agent-exposure"),
            onClose: {})
        #expect(sheet.openedFromLink == false)
        #expect(sheet.isUpdate == false)
    }

    @Test("only the deep-link handler in MacCrabApp.swift sets openedFromLink")
    func onlyDeepLinkHandlerSetsLinkOrigin() throws {
        let sources = Self.packageRoot().appendingPathComponent("Sources")
        let walker = try #require(FileManager.default.enumerator(
            at: sources, includingPropertiesForKeys: nil))
        var setters: [String] = []
        for url in walker.compactMap({ $0 as? URL }) where url.pathExtension == "swift" {
            let text = try String(contentsOf: url, encoding: .utf8)
            if text.contains("openedFromLink: true") {
                setters.append(url.lastPathComponent)
            }
        }
        #expect(setters == ["MacCrabApp.swift"])
    }

    // MARK: - How this plugin runs

    @Test("a first-party plugin is told what applies to it first, with no third-party text before it")
    func firstPartyLineComesFirst() {
        let parts = RaveInstallConsentSheet.runDisclosures(isFirstParty: true)
        #expect(parts.first == .firstParty)
        let firstParty = parts.firstIndex(of: .firstParty)
        let thirdParty = parts.firstIndex(of: .thirdParty)
        if let firstParty, let thirdParty {
            #expect(firstParty < thirdParty)
        }
    }

    @Test("a third-party plugin gets the sandbox text and never the first-party line")
    func thirdPartyGetsSandboxTextOnly() {
        let parts = RaveInstallConsentSheet.runDisclosures(isFirstParty: false)
        #expect(parts == [.thirdParty])
        #expect(!parts.contains(.firstParty))
    }

    @Test("the first-party line names MacCrab's access, Full Disk Access and the network")
    func firstPartyLineSaysWhatApplies() throws {
        let table = try String(
            contentsOf: Self.packageRoot()
                .appendingPathComponent("Sources/MacCrabApp/Resources/en.lproj/Localizable.strings"),
            encoding: .utf8)
        let row = try #require(table.components(separatedBy: "\n")
            .first { $0.hasPrefix("\"rave.consent.howItRuns.firstParty\" = ") })
        #expect(row.contains("without a sandbox"))
        #expect(row.contains("MacCrab's own access"))
        #expect(row.contains("Full Disk Access if you granted it to MacCrab"))
        #expect(row.contains("does not block its network use"))
    }

    // MARK: - Signed short_description

    @Test("parseCatalog keeps the signed short_description and treats it as optional")
    func shortDescriptionDecoded() throws {
        let json = """
        {"plugins": {
          "com.maccrab.forensics.agent-exposure": {
            "display_name": "Agent Exposure",
            "short_description": "Review configured agent components, declared permissions and gaps in local source coverage.",
            "current_version": "1.0.0", "status": "active"
          },
          "com.example.no-summary": {"display_name": "No Summary", "current_version": "1.0.0", "status": "active"},
          "com.example.odd-summary": {"current_version": "1.0.0", "short_description": 42}
        }}
        """
        let entries = try RaveCatalogClient.parseCatalog(data: Data(json.utf8))
        let byID = Dictionary(uniqueKeysWithValues: entries.map { ($0.id, $0) })
        let agent = try #require(byID["com.maccrab.forensics.agent-exposure"])
        #expect(agent.displayName == "Agent Exposure")
        #expect(agent.shortDescription
                == "Review configured agent components, declared permissions and gaps in local source coverage.")
        let noSummary = try #require(byID["com.example.no-summary"])
        #expect(noSummary.shortDescription == nil)
        let odd = try #require(byID["com.example.odd-summary"])
        #expect(odd.shortDescription == nil)
        #expect(odd.displayName == "com.example.odd-summary")
    }

    // MARK: - Catalog key fingerprint

    @Test("the bundled catalog.fingerprint is the SHA-256 of the bundled catalog.pub")
    func fingerprintMatchesBundledKey() throws {
        let keys = Self.packageRoot().appendingPathComponent("Sources/MacCrabApp/Resources/rave-keys")
        let pub = try Data(contentsOf: keys.appendingPathComponent("catalog.pub"))
        #expect(pub.count == 32)
        let digest = SHA256.hash(data: pub).map { String(format: "%02x", $0) }.joined()
        let shipped = try #require(RaveCatalogClient.catalogKeyFingerprint(
            searching: [keys.appendingPathComponent("catalog.fingerprint")]))
        #expect(shipped == digest)
    }

    @Test("the fingerprint is found beside catalog.pub in the shipped app layout, not via Bundle.module")
    func fingerprintFoundInShippedLayout() throws {
        let built = Bundle(for: BundleToken.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("MacCrab_MacCrabApp.bundle/catalog.fingerprint")
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("rave-key-layout-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let app = root.appendingPathComponent("MacCrab.app", isDirectory: true)
        let resourceBundle = app.appendingPathComponent(
            "Contents/Resources/MacCrab_MacCrabApp.bundle", isDirectory: true)
        try FileManager.default.createDirectory(at: resourceBundle, withIntermediateDirectories: true)
        let plist: [String: Any] = [
            "CFBundleIdentifier": "com.maccrab.test.\(UUID().uuidString)",
            "CFBundlePackageType": "APPL",
        ]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: app.appendingPathComponent("Contents/Info.plist"))
        try FileManager.default.copyItem(at: built, to: resourceBundle.appendingPathComponent("catalog.fingerprint"))

        let appBundle = try #require(Bundle(url: app))
        let candidates = RaveCatalogClient.bundledKeyFileURLs(name: "catalog", ext: "fingerprint", in: appBundle)
        let found = try #require(RaveCatalogClient.catalogKeyFingerprint(searching: candidates))
        #expect(found == RaveCatalogClient.catalogKeyFingerprint(searching: [built]))
        #expect(found.count == 64)

        // The key and its fingerprint are looked up through the same list.
        let keyDirs = RaveCatalogClient.bundledKeyFileURLs(name: "catalog", ext: "pub", in: appBundle)
            .map { $0.deletingLastPathComponent().resolvingSymlinksInPath().path }
        let fingerprintDirs = candidates.map { $0.deletingLastPathComponent().resolvingSymlinksInPath().path }
        #expect(keyDirs.contains(resourceBundle.resolvingSymlinksInPath().path))
        #expect(fingerprintDirs.contains(resourceBundle.resolvingSymlinksInPath().path))
    }

    @Test("a fingerprint file is read only when it holds exactly 64 hex characters")
    func fingerprintValidation() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("rave-key-fp-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        func file(_ name: String, _ text: String) throws -> URL {
            let url = dir.appendingPathComponent(name)
            try text.write(to: url, atomically: true, encoding: .utf8)
            return url
        }
        let good = String(repeating: "ab", count: 32)
        let short = try file("short", String(good.dropLast()))
        let notHex = try file("nothex", String(good.dropLast()) + "g")
        let fullwidth = try file("fullwidth", String(good.dropLast()) + "\u{FF11}")
        let empty = try file("empty", "")
        let missing = dir.appendingPathComponent("missing")
        let padded = try file("padded", "  \(good.uppercased())\n")

        #expect(RaveCatalogClient.catalogKeyFingerprint(
            searching: [missing, short, notHex, fullwidth, empty]) == nil)
        #expect(RaveCatalogClient.catalogKeyFingerprint(
            searching: [missing, short, notHex, padded]) == good)
    }
}
