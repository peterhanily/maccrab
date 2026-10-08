// RaveInstallConsentSheetTests.swift
// MacCrabAppTests
//
// The install consent sheet tells the person consenting what they are
// installing and how it will run. These pin the title choice (only a
// maccrab:// link says "Install from MacCrab link"), the "How this plugin
// runs" text (chosen by the runtime's first-party key rule, not the catalog's
// trust tier), the signed short_description decode, and the catalog key
// fingerprint (the key that verified the catalog).

import CryptoKit
import Foundation
import Testing
import MacCrabForensics
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

    @Test("a fresh install from the store is titled Install plugin")
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
        let parts = RaveInstallConsentSheet.runDisclosures(runsInFirstPartyLane: true)
        #expect(parts.first == .firstParty)
        let firstParty = parts.firstIndex(of: .firstParty)
        let thirdParty = parts.firstIndex(of: .thirdParty)
        if let firstParty, let thirdParty {
            #expect(firstParty < thirdParty)
        }
    }

    @Test("a third-party plugin gets the sandbox text and never the first-party line")
    func thirdPartyGetsSandboxTextOnly() {
        let parts = RaveInstallConsentSheet.runDisclosures(runsInFirstPartyLane: false)
        #expect(parts == [.thirdParty])
        #expect(!parts.contains(.firstParty))
    }

    static func entry(trustTier: String, signer: String) -> RaveCatalogEntry {
        RaveCatalogEntry(
            id: "com.maccrab.forensics.agent-exposure", displayName: "Agent Exposure",
            currentVersion: "1.0.0", channel: "official", trustTier: trustTier,
            signerIdentity: "maccrab-rave:first-party", signerPublicKeySHA256: signer,
            status: "active", category: "collector", tags: [], minMaccrabVersion: nil)
    }

    static func disclosures(_ e: RaveCatalogEntry, official: Bool = true, override: Bool = false) -> [RaveInstallConsentSheet.RunDisclosure] {
        RaveInstallConsentSheet.runDisclosures(
            runsInFirstPartyLane: RaveInstallConsentResolver.runsInFirstPartyLane(
                e, officialSource: official, catalogOverrideActive: override))
    }

    @Test("a first-party trust tier with a key that is not the first-party anchor gets the sandbox text")
    func firstPartyTierWithOtherKeyIsSandboxed() {
        let other = String(repeating: "ab", count: 32)
        #expect(other != FirstPartyTrustRoot.publisherKeyFingerprint)
        #expect(Self.disclosures(Self.entry(trustTier: "first-party", signer: other)) == [.thirdParty])
        #expect(Self.disclosures(Self.entry(trustTier: "first-party", signer: "")) == [.thirdParty])
    }

    @Test("the first-party anchor key on the official source gets the first-party line")
    func anchorKeyOnOfficialSourceRunsFirstParty() {
        let anchor = FirstPartyTrustRoot.publisherKeyFingerprint
        #expect(Self.disclosures(Self.entry(trustTier: "first-party", signer: anchor)) == [.firstParty])
        #expect(Self.disclosures(Self.entry(trustTier: "first-party", signer: anchor.uppercased())) == [.firstParty])
    }

    @Test("the anchor key runs first-party whatever the tier says, because the runtime ignores the tier")
    func anchorKeyIgnoresTier() {
        let anchor = FirstPartyTrustRoot.publisherKeyFingerprint
        #expect(Self.disclosures(Self.entry(trustTier: "verified-community", signer: anchor)) == [.firstParty])
    }

    @Test("the anchor key from an unofficial source or under a catalog-key override is sandboxed")
    func anchorKeyRefusedOffOfficialSource() {
        let e = Self.entry(trustTier: "first-party", signer: FirstPartyTrustRoot.publisherKeyFingerprint)
        #expect(Self.disclosures(e, official: false) == [.thirdParty])
        #expect(Self.disclosures(e, override: true) == [.thirdParty])
    }

    @Test("the sheet's lane rule matches FirstPartyExecutionGate for the same inputs")
    func laneRuleMatchesRuntimeGate() {
        let anchor = FirstPartyTrustRoot.publisherKeyFingerprint
        for signer in [anchor, String(repeating: "ab", count: 32), "", "not-hex"] {
            for official in [true, false] {
                for override in [true, false] {
                    let runtime = FirstPartyExecutionGate.evaluate(
                        bundleSigningKeyPubSHA256: signer,
                        expectedPublisherFingerprint: anchor,
                        anchorConfigured: FirstPartyTrustRoot.isConfigured,
                        catalogOverrideActive: override,
                        officialSource: official).isAllowed
                    #expect(RaveInstallConsentResolver.runsInFirstPartyLane(
                        Self.entry(trustTier: "first-party", signer: signer),
                        officialSource: official, catalogOverrideActive: override) == runtime)
                }
            }
        }
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
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: pub)
        let shipped = try String(contentsOf: keys.appendingPathComponent("catalog.fingerprint"), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        #expect(RaveCatalogClient.keyFingerprint(key) == shipped)
    }

    @Test("the catalog key row shows the SHA-256 of the key that verified the catalog")
    func catalogKeyFingerprintIsOfTheVerifyingKey() throws {
        // A key other than the bundled one (what a DEBUG override would verify
        // with) must show its own hash, never the bundled fingerprint.
        let key = Curve25519.Signing.PrivateKey().publicKey
        let expected = SHA256.hash(data: key.rawRepresentation).map { String(format: "%02x", $0) }.joined()
        let shown = RaveCatalogClient.keyFingerprint(key)
        #expect(shown == expected)
        #expect(shown.count == 64)
        #expect(shown == shown.lowercased())
        let bundled = try String(
            contentsOf: Self.packageRoot()
                .appendingPathComponent("Sources/MacCrabApp/Resources/rave-keys/catalog.fingerprint"),
            encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        #expect(shown != bundled)
    }

    @Test("a client that has not verified a catalog reports no catalog key")
    func noCatalogKeyBeforeVerification() async {
        let client = RaveCatalogClient()
        #expect(await client.verifiedCatalogKeySHA256 == nil)
    }

    @Test("the catalog key is found in the shipped app layout, not via Bundle.module")
    func catalogKeyFoundInShippedLayout() throws {
        let built = Bundle(for: BundleToken.self).bundleURL.deletingLastPathComponent()
            .appendingPathComponent("MacCrab_MacCrabApp.bundle/catalog.pub")
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
        try FileManager.default.copyItem(at: built, to: resourceBundle.appendingPathComponent("catalog.pub"))

        let appBundle = try #require(Bundle(url: app))
        let candidates = RaveCatalogClient.bundledKeyFileURLs(name: "catalog", ext: "pub", in: appBundle)
        let found = try #require(candidates.first { (try? Data(contentsOf: $0))?.count == 32 })
        #expect(found.deletingLastPathComponent().resolvingSymlinksInPath().path
                == resourceBundle.resolvingSymlinksInPath().path)
        #expect(try Data(contentsOf: found) == Data(contentsOf: built))
    }
}
