// The plugin catalog shows what the signed catalog says about each plugin.
//
// parseCatalog decodes the index's optional fields without failing on an older
// or newer index, and an entry without a status is never offered. The store
// names and describes a catalog entry with its signed display_name and
// short_description instead of MacCrab's local name table, and search covers
// the signed description. Built-in rows keep their local names.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabForensics

@Suite("Rave catalog: signed names, descriptions and status")
struct RaveStoreListingTests {

    static let pin = String(repeating: "ab", count: 32)

    static func entry(
        id: String,
        displayName: String,
        shortDescription: String? = nil,
        category: String? = "system",
        tags: [String] = []
    ) -> RaveCatalogEntry {
        RaveCatalogEntry(
            id: id,
            displayName: displayName,
            shortDescription: shortDescription,
            currentVersion: "1.0.0",
            channel: "official",
            trustTier: "first-party",
            signerIdentity: "maccrab-rave:first-party",
            signerPublicKeySHA256: pin,
            status: "active",
            category: category,
            tags: tags,
            minMaccrabVersion: nil
        )
    }

    // MARK: - Decoding

    @Test("parseCatalog decodes short_description, kind, privacy_class, requires_encrypted_scan and runtime")
    func decodesOptionalFields() throws {
        let json = """
        {"plugins": {"com.maccrab.forensics.agent-exposure": {
          "id": "com.maccrab.forensics.agent-exposure",
          "display_name": "Agent Exposure",
          "short_description": "Review configured agent components, declared permissions and gaps in local source coverage.",
          "current_version": "0.1.0", "channel": "official", "runtime": "tierB",
          "trust_tier": "first-party", "signer_identity": "maccrab-rave:first-party",
          "signer_public_key_sha256": "\(Self.pin)",
          "kind": "collector", "privacy_class": "content", "requires_encrypted_scan": true,
          "status": "active",
          "metadata": {"category": "system", "tags": ["agents"], "min_maccrab_version": "1.22.3"}
        }}}
        """
        let e = try #require(RaveCatalogClient.parseCatalog(data: Data(json.utf8)).first)
        #expect(e.displayName == "Agent Exposure")
        #expect(e.shortDescription
                == "Review configured agent components, declared permissions and gaps in local source coverage.")
        #expect(e.kind == "collector")
        #expect(e.privacyClass == "content")
        #expect(e.requiresEncryptedScan == true)
        #expect(e.runtime == "tierB")
        #expect(e.status == "active")
        #expect(e.category == "system")
        #expect(e.minMaccrabVersion == "1.22.3")
    }

    @Test("an older index without the optional fields, or a newer one with unknown fields, still parses")
    func optionalFieldsMayBeAbsentOrUnexpected() throws {
        let json = """
        {"plugins": {
          "com.example.old": {"display_name": "Old", "current_version": "1.0.0", "status": "active"},
          "com.example.new": {"display_name": "New", "current_version": "2.0.0", "status": "active",
                              "requires_encrypted_scan": "yes", "kind": 7, "icon_sha256": "ff",
                              "screenshots": ["a.png"]}
        }}
        """
        let byID = Dictionary(uniqueKeysWithValues:
            try RaveCatalogClient.parseCatalog(data: Data(json.utf8)).map { ($0.id, $0) })
        let old = try #require(byID["com.example.old"])
        #expect(old.shortDescription == nil)
        #expect(old.kind == nil)
        #expect(old.privacyClass == nil)
        #expect(old.requiresEncryptedScan == nil)
        #expect(old.runtime == nil)
        let new = try #require(byID["com.example.new"])
        #expect(new.requiresEncryptedScan == nil)
        #expect(new.kind == nil)
        #expect(new.currentVersion == "2.0.0")
    }

    // MARK: - Missing status

    @Test("an entry without a status decodes to an empty status and no install path offers it")
    func missingStatusIsNotOffered() throws {
        // Pinned, first-party, official, floor passes: everything but status.
        let json = """
        {"plugins": {"com.example.no-status": {
          "display_name": "No Status", "current_version": "1.0.0", "channel": "official",
          "trust_tier": "first-party", "signer_identity": "maccrab-rave:first-party",
          "signer_public_key_sha256": "\(Self.pin)"
        }}}
        """
        let e = try #require(RaveCatalogClient.parseCatalog(data: Data(json.utf8)).first)
        #expect(e.status == "")
        // Not listed in the store or counted for the Forensics scans update button.
        #expect(RaveCatalogClient.offeredEntries([e]).isEmpty)
        // And the shared install gate behind the store pill, the scans update
        // button and maccrab:// links (RaveInstallConsentResolver) refuses it.
        let st = RaveCatalogEntryState.compute(entry: e, revocations: nil, floorCheck: { _ in })
        #expect(st.installability == .notOffered)
        #expect(!st.showsInstallPill)
        #expect(st.disabledReason?.isEmpty == false)
    }

    // MARK: - Names

    @Test("a catalog entry is named by its signed display_name, not the local name table")
    func signedNameWinsForCatalogEntries() {
        let id = "com.maccrab.forensics.clickfix-review"
        let e = Self.entry(id: id, displayName: "Suspicious Download Review")
        // The local table would derive a different name from the id.
        #expect(ScannerDisplay.name(forPluginID: id) != "Suspicious Download Review")
        #expect(RaveStoreListing.name(e, isBuiltin: false) == "Suspicious Download Review")
        // The search and sort key is the same signed name.
        #expect(RaveStoreListing.matches(e, query: "suspicious", isBuiltin: false))
    }

    @Test("a blank display_name falls back to the plugin id")
    func blankNameFallsBackToID() {
        let e = Self.entry(id: "com.example.blank", displayName: "  ")
        #expect(RaveStoreListing.name(e, isBuiltin: false) == "com.example.blank")
    }

    @Test("a built-in row keeps MacCrab's local name and description")
    func builtinKeepsLocalName() {
        let id = "com.maccrab.forensics.tcc-lite"
        let e = Self.entry(id: id, displayName: "TCC Lite", shortDescription: "A catalog sentence.")
        #expect(RaveStoreListing.name(e, isBuiltin: true) == ScannerDisplay.name(forPluginID: id))
        #expect(RaveStoreListing.name(e, isBuiltin: true) != "TCC Lite")
        #expect(RaveStoreListing.signedDescription(e, isBuiltin: true) == nil)
    }

    // MARK: - What it does

    @Test("What it does is the signed short_description, when the entry has one")
    func whatItDoesUsesSignedDescription() {
        let summary = "Review configured agent components, declared permissions and gaps in local source coverage."
        let e = Self.entry(id: "com.maccrab.forensics.agent-exposure", displayName: "Agent Exposure",
                           shortDescription: "  \(summary)\n")
        #expect(RaveStoreListing.signedDescription(e, isBuiltin: false) == summary)
        let none = Self.entry(id: "com.example.none", displayName: "None")
        #expect(RaveStoreListing.signedDescription(none, isBuiltin: false) == nil)
        let blank = Self.entry(id: "com.example.blank", displayName: "Blank", shortDescription: " ")
        #expect(RaveStoreListing.signedDescription(blank, isBuiltin: false) == nil)
    }

    // MARK: - Search

    @Test("search finds a word that appears only in the signed short_description")
    func searchCoversShortDescription() {
        let e = Self.entry(
            id: "com.maccrab.forensics.agent-exposure", displayName: "Agent Exposure",
            shortDescription: "Review configured agent components, declared permissions and gaps in local source coverage.",
            tags: ["agents", "mcp"])
        // "permissions" is in neither the name, the id, the category nor the tags.
        #expect(RaveStoreListing.matches(e, query: "permissions", isBuiltin: false))
        #expect(RaveStoreListing.matches(e, query: "  PERMISSIONS ", isBuiltin: false))
        #expect(!RaveStoreListing.matches(e, query: "keychain", isBuiltin: false))
        #expect(RaveStoreListing.matches(e, query: "", isBuiltin: false))
        // Without the description the word is not found, so the hit came from it.
        var bare = e
        bare.shortDescription = nil
        #expect(!RaveStoreListing.matches(bare, query: "permissions", isBuiltin: false))
    }
}
