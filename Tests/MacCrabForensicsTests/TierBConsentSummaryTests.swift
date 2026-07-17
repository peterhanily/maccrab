// TierBConsentSummaryTests — the consent disclosure DERIVED from the enforced
// caps (not the author's declared label), so a plugin can't claim "metadata"
// while it reads chat.db.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("TierBManifest consent summary (derived from enforced caps)")
struct TierBConsentSummaryTests {

    static func manifest(reads: [String] = [], network: [String] = [], declared: String? = nil) -> TierBManifest {
        TierBManifest(id: "com.x.p", displayName: "P", version: "1.0", schemaVersion: 1, description: "d",
                      fileReadSubpaths: reads, networkConnectAllowlist: network, privacyClass: declared)
    }

    @Test("no reads → metadata; not underdeclared")
    func metadataOnly() {
        let s = Self.manifest().consentSummary(home: "/Users/x")
        #expect(s.derivedHighestPrivacy == "metadata")
        #expect(!s.readsPersonalComms)
        #expect(!s.privacyUnderdeclared)
    }

    @Test("reading chat.db → derived personalComms + TCC read flagged")
    func tccRead() {
        let s = Self.manifest(reads: ["/Users/x/Library/Messages/chat.db"]).consentSummary(home: "/Users/x")
        #expect(s.derivedHighestPrivacy == "personalComms")
        #expect(s.readsPersonalComms)
        #expect(s.tccReads == ["/Users/x/Library/Messages/chat.db"])
    }

    @Test("MEDIUM: reading ~/.ssh/id_rsa is consent-gated like chat.db (flagged as a TCC read)")
    func credentialReadConsentGated() {
        // A credential store read must surface in the consent sheet with the same
        // high-friction personalComms class as chat.db — not slip through as an
        // undisclosed direct read.
        let s = Self.manifest(reads: ["/Users/x/.ssh/id_rsa"]).consentSummary(home: "/Users/x")
        #expect(s.derivedHighestPrivacy == "personalComms")
        #expect(s.readsPersonalComms)
        #expect(s.tccReads == ["/Users/x/.ssh/id_rsa"])
        // Declaring a lower class while reading credentials is flagged as under-declared.
        let under = Self.manifest(reads: ["/Users/x/.aws/credentials"], declared: "metadata").consentSummary(home: "/Users/x")
        #expect(under.privacyUnderdeclared)
        #expect(under.readsPersonalComms)
    }

    @Test("declaring 'metadata' while reading chat.db is flagged as UNDER-declared")
    func underdeclared() {
        let s = Self.manifest(reads: ["/Users/x/Library/Messages/chat.db"], declared: "metadata").consentSummary(home: "/Users/x")
        #expect(s.privacyUnderdeclared)
        #expect(s.derivedHighestPrivacy == "personalComms")  // UI shows the derived, not the claimed
    }

    @Test("A1-06: a live-served ~/Library read (Preferences) is elevated above generic 'content'")
    func liveHomeLibraryElevated() {
        // ~/Library/Preferences is served LIVE with host FDA — more sensitive than
        // generic file content, so the derived class is elevated (not "content").
        let s = Self.manifest(reads: ["/Users/x/Library/Preferences/com.example.plist"]).consentSummary(home: "/Users/x")
        #expect(s.derivedHighestPrivacy == "personalComms")
        // A plain, non-Library file read still classifies as generic content.
        let plain = Self.manifest(reads: ["/Users/x/Documents/notes.txt"]).consentSummary(home: "/Users/x")
        #expect(plain.derivedHighestPrivacy == "content")
    }

    @Test("personal-comms read + network = disclosed exfil surface (high friction)")
    func exfilSurface() {
        let s = Self.manifest(reads: ["/Users/x/Library/Messages/chat.db"], network: ["1.2.3.4:443"]).consentSummary(home: "/Users/x")
        #expect(s.isDisclosedExfilSurface)
        #expect(s.hasNetwork)
    }

    @Test("the new consent fields round-trip through the signed manifest JSON")
    func decodeRoundTrip() throws {
        let json = #"""
        {"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d",
         "fileReadSubpaths":["/Users/x/Library/Mail"],"privacyClass":"personalComms",
         "dataSources":["Apple Mail"],"tccRequirements":["FullDiskAccess"]}
        """#
        let m = try JSONDecoder().decode(TierBManifest.self, from: Data(json.utf8))
        #expect(m.privacyClass == "personalComms")
        #expect(m.dataSources == ["Apple Mail"])
        #expect(m.tccRequirements == ["FullDiskAccess"])
    }
}
