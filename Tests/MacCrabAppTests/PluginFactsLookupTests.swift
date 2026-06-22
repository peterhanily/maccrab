// PluginFactsLookup tests — the single source of truth for the rave store's
// per-plugin capability chips (detail panel + consent sheet). Pure: no
// network, no SwiftUI. Locks the data path + the honesty invariants and
// catches drift between ScannerCatalog facts and the display surfaces.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("PluginFactsLookup — store/consent capability chips")
struct PluginFactsLookupTests {

    @Test("A known first-party id returns rich, non-empty facts")
    func knownIDHasFacts() {
        let f = PluginFactsLookup.facts(forPluginID: "com.maccrab.forensics.launchd-lite")
        let facts = try! #require(f)
        #expect(!facts.purpose.isEmpty)
        #expect(!facts.reads.isEmpty)
        #expect(!facts.emits.isEmpty)
    }

    @Test("An unknown / third-party id returns nil (graceful fallback contract)")
    func unknownIDIsNil() {
        #expect(PluginFactsLookup.facts(forPluginID: "com.example.thirdparty.foo") == nil)
    }

    @Test("emits are display-resolved labels, not raw content-type ids")
    func emitsAreLabelled() {
        let f = try! #require(PluginFactsLookup.facts(forPluginID: "com.maccrab.forensics.tcc-lite"))
        // tcc-lite emits "tcc.grant" → "Privacy permission grant".
        #expect(f.emits.contains("Privacy permission grant"))
        #expect(!f.emits.contains("tcc.grant"))
    }

    @Test("Privacy class drives the metadata-only affordance")
    func privacyClassMapped() {
        let meta = try! #require(PluginFactsLookup.facts(forPluginID: "com.maccrab.forensics.launchd-lite"))
        #expect(meta.isMetadataOnly)   // launchd inventory is metadata-only
        let comms = try! #require(PluginFactsLookup.facts(forPluginID: "com.maccrab.forensics.imessage-bodies"))
        #expect(!comms.isMetadataOnly) // message bodies are personal-comms
    }

    @Test("Network/sandbox honesty invariants are present and unchanged")
    func honestyChipsPresent() {
        let f = try! #require(PluginFactsLookup.facts(forPluginID: "com.maccrab.forensics.mail"))
        #expect(f.networkChip == "Network: none (default-deny)")
        #expect(f.sandboxChip == "Not sandboxed")
    }

    @Test("Every catalog-launch-set id resolves to non-nil facts (drift guard)")
    func launchSetCovered() {
        // The 18 first-party catalog entries the store offers. Each must have
        // local facts so the detail panel + consent sheet render real chips —
        // a dropped ScannerCatalog entry would regress to the generic fallback.
        let launchSet = [
            "com.maccrab.forensics.tcc-lite",
            "com.maccrab.forensics.launchd-lite",
            "com.maccrab.forensics.quarantine",
            "com.maccrab.forensics.safari-lite",
            "com.maccrab.forensics.safari-deep",
            "com.maccrab.forensics.mail",
            "com.maccrab.forensics.mail-bodies",
            "com.maccrab.forensics.imessage-metadata",
            "com.maccrab.forensics.imessage-bodies",
            "com.maccrab.forensics.facetime",
            "com.maccrab.forensics.knowledgec",
            "com.maccrab.forensics.biome",
            "com.maccrab.forensics.applescript-runtime",
            "com.maccrab.forensics.posture-analyzer",
            "com.maccrab.forensics.codesigning-graph",
            "com.maccrab.forensics.macho-analyzer",
            "com.maccrab.forensics.dmg-pkg-analyzer",
            "com.maccrab.forensics.plist-analyzer",
        ]
        for id in launchSet {
            #expect(PluginFactsLookup.facts(forPluginID: id) != nil, "missing facts for \(id)")
        }
    }
}
