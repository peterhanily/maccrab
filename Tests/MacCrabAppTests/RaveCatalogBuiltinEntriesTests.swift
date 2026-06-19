// Built-in store rows — the synthesized first-party RaveCatalogEntry rows that
// let the store browse + "Run on this Mac" the built-in scanners while the
// signed third-party catalog is still coming soon. Pins the honesty invariants:
// only runnable (collector/analyzer) types, first-party, NO signer pin, and a
// state that never offers an Install pill (Run only).

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabForensics

@Suite("RaveCatalogClient.builtinEntries — built-in store rows (honesty)")
struct RaveCatalogBuiltinEntriesTests {

    private func builtinEntry(_ id: String) -> RaveCatalogEntry {
        RaveCatalogEntry(
            id: id, displayName: "Test", currentVersion: "1.0.0",
            channel: "official", trustTier: "first-party",
            signerIdentity: "MacCrab (built-in)", signerPublicKeySHA256: "",
            status: "active", category: "collector", tags: [], minMaccrabVersion: nil)
    }

    @Test("synthesizes first-party, no-signer-pin rows, only for runnable types")
    func synthesisFromRegistry() async {
        try? await MacCrabForensicsBootstrap.registerBuiltins()
        let manifests = await PluginRegistry.shared.manifests()
        let rows = RaveCatalogClient.builtinEntries(from: manifests, displayName: { $0 })
        #expect(!rows.isEmpty)  // there ARE built-in collectors/analyzers registered
        for r in rows {
            #expect(r.trustTier == "first-party")
            #expect(r.signerPublicKeySHA256.isEmpty)                    // never pinned
            #expect(r.status == "active")
            #expect(r.category == "collector" || r.category == "analyzer")  // runnable only
        }
        // No non-runnable (enricher/fingerprinter) manifest leaked into the rows.
        let synth = Set(rows.map(\.id))
        let nonRunnable = manifests.filter { $0.type != .collector && $0.type != .analyzer }.map(\.id)
        for id in nonRunnable { #expect(!synth.contains(id)) }
        // Every synthesized id is in the runnable set by construction.
        let runnable = Set(manifests.filter { $0.type == .collector || $0.type == .analyzer }.map(\.id))
        #expect(synth == runnable)
    }

    @Test("built-in state shows NO install pill + an honest caption")
    func builtinStateNoPill() {
        let st = RaveCatalogEntryState(entry: builtinEntry("com.maccrab.forensics.tcc-lite"),
                                       installability: .builtInLocal,
                                       isRevoked: false, revocationReason: nil)
        #expect(st.showsInstallPill == false)
        #expect(st.disabledReason?.contains("Built-in") == true)
    }

    @Test("mergedDisplayEntries de-dups on id, built-in wins, offered untouched")
    func mergedDisplayDedup() {
        let builtin = builtinEntry("com.maccrab.forensics.tcc-lite")
        // An offered catalog entry sharing the built-in id + a distinct one.
        let offeredSameID = RaveCatalogEntry(
            id: "com.maccrab.forensics.tcc-lite", displayName: "Catalog tcc",
            currentVersion: "9.9.9", channel: "official", trustTier: "first-party",
            signerIdentity: "x", signerPublicKeySHA256: String(repeating: "a", count: 64),
            status: "active", category: "collector", tags: [], minMaccrabVersion: nil)
        let offeredDistinct = RaveCatalogEntry(
            id: "com.acme.thirdparty.foo", displayName: "Foo",
            currentVersion: "1.0.0", channel: "contrib", trustTier: "verified-community",
            signerIdentity: "acme", signerPublicKeySHA256: String(repeating: "b", count: 64),
            status: "active", category: "collector", tags: [], minMaccrabVersion: nil)
        let merged = RaveCatalogClient.mergedDisplayEntries(
            builtins: [builtin], offered: [offeredSameID, offeredDistinct])
        // The shared id appears exactly once...
        #expect(merged.filter { $0.id == "com.maccrab.forensics.tcc-lite" }.count == 1)
        // ...and it's the BUILT-IN row (empty signer pin), not the catalog one.
        #expect(merged.first { $0.id == "com.maccrab.forensics.tcc-lite" }?.signerPublicKeySHA256.isEmpty == true)
        // The distinct offered entry still shows.
        #expect(merged.contains { $0.id == "com.acme.thirdparty.foo" })
        #expect(merged.count == 2)
    }

    @Test("a built-in-shaped row never computes to .installable (no signer pin → fail-closed)")
    func builtinNeverInstallable() {
        // Even if a built-in row accidentally reached compute(), the empty signer
        // pin fail-closes to awaitingSignedBinary — never .installable.
        let st = RaveCatalogEntryState.compute(
            entry: builtinEntry("com.maccrab.forensics.tcc-lite"),
            revocations: nil, firstPartyDisplayNames: [], floorCheck: { _ in })
        #expect(st.installability == .awaitingSignedBinary)
        #expect(st.showsInstallPill == false)
    }
}
