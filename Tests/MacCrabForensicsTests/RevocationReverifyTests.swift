// RevocationReverifyTests — the RUNTIME revocation policy that closes the
// install-once-box gap: a plugin revoked AFTER install, or a box offline past the
// staleness ceiling, must not keep silently running an untrusted plugin.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RevocationReverify (runtime staleness escalation)")
struct RevocationReverifyTests {

    static func ref(_ id: String, _ v: String = "1.0") -> RevocationEnforcer.InstalledRef {
        .init(pluginID: id, version: v)
    }

    static func listRevoking(_ id: String, serial: Int? = 5) -> RaveRevocationList {
        RaveRevocationList(
            formatVersion: "1", serial: serial, updatedAt: nil,
            revocations: [RaveRevocation(
                pluginID: id, scope: .allVersions, reason: "bad", code: "MALWARE",
                decidedAt: "2026-01-01T00:00:00Z", decidedBy: ["maintainer"])])
    }

    // MARK: - staleAction

    @Test("fresh data → ok for every trust class")
    func freshOk() {
        let fresh = RaveRevocationFreshness.fresh(age: 100)
        for p in PluginProvenance.allCases {
            #expect(RevocationReverify.staleAction(freshness: fresh, provenance: p) == .ok)
        }
    }

    @Test("stale data fails-closed by trust class: third-party quarantines, store warns, built-in unaffected")
    func staleByClass() {
        let stale = RaveRevocationFreshness.stale(age: 8.0 * 24 * 3600)
        #expect(RevocationReverify.staleAction(freshness: stale, provenance: .thirdParty) == .quarantine(age: 8.0 * 24 * 3600))
        #expect(RevocationReverify.staleAction(freshness: stale, provenance: .store) == .warn(age: 8.0 * 24 * 3600))
        #expect(RevocationReverify.staleAction(freshness: stale, provenance: .builtIn) == .ok)
    }

    @Test("A1-02: a STORE plugin stale past the HARD ceiling escalates warn → quarantine")
    func storeHardCeiling() {
        let ceiling = RevocationReverify.storeRevocationHardCeiling
        // Within the grace window (just under the hard ceiling) a store plugin
        // still only WARNS — the catalog vetting chain vouches for it.
        #expect(RevocationReverify.staleAction(freshness: .stale(age: ceiling - 1), provenance: .store)
                == .warn(age: ceiling - 1))
        // Past the hard ceiling a withheld/blocked signed list must not buy the
        // store plugin unbounded runtime: it fail-closes to quarantine.
        #expect(RevocationReverify.staleAction(freshness: .stale(age: ceiling + 1), provenance: .store)
                == .quarantine(age: ceiling + 1))
        // Built-in remains unaffected regardless of how stale the feed is.
        #expect(RevocationReverify.staleAction(freshness: .stale(age: ceiling + 1), provenance: .builtIn) == .ok)
    }

    @Test("A1-02 sweep: a store plugin stale past the hard ceiling is quarantined (REVOCATION_STALE)")
    func sweepStoreHardCeiling() {
        // No explicit revocation for this id — only the hard-ceiling staleness
        // escalation should fire, and it must catch the STORE plugin now.
        let installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = [
            (Self.ref("com.x.store"), .store),
        ]
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: Self.listRevoking("com.unrelated"),
            freshness: .stale(age: RevocationReverify.storeRevocationHardCeiling + 3600))
        #expect(recs.map { $0.pluginID } == ["com.x.store"])
        #expect(recs.first?.code == "REVOCATION_STALE")
    }

    @Test("A1-02: a store plugin stale WITHIN the hard-ceiling grace window is not quarantined by the sweep")
    func sweepStoreWithinGrace() {
        let installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = [
            (Self.ref("com.x.store"), .store),
        ]
        // 8 days stale: past the 7-day freshness ceiling (so `.stale`) but well
        // within the 30-day hard ceiling → warn only, not quarantined.
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: Self.listRevoking("com.unrelated"),
            freshness: .stale(age: 8.0 * 24 * 3600))
        #expect(recs.isEmpty)
    }

    @Test("never-fetched does NOT fail-close a sideload (no revocation authority yet — audit #6); it only warns")
    func neverFetched() {
        // `.never` = the signed revocation feed has never verified here (the
        // reality until the rave server ships). It must NOT quarantine an
        // operator-TOFU'd sideload — that would make every offline box unable to
        // run its own sideloaded plugin. Only genuine `.stale` escalates (above).
        #expect(RevocationReverify.staleAction(freshness: .never, provenance: .thirdParty) == .warn(age: nil))
        #expect(RevocationReverify.staleAction(freshness: .never, provenance: .store) == .warn(age: nil))
        #expect(RevocationReverify.staleAction(freshness: .never, provenance: .builtIn) == .ok)
    }

    @Test("sweep: a never-fetched-feed box does NOT quarantine an un-revoked third-party sideload (audit #6)")
    func sweepNeverFetchedRunsSideload() {
        // No explicit revocation + never-fetched feed → the operator's sideload
        // runs (contained), instead of being instantly quarantined offline.
        let installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = [
            (Self.ref("com.x.sideload"), .thirdParty),
        ]
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: Self.listRevoking("com.other"), freshness: .never)
        #expect(recs.isEmpty)
    }

    // MARK: - runtimeQuarantine sweep

    @Test("sweep unions explicit revocations with stale-escalated third-party; store/built-in not quarantined")
    func sweepStale() {
        let list = Self.listRevoking("com.x.revoked")
        let installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = [
            (Self.ref("com.x.revoked"), .thirdParty),   // explicit revocation
            (Self.ref("com.x.sideload"), .thirdParty),  // stale-escalated
            (Self.ref("com.x.store"), .store),          // warn only → not quarantined
            (Self.ref("com.x.builtin"), .builtIn),      // unaffected
        ]
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: list,
            freshness: .stale(age: 8.0 * 24 * 3600), now: Date(timeIntervalSince1970: 1_750_000_000))
        let byID = Dictionary(uniqueKeysWithValues: recs.map { ($0.pluginID, $0) })
        #expect(Set(byID.keys) == ["com.x.revoked", "com.x.sideload"])
        // explicit revocation keeps the list's reason/code, NOT the stale code
        #expect(byID["com.x.revoked"]?.code == "MALWARE")
        #expect(byID["com.x.sideload"]?.code == "REVOCATION_STALE")
    }

    @Test("fresh data → only explicit revocations quarantined, no stale escalation")
    func sweepFresh() {
        let list = Self.listRevoking("com.x.revoked")
        let installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = [
            (Self.ref("com.x.revoked"), .thirdParty),
            (Self.ref("com.x.sideload"), .thirdParty),
        ]
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: list, freshness: .fresh(age: 60))
        #expect(recs.map { $0.pluginID } == ["com.x.revoked"])
    }

    @Test("a plugin both revoked AND third-party-stale is listed once (explicit wins)")
    func noDoubleList() {
        let list = Self.listRevoking("com.x.revoked")
        let installed: [(ref: RevocationEnforcer.InstalledRef, provenance: PluginProvenance)] = [
            (Self.ref("com.x.revoked"), .thirdParty),
        ]
        // `.stale` (not `.never`) so the stale escalation genuinely fires and the
        // dedup against the explicit revocation is exercised.
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: list, freshness: .stale(age: 8.0 * 24 * 3600))
        #expect(recs.count == 1)
        #expect(recs.first?.code == "MALWARE")
    }
}
