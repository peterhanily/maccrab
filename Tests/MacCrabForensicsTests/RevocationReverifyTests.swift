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
        let stale = RaveRevocationFreshness.stale(age: 8 * 24 * 3600)
        #expect(RevocationReverify.staleAction(freshness: stale, provenance: .thirdParty) == .quarantine(age: 8 * 24 * 3600))
        #expect(RevocationReverify.staleAction(freshness: stale, provenance: .store) == .warn(age: 8 * 24 * 3600))
        #expect(RevocationReverify.staleAction(freshness: stale, provenance: .builtIn) == .ok)
    }

    @Test("never-fetched is treated as stale (third-party quarantines, store warns)")
    func neverFetched() {
        #expect(RevocationReverify.staleAction(freshness: .never, provenance: .thirdParty) == .quarantine(age: nil))
        #expect(RevocationReverify.staleAction(freshness: .never, provenance: .store) == .warn(age: nil))
        #expect(RevocationReverify.staleAction(freshness: .never, provenance: .builtIn) == .ok)
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
            freshness: .stale(age: 8 * 24 * 3600), now: Date(timeIntervalSince1970: 1_750_000_000))
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
        let recs = RevocationReverify.runtimeQuarantine(
            installed: installed, against: list, freshness: .never)
        #expect(recs.count == 1)
        #expect(recs.first?.code == "MALWARE")
    }
}
