// RevocationEnforcer + quarantine reconciliation tests (O2, S2-03/04).
//
// Covers the pure decision layer:
//   - install refusal across single / range / all scopes
//   - install allowed when not revoked
//   - quarantine reconciliation marks every installed plugin the list revokes
//   - un-quarantine when a version escapes the scope or the id leaves the list
//   - the quarantine record carries the in-effect revocations serial

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RevocationEnforcer (O2 install + quarantine)")
struct RevocationEnforcerTests {

    static func list(serial: Int? = 5, _ revocations: [RaveRevocation]) -> RaveRevocationList {
        RaveRevocationList(
            formatVersion: "0", serial: serial, updatedAt: "x", revocations: revocations
        )
    }

    static func rev(
        id: String,
        scope: RaveRevocationScope,
        code: String = "compromise",
        reason: String = "exfiltrated"
    ) -> RaveRevocation {
        RaveRevocation(
            pluginID: id, scope: scope, reason: reason, code: code,
            decidedAt: "x", decidedBy: ["peterhanily"]
        )
    }

    // MARK: - Install-time

    @Test("install refused on single_version match")
    func installRefusedSingle() {
        let l = Self.list([Self.rev(id: "com.a.one", scope: .singleVersion("1.0.0"))])
        let d = RevocationEnforcer.evaluateInstall(pluginID: "com.a.one", version: "1.0.0", against: l)
        guard case .refused(let hit) = d else { Issue.record("expected refused"); return }
        #expect(hit.code == "compromise")
    }

    @Test("install allowed for a different version under single_version")
    func installAllowedDifferentVersion() {
        let l = Self.list([Self.rev(id: "com.a.one", scope: .singleVersion("1.0.0"))])
        #expect(RevocationEnforcer.evaluateInstall(pluginID: "com.a.one", version: "1.0.1", against: l) == .allowed)
    }

    @Test("install refused inside version_range, allowed outside")
    func installRange() {
        let l = Self.list([Self.rev(id: "com.a.one", scope: .versionRange(from: "1.0.0", to: "1.2.0"))])
        if case .refused = RevocationEnforcer.evaluateInstall(pluginID: "com.a.one", version: "1.1.0", against: l) {} else {
            Issue.record("expected refused inside range")
        }
        #expect(RevocationEnforcer.evaluateInstall(pluginID: "com.a.one", version: "1.3.0", against: l) == .allowed)
    }

    @Test("install refused for any version under all_versions")
    func installAll() {
        let l = Self.list([Self.rev(id: "com.a.one", scope: .allVersions)])
        if case .refused = RevocationEnforcer.evaluateInstall(pluginID: "com.a.one", version: "9.9.9", against: l) {} else {
            Issue.record("expected refused under all_versions")
        }
    }

    @Test("install allowed when id not in the list")
    func installAllowedUnlisted() {
        let l = Self.list([Self.rev(id: "com.a.one", scope: .allVersions)])
        #expect(RevocationEnforcer.evaluateInstall(pluginID: "com.b.two", version: "1.0.0", against: l) == .allowed)
    }

    // MARK: - Runtime quarantine reconciliation

    @Test("reconcile quarantines every installed plugin the list revokes")
    func reconcileMarksRevoked() {
        let installed = [
            RevocationEnforcer.InstalledRef(pluginID: "com.a.one", version: "1.0.0"),
            RevocationEnforcer.InstalledRef(pluginID: "com.b.two", version: "2.0.0"),
            RevocationEnforcer.InstalledRef(pluginID: "com.c.three", version: "3.0.0"),
        ]
        let l = Self.list(serial: 9, [
            Self.rev(id: "com.a.one", scope: .singleVersion("1.0.0")),
            Self.rev(id: "com.c.three", scope: .allVersions),
        ])
        let records = RevocationEnforcer.reconcileQuarantine(installed: installed, against: l)
        let ids = Set(records.map { $0.pluginID })
        #expect(ids == ["com.a.one", "com.c.three"])
        // com.b.two is NOT revoked → not quarantined.
        #expect(!ids.contains("com.b.two"))
        // The record carries the in-effect serial.
        #expect(records.allSatisfy { $0.revocationsSerial == 9 })
    }

    @Test("a version that escapes the range is not quarantined (un-quarantine)")
    func reconcileEscapedVersion() {
        // Installed at 1.3.0; range only revokes [1.0.0, 1.2.0].
        let installed = [RevocationEnforcer.InstalledRef(pluginID: "com.a.one", version: "1.3.0")]
        let l = Self.list([Self.rev(id: "com.a.one", scope: .versionRange(from: "1.0.0", to: "1.2.0"))])
        let records = RevocationEnforcer.reconcileQuarantine(installed: installed, against: l)
        #expect(records.isEmpty)
    }

    @Test("an empty list reconciles to no quarantine (un-quarantine all)")
    func reconcileEmptyList() {
        let installed = [RevocationEnforcer.InstalledRef(pluginID: "com.a.one", version: "1.0.0")]
        let l = Self.list([])
        #expect(RevocationEnforcer.reconcileQuarantine(installed: installed, against: l).isEmpty)
    }

    @Test("quarantine record carries reason + code + advisory from the matching entry")
    func reconcileRecordFields() {
        let installed = [RevocationEnforcer.InstalledRef(pluginID: "com.a.one", version: "1.0.0")]
        let entry = RaveRevocation(
            pluginID: "com.a.one", scope: .allVersions,
            reason: "supply-chain incident", code: "supply_chain_incident",
            advisoryURL: "https://example.com/advisory",
            decidedAt: "x", decidedBy: ["peterhanily"]
        )
        let records = RevocationEnforcer.reconcileQuarantine(installed: installed, against: Self.list([entry]))
        #expect(records.count == 1)
        #expect(records[0].reason == "supply-chain incident")
        #expect(records[0].code == "supply_chain_incident")
        #expect(records[0].advisoryURL == "https://example.com/advisory")
        #expect(records[0].installedVersion == "1.0.0")
    }
}
