// RaveCatalogEntryState (S4-X2) install-gating policy tests.
//
// The dashboard un-gated the plugin catalog behind the VERIFIED install path.
// The whole storefront-honesty contract lives in RaveCatalogEntryState.compute:
//   - A live Install pill is ONLY offered for an entry with a real
//     operator-signed binary (publisher-key pin present), whose version floor
//     passes, and which is not revoked.
//   - An official-channel entry with NO publisher-key pin is pre-ceremony — its
//     artifact hash is still a placeholder — so NO pill ("operator-signed
//     binary required").
//   - pre-release entries show status, not a live pill.
//   - version-floor-blocked / revoked entries show their reason, not a pill.
//   - Revocation takes precedence over everything else.
//
// These tests pin that policy down purely (no network, no trust-state side
// effects) by injecting the floor check.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabForensics

@Suite("RaveCatalogEntryState (S4-X2 catalog install gating)")
struct RaveCatalogEntryStateTests {

    /// A valid 64-char lowercase-hex SHA-256 (publisher-key pin).
    static let pin = String(repeating: "ab", count: 32)

    static func entry(
        id: String = "com.maccrab.hosts-collector",
        version: String = "1.0.0",
        channel: String = "official",
        trustTier: String = "first-party",
        signerPin: String = pin,
        status: String = "official",
        minVersion: String? = nil
    ) -> RaveCatalogEntry {
        RaveCatalogEntry(
            id: id,
            currentVersion: version,
            channel: channel,
            trustTier: trustTier,
            signerIdentity: "maccrab-rave:first-party",
            signerPublicKeySHA256: signerPin,
            status: status,
            category: "collector",
            tags: ["dns"],
            minMaccrabVersion: minVersion
        )
    }

    /// A floor check that always passes (the running build satisfies the floor).
    static let floorOK: (RaveCatalogEntry) throws -> Void = { _ in }

    /// A floor check that always refuses with a version-floor reason.
    static let floorBlocked: (RaveCatalogEntry) throws -> Void = { e in
        throw RaveCatalogError.versionFloor(reason: "Refusing to install \(e.id): needs a newer MacCrab.")
    }

    static func revocationList(_ revs: [RaveRevocation]) -> RaveRevocationList {
        RaveRevocationList(formatVersion: "0", serial: 5, updatedAt: "x", revocations: revs)
    }

    static func rev(id: String, scope: RaveRevocationScope, reason: String = "compromised") -> RaveRevocation {
        RaveRevocation(pluginID: id, scope: scope, reason: reason, code: "compromise",
                       decidedAt: "x", decidedBy: ["peterhanily"])
    }

    // MARK: - Installable (the only live-pill case)

    @Test("pinned + floor-pass + not revoked → installable, shows live pill")
    func installable() {
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(), revocations: nil, floorCheck: Self.floorOK
        )
        #expect(st.installability == .installable)
        #expect(st.showsInstallPill)
        #expect(st.isSignerPinned)
        #expect(st.disabledReason == nil)
        #expect(!st.isRevoked)
    }

    // MARK: - Placeholder gate (operator-signed binary required)

    @Test("official entry with NO publisher-key pin → awaiting signed binary, no pill")
    func unpinnedOfficial() {
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(signerPin: ""), revocations: nil, floorCheck: Self.floorOK
        )
        #expect(st.installability == .awaitingSignedBinary)
        #expect(!st.showsInstallPill)
        #expect(!st.isSignerPinned)
        #expect(st.disabledReason?.contains("Operator-signed binary required") == true)
    }

    @Test("a placeholder (non-hex) pin is treated as absent → no pill")
    func placeholderPin() {
        // A pre-ceremony catalog may carry a placeholder like "PENDING" or a
        // string of zeros that isn't a real digest; isSHA256Hex rejects both.
        for placeholder in ["PENDING", "TBD", String(repeating: "0", count: 10), "not-a-hash"] {
            let st = RaveCatalogEntryState.compute(
                entry: Self.entry(signerPin: placeholder), revocations: nil, floorCheck: Self.floorOK
            )
            #expect(st.installability == .awaitingSignedBinary, "placeholder pin \(placeholder) must not be installable")
            #expect(!st.showsInstallPill)
        }
    }

    // MARK: - Pre-release (status, not a live pill)

    @Test("pre-release status → no live pill even if pinned")
    func preRelease() {
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(status: "pre-release"), revocations: nil, floorCheck: Self.floorOK
        )
        #expect(st.installability == .preRelease)
        #expect(!st.showsInstallPill)
        #expect(st.disabledReason?.contains("Pre-release") == true)
    }

    // MARK: - Version floor (fail-closed, reason surfaced)

    @Test("version-floor refusal → blocked, no pill, reason carried")
    func floorBlocked() {
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(minVersion: "9.9.9"), revocations: nil, floorCheck: Self.floorBlocked
        )
        guard case .versionFloorBlocked(let reason) = st.installability else {
            Issue.record("expected versionFloorBlocked"); return
        }
        #expect(reason.contains("newer MacCrab"))
        #expect(!st.showsInstallPill)
    }

    // MARK: - Revocation (highest precedence)

    @Test("revoked entry → no pill, badged revoked, even when pinned + floor-pass")
    func revoked() {
        let list = Self.revocationList([
            Self.rev(id: "com.maccrab.hosts-collector", scope: .singleVersion("1.0.0"), reason: "key compromise")
        ])
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(version: "1.0.0"), revocations: list, floorCheck: Self.floorOK
        )
        guard case .revoked(let reason) = st.installability else {
            Issue.record("expected revoked"); return
        }
        #expect(reason == "key compromise")
        #expect(st.isRevoked)
        #expect(st.revocationReason == "key compromise")
        #expect(!st.showsInstallPill)
    }

    @Test("revocation wins over a passing version floor AND a present pin")
    func revocationPrecedence() {
        let list = Self.revocationList([
            Self.rev(id: "com.maccrab.hosts-collector", scope: .allVersions)
        ])
        // Pinned, official, floor would pass — but it's revoked.
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(), revocations: list, floorCheck: Self.floorOK
        )
        #expect(st.isRevoked)
        #expect(!st.showsInstallPill)
    }

    @Test("a revocation for a DIFFERENT version does not block install")
    func revocationDifferentVersion() {
        let list = Self.revocationList([
            Self.rev(id: "com.maccrab.hosts-collector", scope: .singleVersion("0.9.0"))
        ])
        let st = RaveCatalogEntryState.compute(
            entry: Self.entry(version: "1.0.0"), revocations: list, floorCheck: Self.floorOK
        )
        #expect(!st.isRevoked)
        #expect(st.installability == .installable)
    }

    // MARK: - Default fail-closed shape

    @Test("the no-pill cases all withhold the live pill (no install can be faked)")
    func noFakeInstall() {
        let cases: [RaveCatalogEntryState.Installability] = [
            .awaitingSignedBinary, .preRelease,
            .versionFloorBlocked(reason: "x"), .revoked(reason: "x"),
        ]
        for inst in cases {
            let st = RaveCatalogEntryState(
                entry: Self.entry(), installability: inst, isRevoked: false, revocationReason: nil
            )
            #expect(!st.showsInstallPill, "\(inst) must never show a live install pill")
        }
    }
}
