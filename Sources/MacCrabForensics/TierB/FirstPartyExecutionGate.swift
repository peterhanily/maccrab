// FirstPartyExecutionGate — the SOLE pure predicate authorizing UNSANDBOXED
// first-party Tier-B execution (Shape 2, Phase 0). Fail-closed at every clause.
//
// The caller MUST have already run the full crypto chain
// (PluginSignatureVerifier.verify: 4 files present, sig/key sizes, key trusted +
// NOT revoked, Ed25519 over the canonical payload) AND the quarantine check.
// This gate adds the one thing that chain does not prove: that the bundle is
// signed by THE first-party publisher key (an exact match to the compiled-in
// FirstPartyTrustRoot anchor), plus two defense-in-depth refusals (a swapped
// catalog trust root, or a non-official source, can never mint first-party
// execution). The ONLY positive authority is the fingerprint match — catalog
// trust_tier, trusted-keys.json membership, and the install receipt are NOT
// inputs by design (each was shown to let third-party code run).

import Foundation

public enum FirstPartyExecutionDecision: Sendable, Equatable {
    case allow
    case deny(reason: String)
    public var isAllowed: Bool { if case .allow = self { return true } else { return false } }
}

public enum FirstPartyExecutionGate {

    /// Decide whether a verified Tier-B bundle may run as a TRUSTED (unsandboxed)
    /// subprocess. PURE + fail-closed.
    ///
    /// - bundleSigningKeyPubSHA256: SHA-256 (hex) of the bundle's signing.key.pub.
    /// - expectedPublisherFingerprint: the compiled-in anchor
    ///   (FirstPartyTrustRoot.publisherKeyFingerprint).
    /// - anchorConfigured: FirstPartyTrustRoot.isConfigured (false → fail-closed).
    /// - catalogOverrideActive: a catalog-trust-root env override is in effect.
    /// - officialSource: the catalog came from the official production host.
    public static func evaluate(
        bundleSigningKeyPubSHA256: String,
        expectedPublisherFingerprint: String,
        anchorConfigured: Bool,
        catalogOverrideActive: Bool,
        officialSource: Bool
    ) -> FirstPartyExecutionDecision {
        guard anchorConfigured else {
            return .deny(reason: "first-party publisher key not configured (fail-closed)")
        }
        if catalogOverrideActive {
            return .deny(reason: "catalog trust-root override active — first-party execution refused")
        }
        guard officialSource else {
            return .deny(reason: "non-official catalog source — first-party execution refused")
        }
        let got = bundleSigningKeyPubSHA256.lowercased()
        let want = expectedPublisherFingerprint.lowercased()
        guard got.count == 64, want.count == 64,
              got.allSatisfy({ $0.isHexDigit }), want.allSatisfy({ $0.isHexDigit }) else {
            return .deny(reason: "malformed fingerprint")
        }
        guard got == want else {
            return .deny(reason: "bundle is not signed by the first-party publisher key")
        }
        return .allow
    }
}
