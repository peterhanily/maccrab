// ThirdPartyExecutionGate — the SOLE pure predicate authorizing SANDBOXED
// third-party / sideload Tier-B execution. Fail-closed at every clause. The
// disjoint twin of FirstPartyExecutionGate: that gate authorizes UNSANDBOXED
// first-party code (byte-match to the compiled-in publisher anchor); this gate
// authorizes UNTRUSTED code that will run ONLY under the deny-default sandbox.
//
// The two lanes never cross. A bundle that matches the first-party anchor is
// REFUSED here (it must take the unsandboxed first-party lane, not be double-
// handled), and FirstPartyExecutionGate refuses everything that is not the
// anchor. SandboxedTierBRunner additionally hard-refuses isFirstParty, and
// FirstPartyTierBRunner hard-refuses anything not isFirstParty.
//
// THE LOAD-BEARING CLAUSE: `sandboxRuntimeAvailable`. On an FDA/TCC host the
// sandbox is the only thing that makes a fooled review non-catastrophic, so if
// the sandbox runtime cannot be brought up (trampoline binary missing/not
// executable, or the SBPL fails to compile/load) this gate DENIES — third-party
// code must be contained-or-nothing, never run uncontained as a fallback.
//
// AUTHORITY MODEL (Plan §3.1, Lens C): positive authority is the operator
// trusting the publisher key (trusted-keys.json membership — the install path
// already requires it) OR a verified curated-catalog receipt. It is NEVER the
// catalog `trust_tier` (forgeable payload), NEVER the first-party publisher
// anchor (that is the OTHER lane), and NEVER a bare locally-forgeable install
// receipt. Because the sandbox contains the result, the authority bar is "the
// operator/curation chose to install this", not the first-party keystone.

import Foundation

public enum ThirdPartyExecutionDecision: Sendable, Equatable {
    case allow
    case deny(reason: String)
    public var isAllowed: Bool { if case .allow = self { return true } else { return false } }
}

public enum ThirdPartyExecutionGate {

    /// Decide whether a verified Tier-B bundle may run as a SANDBOXED subprocess.
    /// PURE + fail-closed. The caller MUST have already run the full crypto chain
    /// (PluginSignatureVerifier.verify) AND the quarantine check via resolve();
    /// this gate adds the execution-authority + containment-availability decision.
    ///
    /// - sandboxRuntimeAvailable: the signed trampoline is present + executable
    ///   (SandboxedTierBRunner.isRuntimeAvailable). FALSE → deny (never run
    ///   uncontained). The single most important clause. NOTE: SBPL validity +
    ///   deny-default CONTENT are not pre-checked here — they are enforced at
    ///   runtime by the trampoline (sandbox_init failure / a non-deny-default or
    ///   permissive profile → _exit before execv), so a bad profile fails closed
    ///   at spawn, not in this predicate.
    /// - isFirstPartyAnchorMatch: the bundle's signing key byte-matches the
    ///   compiled-in first-party publisher anchor. TRUE → deny (wrong lane;
    ///   first-party code runs unsandboxed via the first-party lane only).
    /// - operatorTrustsPublisherKey: the publisher key is in trusted-keys.json
    ///   (the install path requires this; it is the sideload authority).
    /// - hasValidCuratedReceipt: a verified curated-catalog install receipt exists
    ///   (the curated authority). Either this OR operatorTrustsPublisherKey is the
    ///   positive authority.
    /// - isRevoked: the publisher key or plugin id is on a signed revocation /
    ///   quarantine. TRUE → deny.
    /// - catalogOverrideActive: a DEBUG catalog-trust-root override is in effect.
    ///   It can only undermine the CURATED authority (the override could swap the
    ///   catalog signer), so it voids hasValidCuratedReceipt — but operator
    ///   sideload trust, which does not depend on the catalog, still stands.
    public static func evaluate(
        sandboxRuntimeAvailable: Bool,
        isFirstPartyAnchorMatch: Bool,
        operatorTrustsPublisherKey: Bool,
        hasValidCuratedReceipt: Bool,
        isRevoked: Bool,
        catalogOverrideActive: Bool
    ) -> ThirdPartyExecutionDecision {
        // 1. Contained-or-nothing. Checked FIRST so no other positive signal can
        //    let third-party code run when the sandbox cannot be established.
        guard sandboxRuntimeAvailable else {
            return .deny(reason: "sandbox runtime unavailable — refusing to run third-party code uncontained (fail-closed)")
        }
        // 2. Disjoint lanes. A first-party-anchor bundle must NOT be handled by
        //    the sandboxed lane; it belongs to the unsandboxed first-party lane.
        if isFirstPartyAnchorMatch {
            return .deny(reason: "bundle matches the first-party publisher anchor — must use the unsandboxed first-party lane, not the sandboxed lane")
        }
        // 3. Revocation pre-empts every authority.
        if isRevoked {
            return .deny(reason: "publisher key or plugin id is revoked")
        }
        // 4. Positive authority: operator sideload trust OR a curated receipt that
        //    the catalog-override does not void. A bare install receipt is NOT an
        //    input — the caller must pass a *verified curated* receipt.
        let curatedAuthority = hasValidCuratedReceipt && !catalogOverrideActive
        guard operatorTrustsPublisherKey || curatedAuthority else {
            if hasValidCuratedReceipt && catalogOverrideActive {
                return .deny(reason: "curated-catalog authority void under an active catalog trust-root override, and no operator sideload trust")
            }
            return .deny(reason: "no execution authority — neither operator-trusted publisher key nor a verified curated-catalog receipt")
        }
        return .allow
    }
}
