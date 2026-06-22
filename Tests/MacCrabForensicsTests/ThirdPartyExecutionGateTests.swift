// ThirdPartyExecutionGateTests — the fail-closed authority for SANDBOXED
// third-party Tier-B execution. The disjoint twin of FirstPartyExecutionGate's
// tests. Every clause is a refusal that protects the load-bearing invariant:
// untrusted code runs CONTAINED or NOT AT ALL, and never crosses into the
// first-party (unsandboxed) lane.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("ThirdPartyExecutionGate (sandboxed lane, fail-closed)")
struct ThirdPartyExecutionGateTests {

    // A fully-authorized, runnable baseline; individual tests flip one input.
    static func allow(
        sandboxRuntimeAvailable: Bool = true,
        isFirstPartyAnchorMatch: Bool = false,
        operatorTrustsPublisherKey: Bool = true,
        hasValidCuratedReceipt: Bool = false,
        isRevoked: Bool = false,
        catalogOverrideActive: Bool = false
    ) -> ThirdPartyExecutionDecision {
        ThirdPartyExecutionGate.evaluate(
            sandboxRuntimeAvailable: sandboxRuntimeAvailable,
            isFirstPartyAnchorMatch: isFirstPartyAnchorMatch,
            operatorTrustsPublisherKey: operatorTrustsPublisherKey,
            hasValidCuratedReceipt: hasValidCuratedReceipt,
            isRevoked: isRevoked,
            catalogOverrideActive: catalogOverrideActive)
    }

    @Test("happy path: operator-trusted, sandbox available, not anchor, not revoked → allow")
    func happyOperatorTrust() {
        #expect(Self.allow().isAllowed)
    }

    @Test("happy path: curated receipt (no override) is sufficient authority")
    func happyCurated() {
        #expect(Self.allow(operatorTrustsPublisherKey: false, hasValidCuratedReceipt: true).isAllowed)
    }

    @Test("THE clause: sandbox runtime unavailable → deny, even with full authority")
    func sandboxUnavailableDenies() {
        let d = Self.allow(sandboxRuntimeAvailable: false)
        #expect(!d.isAllowed)
        if case .deny(let r) = d { #expect(r.lowercased().contains("uncontained")) } else { Issue.record("expected deny") }
    }

    @Test("sandbox-unavailable is checked FIRST (wins over every other signal)")
    func sandboxUnavailableWins() {
        // Even a first-party-anchor + revoked + no-authority bundle reports the
        // sandbox reason — the contained-or-nothing clause is the outermost gate.
        let d = ThirdPartyExecutionGate.evaluate(
            sandboxRuntimeAvailable: false,
            isFirstPartyAnchorMatch: true,
            operatorTrustsPublisherKey: false,
            hasValidCuratedReceipt: false,
            isRevoked: true,
            catalogOverrideActive: true)
        if case .deny(let r) = d { #expect(r.lowercased().contains("uncontained")) } else { Issue.record("expected deny") }
    }

    @Test("disjoint lanes: a first-party-anchor bundle is refused by the sandboxed lane")
    func firstPartyAnchorDenied() {
        let d = Self.allow(isFirstPartyAnchorMatch: true)
        #expect(!d.isAllowed)
        if case .deny(let r) = d { #expect(r.lowercased().contains("first-party")) } else { Issue.record("expected deny") }
    }

    @Test("revocation pre-empts every authority")
    func revokedDenied() {
        #expect(!Self.allow(isRevoked: true).isAllowed)
        // even with a curated receipt
        #expect(!Self.allow(operatorTrustsPublisherKey: false, hasValidCuratedReceipt: true, isRevoked: true).isAllowed)
    }

    @Test("no authority at all → deny")
    func noAuthorityDenied() {
        let d = Self.allow(operatorTrustsPublisherKey: false, hasValidCuratedReceipt: false)
        #expect(!d.isAllowed)
    }

    @Test("catalog override VOIDS a curated receipt (curated authority depends on the catalog signer)")
    func overrideVoidsCurated() {
        let d = Self.allow(operatorTrustsPublisherKey: false, hasValidCuratedReceipt: true, catalogOverrideActive: true)
        #expect(!d.isAllowed)
        if case .deny(let r) = d { #expect(r.lowercased().contains("override")) } else { Issue.record("expected deny") }
    }

    @Test("operator sideload trust survives a catalog override (independent of the catalog)")
    func operatorTrustSurvivesOverride() {
        // override is active and the curated receipt is void, but the operator
        // explicitly trusts the key → still allow (sandboxed).
        #expect(Self.allow(operatorTrustsPublisherKey: true, hasValidCuratedReceipt: true, catalogOverrideActive: true).isAllowed)
    }

    @Test("trust_tier / payload is NOT an input — only the documented authorities are")
    func noPayloadAuthority() {
        // There is no parameter for trust_tier by design; with neither operator
        // trust nor a curated receipt, nothing can authorize.
        #expect(!Self.allow(operatorTrustsPublisherKey: false, hasValidCuratedReceipt: false, catalogOverrideActive: false).isAllowed)
    }
}
