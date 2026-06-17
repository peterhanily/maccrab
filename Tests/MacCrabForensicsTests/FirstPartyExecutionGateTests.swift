// FirstPartyExecutionGate / FirstPartyTrustRoot (Shape 2, Phase 0) — the
// keystone that authorizes UNSANDBOXED first-party Tier-B execution. These tests
// pin the fail-closed predicate against every attack the design pass surfaced:
// the ONLY thing that grants execution is an exact match to the compiled-in
// publisher fingerprint, and catalog trust_tier / trusted-keys membership / the
// install receipt are not even inputs.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("FirstPartyExecutionGate (Shape 2 Phase 0 keystone)")
struct FirstPartyExecutionGateTests {

    // A well-formed, non-sentinel publisher fingerprint to exercise the allow path
    // (production bakes the real one in; the gate is pure so any 64-hex works).
    static let publisher = String(repeating: "a", count: 64)
    static let other = String(repeating: "b", count: 64)

    @Test("exact publisher-key match + configured + official + no override → allow")
    func allowHappyPath() {
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: Self.publisher,
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: true)
        #expect(d == .allow)
    }

    @Test("a DIFFERENT (third-party) key → deny, even with everything else green")
    func denyWrongKey() {
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: Self.other,
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: true)
        #expect(!d.isAllowed)
    }

    @Test("anchor NOT configured (sentinel) → deny, even with a matching key")
    func denyUnconfiguredAnchor() {
        // Mirrors the SHIP state: until the operator bakes in the real publisher
        // fingerprint, first-party execution is disabled.
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: Self.publisher,
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: false, catalogOverrideActive: false, officialSource: true)
        #expect(!d.isAllowed)
    }

    @Test("catalog trust-root override active → deny, even with a matching key (defense in depth)")
    func denyCatalogOverride() {
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: Self.publisher,
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: true, officialSource: true)
        #expect(!d.isAllowed)
    }

    @Test("non-official catalog source → deny, even with a matching key (defense in depth)")
    func denyNonOfficialSource() {
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: Self.publisher,
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: false)
        #expect(!d.isAllowed)
    }

    @Test("malformed fingerprints (short / non-hex) → deny")
    func denyMalformed() {
        let short = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: "abc",
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: true)
        #expect(!short.isAllowed)
        let nonHex = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: String(repeating: "z", count: 64),
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: true)
        #expect(!nonHex.isAllowed)
    }

    @Test("match is case-insensitive on the hex")
    func caseInsensitive() {
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: Self.publisher.uppercased(),
            expectedPublisherFingerprint: Self.publisher,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: true)
        #expect(d == .allow)
    }

    // MARK: - FirstPartyTrustRoot

    @Test("ships fail-closed: the compiled-in anchor is the unset sentinel until the operator configures it")
    func shipsUnconfigured() {
        // This documents the GA prerequisite: isConfigured must be made true (by
        // baking in the real publisher fingerprint) before first-party execution
        // can ever be authorized.
        #expect(FirstPartyTrustRoot.publisherKeyFingerprint == FirstPartyTrustRoot.unsetSentinel)
        #expect(FirstPartyTrustRoot.isConfigured == false)
    }

    @Test("fingerprint(ofSigningKey:) is the lowercase-hex SHA-256 of the raw key bytes")
    func fingerprintMatchesSHA256() {
        let raw = Data((0..<32).map { UInt8($0) })
        let got = FirstPartyTrustRoot.fingerprint(ofSigningKey: raw)
        let want = SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
        #expect(got == want)
        #expect(got.count == 64)
        // End-to-end: a key whose fingerprint equals the anchor is allowed.
        let d = FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: got,
            expectedPublisherFingerprint: want,
            anchorConfigured: true, catalogOverrideActive: false, officialSource: true)
        #expect(d == .allow)
    }
}
