// FirstPartyExecutionGateInvariantTests — Owner-issue hardening of the SOLE
// predicate that authorizes UNSANDBOXED first-party Tier-B execution.
//
// The existing FirstPartyExecutionGateTests pin individual edge cases. This file
// turns the gate into an INVARIANT (Issue 1) and proves the .allow space is
// COMPLETE / minimal (Issue 2):
//
//   Issue 1 — call FirstPartyExecutionGate.evaluate DIRECTLY with HOSTILE inputs
//   (not via runFirstPartyTierBCollector). A different caller — or an attacker
//   who reaches the gate — can pass inputs the CLI would never produce
//   (uppercase / whitespace / wrong-length / empty hex, a "matching" bundle key
//   against the UNSET sentinel, a swapped catalog root). Assert .deny in EVERY
//   non-perfect case (fail-closed).
//
//   Issue 2 — the .allow space is EXACTLY one tuple. We enumerate the full
//   Cartesian product of the boolean flags × a fingerprint-match axis and assert
//   that the SINGLE allow is (configured + exact-match + official + no-override),
//   and the deny set is its complete complement — nothing missing, nothing extra.
//
// Mutation note (verified by reasoning against the source): if any clause
// regressed to fail-OPEN — e.g. dropping the `guard anchorConfigured`, the
// `catalogOverrideActive` refusal, the `officialSource` guard, the 64-hex/length
// validation, or the final `got == want` — `exhaustiveAllowSpaceIsExactlyOne`
// would see >1 allow (or an allow on a hostile input) and FAIL. Likewise, if hex
// normalization were dropped, `caseAndWhitespace...` would flip.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("FirstPartyExecutionGate — invariant + complete allow-space (owner issues)")
struct FirstPartyExecutionGateInvariantTests {

    // A well-formed, non-sentinel 64-hex publisher fingerprint. The gate is pure,
    // so any 64-hex string works as the "configured anchor" for these tests.
    static let anchor = String(repeating: "a", count: 64)
    static let other  = String(repeating: "b", count: 64)

    private func decide(
        key: String,
        anchor: String = anchor,
        configured: Bool = true,
        override: Bool = false,
        official: Bool = true
    ) -> FirstPartyExecutionDecision {
        FirstPartyExecutionGate.evaluate(
            bundleSigningKeyPubSHA256: key,
            expectedPublisherFingerprint: anchor,
            anchorConfigured: configured,
            catalogOverrideActive: override,
            officialSource: official)
    }

    // MARK: - Issue 2: the allow-space is EXACTLY one tuple (completeness)

    @Test("the .allow space is EXACTLY {configured + exact-match + official + no-override} — nothing else")
    func exhaustiveAllowSpaceIsExactlyOne() {
        // Fingerprint-match axis: a key that matches the anchor exactly vs one
        // that does not. (Hostile-hex variants are exercised separately below.)
        let matchAxis: [(label: String, key: String, matches: Bool)] = [
            ("exact-match", Self.anchor, true),
            ("wrong-key",   Self.other,  false),
        ]

        var allows: [String] = []
        for configured in [true, false] {
            for override in [true, false] {
                for official in [true, false] {
                    for m in matchAxis {
                        let d = decide(key: m.key,
                                       configured: configured,
                                       override: override,
                                       official: official)
                        let label = "configured=\(configured) override=\(override) official=\(official) \(m.label)"
                        // The one and only allow tuple.
                        let isThePerfectTuple = configured && !override && official && m.matches
                        if isThePerfectTuple {
                            #expect(d == .allow, "the perfect tuple must allow: \(label)")
                            allows.append(label)
                        } else {
                            #expect(!d.isAllowed, "every non-perfect tuple must DENY: \(label)")
                        }
                    }
                }
            }
        }
        // COMPLETENESS: exactly one allow across the entire product.
        #expect(allows.count == 1, "exactly one tuple may allow; got \(allows)")
        #expect(allows == ["configured=true override=false official=true exact-match"])
    }

    // MARK: - Issue 1: anchor-not-configured fails closed EVEN when keys "match"

    @Test("anchor unset-sentinel: a bundle key that byte-equals the sentinel must STILL deny (not-configured wins)")
    func unsetSentinelDeniesEvenWhenBundleKeyMatchesIt() {
        // Hostile shape: the operator hasn't baked in a real anchor, so the
        // compiled-in anchor is the all-zeros sentinel. An attacker ships a
        // bundle whose signing-key SHA256 is ALSO all-zeros so the bytes "match".
        // The gate must refuse because anchorConfigured==false short-circuits
        // BEFORE any fingerprint comparison.
        let sentinel = FirstPartyTrustRoot.unsetSentinel
        let d = decide(key: sentinel, anchor: sentinel, configured: false)
        #expect(d == .deny(reason: "first-party publisher key not configured (fail-closed)"))
        #expect(!d.isAllowed)
        // And the SHIP state proves this is the live default: the compiled-in
        // anchor is the sentinel and isConfigured is false, so production cannot
        // be tricked into the allow path until the operator configures it.
        #expect(FirstPartyTrustRoot.publisherKeyFingerprint == sentinel)
        #expect(FirstPartyTrustRoot.isConfigured == false)
    }

    @Test("the unset-sentinel anchor never allows for ANY key (configured stays true to isolate the comparison)")
    func sentinelAnchorWithMatchingKeyConfiguredTrue() {
        // Even if a future bug let isConfigured report true while the anchor is
        // still the sentinel, an all-zeros bundle key is 64-hex and would match.
        // This documents that the SOLE defense there is FirstPartyTrustRoot.
        // isConfigured (asserted false above) — the gate itself, given a 64-hex
        // sentinel anchor + matching key + configured=true, returns .allow.
        // We assert that explicitly so the dependency is visible, not hidden.
        let sentinel = FirstPartyTrustRoot.unsetSentinel
        let d = decide(key: sentinel, anchor: sentinel, configured: true)
        #expect(d == .allow,
                "gate is pure: a 64-hex sentinel anchor with a matching key + configured=true allows — the only guard against this is isConfigured()==false (asserted)")
    }

    // MARK: - Issue 1: hostile hex — no normalization bypass

    @Test("hostile fingerprint hex variants → deny (no normalization bypass)")
    func hostileHexVariantsAllDeny() {
        // Each variant is a string a sanitizing CLI would never emit but a raw
        // caller / attacker can. None may slip through to .allow.
        let hostileKeys: [(label: String, key: String)] = [
            ("empty",                ""),
            ("too-short",            String(repeating: "a", count: 63)),
            ("too-long",             String(repeating: "a", count: 65)),
            ("leading-space",        " " + String(repeating: "a", count: 63)),
            ("trailing-space",       String(repeating: "a", count: 63) + " "),
            ("internal-space",       String(repeating: "a", count: 32) + " " + String(repeating: "a", count: 31)),
            ("newline",              String(repeating: "a", count: 63) + "\n"),
            ("0x-prefix",            "0x" + String(repeating: "a", count: 62)),
            ("non-hex-z",            String(repeating: "z", count: 64)),
            ("non-hex-g",            String(repeating: "g", count: 64)),
            ("unicode-digit",        String(repeating: "a", count: 63) + "\u{0660}"), // ARABIC-INDIC ZERO
        ]
        for v in hostileKeys {
            let d = decide(key: v.key)
            #expect(!d.isAllowed, "hostile fingerprint '\(v.label)' must deny")
        }
    }

    @Test("uppercase / mixed-case hex of the SAME key still allows (case-insensitive, but only for valid hex)")
    func caseAndWhitespaceNormalization() {
        // Case-folding is the ONLY normalization. Upper/mixed of a valid 64-hex
        // matching key allows; the same key with surrounding whitespace does NOT
        // (whitespace is not trimmed — length/hex validation rejects it).
        #expect(decide(key: Self.anchor.uppercased()).isAllowed)
        let mixed = String(Self.anchor.enumerated().map { $0.offset.isMultiple(of: 2) ? Character("A") : Character("a") })
        // mixed is 64 chars of A/a — a case variant of the all-'a' anchor.
        #expect(decide(key: mixed, anchor: Self.anchor).isAllowed)
        // But whitespace-padded uppercase fails (length != 64 after the space).
        #expect(!decide(key: " " + Self.anchor.uppercased()).isAllowed)
    }

    // MARK: - Issue 1: defense-in-depth refusals dominate a matching key

    @Test("override OR non-official refuses even with an EXACT matching key + configured anchor")
    func defenseInDepthRefusalsDominateMatch() {
        // Both independently fail-closed; neither can be bought back by a perfect
        // fingerprint match. (The product test above already covers the matrix;
        // this names the two defense-in-depth clauses explicitly.)
        #expect(decide(key: Self.anchor, override: true).isAllowed == false)
        #expect(decide(key: Self.anchor, official: false).isAllowed == false)
        // Order of precedence: override is checked before official, which is
        // checked before the fingerprint. A malformed key + override still cites
        // the override (the earlier clause), proving short-circuit ordering.
        let d = decide(key: "garbage", override: true)
        #expect(d == .deny(reason: "catalog trust-root override active — first-party execution refused"))
    }

    // MARK: - End-to-end: real SHA-256 fingerprint round-trips to .allow, exactly once

    @Test("a real Ed25519 key's SHA-256 fingerprint allows iff anchor == that fingerprint")
    func realFingerprintRoundTrip() {
        let raw = Data((0..<32).map { UInt8($0 &* 7 &+ 3) })
        let fp = FirstPartyTrustRoot.fingerprint(ofSigningKey: raw)
        #expect(fp.count == 64)
        #expect(decide(key: fp, anchor: fp).isAllowed)            // matches → allow
        #expect(!decide(key: fp, anchor: Self.other).isAllowed)   // anchor differs → deny
    }
}
