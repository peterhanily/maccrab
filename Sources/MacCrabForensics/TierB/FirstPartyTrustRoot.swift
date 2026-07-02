// FirstPartyTrustRoot — the compiled-in cryptographic anchor that authorizes
// UNSANDBOXED first-party Tier-B plugin execution (Shape 2, Phase 0).
//
// SECURITY KEYSTONE. A first-party Tier-B plugin runs as a TRUSTED subprocess
// with NO sandbox profile (it inherits the host's Full-Disk-Access / TCC), so
// the authority to run it must be unforgeable AND immutable: the SHA-256 of the
// plugin bundle's `signing.key.pub` must byte-equal `publisherKeyFingerprint`,
// a constant baked into the SIGNED app binary at build time. It is deliberately
// NOT any of these (the design's attack pass ran THIRD-PARTY code against each):
//   - catalog `trust_tier`            — catalog PAYLOAD, forgeable JSON
//   - the catalog trust-root key      — catalog.fingerprint signs the CATALOG,
//                                       not plugin bundles; a different key
//   - trusted-keys.json membership    — proves "a trusted signer", not THE
//                                       first-party one; widened by sideload/TOFU
//   - the install receipt             — locally forgeable by a non-root attacker
//
// OPERATOR / KEYHOLDER: before GA, generate the first-party plugin-signing
// Ed25519 keypair OFFLINE and set `publisherKeyFingerprint` to the lowercase-hex
// SHA-256 of its raw 32-byte public key (the bundle's signing.key.pub). Until
// then it is the UNSET sentinel and first-party execution is FAIL-CLOSED — the
// safe default. This is the single point of trust for ALL first-party plugins:
// its custody equals the trust of the app binary itself. It MUST stay a
// build-time constant — never read it from a file or env (that re-introduces the
// catalog-trust-root swap attack this anchor exists to close).

import Foundation
import CryptoKit

public enum FirstPartyTrustRoot {

    /// Sentinel meaning "no publisher key configured" → first-party execution
    /// stays fail-closed. 64 zero-hex chars; never a real SHA-256 of a key.
    public static let unsetSentinel = String(repeating: "0", count: 64)

    /// SHA-256 (lowercase hex) of the first-party plugin-signing public key.
    /// OPERATOR: replace the sentinel with the real fingerprint at the GA signing
    /// ceremony (Runbook P / Q). Build-time constant ONLY.
    ///
    /// KEYHOLDER: set to the SHA-256 of the first-party publisher's
    /// signing.key.pub. This authorizes UNSANDBOXED, full-FDA first-party
    /// execution — confirm this value equals the OFFLINE-held first-party
    /// signing key's fingerprint before shipping (it must NOT be trusted purely
    /// because an on-disk bundle happens to hash to it).
    public static let publisherKeyFingerprint: String =
        "07e39eb12c15b8052f5249134ea3337a0789ebc799d1c58d097aaa548a8aaae3"

    /// True iff a real (configured, well-formed, non-sentinel) fingerprint is
    /// baked in. When false, first-party execution is disabled (fail-closed).
    public static var isConfigured: Bool {
        let f = publisherKeyFingerprint.lowercased()
        return f.count == 64 && f != unsetSentinel && f.allSatisfy { $0.isHexDigit }
    }

    /// SHA-256 (lowercase hex) of a bundle's raw `signing.key.pub` bytes — the
    /// value compared against `publisherKeyFingerprint`.
    public static func fingerprint(ofSigningKey raw: Data) -> String {
        SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined()
    }
}
