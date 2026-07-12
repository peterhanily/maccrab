// LocalTrustSigner — A1-03. Synchronous per-host P256/ECDSA-SHA256 signer for
// LOCAL trust artifacts (the S2-AR anti-rollback high-water marks and the
// publisher trusted-keys list). It seals a small JSON `body` object into an
// envelope carrying the signature + the signing public key, so a reader can
// prove the file was produced by THIS host and fail CLOSED — instead of
// silently resetting to first-seen / an empty trust set — when it wasn't.
//
// Why a dedicated key instead of literally threading the async TrustSubstrate
// (the install-receipt / trace-bundle signer)?
//   - The consumers are read from SYNCHRONOUS paths (e.g. the SwiftUI
//     revocation-freshness line calls RaveTrustStateStore.load()); TrustSubstrate
//     is an async actor, so reusing it would force the whole trust-state read/
//     write surface async and ripple `await` across maccrabctl, MacCrabApp and
//     MacCrabForensics — far beyond a Low-severity tightening.
//   - TrustSubstrate prefers a Secure-Enclave key on a cold host; a synchronous
//     bridge would have to resolve the SE-vs-filesystem mode and could preempt
//     that choice on first write. A dedicated key avoids that cold-bootstrap
//     mode conflict entirely.
// It reuses the SAME primitive (P256 ECDSA over SHA-256, DER) and the SAME
// 0o600 / symlink-refusing key-storage discipline as TrustSubstrate, so the
// practical protection is equivalent for the threat this closes: a same-uid
// *write* primitive (path traversal, symlink swap, accidental corruption, a
// naive hand-edit) that can overwrite a trust file but cannot invoke this host's
// signing key. Verification pins the embedded key to this host's key, so an
// attacker who re-signs with their OWN key is rejected too.
//
// Residual (documented, same as the SE key would have): a same-uid *code-exec*
// attacker can read the key file and forge — exactly as they could invoke the SE
// key — and deleting BOTH a trust file and its `.signkey` looks like a fresh
// bootstrap. The value is detectability + defeating weaker write-only primitives,
// on top of the sandbox that already contains a fooled trust.

import Foundation
import CryptoKit

public struct LocalTrustSigner: Sendable {

    /// Path to this host's dedicated P256 signing key (DER, 0o600). Generated
    /// lazily on first `seal`.
    private let keyPath: URL

    public init(keyPath: URL) { self.keyPath = keyPath }

    /// Envelope schema. Present-file readers use `isEnvelope` to tell a sealed
    /// file apart from legacy-unsigned / garbage (both of which fail closed).
    public static let schemaVersion = 2

    /// True when `obj` has the sealed-envelope shape (body + signature + key).
    public static func isEnvelope(_ obj: [String: Any]) -> Bool {
        obj["body"] as? [String: Any] != nil
            && obj["signature"] as? String != nil
            && obj["public_key_der"] as? String != nil
    }

    /// Seal `body` into a signed envelope dictionary. `body` is signed in its
    /// canonical (sorted-key, compact) form so verification is order-independent.
    /// Generates the host key on first use.
    public func seal(body: [String: Any]) throws -> [String: Any] {
        let canonical = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let key = try loadOrGenerateKey()
        let signature = try key.signature(for: canonical).derRepresentation
        return [
            "schema_version": Self.schemaVersion,
            "body": body,
            "signature": signature.base64EncodedString(),
            "public_key_der": key.publicKey.derRepresentation.base64EncodedString(),
        ]
    }

    /// Open a sealed envelope, returning the verified `body` — or nil if the
    /// object is not a valid, host-signed envelope. A caller that gets nil for a
    /// PRESENT file MUST treat it as tampered and fail closed. Reasons for nil:
    /// missing fields, the embedded key isn't this host's key (forged), no host
    /// key exists yet (the file was signed by a key that's since gone), or a bad
    /// signature (body mutated in place).
    public func open(_ obj: [String: Any]) -> [String: Any]? {
        guard let body = obj["body"] as? [String: Any],
              let sigB64 = obj["signature"] as? String,
              let signature = Data(base64Encoded: sigB64),
              let pubB64 = obj["public_key_der"] as? String,
              let embeddedPub = Data(base64Encoded: pubB64) else { return nil }
        // Pin: the embedded key must be THIS host's signing key. An attacker who
        // re-signs a forged body with their own key embeds a different pubkey.
        guard let pinned = pinnedPublicKeyDER(), pinned == embeddedPub else { return nil }
        guard let canonical = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]),
              let key = try? P256.Signing.PublicKey(derRepresentation: embeddedPub),
              let ecdsa = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              key.isValidSignature(ecdsa, for: canonical) else { return nil }
        return body
    }

    /// This host's signing public key (DER), or nil if the key doesn't exist yet.
    public func pinnedPublicKeyDER() -> Data? {
        (try? loadKey())?.publicKey.derRepresentation
    }

    // MARK: - Key material (0o600, symlink-refusing — mirrors TrustSubstrate)

    private func loadKey() throws -> P256.Signing.PrivateKey {
        // Refuse to load through a symlink (key-substitution attempt), matching
        // FilesystemTrustSubstrateStorage.loadFilesystemPrivateKey.
        var st = stat()
        if lstat(keyPath.path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK {
            throw NSError(domain: "LocalTrustSigner", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "signing key is a symlink — refusing to load"
            ])
        }
        let der = try Data(contentsOf: keyPath)
        return try P256.Signing.PrivateKey(derRepresentation: der)
    }

    private func loadOrGenerateKey() throws -> P256.Signing.PrivateKey {
        if let key = try? loadKey() { return key }
        let key = P256.Signing.PrivateKey()
        try FileManager.default.createDirectory(
            at: keyPath.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try key.derRepresentation.write(to: keyPath, options: .atomic)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: keyPath.path
        )
        return key
    }
}
