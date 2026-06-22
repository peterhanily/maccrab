// CryptoSigning — thin wrapper exposing Curve25519.Signing
// outside CryptoKit-import scopes. Used by TierBRegistry to do
// the belt-and-suspenders second verify without exposing
// CryptoKit types throughout the module.

import Foundation
import CryptoKit

public enum CryptoSigning {
    public static func publicKey(rawRepresentation: Data) throws -> Curve25519.Signing.PublicKey {
        try Curve25519.Signing.PublicKey(rawRepresentation: rawRepresentation)
    }

    /// Generate a fresh Ed25519 (Curve25519) plugin-signing keypair. The private
    /// raw is 32 bytes — keep it OFFLINE; never commit it or place it in a bundle.
    public static func newSigningKey() -> (privateRaw: Data, publicRaw: Data, publicHex: String) {
        let key = Curve25519.Signing.PrivateKey()
        let pub = key.publicKey.rawRepresentation
        return (key.rawRepresentation, pub, hex(pub))
    }

    /// Sign a Tier-B bundle (manifest + binary) in place, writing `signature` +
    /// `signing.key.pub`. Returns the publisher public-key hex. The CLI uses this
    /// so it never imports CryptoKit. `privateKeyRaw` is the 32-byte raw key.
    public static func signBundle(atPath bundlePath: String, privateKeyRaw: Data) throws -> String {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyRaw)
        try PluginSignatureVerifier.sign(
            bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: URL(fileURLWithPath: bundlePath)),
            privateKey: key)
        return hex(key.publicKey.rawRepresentation)
    }

    static func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
}
