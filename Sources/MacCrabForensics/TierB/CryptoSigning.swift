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
}
