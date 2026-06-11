// RaveSignerPin — O1b publisher-key pin policy (S2-01/02), shared by both
// rave catalog clients (maccrabctl PluginCatalogFetch + dashboard
// RaveCatalogClient) so the fail-closed rule has exactly one implementation.
//
// The pin binds *which publisher key* the signature-verified catalog endorsed
// (`signer_public_key_sha256`) to *which key the downloaded bundle actually
// carries* (`SHA256(signing.key.pub)`), independent of the artifact hash
// (transport integrity) and the bundle's own self-signature (self-attesting).
//
// Fail-closed rule:
//   - pin present  → bundle key sha256 MUST equal it, else reject.
//   - pin absent   → reject on an official (non-"pre-release") channel.
//                    A "pre-release" entry may install unpinned ONLY when the
//                    caller passes an explicit opt-in.

import Foundation
import CryptoKit

public enum RaveSignerPinError: Error, Equatable, CustomStringConvertible {
    case mismatch(expected: String, actual: String)
    case missingBundleKey(expected: String)
    case absentOnOfficial(id: String)

    public var description: String {
        switch self {
        case .mismatch(let expected, let actual):
            return "Publisher-key pin mismatch — catalog endorses signer key sha256 \(expected), but the bundle's signing.key.pub hashes to \(actual)."
        case .missingBundleKey(let expected):
            return "Publisher-key pin set (\(expected)) but the bundle has no readable signing.key.pub."
        case .absentOnOfficial(let id):
            return "Catalog entry for \(id) has no signer_public_key_sha256 on an official (non-pre-release) channel — refusing to install (fail-closed)."
        }
    }
}

public enum RaveSignerPin {

    /// True iff `s` is exactly 64 lowercase-hex characters (a SHA-256 digest).
    public static func isSHA256Hex(_ s: String) -> Bool {
        guard s.count == 64 else { return false }
        for ch in s.utf8 {
            let isDigit = ch >= 0x30 && ch <= 0x39   // 0-9
            let isLowerAF = ch >= 0x61 && ch <= 0x66 // a-f
            if !(isDigit || isLowerAF) { return false }
        }
        return true
    }

    /// hex-lower SHA-256 of `data`.
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Pure policy decision: given the catalog-endorsed pin (`expectedPin`,
    /// may be nil/empty when absent), the entry's `status`, the opt-in flag,
    /// and the bundle's signing.key.pub bytes (`bundleKeyData`, may be nil when
    /// unreadable), throw if the install must be refused. Returns normally when
    /// the install may proceed.
    ///
    /// `expectedPin` should already be lowercased; an empty string is treated
    /// as "absent".
    public static func enforce(
        expectedPin: String?,
        status: String?,
        pluginID: String,
        bundleKeyData: Data?,
        allowUnpinnedPrerelease: Bool
    ) throws {
        let pin = (expectedPin?.isEmpty == false) ? expectedPin! : nil
        guard let expected = pin else {
            // No pin in the catalog. Pre-release entries may opt into an
            // unpinned install; everything else fails closed.
            let isPrerelease = (status == "pre-release")
            if isPrerelease && allowUnpinnedPrerelease { return }
            throw RaveSignerPinError.absentOnOfficial(id: pluginID)
        }
        guard let keyData = bundleKeyData else {
            throw RaveSignerPinError.missingBundleKey(expected: expected)
        }
        let actual = sha256Hex(keyData)
        guard actual == expected else {
            throw RaveSignerPinError.mismatch(expected: expected, actual: actual)
        }
    }
}
