// PluginSignatureVerifier — Ed25519 signing + verification for
// Tier B (third-party) plugin manifests.
//
// Plan §3.6 "Discovery, loading, signing" + §3.9 trust model +
// §12 third-party plugin store + feasibility memo (Audit Pass
// 2026-E future).
//
// Status: LIVE — the verifier on the install + trust + execution path. Used by
// PluginInstaller (install/trust), TierBRegistry (resolve + verifyAll), and both
// execution gates; verifies the Ed25519 signature over the canonical signed
// payload before a plugin can be trusted or run.
//
// Design:
//   1. A "signed plugin bundle" is a directory containing:
//      - manifest.json   (Tier B manifest body)
//      - binary          (the executable)
//      - signature       (raw 64-byte Ed25519 signature)
//      - signing.key.pub (32-byte Ed25519 public key)
//   2. The signature covers SHA-256(manifest.json) || SHA-256(binary).
//      Hashing-then-signing avoids loading large binaries into the
//      signer; the verifier re-hashes to verify.
//   3. The plug-in store's signing CA holds a small allowlist of
//      trusted publisher public keys (`PluginTrustStore`). At
//      install time, the operator decides whether to trust the
//      key. At load time, the verifier checks signature + key
//      allowlist + revocation list (revocation in task tier-b-2.3).

import Foundation
import CryptoKit

public struct PluginSignatureVerifier {

    public enum VerifyError: Error, Equatable, CustomStringConvertible {
        case manifestMissing(path: String)
        case binaryMissing(path: String)
        case signatureMissing(path: String)
        case publicKeyMissing(path: String)
        case publicKeyMalformed(message: String)
        case signatureMalformed(message: String)
        case signatureMismatch
        case publisherKeyNotTrusted(keyHex: String)
        case publisherKeyRevoked(keyHex: String)

        public var description: String {
            switch self {
            case .manifestMissing(let p): return "PluginSignatureVerifier: manifest missing at \(p)"
            case .binaryMissing(let p): return "PluginSignatureVerifier: binary missing at \(p)"
            case .signatureMissing(let p): return "PluginSignatureVerifier: signature missing at \(p)"
            case .publicKeyMissing(let p): return "PluginSignatureVerifier: signing.key.pub missing at \(p)"
            case .publicKeyMalformed(let m): return "PluginSignatureVerifier: signing key malformed: \(m)"
            case .signatureMalformed(let m): return "PluginSignatureVerifier: signature malformed: \(m)"
            case .signatureMismatch: return "PluginSignatureVerifier: signature does not verify"
            case .publisherKeyNotTrusted(let k): return "PluginSignatureVerifier: publisher key \(k) is not in the trust store"
            case .publisherKeyRevoked(let k): return "PluginSignatureVerifier: publisher key \(k) is on the revocation list"
            }
        }
    }

    /// Standardized filenames inside a signed plugin bundle.
    public struct BundleLayout: Sendable {
        public let bundleRoot: URL
        public var manifestPath: String { bundleRoot.appendingPathComponent("manifest.json").path }
        public var binaryPath: String { bundleRoot.appendingPathComponent("binary").path }
        public var signaturePath: String { bundleRoot.appendingPathComponent("signature").path }
        public var publicKeyPath: String { bundleRoot.appendingPathComponent("signing.key.pub").path }
        public init(bundleRoot: URL) { self.bundleRoot = bundleRoot }
    }

    /// Trust store for verified-publisher Ed25519 public keys.
    /// Live impl will read from a project-signed allowlist JSON;
    /// research impl: in-memory set of allowed key hex strings.
    public struct TrustStore: Sendable {
        public let allowedKeyHexes: Set<String>
        public let revokedKeyHexes: Set<String>
        public init(allowedKeyHexes: Set<String>, revokedKeyHexes: Set<String> = []) {
            self.allowedKeyHexes = allowedKeyHexes
            self.revokedKeyHexes = revokedKeyHexes
        }
        public static let researchEmpty = TrustStore(allowedKeyHexes: [])
    }

    /// Verify a signed plugin bundle. Returns the manifest JSON
    /// bytes (caller decodes to PluginManifest) on success.
    /// Throws on any verification step failure.
    public static func verify(
        bundle: BundleLayout,
        trustStore: TrustStore
    ) throws -> Data {
        let fm = FileManager.default
        guard fm.fileExists(atPath: bundle.manifestPath) else {
            throw VerifyError.manifestMissing(path: bundle.manifestPath)
        }
        guard fm.fileExists(atPath: bundle.binaryPath) else {
            throw VerifyError.binaryMissing(path: bundle.binaryPath)
        }
        guard fm.fileExists(atPath: bundle.signaturePath) else {
            throw VerifyError.signatureMissing(path: bundle.signaturePath)
        }
        guard fm.fileExists(atPath: bundle.publicKeyPath) else {
            throw VerifyError.publicKeyMissing(path: bundle.publicKeyPath)
        }

        let manifestData = try Data(contentsOf: URL(fileURLWithPath: bundle.manifestPath))
        let binaryData = try Data(contentsOf: URL(fileURLWithPath: bundle.binaryPath))
        let signature = try Data(contentsOf: URL(fileURLWithPath: bundle.signaturePath))
        let publicKeyBytes = try Data(contentsOf: URL(fileURLWithPath: bundle.publicKeyPath))

        guard signature.count == 64 else {
            throw VerifyError.signatureMalformed(message: "expected 64 bytes, got \(signature.count)")
        }
        guard publicKeyBytes.count == 32 else {
            throw VerifyError.publicKeyMalformed(message: "expected 32 bytes, got \(publicKeyBytes.count)")
        }
        let publicKey: Curve25519.Signing.PublicKey
        do {
            publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
        } catch {
            throw VerifyError.publicKeyMalformed(message: error.localizedDescription)
        }

        let keyHex = publicKeyBytes.map { String(format: "%02x", $0) }.joined()
        if trustStore.revokedKeyHexes.contains(keyHex) {
            throw VerifyError.publisherKeyRevoked(keyHex: keyHex)
        }
        guard trustStore.allowedKeyHexes.contains(keyHex) else {
            throw VerifyError.publisherKeyNotTrusted(keyHex: keyHex)
        }

        let signedPayload = canonicalSignedPayload(
            manifestData: manifestData,
            binaryData: binaryData
        )
        guard publicKey.isValidSignature(signature, for: signedPayload) else {
            throw VerifyError.signatureMismatch
        }
        return manifestData
    }

    /// Sign a plugin bundle (developer-side helper). The
    /// developer would normally run this from a CLI; we expose it
    /// here so tests + the future maccrabctl-plugin-sign command
    /// have a single canonical signing path.
    public static func sign(
        bundle: BundleLayout,
        privateKey: Curve25519.Signing.PrivateKey
    ) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: bundle.manifestPath) else {
            throw VerifyError.manifestMissing(path: bundle.manifestPath)
        }
        guard fm.fileExists(atPath: bundle.binaryPath) else {
            throw VerifyError.binaryMissing(path: bundle.binaryPath)
        }
        let manifestData = try Data(contentsOf: URL(fileURLWithPath: bundle.manifestPath))
        let binaryData = try Data(contentsOf: URL(fileURLWithPath: bundle.binaryPath))
        let payload = canonicalSignedPayload(
            manifestData: manifestData,
            binaryData: binaryData
        )
        let signature = try privateKey.signature(for: payload)
        try signature.write(to: URL(fileURLWithPath: bundle.signaturePath))
        let pubKey = privateKey.publicKey.rawRepresentation
        try pubKey.write(to: URL(fileURLWithPath: bundle.publicKeyPath))
    }

    /// The canonical bytes that get signed:
    ///   "maccrab-tierb-plugin-v1\n" || sha256(manifest) || sha256(binary)
    /// The version prefix gives us future extensibility — v2 can
    /// add new fields without colliding with v1 signatures.
    public static func canonicalSignedPayload(
        manifestData: Data,
        binaryData: Data
    ) -> Data {
        var payload = Data("maccrab-tierb-plugin-v1\n".utf8)
        payload.append(contentsOf: SHA256.hash(data: manifestData))
        payload.append(contentsOf: SHA256.hash(data: binaryData))
        return payload
    }
}
