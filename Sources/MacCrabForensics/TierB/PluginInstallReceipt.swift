// PluginInstallReceipt — O3b (S2-06) signed, offline-verifiable install
// receipt. On every successful rave-catalog install the client records WHAT it
// installed and against WHICH trust state, then signs that record with the
// per-install P256 TrustSubstrate key (the same primitive that signs trace /
// evidence bundles). A third party can later verify the receipt offline using
// only the bundled public key — no callback into the engine.
//
// Layout on disk: <supportDir>/plugin_receipts/<plugin-id>.receipt.json
//   {
//     "schema_version": 1,
//     "body": { ...the signed fields, see ReceiptBody... },
//     "signature": "<base64 DER ECDSA-P256-SHA256 over canonical(body)>",
//     "public_key_der": "<base64 SPKI DER of the signing public key>"
//   }
//
// The signature commits to a CANONICAL serialization of `body` (JSON with
// sorted keys, no insignificant whitespace) so the verifier reproduces the
// exact signed bytes regardless of dictionary ordering. Mutating any body
// field (e.g. swapping artifact_sha256) breaks verification — that's the
// tamper-evidence property the test exercises.

import Foundation
import CryptoKit
import MacCrabCore

/// The signed payload of an install receipt. Every field is provenance the
/// operator (or an auditor) needs to answer "what exactly did this machine
/// install, and what trust state was in effect when it did?".
public struct PluginInstallReceiptBody: Sendable, Equatable, Codable {
    public let pluginID: String
    public let version: String
    public let artifactSHA256: String
    /// sha256 hex of the publisher's signing.key.pub, as endorsed by the
    /// catalog (the O1b pin). Empty when the entry was an unpinned pre-release.
    public let signerPublicKeySHA256: String
    /// The catalog_serial in effect at install (anti-rollback provenance).
    public let catalogSerial: Int?
    /// The revocations serial in effect at install.
    public let revocationSerial: Int?
    /// The running MacCrab version that performed the install.
    public let appVersion: String
    /// ISO-8601 install timestamp.
    public let timestamp: String

    public init(
        pluginID: String,
        version: String,
        artifactSHA256: String,
        signerPublicKeySHA256: String,
        catalogSerial: Int?,
        revocationSerial: Int?,
        appVersion: String,
        timestamp: String
    ) {
        self.pluginID = pluginID
        self.version = version
        self.artifactSHA256 = artifactSHA256
        self.signerPublicKeySHA256 = signerPublicKeySHA256
        self.catalogSerial = catalogSerial
        self.revocationSerial = revocationSerial
        self.appVersion = appVersion
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case pluginID = "plugin_id"
        case version
        case artifactSHA256 = "artifact_sha256"
        case signerPublicKeySHA256 = "signer_public_key_sha256"
        case catalogSerial = "catalog_serial"
        case revocationSerial = "revocation_serial"
        case appVersion = "app_version"
        case timestamp
    }

    /// Canonical bytes the signature commits to: JSON with sorted keys and no
    /// insignificant whitespace. Deterministic across encoder runs so a
    /// verifier reproduces exactly these bytes from the parsed body.
    public func canonicalBytes() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }
}

public enum PluginInstallReceiptError: Error, CustomStringConvertible {
    case writeFailed(String)
    case readFailed(String)
    case malformed(String)
    case signatureInvalid

    public var description: String {
        switch self {
        case .writeFailed(let m): return "Receipt write failed: \(m)"
        case .readFailed(let m):  return "Receipt read failed: \(m)"
        case .malformed(let m):   return "Receipt malformed: \(m)"
        case .signatureInvalid:   return "Receipt signature does not verify (tampered or wrong key)."
        }
    }
}

/// Emits + verifies install receipts. Signing reuses the P256 TrustSubstrate;
/// the receipt embeds the signing public key (SPKI DER) so verification is
/// fully self-contained — `verify(at:)` needs nothing but the file.
public struct PluginInstallReceiptStore: Sendable {
    private let receiptsDir: URL
    private let substrate: TrustSubstrate

    /// `receiptsDir` is `<supportDir>/plugin_receipts`. `substrate` signs the
    /// canonical body bytes. For tests, pass an in-memory-backed substrate and
    /// a temp dir.
    public init(receiptsDir: URL, substrate: TrustSubstrate) {
        self.receiptsDir = receiptsDir
        self.substrate = substrate
    }

    public var directoryPath: String { receiptsDir.path }

    public func receiptURL(forPluginID id: String) -> URL {
        receiptsDir.appendingPathComponent("\(id).receipt.json")
    }

    /// Sign + write a receipt for a successful install. Returns the path
    /// written. Best-effort callers should `try?` this — a receipt write
    /// failure must never unwind a completed install.
    @discardableResult
    public func emit(_ body: PluginInstallReceiptBody) async throws -> URL {
        let canonical = try body.canonicalBytes()
        let signature = try await substrate.sign(canonical)
        let publicKey = try await substrate.publicKey()

        var top: [String: Any] = [
            "schema_version": 1,
            "body": try JSONSerialization.jsonObject(with: canonical),
            "signature": signature.base64EncodedString(),
            "public_key_der": publicKey.derBytes.base64EncodedString(),
        ]
        // `body` is re-serialized below with sorted keys; the verifier
        // re-canonicalizes from the parsed body, NOT from these bytes, so the
        // on-disk pretty-printing is purely cosmetic.
        _ = top

        do {
            try FileManager.default.createDirectory(
                at: receiptsDir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw PluginInstallReceiptError.writeFailed("mkdir \(receiptsDir.path): \(error)")
        }

        let data: Data
        do {
            data = try JSONSerialization.data(
                withJSONObject: top,
                options: [.prettyPrinted, .sortedKeys]
            )
        } catch {
            throw PluginInstallReceiptError.writeFailed("serialize: \(error)")
        }

        let url = receiptURL(forPluginID: body.pluginID)
        do {
            try data.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path
            )
        } catch {
            throw PluginInstallReceiptError.writeFailed("write \(url.path): \(error)")
        }
        return url
    }

    /// Verify a receipt at `url` offline using only its embedded public key.
    /// Returns the parsed body on success; throws on malformed JSON or a bad
    /// signature (tamper). Static so a third-party validator can call it
    /// without constructing a substrate.
    public static func verify(at url: URL) throws -> PluginInstallReceiptBody {
        let data: Data
        do { data = try Data(contentsOf: url) }
        catch { throw PluginInstallReceiptError.readFailed("\(url.path): \(error)") }
        return try verify(data: data)
    }

    /// Verify receipt bytes directly (test seam + in-memory verification).
    public static func verify(data: Data) throws -> PluginInstallReceiptBody {
        guard let top = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PluginInstallReceiptError.malformed("not a JSON object")
        }
        guard let bodyObj = top["body"] else {
            throw PluginInstallReceiptError.malformed("missing 'body'")
        }
        guard let sigB64 = top["signature"] as? String,
              let signature = Data(base64Encoded: sigB64) else {
            throw PluginInstallReceiptError.malformed("missing/invalid 'signature'")
        }
        guard let keyB64 = top["public_key_der"] as? String,
              let pubDER = Data(base64Encoded: keyB64) else {
            throw PluginInstallReceiptError.malformed("missing/invalid 'public_key_der'")
        }

        // Re-encode the parsed body into the SAME canonical form the signer
        // used, so verification is independent of the file's pretty-printing.
        let bodyData: Data
        do {
            bodyData = try JSONSerialization.data(withJSONObject: bodyObj)
        } catch {
            throw PluginInstallReceiptError.malformed("body not serializable: \(error)")
        }
        let body: PluginInstallReceiptBody
        do {
            body = try JSONDecoder().decode(PluginInstallReceiptBody.self, from: bodyData)
        } catch {
            throw PluginInstallReceiptError.malformed("body decode: \(error)")
        }
        let canonical = try body.canonicalBytes()

        // Verify the DER ECDSA-P256-SHA256 signature against the embedded key.
        let p256Key: P256.Signing.PublicKey
        do { p256Key = try P256.Signing.PublicKey(derRepresentation: pubDER) }
        catch { throw PluginInstallReceiptError.malformed("public key DER: \(error)") }
        let p256Sig: P256.Signing.ECDSASignature
        do { p256Sig = try P256.Signing.ECDSASignature(derRepresentation: signature) }
        catch { throw PluginInstallReceiptError.signatureInvalid }

        guard p256Key.isValidSignature(p256Sig, for: canonical) else {
            throw PluginInstallReceiptError.signatureInvalid
        }
        return body
    }
}
