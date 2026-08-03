// BlobVault — AES-GCM encrypted blob storage under <case>/vault/.
//
// Plan reference: §3.4 — "vault/blobs/<sha256-prefix>/<sha256> —
// AES-GCM encrypted, per-blob nonce."
//
// One BlobVault per open case; constructed by CaseManager and held
// alongside ArtifactStore for the lifetime of an unlocked case.

import Foundation
import CryptoKit

/// Encrypted blob storage. The DEK is the same 32-byte AES-256 key
/// applied to the case.sqlite SQLCipher store, so unlocking the
/// case unlocks the vault — no separate auth dance.
public actor BlobVault {

    private let layout: CaseDirectoryLayout
    private let key: SymmetricKey

    public init(layout: CaseDirectoryLayout, dek: Data) throws {
        guard dek.count == 32 else {
            throw BlobVaultError.malformedDEK(actualBytes: dek.count)
        }
        self.layout = layout
        self.key = SymmetricKey(data: dek)
    }

    /// Store a blob. Returns `(sha256, relpath)` so the caller can
    /// stamp `artifacts.sha256` + `artifacts.blob_relpath`. Path:
    ///     vault/blobs/<first-2-hex>/<sha256>
    ///
    /// File contents: AES-GCM combined ciphertext (12-byte RANDOM
    /// nonce + ciphertext + 16-byte tag).
    ///
    /// The nonce used to be the first 96 bits of the content sha256 so
    /// that two stores of the same content produced byte-identical
    /// files. That is a nonce-reuse hazard, not a dedup feature: a
    /// 96-bit truncation collides for DIFFERENT plaintexts at the ~2^48
    /// birthday bound, and two different blobs sealed under the SAME
    /// per-case key with the SAME nonce leak the GHASH authentication
    /// subkey — i.e. tag forgery inside the evidence vault. Collectors
    /// ingest attacker-influenced content (downloads, mail bodies,
    /// clipboard, quarantine records), so the attacker gets to choose
    /// the colliding plaintexts. Dedup is unaffected: it is keyed on the
    /// blob FILENAME (the sha256, unchanged) via `has(sha256:)`, and
    /// `load` reads the nonce out of `SealedBox.combined`, so blobs
    /// written by earlier builds still decrypt.
    @discardableResult
    public func store(_ data: Data) throws -> (sha256: String, relpath: String) {
        let digest = SHA256.hash(data: data)
        let sha = digest.map { String(format: "%02x", $0) }.joined()

        let sealed = try AES.GCM.seal(data, using: key)

        let destination = layout.blobPath(for: sha)
        // Make sure the prefix directory exists. createDirectory
        // is idempotent with intermediates.
        let parentDir = destination.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: parentDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )

        guard let combined = sealed.combined else {
            throw BlobVaultError.sealFailed
        }
        try combined.write(to: destination, options: [.atomic])
        // Lock down per-file perms; createDirectory's attributes
        // don't propagate to the file we just wrote.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: destination.path
        )

        return (sha, layout.blobRelpath(for: sha))
    }

    /// Load + decrypt a blob by sha256.
    public func load(sha256: String) throws -> Data {
        try Self.validateSHA256(sha256)
        let path = layout.blobPath(for: sha256)
        let encrypted = try Data(contentsOf: path)
        let box = try AES.GCM.SealedBox(combined: encrypted)
        let plaintext = try AES.GCM.open(box, using: key)
        let actual = SHA256.hash(data: plaintext)
            .map { String(format: "%02x", $0) }
            .joined()
        guard actual.caseInsensitiveCompare(sha256) == .orderedSame else {
            throw BlobVaultError.integrityMismatch(
                expectedSha256: sha256.lowercased(),
                actualSha256: actual
            )
        }
        return plaintext
    }

    /// `true` iff a blob with this sha256 has been previously
    /// stored in this vault. Callers use this for dedup-skip
    /// optimization before calling `store(_:)`.
    public func has(sha256: String) throws -> Bool {
        try Self.validateSHA256(sha256)
        return FileManager.default.fileExists(atPath: layout.blobPath(for: sha256).path)
    }

    /// Delete a blob if present. Idempotent: missing file is fine.
    public func delete(sha256: String) throws {
        try Self.validateSHA256(sha256)
        try? FileManager.default.removeItem(at: layout.blobPath(for: sha256))
    }

    /// `blobPath(for:)` is deliberately a lightweight layout helper, not a
    /// parser. Every API that accepts an externally sourced digest therefore
    /// validates before resolving it. Without this gate a value such as
    /// `../../manifest.json` escapes `vault/blobs/`; `delete` could unlink a
    /// file outside the vault and `has` became a filesystem-existence oracle.
    private static func validateSHA256(_ value: String) throws {
        let bytes = value.utf8
        guard bytes.count == 64,
              bytes.allSatisfy({ byte in
                  (byte >= 48 && byte <= 57) ||
                  (byte >= 65 && byte <= 70) ||
                  (byte >= 97 && byte <= 102)
              }) else {
            throw BlobVaultError.malformedSha256
        }
    }
}

public enum BlobVaultError: Error, CustomStringConvertible {
    case malformedDEK(actualBytes: Int)
    case malformedSha256
    case integrityMismatch(expectedSha256: String, actualSha256: String)
    case sealFailed

    public var description: String {
        switch self {
        case .malformedDEK(let n):
            return "BlobVault: DEK must be 32 bytes; got \(n)"
        case .malformedSha256:
            return "BlobVault: sha256 not a 64-hex-char string"
        case .integrityMismatch(let expected, let actual):
            return "BlobVault: decrypted content hash \(actual) does not match requested \(expected)"
        case .sealFailed:
            return "BlobVault: AES-GCM.seal produced no combined output"
        }
    }
}
