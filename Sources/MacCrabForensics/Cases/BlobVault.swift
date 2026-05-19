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
    /// File contents: AES-GCM combined ciphertext (12-byte nonce +
    /// ciphertext + 16-byte tag). Per plan §3.4 the nonce is
    /// derived from the sha256 so two stores of the same content
    /// produce byte-identical files — useful for dedup-driven
    /// retention enforcement later.
    @discardableResult
    public func store(_ data: Data) throws -> (sha256: String, relpath: String) {
        let digest = SHA256.hash(data: data)
        let sha = digest.map { String(format: "%02x", $0) }.joined()

        let nonce = try Self.nonce(for: sha)
        let sealed = try AES.GCM.seal(data, using: key, nonce: nonce)

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
        let path = layout.blobPath(for: sha256)
        let encrypted = try Data(contentsOf: path)
        let box = try AES.GCM.SealedBox(combined: encrypted)
        return try AES.GCM.open(box, using: key)
    }

    /// `true` iff a blob with this sha256 has been previously
    /// stored in this vault. Callers use this for dedup-skip
    /// optimization before calling `store(_:)`.
    public func has(sha256: String) -> Bool {
        FileManager.default.fileExists(atPath: layout.blobPath(for: sha256).path)
    }

    /// Delete a blob if present. Idempotent: missing file is fine.
    public func delete(sha256: String) {
        try? FileManager.default.removeItem(at: layout.blobPath(for: sha256))
    }

    // MARK: - Nonce derivation

    /// AES-GCM nonces are 12 bytes. Per plan §3.4 we derive the
    /// nonce from the blob's sha256 so identical content produces
    /// identical ciphertext on storage — the dedup property the
    /// plan asks for. Two-key + nonce reuse would be catastrophic
    /// in AES-GCM, but the key+nonce pair is content-derived so
    /// the only way to hit a collision is to encrypt the SAME
    /// content twice (which is fine — same plaintext, same
    /// ciphertext, no information leaked beyond "this content
    /// exists").
    private static func nonce(for sha256Hex: String) throws -> AES.GCM.Nonce {
        // Take the first 24 hex chars (12 bytes) of the sha256.
        let prefix = String(sha256Hex.prefix(24))
        guard prefix.count == 24 else {
            throw BlobVaultError.malformedSha256
        }
        var bytes = [UInt8]()
        var i = prefix.startIndex
        while i < prefix.endIndex {
            let next = prefix.index(i, offsetBy: 2)
            guard let b = UInt8(prefix[i..<next], radix: 16) else {
                throw BlobVaultError.malformedSha256
            }
            bytes.append(b)
            i = next
        }
        return try AES.GCM.Nonce(data: bytes)
    }
}

public enum BlobVaultError: Error, CustomStringConvertible {
    case malformedDEK(actualBytes: Int)
    case malformedSha256
    case sealFailed

    public var description: String {
        switch self {
        case .malformedDEK(let n):
            return "BlobVault: DEK must be 32 bytes; got \(n)"
        case .malformedSha256:
            return "BlobVault: sha256 not a 64-hex-char string"
        case .sealFailed:
            return "BlobVault: AES-GCM.seal produced no combined output"
        }
    }
}
