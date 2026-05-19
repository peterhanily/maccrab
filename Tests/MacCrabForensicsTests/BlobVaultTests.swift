// BlobVault tests — AES-GCM round-trip, deterministic nonce
// derivation, file layout, has() / delete() semantics.

import Foundation
import CryptoKit
import Testing
@testable import MacCrabForensics

@Suite("BlobVault")
struct BlobVaultTests {

    private func tempLayout() -> CaseDirectoryLayout {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-blob-test-\(UUID().uuidString)")
        let id = "blob-case-1"
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: id)
        try? layout.createDirectoryStructure()
        return layout
    }

    private func freshKey() -> Data {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }

    @Test("store + load round-trip recovers the original bytes")
    func roundTrip() async throws {
        let layout = tempLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }

        let vault = try BlobVault(layout: layout, dek: freshKey())
        let original = Data("hello plugin platform world".utf8)
        let (sha, relpath) = try await vault.store(original)
        #expect(sha.count == 64)
        #expect(relpath.hasPrefix("vault/blobs/"))

        let loaded = try await vault.load(sha256: sha)
        #expect(loaded == original)
    }

    @Test("BlobVault rejects non-32-byte DEKs at init")
    func rejectsBadKey() {
        let layout = tempLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        #expect(throws: BlobVaultError.self) {
            _ = try BlobVault(layout: layout, dek: Data(repeating: 0, count: 16))
        }
    }

    @Test("Stored file lives at vault/blobs/<2-hex-prefix>/<sha256>")
    func filePathLayout() async throws {
        let layout = tempLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let vault = try BlobVault(layout: layout, dek: freshKey())
        let (sha, _) = try await vault.store(Data("path-test".utf8))

        let expected = layout.vaultRoot
            .appendingPathComponent(String(sha.prefix(2)))
            .appendingPathComponent(sha)
        #expect(FileManager.default.fileExists(atPath: expected.path))
    }

    @Test("has() reports false before store, true after, false after delete")
    func hasSemantics() async throws {
        let layout = tempLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let vault = try BlobVault(layout: layout, dek: freshKey())

        let payload = Data("has-test".utf8)
        let sha = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()

        let before = await vault.has(sha256: sha)
        #expect(before == false)

        _ = try await vault.store(payload)
        let mid = await vault.has(sha256: sha)
        #expect(mid == true)

        await vault.delete(sha256: sha)
        let after = await vault.has(sha256: sha)
        #expect(after == false)
    }

    @Test("Two stores of identical content produce byte-identical files (deterministic nonce)")
    func deterministicCiphertext() async throws {
        let layout = tempLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let key = freshKey()
        let vault1 = try BlobVault(layout: layout, dek: key)
        let payload = Data("same content twice".utf8)
        let (sha, _) = try await vault1.store(payload)
        let firstBytes = try Data(contentsOf: layout.blobPath(for: sha))

        // Delete and re-store from a freshly-constructed vault (same
        // key) to prove ciphertext equality across separate
        // invocations.
        await vault1.delete(sha256: sha)
        let vault2 = try BlobVault(layout: layout, dek: key)
        _ = try await vault2.store(payload)
        let secondBytes = try Data(contentsOf: layout.blobPath(for: sha))

        #expect(firstBytes == secondBytes)
    }

    @Test("Wrong key fails AES-GCM open with a CryptoKit error")
    func wrongKeyFailsOpen() async throws {
        let layout = tempLayout()
        defer { try? FileManager.default.removeItem(at: layout.caseDirectory) }
        let key1 = freshKey()
        let vault1 = try BlobVault(layout: layout, dek: key1)
        let (sha, _) = try await vault1.store(Data("secret".utf8))

        let key2 = freshKey()
        let vault2 = try BlobVault(layout: layout, dek: key2)
        await #expect(throws: (any Error).self) {
            _ = try await vault2.load(sha256: sha)
        }
    }
}

@Suite("CaseDirectoryLayout")
struct CaseDirectoryLayoutTests {

    @Test("Blob relpath is `vault/blobs/<2-hex>/<sha>`")
    func relpath() {
        let layout = CaseDirectoryLayout(
            casesRoot: URL(fileURLWithPath: "/tmp/x"),
            caseID: "y"
        )
        let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        #expect(layout.blobRelpath(for: sha) == "vault/blobs/ab/\(sha)")
    }

    @Test("createDirectoryStructure is idempotent")
    func createIdempotent() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-layout-\(UUID().uuidString)")
        let layout = CaseDirectoryLayout(casesRoot: root, caseID: "id-1")
        defer { try? FileManager.default.removeItem(at: root) }
        try layout.createDirectoryStructure()
        try layout.createDirectoryStructure()  // second call must not throw
        #expect(FileManager.default.fileExists(atPath: layout.vaultRoot.path))
        #expect(FileManager.default.fileExists(atPath: layout.snapshotsRoot.path))
    }
}
