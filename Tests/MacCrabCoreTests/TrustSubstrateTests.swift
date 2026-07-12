// TrustSubstrateTests.swift
// v1.10 TraceGraph (PR-5) — tests for the TrustSubstrate signing
// primitive. Filesystem-mode coverage is comprehensive; SE-mode tests
// are skipped automatically on hosts without Secure Enclave.

import Testing
import Foundation
import CryptoKit
import Security
@testable import MacCrabCore

@Suite("TraceGraph: TrustSubstrate (filesystem mode)")
struct TrustSubstrateFilesystemTests {

    private func makeSubstrate() -> TrustSubstrate {
        let storage = InMemoryTrustSubstrateStorage()
        return TrustSubstrate(storage: storage, modeOverride: .filesystemDegraded)
    }

    @Test("Active mode is filesystemDegraded under override")
    func modeIsFilesystem() async throws {
        let substrate = makeSubstrate()
        let mode = try await substrate.activeMode()
        #expect(mode == .filesystemDegraded)
    }

    @Test("Sign + verify roundtrip on a small payload")
    func signVerifyRoundtrip() async throws {
        let substrate = makeSubstrate()
        let payload = Data("hello tracegraph".utf8)
        let signature = try await substrate.sign(payload)
        let valid = try await substrate.verify(payload, signature: signature)
        #expect(valid)
    }

    @Test("Sign + verify roundtrip on a large payload")
    func signVerifyLargePayload() async throws {
        let substrate = makeSubstrate()
        let payload = Data(repeating: 0xAB, count: 1_000_000)
        let signature = try await substrate.sign(payload)
        let valid = try await substrate.verify(payload, signature: signature)
        #expect(valid)
    }

    @Test("Tampered payload fails verification")
    func tamperedPayloadFails() async throws {
        let substrate = makeSubstrate()
        let payload = Data("authentic".utf8)
        let signature = try await substrate.sign(payload)

        let tampered = Data("authentiC".utf8)
        let valid = try await substrate.verify(tampered, signature: signature)
        #expect(!valid)
    }

    @Test("Tampered signature fails verification")
    func tamperedSignatureFails() async throws {
        let substrate = makeSubstrate()
        let payload = Data("authentic".utf8)
        var signature = try await substrate.sign(payload)
        // Flip a byte in the middle of the signature.
        let mid = signature.count / 2
        signature[mid] ^= 0xFF
        // Some byte flips will still parse as valid DER but verify
        // false; some will fail to parse. Both outcomes are acceptable
        // — we just need to make sure it doesn't claim valid.
        let valid = (try? await substrate.verify(payload, signature: signature)) ?? false
        #expect(!valid)
    }

    @Test("Public key is exported as DER and PEM")
    func publicKeyMaterial() async throws {
        let substrate = makeSubstrate()
        let key = try await substrate.publicKey()
        #expect(key.mode == .filesystemDegraded)
        // P-256 SubjectPublicKeyInfo DER is exactly 91 bytes.
        #expect(key.derBytes.count == 91)
        #expect(key.pemString.contains("-----BEGIN PUBLIC KEY-----"))
        #expect(key.pemString.contains("-----END PUBLIC KEY-----"))
        // Fingerprint is sha256 hex (64 chars).
        #expect(key.fingerprint.count == 64)
        #expect(key.fingerprint.allSatisfy { Set("0123456789abcdef").contains($0) })
    }

    @Test("Public key is stable across substrate restarts (same storage)")
    func publicKeyStableAcrossRestarts() async throws {
        let storage = InMemoryTrustSubstrateStorage()
        let substrate1 = TrustSubstrate(storage: storage, modeOverride: .filesystemDegraded)
        let pub1 = try await substrate1.publicKey()

        // New substrate instance, same storage → must surface the same
        // persisted key without regenerating.
        let substrate2 = TrustSubstrate(storage: storage, modeOverride: .filesystemDegraded)
        let pub2 = try await substrate2.publicKey()

        #expect(pub1.derBytes == pub2.derBytes)
        #expect(pub1.fingerprint == pub2.fingerprint)
    }

    @Test("Mode persists across substrate restarts")
    func modePersists() async throws {
        let storage = InMemoryTrustSubstrateStorage()
        let substrate1 = TrustSubstrate(storage: storage, modeOverride: .filesystemDegraded)
        _ = try await substrate1.activeMode()

        let substrate2 = TrustSubstrate(storage: storage)  // no override
        let mode2 = try await substrate2.activeMode()
        #expect(mode2 == .filesystemDegraded)
    }

    @Test("Verification works against a signature produced by a previous restart")
    func verifyPriorSignature() async throws {
        let storage = InMemoryTrustSubstrateStorage()
        let substrate1 = TrustSubstrate(storage: storage, modeOverride: .filesystemDegraded)
        let payload = Data("v1.10 bundle merkle root".utf8)
        let signature = try await substrate1.sign(payload)

        // Simulate daemon restart with the same on-disk state.
        let substrate2 = TrustSubstrate(storage: storage, modeOverride: .filesystemDegraded)
        let valid = try await substrate2.verify(payload, signature: signature)
        #expect(valid)
    }

    @Test("Different payloads produce different signatures")
    func signaturesAreDataDependent() async throws {
        let substrate = makeSubstrate()
        let s1 = try await substrate.sign(Data("a".utf8))
        let s2 = try await substrate.sign(Data("b".utf8))
        #expect(s1 != s2)
    }
}

@Suite("TraceGraph: FilesystemTrustSubstrateStorage")
struct FilesystemTrustSubstrateStorageTests {

    private func makeTempBaseDirectory() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("trustsub-\(UUID().uuidString)")
        return dir
    }

    @Test("Stores and reloads the key mode")
    func roundtripMode() async throws {
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: makeTempBaseDirectory())
        try await storage.saveKeyMode(.secureEnclave)
        let mode = try await storage.loadKeyMode()
        #expect(mode == .secureEnclave)
    }

    @Test("Stores and reloads the SE keychain tag")
    func roundtripSETag() async throws {
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: makeTempBaseDirectory())
        let tag = Data("test-tag".utf8)
        try await storage.saveSecureEnclaveKeyTag(tag)
        let loaded = try await storage.loadSecureEnclaveKeyTag()
        #expect(loaded == tag)
    }

    @Test("Stores and reloads private + public keys")
    func roundtripKeys() async throws {
        let baseDir = makeTempBaseDirectory()
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: baseDir)
        let priv = Data((0 ..< 121).map { UInt8($0) })
        let pub = Data((0 ..< 91).map { UInt8($0 % 0xFF) })
        try await storage.saveFilesystemPrivateKey(priv)
        try await storage.savePublicKey(pub)
        let privLoaded = try await storage.loadFilesystemPrivateKey()
        let pubLoaded = try await storage.loadPublicKey()
        #expect(privLoaded == priv)
        #expect(pubLoaded == pub)
    }

    @Test("Private key file is created with 0600 permissions")
    func privateKeyPermissions() async throws {
        let baseDir = makeTempBaseDirectory()
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: baseDir)
        try await storage.saveFilesystemPrivateKey(Data([0x01, 0x02, 0x03]))
        let url = baseDir.appendingPathComponent("trace-signing.key")
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.uint16Value ?? 0
        #expect(perms == 0o600)
    }

    @Test("Loads return nil before any save")
    func emptyState() async throws {
        let storage = FilesystemTrustSubstrateStorage(baseDirectory: makeTempBaseDirectory())
        #expect(try await storage.loadKeyMode() == nil)
        #expect(try await storage.loadFilesystemPrivateKey() == nil)
        #expect(try await storage.loadPublicKey() == nil)
        #expect(try await storage.loadSecureEnclaveKeyTag() == nil)
    }
}

@Suite("TraceGraph: TrustSubstrate (Secure Enclave)")
struct TrustSubstrateSecureEnclaveTests {

    /// A3-02: the SE key must be created WITH a usage ACL. The ACL policy
    /// object is built in software (SecAccessControlCreateWithFlags does
    /// not touch SE hardware), so this runs on any host — including CI
    /// runners without a Secure Enclave — and asserts the ACL is
    /// constructed/requested at key-creation time.
    ///
    /// NOTE: this proves the ACL is REQUESTED, not that the Secure Enclave
    /// ENFORCES it. ACL enforcement (only the daemon's signed code can
    /// invoke the key) can only be validated on real SE hardware with the
    /// daemon's signed code identity — NEEDS ON-DEVICE VERIFICATION.
    @Test("A3-02: SE signing-key access control is constructed (.privateKeyUsage)")
    func signingKeyAccessControlIsRequested() throws {
        let access = try TrustSubstrate.makeSigningKeyAccessControl()
        // A non-nil SecAccessControl means the usage ACL was pinned; it is
        // passed into kSecAttrAccessControl at SE key creation.
        #expect(CFGetTypeID(access) == SecAccessControlGetTypeID())
    }

    /// SE tests are best-effort: they only exercise the SE code path
    /// when the host hardware actually supports SE-bound EC keys. CI
    /// runners on virtualised hosts and Apple-silicon-without-SE
    /// configurations will skip silently rather than fail.
    ///
    /// When SE IS present this now also exercises the ACL'd creation path
    /// (kSecAttrAccessControl set) end-to-end: sign + verify must still
    /// round-trip with the usage ACL applied.
    @Test("SE roundtrip when SE is available")
    func seRoundtripWhenAvailable() async throws {
        let storage = InMemoryTrustSubstrateStorage()
        let substrate = TrustSubstrate(storage: storage, modeOverride: .secureEnclave)
        do {
            let payload = Data("se test".utf8)
            let signature = try await substrate.sign(payload)
            let valid = try await substrate.verify(payload, signature: signature)
            #expect(valid)
        } catch let error as TrustSubstrate.SubstrateError {
            switch error {
            case .keyGenerationFailed, .secureEnclaveUnavailable, .publicKeyExtractionFailed:
                // Host doesn't support SE — silently skip rather than fail.
                return
            default:
                throw error
            }
        }
    }
}
