// Ed25519 plugin manifest signing + verification tests.
//
// Covers the sign→verify round trip, the four rejection cases
// (untrusted key, revoked key, tampered manifest, tampered
// binary), and bundle-format errors. Plan §3.6 + §3.9.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("PluginSignatureVerifier")
struct PluginSignatureVerifierTests {

    static func freshBundle(
        manifest: Data = Data("{\"id\":\"test\",\"version\":\"1.0\"}".utf8),
        binary: Data = Data("#!/bin/sh\necho hi\n".utf8)
    ) throws -> PluginSignatureVerifier.BundleLayout {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("plugin-sig-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let layout = PluginSignatureVerifier.BundleLayout(bundleRoot: root)
        try manifest.write(to: URL(fileURLWithPath: layout.manifestPath))
        try binary.write(to: URL(fileURLWithPath: layout.binaryPath))
        return layout
    }

    @Test("sign + verify round trip succeeds")
    func signVerifyRoundTrip() throws {
        let bundle = try Self.freshBundle()
        defer { try? FileManager.default.removeItem(at: bundle.bundleRoot) }
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(bundle: bundle, privateKey: key)
        let keyHex = key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let trust = PluginSignatureVerifier.TrustStore(allowedKeyHexes: [keyHex])
        let manifest = try PluginSignatureVerifier.verify(bundle: bundle, trustStore: trust)
        #expect(!manifest.isEmpty)
    }

    @Test("untrusted publisher key is rejected")
    func untrustedKeyRejected() throws {
        let bundle = try Self.freshBundle()
        defer { try? FileManager.default.removeItem(at: bundle.bundleRoot) }
        try PluginSignatureVerifier.sign(
            bundle: bundle,
            privateKey: Curve25519.Signing.PrivateKey()
        )
        let trust = PluginSignatureVerifier.TrustStore(allowedKeyHexes: ["aa" + String(repeating: "00", count: 31)])
        do {
            _ = try PluginSignatureVerifier.verify(bundle: bundle, trustStore: trust)
            Issue.record("expected publisherKeyNotTrusted")
        } catch PluginSignatureVerifier.VerifyError.publisherKeyNotTrusted {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("revoked publisher key is rejected even when allowlisted")
    func revokedKeyRejected() throws {
        let bundle = try Self.freshBundle()
        defer { try? FileManager.default.removeItem(at: bundle.bundleRoot) }
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(bundle: bundle, privateKey: key)
        let keyHex = key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let trust = PluginSignatureVerifier.TrustStore(
            allowedKeyHexes: [keyHex],
            revokedKeyHexes: [keyHex]
        )
        do {
            _ = try PluginSignatureVerifier.verify(bundle: bundle, trustStore: trust)
            Issue.record("expected publisherKeyRevoked")
        } catch PluginSignatureVerifier.VerifyError.publisherKeyRevoked {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("tampered manifest fails verification")
    func tamperedManifestRejected() throws {
        let bundle = try Self.freshBundle()
        defer { try? FileManager.default.removeItem(at: bundle.bundleRoot) }
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(bundle: bundle, privateKey: key)
        try Data("{\"id\":\"tampered\"}".utf8)
            .write(to: URL(fileURLWithPath: bundle.manifestPath))
        let keyHex = key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let trust = PluginSignatureVerifier.TrustStore(allowedKeyHexes: [keyHex])
        do {
            _ = try PluginSignatureVerifier.verify(bundle: bundle, trustStore: trust)
            Issue.record("expected signatureMismatch")
        } catch PluginSignatureVerifier.VerifyError.signatureMismatch {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("tampered binary fails verification")
    func tamperedBinaryRejected() throws {
        let bundle = try Self.freshBundle()
        defer { try? FileManager.default.removeItem(at: bundle.bundleRoot) }
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(bundle: bundle, privateKey: key)
        // Modify binary post-sign.
        try Data("#!/bin/sh\necho TAMPERED\n".utf8)
            .write(to: URL(fileURLWithPath: bundle.binaryPath))
        let keyHex = key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        let trust = PluginSignatureVerifier.TrustStore(allowedKeyHexes: [keyHex])
        do {
            _ = try PluginSignatureVerifier.verify(bundle: bundle, trustStore: trust)
            Issue.record("expected signatureMismatch")
        } catch PluginSignatureVerifier.VerifyError.signatureMismatch {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("missing files report the right error")
    func missingFilesReportProperly() throws {
        let bundle = try Self.freshBundle()
        defer { try? FileManager.default.removeItem(at: bundle.bundleRoot) }
        // No signature yet.
        do {
            _ = try PluginSignatureVerifier.verify(
                bundle: bundle,
                trustStore: .researchEmpty
            )
            Issue.record("expected signatureMissing")
        } catch PluginSignatureVerifier.VerifyError.signatureMissing {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("canonical payload is stable across runs")
    func canonicalPayloadIsStable() {
        let manifestA = Data("{\"x\":1}".utf8)
        let binaryA = Data([0xFE, 0xED, 0xFA, 0xCF])
        let p1 = PluginSignatureVerifier.canonicalSignedPayload(
            manifestData: manifestA,
            binaryData: binaryA
        )
        let p2 = PluginSignatureVerifier.canonicalSignedPayload(
            manifestData: manifestA,
            binaryData: binaryA
        )
        #expect(p1 == p2)
        // Versioned prefix + 32 bytes manifest hash + 32 bytes
        // binary hash = 24 + 32 + 32 = 88 bytes.
        #expect(p1.count == 88)
        #expect(p1.starts(with: Data("maccrab-tierb-plugin-v1\n".utf8)))
    }
}
