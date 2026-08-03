// AgentSessionBundleTests.swift
//
// Wave-3 P3: a session bundle is a tamper-evident, optionally-signed
// black box. Pins that export→verify round-trips, that any content tamper
// breaks the Merkle root, and that the unsigned (no-key) path still
// produces a valid Merkle bundle.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("AgentSessionBundle")
struct AgentSessionBundleTests {

    private func tmp(_ tag: String) -> URL {
        URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("\(tag)-\(UUID().uuidString)")
    }

    @Test("export → verify round-trips; content tamper breaks the Merkle root")
    func roundTripAndTamper() async throws {
        let dir = tmp("sess-bundle")
        let keys = tmp("sess-keys")
        defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: keys) }
        // Force the no-entitlement CryptoKit path (WAVE3-02) so signing
        // ACTUALLY happens — the same override the MCP export handler uses.
        let ts = TrustSubstrate(storage: FilesystemTrustSubstrateStorage(baseDirectory: keys),
                                modeOverride: .filesystemDegraded)

        let res = try await AgentSessionBundle.export(
            sessionId: "S1",
            eventsJsonl: ["{\"seq\":1}", "{\"seq\":2}"],
            alertsJson: "[{\"rule\":\"x\"}]",
            mutationsJson: "[{\"op\":\"suppress\"}]",
            metadataJson: "{\"session_id\":\"S1\"}",
            to: dir, trustSubstrate: ts
        )
        #expect(!res.merkleRoot.isEmpty)
        #expect(res.signed)              // WAVE3-02: signing must succeed via filesystemDegraded
        #expect(res.signError == nil)

        let v = try await AgentSessionBundle.verify(at: dir, trustSubstrate: ts)
        #expect(v.merkleOk)
        #expect(v.signatureOk)
        #expect(v.signerIsLocalInstall)
        #expect(v.signerTrusted)
        #expect(v.authenticated)

        // Tamper a content file → the recomputed Merkle no longer matches
        // the signed root.
        try Data("tampered\n".utf8).write(to: dir.appendingPathComponent("events.jsonl"))
        let v2 = try await AgentSessionBundle.verify(at: dir, trustSubstrate: ts)
        #expect(!v2.merkleOk)
    }

    /// SEC-2: the forgery the audit called out — tamper content AND re-patch
    /// signature.json's merkle_root to match. Merkle alone (merkleOk) would
    /// pass, but the SIGNATURE is over the original root, so signatureOk must
    /// be false. This is exactly why a real signature (WAVE3-02) is required.
    @Test("forgery: re-patching the merkle_root to match tampered content is caught by the signature")
    func forgeryCaughtBySignature() async throws {
        let dir = tmp("sess-bundle-forge")
        let keys = tmp("sess-forge-keys")
        defer { try? FileManager.default.removeItem(at: dir); try? FileManager.default.removeItem(at: keys) }
        let ts = TrustSubstrate(storage: FilesystemTrustSubstrateStorage(baseDirectory: keys),
                                modeOverride: .filesystemDegraded)

        let res = try await AgentSessionBundle.export(
            sessionId: "S9", eventsJsonl: ["{\"seq\":1}"], alertsJson: "[]",
            mutationsJson: "[]", metadataJson: "{}", to: dir, trustSubstrate: ts)
        #expect(res.signed)

        // Attacker rewrites the timeline...
        try Data("{\"seq\":\"forged\"}\n".utf8).write(to: dir.appendingPathComponent("events.jsonl"))
        // ...and re-patches the stored merkle_root to the new content's root.
        let sigURL = dir.appendingPathComponent("integrity/signature.json")
        var sig = try JSONSerialization.jsonObject(with: Data(contentsOf: sigURL)) as! [String: Any]
        sig["merkle_root"] = try BundleMerkle.compute(forBundleAt: dir).merkleRoot
        try JSONSerialization.data(withJSONObject: sig, options: [.sortedKeys]).write(to: sigURL)

        let v = try await AgentSessionBundle.verify(at: dir, trustSubstrate: ts)
        #expect(v.merkleOk)          // attacker matched content↔root...
        #expect(!v.signatureOk)      // ...but the signature over the ORIGINAL root no longer verifies
        #expect(!v.authenticated)
    }

    @Test("foreign self-signer is self-consistent but untrusted unless explicitly pinned")
    func foreignSignerNeedsExternalTrustAnchor() async throws {
        let dir = tmp("sess-bundle-foreign")
        let foreignKeys = tmp("sess-foreign-keys")
        let localKeys = tmp("sess-local-keys")
        defer {
            try? FileManager.default.removeItem(at: dir)
            try? FileManager.default.removeItem(at: foreignKeys)
            try? FileManager.default.removeItem(at: localKeys)
        }
        let foreign = TrustSubstrate(
            storage: FilesystemTrustSubstrateStorage(baseDirectory: foreignKeys),
            modeOverride: .filesystemDegraded
        )
        let local = TrustSubstrate(
            storage: FilesystemTrustSubstrateStorage(baseDirectory: localKeys),
            modeOverride: .filesystemDegraded
        )

        let exported = try await AgentSessionBundle.export(
            sessionId: "S-foreign", eventsJsonl: ["{\"seq\":1}"], alertsJson: "[]",
            mutationsJson: "[]", metadataJson: "{}", to: dir, trustSubstrate: foreign
        )
        #expect(exported.signed)

        let unpinned = try await AgentSessionBundle.verify(at: dir, trustSubstrate: local)
        #expect(unpinned.merkleOk)
        #expect(unpinned.signatureOk, "the foreign signature is cryptographically valid")
        #expect(!unpinned.signerIsLocalInstall)
        #expect(!unpinned.signerTrusted, "a bundle-provided key is not its own trust anchor")
        #expect(!unpinned.authenticated)

        let foreignFingerprint = try await foreign.publicKeyFingerprint()
        let pinned = try await AgentSessionBundle.verify(
            at: dir,
            trustSubstrate: local,
            options: .init(pinnedKeyFingerprint: foreignFingerprint)
        )
        #expect(!pinned.signerIsLocalInstall)
        #expect(pinned.signerTrusted)
        #expect(pinned.authenticated, "an out-of-band expected fingerprint authenticates a foreign signer")

        let wrongPin = String(repeating: "0", count: 64)
        let rejected = try await AgentSessionBundle.verify(
            at: dir,
            trustSubstrate: local,
            options: .init(pinnedKeyFingerprint: wrongPin)
        )
        #expect(rejected.signatureOk)
        #expect(!rejected.signerTrusted)
        #expect(!rejected.authenticated)
    }

    @Test("rewrite + re-sign with an attacker key preserves integrity but fails authentication")
    func rewriteAndResignIsUntrusted() async throws {
        let dir = tmp("sess-bundle-resign")
        let legitimateKeys = tmp("sess-legitimate-keys")
        let attackerKeys = tmp("sess-attacker-keys")
        defer {
            try? FileManager.default.removeItem(at: dir)
            try? FileManager.default.removeItem(at: legitimateKeys)
            try? FileManager.default.removeItem(at: attackerKeys)
        }
        let legitimate = TrustSubstrate(
            storage: FilesystemTrustSubstrateStorage(baseDirectory: legitimateKeys),
            modeOverride: .filesystemDegraded
        )
        let attacker = TrustSubstrate(
            storage: FilesystemTrustSubstrateStorage(baseDirectory: attackerKeys),
            modeOverride: .filesystemDegraded
        )

        _ = try await AgentSessionBundle.export(
            sessionId: "S-resign", eventsJsonl: ["{\"seq\":1,\"command\":\"safe\"}"],
            alertsJson: "[]", mutationsJson: "[]", metadataJson: "{}",
            to: dir, trustSubstrate: legitimate
        )

        // The attacker replaces evidence, recomputes the root, and replaces
        // every signer-controlled integrity field with a fresh key/signature.
        try Data("{\"seq\":1,\"command\":\"attacker-rewrite\"}\n".utf8)
            .write(to: dir.appendingPathComponent("events.jsonl"))
        let forgedRoot = try BundleMerkle.compute(forBundleAt: dir).merkleRoot
        let forgedSignature = try await attacker.sign(Data(forgedRoot.utf8))
        let attackerPublicKey = try await attacker.publicKey()

        let signatureURL = dir.appendingPathComponent("integrity/signature.json")
        var signatureObject = try JSONSerialization.jsonObject(
            with: Data(contentsOf: signatureURL)
        ) as! [String: Any]
        signatureObject["merkle_root"] = forgedRoot
        signatureObject["signature_hex"] = forgedSignature
            .map { String(format: "%02x", $0) }.joined()
        signatureObject["public_key_fingerprint"] = attackerPublicKey.fingerprint
        try JSONSerialization.data(withJSONObject: signatureObject, options: [.sortedKeys])
            .write(to: signatureURL)
        try attackerPublicKey.derBytes.write(
            to: dir.appendingPathComponent("integrity/session-signing.pub")
        )

        let result = try await AgentSessionBundle.verify(at: dir, trustSubstrate: legitimate)
        #expect(result.merkleOk, "the attacker made content and Merkle root agree")
        #expect(result.signatureOk, "the attacker produced a valid signature with their own key")
        #expect(result.signerFingerprint == attackerPublicKey.fingerprint)
        #expect(!result.signerIsLocalInstall)
        #expect(!result.signerTrusted)
        #expect(!result.authenticated, "self-signed rewrite must never become authenticated evidence")
    }

    @Test("unsigned export still produces a valid, verifiable Merkle bundle")
    func unsignedBundle() async throws {
        let dir = tmp("sess-bundle-unsigned")
        defer { try? FileManager.default.removeItem(at: dir) }

        let res = try await AgentSessionBundle.export(
            sessionId: "S2", eventsJsonl: [], alertsJson: "[]",
            mutationsJson: "[]", metadataJson: "{}", to: dir, trustSubstrate: nil
        )
        #expect(!res.signed)

        let v = try await AgentSessionBundle.verify(at: dir, trustSubstrate: nil)
        #expect(v.merkleOk)
        #expect(!v.signed)
        #expect(!v.signerTrusted)
        #expect(!v.authenticated)
    }

    @Test("verification rejects symlinked evidence before reading it")
    func rejectsSymlinkedEvidence() async throws {
        let dir = tmp("sess-bundle-symlink")
        defer { try? FileManager.default.removeItem(at: dir) }
        _ = try await AgentSessionBundle.export(
            sessionId: "S-link", eventsJsonl: ["{\"seq\":1}"], alertsJson: "[]",
            mutationsJson: "[]", metadataJson: "{}", to: dir, trustSubstrate: nil
        )
        let events = dir.appendingPathComponent("events.jsonl")
        try FileManager.default.removeItem(at: events)
        try FileManager.default.createSymbolicLink(
            atPath: events.path,
            withDestinationPath: "/dev/zero"
        )

        await #expect(throws: SafeTraceArchiveExtractor.ExtractionError.self) {
            _ = try await AgentSessionBundle.verify(at: dir, trustSubstrate: nil)
        }
    }

    @Test("export refuses to overwrite an existing directory")
    func refusesExisting() async throws {
        let dir = tmp("sess-bundle-exists")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        await #expect(throws: (any Error).self) {
            try await AgentSessionBundle.export(
                sessionId: "S3", eventsJsonl: [], alertsJson: "[]",
                mutationsJson: "[]", metadataJson: "{}", to: dir, trustSubstrate: nil
            )
        }
    }

    @Test("export refuses a preplanted bundle-root symlink without touching its target")
    func refusesRootSymlink() async throws {
        let root = tmp("sess-bundle-root-link")
        let outside = root.appendingPathComponent("outside", isDirectory: true)
        let target = root.appendingPathComponent("session.maccrabsession")
        try FileManager.default.createDirectory(
            at: outside,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let sentinel = outside.appendingPathComponent("sentinel")
        try Data("unchanged".utf8).write(to: sentinel)
        try FileManager.default.createSymbolicLink(
            atPath: target.path,
            withDestinationPath: outside.path
        )

        await #expect(throws: (any Error).self) {
            _ = try await AgentSessionBundle.export(
                sessionId: "S-link-root",
                eventsJsonl: ["{\"seq\":1}"],
                alertsJson: "[]",
                mutationsJson: "[]",
                metadataJson: "{}",
                to: target,
                trustSubstrate: nil
            )
        }
        #expect(try String(contentsOf: sentinel, encoding: .utf8) == "unchanged")
        #expect(!FileManager.default.fileExists(
            atPath: outside.appendingPathComponent("manifest.json").path
        ))
    }
}
