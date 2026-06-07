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
}
