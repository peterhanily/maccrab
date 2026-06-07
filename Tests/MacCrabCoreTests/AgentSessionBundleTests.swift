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
        let ts = TrustSubstrate(storage: FilesystemTrustSubstrateStorage(baseDirectory: keys))

        let res = try await AgentSessionBundle.export(
            sessionId: "S1",
            eventsJsonl: ["{\"seq\":1}", "{\"seq\":2}"],
            alertsJson: "[{\"rule\":\"x\"}]",
            mutationsJson: "[{\"op\":\"suppress\"}]",
            metadataJson: "{\"session_id\":\"S1\"}",
            to: dir, trustSubstrate: ts
        )
        #expect(!res.merkleRoot.isEmpty)

        let v = try await AgentSessionBundle.verify(at: dir, trustSubstrate: ts)
        #expect(v.merkleOk)
        if res.signed { #expect(v.signatureOk) }   // signature verifies when a key was available

        // Tamper a content file → the recomputed Merkle no longer matches
        // the signed root.
        try Data("tampered\n".utf8).write(to: dir.appendingPathComponent("events.jsonl"))
        let v2 = try await AgentSessionBundle.verify(at: dir, trustSubstrate: ts)
        #expect(!v2.merkleOk)
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
