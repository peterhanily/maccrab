// PluginInstallReceipt (O3b / S2-06) tests — sign a receipt, verify it
// offline, and confirm any tamper to the signed body breaks verification.
//
// Uses a filesystem-degraded TrustSubstrate over in-memory storage so CI runs
// without Secure Enclave.

import Testing
import Foundation
import MacCrabCore
@testable import MacCrabForensics

@Suite("PluginInstallReceipt (S2-06 signed install receipt)")
struct PluginInstallReceiptTests {

    private func makeSubstrate() -> TrustSubstrate {
        // Force filesystem-degraded so SE probing is skipped on CI hosts.
        TrustSubstrate(storage: InMemoryTrustSubstrateStorage(), modeOverride: .filesystemDegraded)
    }

    private func sampleBody() -> PluginInstallReceiptBody {
        PluginInstallReceiptBody(
            pluginID: "com.maccrab.hosts-collector",
            version: "1.2.0",
            artifactSHA256: String(repeating: "a", count: 64),
            signerPublicKeySHA256: String(repeating: "b", count: 64),
            catalogSerial: 42,
            revocationSerial: 7,
            appVersion: "1.19.0",
            timestamp: "2026-06-11T00:00:00Z"
        )
    }

    @Test("emit then verify round-trips the body")
    func emitVerifyRoundTrip() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-receipt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }

        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        let body = sampleBody()
        let url = try await store.emit(body)

        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(url.lastPathComponent == "com.maccrab.hosts-collector.receipt.json")

        let verified = try PluginInstallReceiptStore.verify(at: url)
        #expect(verified == body)
        #expect(verified.catalogSerial == 42)
        #expect(verified.revocationSerial == 7)
        #expect(verified.appVersion == "1.19.0")
    }

    @Test("verify offline uses only the receipt's embedded key")
    func verifyOfflineFromBytes() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-receipt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        let url = try await store.emit(sampleBody())
        let data = try Data(contentsOf: url)
        // Verify from bytes — no substrate, no file path dependency.
        let body = try PluginInstallReceiptStore.verify(data: data)
        #expect(body.pluginID == "com.maccrab.hosts-collector")
    }

    @Test("tampering with the signed body breaks verification")
    func tamperDetected() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-receipt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        let url = try await store.emit(sampleBody())

        // Load, mutate the artifact hash inside the signed body, rewrite.
        let data = try Data(contentsOf: url)
        var top = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var body = try #require(top["body"] as? [String: Any])
        body["artifact_sha256"] = String(repeating: "f", count: 64)  // swapped artifact
        top["body"] = body
        let tampered = try JSONSerialization.data(withJSONObject: top)

        // Verification must now FAIL (signature no longer matches the body).
        #expect(throws: PluginInstallReceiptError.self) {
            try PluginInstallReceiptStore.verify(data: tampered)
        }
    }

    @Test("tampering with the signature breaks verification")
    func tamperedSignatureDetected() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-receipt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        let url = try await store.emit(sampleBody())

        let data = try Data(contentsOf: url)
        var top = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        // Flip the signature to a different-but-well-formed base64 blob.
        top["signature"] = Data(repeating: 0x01, count: 70).base64EncodedString()
        let tampered = try JSONSerialization.data(withJSONObject: top)

        #expect(throws: PluginInstallReceiptError.self) {
            try PluginInstallReceiptStore.verify(data: tampered)
        }
    }

    @Test("missing fields → malformed")
    func malformedDetected() {
        let notAReceipt = Data(#"{"hello":"world"}"#.utf8)
        #expect(throws: PluginInstallReceiptError.self) {
            try PluginInstallReceiptStore.verify(data: notAReceipt)
        }
    }

    @Test("pinned verify accepts a receipt signed by the pinned key")
    func pinnedVerifyAcceptsMatchingKey() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-receipt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let substrate = makeSubstrate()
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: substrate)
        let url = try await store.emit(sampleBody())
        let hostKey = try await substrate.publicKey().derBytes
        let body = try PluginInstallReceiptStore.verify(at: url, pinnedPublicKeyDER: hostKey)
        #expect(body.catalogSerial == 42)
    }

    @Test("pinned verify REJECTS a well-signed receipt whose key isn't the pin (untrustedSigner)")
    func pinnedVerifyRejectsForeignKey() async throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-receipt-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        // Receipt is validly self-signed by an attacker substrate...
        let attacker = makeSubstrate()
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: attacker)
        let url = try await store.emit(sampleBody())
        // ...but the pin is a DIFFERENT host key. Unpinned verify still passes
        // (tamper-free) — pinned verify must reject as untrustedSigner.
        _ = try PluginInstallReceiptStore.verify(at: url)   // unpinned: tamper-free
        let hostKey = try await makeSubstrate().publicKey().derBytes
        do {
            _ = try PluginInstallReceiptStore.verify(at: url, pinnedPublicKeyDER: hostKey)
            Issue.record("pinned verify accepted a foreign-signed receipt")
        } catch let error as PluginInstallReceiptError {
            guard case .untrustedSigner = error else {
                Issue.record("expected .untrustedSigner, got \(error)")
                return
            }
        }
    }
}
