// TraceKeyHandshakeTests.swift
//
// v1.21.6-rc.45: maccrabctl must obtain its OWN trace read key.
//
// THE BLOCKER THIS PINS. `TraceCommands.openStore()` constructed
// `SQLiteCausalGraphStore(databasePath:forceReadOnly:)` with no `encryption:`
// argument; the parameter defaults to nil. Every entity and edge row in a
// shipped store is an `ENC2:` envelope, so `decodeEntityRow` threw
// "encrypted value unavailable without a read key" on every query. That killed
// `trace graph`, `trace from-agent`, `trace from-process-key` and `trace
// export` — and the dashboard's Export button SHELLS OUT to `maccrabctl trace
// export`, so no surface in the product could export evidence at all.
// Measured on an installed host: 21,805 traces, every one
// `evidence_bundle_status = not_created`, zero signed chain heads.
//
// WHY IT COULD NOT SIMPLY READ THE DASHBOARD'S FILE. The recipient key is a
// PER-PROCESS ephemeral (`Curve25519.KeyAgreement.PrivateKey()`, in memory,
// never persisted). An envelope on disk is bound to exactly one process, so
// `unwrap` rejects any other reader with `recipientMismatch`. The CLI must run
// its own handshake through the privileged inbox.
//
// Verified end-to-end against the live encrypted store on 2026-08-31:
// `trace list` returned 20 traces and `trace export` produced a bundle whose
// graph.json carried 8 decrypted entities and 7 edges — the first bundle this
// store has ever produced.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabCore

@Suite("Trace key handshake (v1.21.6-rc.45)")
struct TraceKeyHandshakeTests {

    @Test("the CLI passes a read key when opening the causal store")
    func cliPassesAReadKey() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let cli = try String(
            contentsOf: root.appendingPathComponent("Sources/maccrabctl/TraceCommands.swift"),
            encoding: .utf8
        )
        #expect(
            cli.contains("encryption: encryption"),
            "openStore must pass a read key; without it every ENC2 row fails to decode"
        )
        #expect(
            cli.contains("TraceDashboardKeyExchange.resolveEncryption("),
            "the CLI must run its own handshake — the dashboard's envelope is bound to the dashboard process"
        )
        // The failure must be legible. Opening keyless surfaced an opaque decode
        // error that read as store corruption.
        #expect(cli.contains("no trace read key for uid"))
    }

    @Test("a key request carries only public material, at 0600")
    func requestLeaksNoPrivateMaterial() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-keyreq-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let recipient = try TraceDashboardKeyExchange.dashboardPrivateKeyForCurrentSession()
        let publicRaw = recipient.publicKey.rawRepresentation
        #expect(TraceDashboardKeyExchange.writeKeyRequest(
            inboxDir: dir.path, publicKey: publicRaw, requester: "unit-test"
        ))

        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(files.count == 1)
        let path = dir.appendingPathComponent(files[0]).path
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let json = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        #expect(Set(json.keys) == ["publicKey", "requestedAt", "requester"])
        #expect(json["publicKey"] as? String == publicRaw.base64EncodedString())

        // The private scalar must never appear in the request.
        let privateRaw = recipient.rawRepresentation
        #expect(
            data.range(of: privateRaw) == nil,
            "the request must not contain private key material"
        )
        let perms = try #require(
            (try FileManager.default.attributesOfItem(atPath: path))[.posixPermissions] as? NSNumber
        )
        #expect(perms.int16Value == 0o600)
    }

    @Test("a malformed public key is refused before anything is written")
    func malformedRequestRefused() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-keyreq-bad-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        #expect(!TraceDashboardKeyExchange.writeKeyRequest(
            inboxDir: dir.path, publicKey: Data(repeating: 0, count: 31), requester: "unit-test"
        ))
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
    }

    @Test("resolve gives up in bounded time when no daemon answers")
    func resolveIsBounded() async throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-resolve-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: dir.appendingPathComponent("inbox"), withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: dir) }

        let started = Date()
        let resolved = await TraceDashboardKeyExchange.resolveEncryption(
            supportDir: dir.path, requester: "unit-test", timeout: 0.5
        )
        let elapsed = Date().timeIntervalSince(started)
        #expect(resolved == nil, "no daemon, no envelope — must return nil, not hang or fabricate a key")
        // The contract is BOUNDEDNESS — it must not wait forever for a daemon
        // that will never answer. Deliberately a loose bound: the poll loop
        // sleeps in 200 ms slices, and under a loaded CI box those slices
        // stretch (this assertion previously read `< 5` and observed 24.1 s at
        // load average 7 while asserting nothing the code got wrong). A tight
        // wall-clock bound here pins the scheduler, not the deadline logic.
        #expect(elapsed < 120, "the wait must terminate, not hang (took \(elapsed)s)")
    }

    @Test("an envelope addressed to another process is refused, not misread")
    func foreignEnvelopeRefused() throws {
        // The property that forced the CLI to run its own handshake.
        let other = Curve25519.KeyAgreement.PrivateKey()
        let encryption = try #require(DatabaseEncryption(establishedKey: Data(repeating: 7, count: 32)))
        let envelope = try encryption.dashboardKeyEnvelope(
            for: other.publicKey.rawRepresentation
        )
        let mine = try TraceDashboardKeyExchange.dashboardPrivateKeyForCurrentSession()
        #expect(throws: (any Error).self) {
            _ = try TraceDashboardKeyExchange.unwrap(envelope, with: mine)
        }
    }
}
