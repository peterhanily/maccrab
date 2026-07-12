// TierBIPC (Shape 2 Phase 2a) — the frozen host↔plugin wire contract. These pin
// the round-trip + the JSONL framing both the host runner and the (separate-
// session) plugin author build against, so the two sides can't silently drift.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("TierBIPC wire contract")
struct TierBIPCTests {

    static func enc<T: Encodable>(_ v: T) throws -> Data { try JSONEncoder().encode(v) }
    static func dec<T: Decodable>(_ t: T.Type, _ d: Data) throws -> T { try JSONDecoder().decode(t, from: d) }

    @Test("TierBCollectRequest round-trips")
    func requestRoundTrip() throws {
        let req = TierBCollectRequest(
            pluginID: "com.maccrab.forensics.posture-pro", pluginVersion: "1.0.0",
            scratchDir: "/tmp/scratch", windowStartUnix: 100, windowEndUnix: 200)
        let back = try Self.dec(TierBCollectRequest.self, Self.enc(req))
        #expect(back.protocolVersion == TierBIPC.protocolVersion)
        #expect(back.pluginID == "com.maccrab.forensics.posture-pro")
        #expect(back.scratchDir == "/tmp/scratch")
        #expect(back.windowStartUnix == 100 && back.windowEndUnix == 200)
    }

    @Test("artifact line round-trips through the tagged envelope (incl. nested JSONValue)")
    func artifactLineRoundTrip() throws {
        let dto = TierBArtifactDTO(
            contentType: "posture.score", summary: "Grade A",
            data: ["score": .integer(95), "nested": .object(["k": .array([.string("v")])])],
            privacyClass: "metadata", confidence: "high", sourcePath: "/etc/(untrusted)")
        let back = try Self.dec(TierBOutputLine.self, Self.enc(TierBOutputLine.artifact(dto)))
        guard case .artifact(let a) = back else { Issue.record("expected .artifact"); return }
        #expect(a.contentType == "posture.score")
        #expect(a.summary == "Grade A")
        #expect(a.privacyClass == "metadata")
        #expect(a.data["score"] == .integer(95))
        #expect(a.data["nested"] == .object(["k": .array([.string("v")])]))
        #expect(a.sourcePath == "/etc/(untrusted)")
    }

    @Test("result line round-trips and is distinguished from an artifact line")
    func resultLineRoundTrip() throws {
        let back = try Self.dec(TierBOutputLine.self, Self.enc(TierBOutputLine.result(
            TierBCollectResult(status: "ok", notes: ["scanned 7 controls"]))))
        guard case .result(let r) = back else { Issue.record("expected .result"); return }
        #expect(r.status == "ok")
        #expect(r.notes == ["scanned 7 controls"])
    }

    @Test("encoded output lines contain NO raw newline → newline-delimited framing is safe")
    func jsonlFramingIsNewlineSafe() throws {
        // A summary with an embedded newline must encode as \\n (0x5C 0x6E), never
        // a raw 0x0A, or the host's line-splitter would corrupt the stream.
        let line = TierBOutputLine.artifact(TierBArtifactDTO(
            contentType: "x", summary: "line one\nline two", data: ["s": .string("a\nb")]))
        let data = try Self.enc(line)
        #expect(!data.contains(0x0A))
    }

    // MARK: - protocolVersion enforcement (D-01)

    @Test("result line echoes the host protocolVersion and round-trips")
    func resultEchoesProtocolVersion() throws {
        let back = try Self.dec(TierBCollectResult.self, Self.enc(TierBCollectResult(status: "ok")))
        #expect(back.protocolVersion == TierBIPC.protocolVersion)
        #expect(back.status == "ok")
    }

    @Test("a result line echoing a MISMATCHED protocolVersion is a host-side hard error at decode")
    func mismatchedProtocolVersionRejected() {
        let json = Data(#"{"status":"ok","protocolVersion":999}"#.utf8)
        #expect(throws: TierBIPC.ProtocolError.versionMismatch(host: TierBIPC.protocolVersion, plugin: 999)) {
            _ = try JSONDecoder().decode(TierBCollectResult.self, from: json)
        }
    }

    @Test("an ABSENT protocolVersion is tolerated (back-compat with the bundled example collector)")
    func absentProtocolVersionTolerated() throws {
        let r = try JSONDecoder().decode(TierBCollectResult.self, from: Data(#"{"status":"ok"}"#.utf8))
        #expect(r.protocolVersion == TierBIPC.protocolVersion)
        #expect(r.status == "ok")
    }

    @Test("host read path drops a mismatched-version result line → no terminal result + a decode error")
    func parseRejectsMismatchedResultLine() {
        // The runner decodes each JSONL line as a TierBOutputLine; a result line
        // echoing a different protocolVersion fails to decode, so parseOutputLines
        // yields NO terminal result and counts a decode error — downstream the
        // bridge maps a missing result to CollectionResult status .error.
        let stdout = Data(#"{"kind":"result","result":{"status":"ok","protocolVersion":2}}"#.utf8) + Data([0x0A])
        let parsed = FirstPartyTierBRunner.parseOutputLines(stdout)
        #expect(parsed.result == nil)
        #expect(parsed.decodeErrors == 1)
    }
}
