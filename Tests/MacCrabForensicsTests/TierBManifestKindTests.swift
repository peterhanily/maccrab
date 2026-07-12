// TierBManifest.kind (B1) — the manifest role field the hero plugin (posture-pro)
// is blocked on. Optional + back-compatible: existing manifests (no kind) decode
// to nil; "collector"/"analyzer" decode to their case.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("TierBManifest kind (B1)")
struct TierBManifestKindTests {

    static func decode(_ json: String) throws -> TierBManifest {
        try JSONDecoder().decode(TierBManifest.self, from: Data(json.utf8))
    }

    @Test("kind:collector decodes")
    func collector() throws {
        let m = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d","kind":"collector"}"#)
        #expect(m.kind == .collector)
    }

    @Test("kind:analyzer decodes")
    func analyzer() throws {
        let m = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d","kind":"analyzer"}"#)
        #expect(m.kind == .analyzer)
    }

    @Test("absent kind decodes to nil (back-compat with existing manifests)")
    func absent() throws {
        let m = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":1,"description":"d"}"#)
        #expect(m.kind == nil)
    }

    @Test("kind round-trips through encode/decode")
    func roundTrip() throws {
        let m = TierBManifest(id: "com.x.p", displayName: "P", version: "1.0",
                              schemaVersion: 1, description: "d", kind: .collector)
        let back = try JSONDecoder().decode(TierBManifest.self, from: JSONEncoder().encode(m))
        #expect(back.kind == .collector)
    }

    // MARK: - schemaVersion guard (D-02) — parity with PluginManifest

    @Test("schemaVersion 0 is rejected at decode")
    func schemaVersionZeroRejected() {
        #expect(throws: TierBManifest.ValidationError.schemaVersionMustBePositive(0)) {
            _ = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":0,"description":"d"}"#)
        }
    }

    @Test("negative schemaVersion is rejected at decode")
    func schemaVersionNegativeRejected() {
        #expect(throws: TierBManifest.ValidationError.schemaVersionMustBePositive(-3)) {
            _ = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":-3,"description":"d"}"#)
        }
    }

    @Test("absent schemaVersion is rejected at decode")
    func schemaVersionAbsentRejected() {
        #expect(throws: (any Error).self) {
            _ = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","description":"d"}"#)
        }
    }

    @Test("a valid schemaVersion loads")
    func schemaVersionValidLoads() throws {
        let m = try Self.decode(#"{"id":"com.x.p","displayName":"P","version":"1.0","schemaVersion":2,"description":"d"}"#)
        #expect(m.schemaVersion == 2)
    }
}
