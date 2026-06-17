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
}
