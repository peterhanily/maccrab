// PluginProvenance (v1.19.0) — classify an installed plugin's origin from its
// signed install receipt: a catalog_serial means rave-store-sourced; anything
// else is an operator-trusted third-party sideload. Built-ins are .builtIn.
//
// Uses a filesystem-degraded TrustSubstrate over in-memory storage so CI runs
// without Secure Enclave (mirrors PluginInstallReceiptTests).

import Testing
import Foundation
import MacCrabCore
@testable import MacCrabForensics

@Suite("PluginProvenance (v1.19.0 plugin origin badge)")
struct PluginProvenanceTests {

    private func makeSubstrate() -> TrustSubstrate {
        TrustSubstrate(storage: InMemoryTrustSubstrateStorage(), modeOverride: .filesystemDegraded)
    }

    private func body(id: String, catalogSerial: Int?) -> PluginInstallReceiptBody {
        PluginInstallReceiptBody(
            pluginID: id, version: "1.0.0",
            artifactSHA256: String(repeating: "a", count: 64),
            signerPublicKeySHA256: String(repeating: "b", count: 64),
            catalogSerial: catalogSerial, revocationSerial: 1,
            appVersion: "1.19.0", timestamp: "2026-06-15T00:00:00Z")
    }

    private func freshDir() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("maccrab-prov-\(UUID().uuidString)")
    }

    @Test("enum rawValues + display names are stable (UI/MCP/CLI contract)")
    func enumShape() {
        #expect(PluginProvenance.builtIn.rawValue == "built-in")
        #expect(PluginProvenance.thirdParty.rawValue == "third-party")
        #expect(PluginProvenance.store.rawValue == "store")
        #expect(PluginProvenance.store.displayName == "Store")
        #expect(PluginProvenance.allCases.count == 3)
    }

    @Test("a signed catalog receipt (carries catalog_serial) classifies as .store")
    func storeReceiptIsStore() async throws {
        let dir = freshDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        _ = try await store.emit(body(id: "com.x.store", catalogSerial: 5))
        #expect(PluginProvenance.forInstalled(pluginID: "com.x.store", receiptsDir: dir) == .store)
    }

    @Test("a signed receipt WITHOUT a catalog_serial classifies as .thirdParty (sideload)")
    func noCatalogSerialIsThirdParty() async throws {
        let dir = freshDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        _ = try await store.emit(body(id: "com.x.side", catalogSerial: nil))
        #expect(PluginProvenance.forInstalled(pluginID: "com.x.side", receiptsDir: dir) == .thirdParty)
    }

    @Test("no receipt at all classifies as .thirdParty (operator-trusted sideload)")
    func noReceiptIsThirdParty() {
        let dir = freshDir()  // never created on disk
        #expect(PluginProvenance.forInstalled(pluginID: "com.x.none", receiptsDir: dir) == .thirdParty)
    }
}
