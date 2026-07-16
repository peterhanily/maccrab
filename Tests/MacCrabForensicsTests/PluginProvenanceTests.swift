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

    @Test("a receipt signed by THIS host's key (catalog_serial) classifies as .store")
    func storeReceiptIsStore() async throws {
        let dir = freshDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let substrate = makeSubstrate()
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: substrate)
        _ = try await store.emit(body(id: "com.x.store", catalogSerial: 5))
        let hostKey = try await substrate.publicKey().derBytes
        #expect(PluginProvenance.forInstalled(
            pluginID: "com.x.store", receiptsDir: dir, pinnedPublicKeyDER: hostKey) == .store)
    }

    @Test("a host-signed receipt WITHOUT a catalog_serial classifies as .thirdParty (sideload)")
    func noCatalogSerialIsThirdParty() async throws {
        let dir = freshDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let substrate = makeSubstrate()
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: substrate)
        _ = try await store.emit(body(id: "com.x.side", catalogSerial: nil))
        let hostKey = try await substrate.publicKey().derBytes
        #expect(PluginProvenance.forInstalled(
            pluginID: "com.x.side", receiptsDir: dir, pinnedPublicKeyDER: hostKey) == .thirdParty)
    }

    @Test("a self/foreign-signed receipt with a catalog_serial does NOT become .store (pin rejects it)")
    func foreignSignedStoreReceiptDowngrades() async throws {
        let dir = freshDir(); defer { try? FileManager.default.removeItem(at: dir) }
        // Receipt is signed by an ATTACKER substrate (a self-signed "store"
        // receipt dropped into plugin_receipts/), but the pin is THIS host's key.
        let attacker = makeSubstrate()
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: attacker)
        _ = try await store.emit(body(id: "com.x.forged", catalogSerial: 9))
        let hostKey = try await makeSubstrate().publicKey().derBytes  // a different key
        #expect(PluginProvenance.forInstalled(
            pluginID: "com.x.forged", receiptsDir: dir, pinnedPublicKeyDER: hostKey) == .thirdParty)
    }

    @Test("no host pin key available → cannot establish .store → .thirdParty")
    func noPinKeyDowngrades() async throws {
        let dir = freshDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let store = PluginInstallReceiptStore(receiptsDir: dir, substrate: makeSubstrate())
        _ = try await store.emit(body(id: "com.x.unpinned", catalogSerial: 5))
        // No pinnedPublicKeyDER passed and no <dir>/../keys/trace-signing.pub on
        // disk → the host key can't be established → downgrade.
        #expect(PluginProvenance.forInstalled(pluginID: "com.x.unpinned", receiptsDir: dir) == .thirdParty)
    }

    @Test("no receipt at all classifies as .thirdParty (operator-trusted sideload)")
    func noReceiptIsThirdParty() async throws {
        let dir = freshDir()  // never created on disk
        let hostKey = try await makeSubstrate().publicKey().derBytes
        #expect(PluginProvenance.forInstalled(
            pluginID: "com.x.none", receiptsDir: dir, pinnedPublicKeyDER: hostKey) == .thirdParty)
    }
}
