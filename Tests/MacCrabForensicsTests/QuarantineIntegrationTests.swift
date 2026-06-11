// Quarantine store + runtime-gate integration tests (O2, S2-03/04).
//
// Covers the end-to-end quarantine path against a real on-disk install:
//   - PluginInstaller.applyQuarantine round-trips through quarantine.json
//     (0o600), isQuarantined reflects it
//   - installed-then-revoked → reconcile marks quarantine WITHOUT deleting the
//     bundle (evidence preserved); TierBRegistry.resolve refuses to load it
//   - un-quarantine (empty list) lets a previously-quarantined plugin resolve
//     again
//   - the remote signed list AUGMENTS, doesn't replace, the local
//     revoked-keys.json (both lists coexist)

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("Quarantine (O2 store + runtime gate)")
struct QuarantineIntegrationTests {

    /// A fully-signed bundle with a proper-SemVer manifest and a runnable
    /// script binary (the quarantine gate fires before binary verification, so
    /// a script binary is sufficient to exercise it through install).
    static func signedSemverBundle(
        pluginID: String,
        version: String
    ) throws -> (sourceDir: URL, publicKeyHex: String) {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("quarantine-bundle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let manifest = TierBManifest(
            id: pluginID, displayName: "q", version: version,
            schemaVersion: 1, description: "q"
        )
        let manifestData = try JSONEncoder().encode(manifest)
        try manifestData.write(to: root.appendingPathComponent("manifest.json"))
        try Data("#!/bin/sh\necho test\n".utf8).write(to: root.appendingPathComponent("binary"))
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(
            bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: root),
            privateKey: key
        )
        let hex = key.publicKey.rawRepresentation.map { String(format: "%02x", $0) }.joined()
        return (root, hex)
    }

    static func freshInstaller() -> PluginInstaller {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("quarantine-root-\(UUID().uuidString)")
        return PluginInstaller(pluginsRoot: root)
    }

    static func record(id: String, version: String, serial: Int? = 4) -> PluginInstaller.QuarantineRecord {
        PluginInstaller.QuarantineRecord(
            pluginID: id, installedVersion: version,
            reason: "exfiltrated", code: "compromise",
            advisoryURL: "https://example.com/a",
            revocationsSerial: serial,
            quarantinedAt: "2026-06-11T00:00:00Z"
        )
    }

    // MARK: - Store round-trip

    @Test("applyQuarantine round-trips through quarantine.json")
    func quarantineRoundTrip() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        try await installer.applyQuarantine([Self.record(id: "com.a.one", version: "1.0.0")])
        let q = await installer.currentQuarantine()
        #expect(q.count == 1)
        #expect(q["com.a.one"]?.reason == "exfiltrated")
        #expect(q["com.a.one"]?.code == "compromise")
        #expect(q["com.a.one"]?.installedVersion == "1.0.0")
        #expect(q["com.a.one"]?.revocationsSerial == 4)
        #expect(q["com.a.one"]?.advisoryURL == "https://example.com/a")
        #expect(await installer.isQuarantined("com.a.one"))
        #expect(!(await installer.isQuarantined("com.b.two")))
    }

    @Test("quarantine.json is locked 0o600")
    func quarantineFileMode() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        try await installer.applyQuarantine([Self.record(id: "com.a.one", version: "1.0.0")])
        let path = (installer.pluginsRootPath as NSString).appendingPathComponent("quarantine.json")
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
        #expect(perms == 0o600)
    }

    @Test("applyQuarantine replaces the set (un-quarantine when absent)")
    func quarantineReplaces() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        try await installer.applyQuarantine([Self.record(id: "com.a.one", version: "1.0.0")])
        #expect(await installer.isQuarantined("com.a.one"))
        // Reconcile with an empty set → un-quarantine.
        try await installer.applyQuarantine([])
        #expect(!(await installer.isQuarantined("com.a.one")))
    }

    // MARK: - Runtime gate (installed → revoked → quarantined, not deleted)

    @Test("installed-then-revoked is quarantined, NOT deleted, and refuses load")
    func installedThenRevokedQuarantined() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let (src, _) = try Self.signedSemverBundle(pluginID: "com.test.q.victim", version: "1.0.0")
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)

        // The plugin is now installed + loadable. Simulate the revocation
        // reconciliation: a signed list revokes this id@1.0.0.
        let list = RaveRevocationList(
            formatVersion: "0", serial: 8, updatedAt: "x",
            revocations: [RaveRevocation(
                pluginID: "com.test.q.victim", scope: .singleVersion("1.0.0"),
                reason: "exfiltrated", code: "compromise",
                decidedAt: "x", decidedBy: ["peterhanily"]
            )]
        )
        let installed = (try await installer.list()).map {
            RevocationEnforcer.InstalledRef(
                pluginID: $0.pluginID,
                version: (try? TierBManifest.load(fromBundlePath: $0.installRoot))?.version ?? ""
            )
        }
        let records = RevocationEnforcer.reconcileQuarantine(installed: installed, against: list)
        try await installer.applyQuarantine(records)

        // Quarantined, with the in-effect serial recorded.
        #expect(await installer.isQuarantined("com.test.q.victim"))
        #expect((await installer.currentQuarantine())["com.test.q.victim"]?.revocationsSerial == 8)

        // The bundle is STILL ON DISK (quarantine ≠ delete).
        let bundlePath = (installer.pluginsRootPath as NSString)
            .appendingPathComponent("com.test.q.victim")
        #expect(FileManager.default.fileExists(atPath: bundlePath))
        // And it's still listed as installed.
        #expect((try await installer.list()).contains { $0.pluginID == "com.test.q.victim" })

        // TierBRegistry refuses to load it — gate fires before verification.
        let registry = TierBRegistry(installer: installer)
        do {
            _ = try await registry.resolve(pluginID: "com.test.q.victim")
            Issue.record("expected RegistryError.quarantined")
        } catch TierBRegistry.RegistryError.quarantined(let id, _) {
            #expect(id == "com.test.q.victim")
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("un-quarantine (list no longer revokes) lets resolve proceed again")
    func unquarantineReenables() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let (src, _) = try Self.signedSemverBundle(pluginID: "com.test.q.repaired", version: "1.0.0")
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)

        // Quarantine, then reconcile against an empty list → un-quarantine.
        try await installer.applyQuarantine([Self.record(id: "com.test.q.repaired", version: "1.0.0")])
        #expect(await installer.isQuarantined("com.test.q.repaired"))
        let emptyList = RaveRevocationList(formatVersion: "0", serial: 9, updatedAt: "x", revocations: [])
        let installed = (try await installer.list()).map {
            RevocationEnforcer.InstalledRef(
                pluginID: $0.pluginID,
                version: (try? TierBManifest.load(fromBundlePath: $0.installRoot))?.version ?? ""
            )
        }
        try await installer.applyQuarantine(
            RevocationEnforcer.reconcileQuarantine(installed: installed, against: emptyList)
        )
        #expect(!(await installer.isQuarantined("com.test.q.repaired")))
        // resolve now passes the quarantine gate (proceeds to verification,
        // which succeeds for this trusted+signed bundle).
        let registry = TierBRegistry(installer: installer)
        let plugin = try await registry.resolve(pluginID: "com.test.q.repaired")
        #expect(plugin.pluginID == "com.test.q.repaired")
        registry.cleanupVerifiedBinary(plugin)
    }

    @Test("remote quarantine AUGMENTS, doesn't replace, the local revoked-keys list")
    func augmentsLocalRevokedKeys() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        // Operator manually revokes a key.
        try await installer.revokeKey(String(repeating: "ab", count: 32))
        // Remote reconciliation quarantines a (different) plugin by id+version.
        try await installer.applyQuarantine([Self.record(id: "com.test.q.remote", version: "1.0.0")])
        // BOTH lists are intact — quarantine didn't touch revoked-keys.json.
        let revoked = await installer.currentRevokedKeys()
        #expect(revoked.contains(String(repeating: "ab", count: 32)))
        #expect(await installer.isQuarantined("com.test.q.remote"))
    }
}
