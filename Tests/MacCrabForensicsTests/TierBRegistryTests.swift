// TierBRegistry + sandbox enforcement tests.
//
// Live test exercises the full chain: install signed bundle →
// verify → load manifest → spawn under sandbox profile → assert
// probe artifact reflects sandbox enforcement.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("TierBRegistry + sandbox enforcement")
struct TierBRegistryTests {

    static var fixtureBinaryPath: String? {
        let candidates = [
            ".build/debug/tier-b-fixture-plugin",
            ".build/release/tier-b-fixture-plugin",
        ]
        let fm = FileManager.default
        for c in candidates where fm.isExecutableFile(atPath: c) {
            return c
        }
        return nil
    }

    /// Build a fully-signed Tier B bundle in a fresh temp dir
    /// with the supplied manifest. Returns the bundle source +
    /// the publisher hex.
    static func signedBundle(
        manifest: TierBManifest,
        binaryPath: String
    ) throws -> (sourceDir: URL, publicKeyHex: String) {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tierb-registry-bundle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let manifestData = try JSONEncoder().encode(manifest)
        try manifestData.write(to: root.appendingPathComponent("manifest.json"))
        try FileManager.default.copyItem(
            atPath: binaryPath,
            toPath: root.appendingPathComponent("binary").path
        )
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(
            bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: root),
            privateKey: key
        )
        let hex = key.publicKey.rawRepresentation
            .map { String(format: "%02x", $0) }.joined()
        return (root, hex)
    }

    static func freshInstaller() -> PluginInstaller {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tierb-registry-root-\(UUID().uuidString)")
        return PluginInstaller(pluginsRoot: root)
    }

    @Test("resolve succeeds for a verified installed plugin")
    func resolveVerifiedInstalled() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let manifest = TierBManifest(
            id: "com.test.tier-b.basic",
            displayName: "test",
            version: "1.0",
            schemaVersion: 1,
            description: "test"
        )
        let (src, _) = try Self.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)
        let plugin = try await registry.resolve(pluginID: "com.test.tier-b.basic")
        #expect(plugin.pluginID == "com.test.tier-b.basic")
        #expect(plugin.manifest.version == "1.0")
    }

    @Test("resolve refuses revoked plugin")
    func resolveRefusesRevoked() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let manifest = TierBManifest(
            id: "com.test.tier-b.revoked",
            displayName: "test",
            version: "1.0",
            schemaVersion: 1,
            description: "test"
        )
        let (src, hex) = try Self.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        try await installer.revokeKey(hex)
        let registry = TierBRegistry(installer: installer)
        do {
            _ = try await registry.resolve(pluginID: "com.test.tier-b.revoked")
            Issue.record("expected verification failure on revoked key")
        } catch TierBRegistry.RegistryError.verificationFailed {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("verifyAll reports verified + failed buckets")
    func verifyAllReports() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }

        // Install two; revoke one.
        let m1 = TierBManifest(id: "com.test.tier-b.a", displayName: "a", version: "1", schemaVersion: 1, description: "a")
        let (src1, _) = try Self.signedBundle(manifest: m1, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src1) }
        _ = try await installer.install(sourceDir: src1, trustOnInstall: true)

        let m2 = TierBManifest(id: "com.test.tier-b.b", displayName: "b", version: "1", schemaVersion: 1, description: "b")
        let (src2, hex2) = try Self.signedBundle(manifest: m2, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src2) }
        _ = try await installer.install(sourceDir: src2, trustOnInstall: true)
        try await installer.revokeKey(hex2)

        let registry = TierBRegistry(installer: installer)
        let report = await registry.verifyAll()
        #expect(report.total == 2)
        #expect(report.verified.count == 1)
        #expect(report.failed.count == 1)
        #expect(report.verified.first?.pluginID == "com.test.tier-b.a")
        #expect(report.failed.first?.pluginID == "com.test.tier-b.b")
    }

    @Test("runCollectAndCommit enforces manifest sandbox: /etc denied without allow")
    func sandboxBlocksEtcByDefault() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let manifest = TierBManifest(
            id: "com.test.tier-b.sandbox-strict",
            displayName: "strict",
            version: "1.0",
            schemaVersion: 1,
            description: "strict",
            fileReadSubpaths: []   // no allowances
        )
        let (src, _) = try Self.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)

        let storeRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tierb-sandbox-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: storeRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: storeRoot) }
        let layout = CaseDirectoryLayout(
            casesRoot: storeRoot,
            caseID: "tier-b-sandbox-case"
        )
        try FileManager.default.createDirectory(at: layout.caseDirectory, withIntermediateDirectories: true)
        let store = try await ArtifactStore(
            path: layout.sqliteFile.path,
            dek: nil,
            encryptionState: .plaintext
        )
        try await store.insertCase(CaseRecord(
            id: "tier-b-sandbox-case",
            name: "tier-b-sandbox-case",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        let (committed, _, _) = try await registry.runCollectAndCommit(
            pluginID: "com.test.tier-b.sandbox-strict",
            caseID: "tier-b-sandbox-case",
            caseName: "tier-b-sandbox-case",
            encryptionState: .plaintext,
            store: store,
            tickCount: 1,
            probeRead: "/private/etc/hosts"
        )
        #expect(committed == 2)
        // Inspect the probe artifact to confirm readable=false.
        let arts = try await store.query(ArtifactQuery(
            caseID: "tier-b-sandbox-case",
            contentType: "tier_b_fixture.probe_read",
            limit: 10
        ))
        #expect(arts.count == 1)
        let dataJSON = arts.first?.record.data["readable_inside_subprocess"]
        #expect(dataJSON == JSONValue.bool(false), "Sandbox should block /private/etc/hosts read")
    }

    @Test("runCollectAndCommit honors manifest fileReadSubpaths: /etc allowed")
    func sandboxAllowsManifestDeclaredEtc() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let manifest = TierBManifest(
            id: "com.test.tier-b.sandbox-allows-etc",
            displayName: "etc-allowed",
            version: "1.0",
            schemaVersion: 1,
            description: "etc-allowed",
            fileReadSubpaths: ["/private/etc"]
        )
        let (src, _) = try Self.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)

        let storeRoot = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tierb-sandbox-allow-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: storeRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: storeRoot) }
        let layout = CaseDirectoryLayout(casesRoot: storeRoot, caseID: "tier-b-sandbox-allow-case")
        try FileManager.default.createDirectory(at: layout.caseDirectory, withIntermediateDirectories: true)
        let store = try await ArtifactStore(
            path: layout.sqliteFile.path,
            dek: nil,
            encryptionState: .plaintext
        )
        try await store.insertCase(CaseRecord(
            id: "tier-b-sandbox-allow-case",
            name: "tier-b-sandbox-allow-case",
            createdAt: Date(),
            encryptionState: .plaintext
        ))
        let (_, _, _) = try await registry.runCollectAndCommit(
            pluginID: "com.test.tier-b.sandbox-allows-etc",
            caseID: "tier-b-sandbox-allow-case",
            caseName: "tier-b-sandbox-allow-case",
            encryptionState: .plaintext,
            store: store,
            tickCount: 1,
            probeRead: "/private/etc/hosts"
        )
        let arts = try await store.query(ArtifactQuery(
            caseID: "tier-b-sandbox-allow-case",
            contentType: "tier_b_fixture.probe_read",
            limit: 10
        ))
        #expect(arts.count == 1)
        let dataJSON = arts.first?.record.data["readable_inside_subprocess"]
        #expect(dataJSON == JSONValue.bool(true), "Manifest allowlist for /private/etc should override baseline deny")
    }
}
