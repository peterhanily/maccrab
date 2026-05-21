// TierBBootstrap tests — verify the auto-discovery + status
// surface used by `maccrabctl plugin daemon-status` and
// `run-all-installed`.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("TierBBootstrap")
struct TierBBootstrapTests {

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

    @Test("status returns empty + zeros when no plugins installed")
    func emptyState() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("bootstrap-empty-\(UUID().uuidString)")
        let installer = PluginInstaller(pluginsRoot: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let bootstrap = TierBBootstrap(installer: installer)
        let status = await bootstrap.refresh()
        #expect(status.verified.isEmpty)
        #expect(status.failed.isEmpty)
        #expect(status.trustedKeyCount == 0)
        #expect(status.revokedKeyCount == 0)
        #expect(status.allVerified)
    }

    @Test("status reports verified plugins")
    func verifiedPluginsReported() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.bootstrap.a",
            displayName: "a",
            version: "1.0",
            schemaVersion: 1,
            description: "a"
        )
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let bootstrap = TierBBootstrap(installer: installer)
        let status = await bootstrap.refresh()
        #expect(status.verified.count == 1)
        #expect(status.verified.first?.pluginID == "com.test.bootstrap.a")
        #expect(status.verified.first?.version == "1.0")
        #expect(status.failed.isEmpty)
        #expect(status.trustedKeyCount == 1)
    }

    @Test("status reports failed plugins on revoked key")
    func failedReported() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.bootstrap.revoked",
            displayName: "rev",
            version: "1.0",
            schemaVersion: 1,
            description: "rev"
        )
        let (src, hex) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        try await installer.revokeKey(hex)
        let bootstrap = TierBBootstrap(installer: installer)
        let status = await bootstrap.refresh()
        #expect(status.verified.isEmpty)
        #expect(status.failed.count == 1)
        #expect(status.failed.first?.pluginID == "com.test.bootstrap.revoked")
        #expect(!status.allVerified)
    }

    @Test("status caches; refresh forces re-verify")
    func cacheBehavior() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.bootstrap.cache",
            displayName: "cache",
            version: "1.0",
            schemaVersion: 1,
            description: "cache"
        )
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let bootstrap = TierBBootstrap(installer: installer)
        let s1 = await bootstrap.status(force: false)
        // Subsequent status() within the cache window returns the
        // same timestamp.
        let s2 = await bootstrap.status(force: false)
        #expect(s1.verifiedAt == s2.verifiedAt)
        // force: true allocates a new verification (different timestamp).
        try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        let s3 = await bootstrap.status(force: true)
        #expect(s3.verifiedAt > s1.verifiedAt)
    }

    @Test("status verified bundles' temp binaries are cleaned up")
    func tempBinariesCleanedUp() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.bootstrap.cleanup",
            displayName: "cleanup",
            version: "1.0",
            schemaVersion: 1,
            description: "cleanup"
        )
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        // Snapshot tmpdir before + after refresh.
        let tmpdir = NSTemporaryDirectory()
        let before = (try? FileManager.default.contentsOfDirectory(atPath: tmpdir)) ?? []
        let beforeVerified = before.filter { $0.hasPrefix("maccrab-tier-b-verified-") }
        let bootstrap = TierBBootstrap(installer: installer)
        _ = await bootstrap.refresh()
        let after = (try? FileManager.default.contentsOfDirectory(atPath: tmpdir)) ?? []
        let afterVerified = after.filter { $0.hasPrefix("maccrab-tier-b-verified-") }
        // The bootstrap shouldn't leak temp binaries.
        #expect(afterVerified.count == beforeVerified.count)
    }
}
