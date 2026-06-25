// PluginInstaller install/trust/revoke tests.
//
// Covers the operator workflow:
//   - install with --trust-on-install succeeds
//   - install without trust fails
//   - reinstall without --force fails
//   - reinstall with --force succeeds
//   - revoke key blocks re-install even with trust-on-install
//   - uninstall + list

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("PluginInstaller")
struct PluginInstallerTests {

    /// Build a freshly-signed bundle directory + return its URL
    /// plus the publisher key's hex.
    static func freshSignedBundle(
        pluginID: String = "com.test.tier-b.fixture"
    ) throws -> (sourceDir: URL, publicKeyHex: String) {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("installer-source-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let manifest = "{\"id\":\"\(pluginID)\",\"version\":\"1.0\"}"
        try Data(manifest.utf8).write(to: root.appendingPathComponent("manifest.json"))
        try Data("#!/bin/sh\necho test\n".utf8).write(to: root.appendingPathComponent("binary"))
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
            .appendingPathComponent("installer-root-\(UUID().uuidString)")
        return PluginInstaller(pluginsRoot: root)
    }

    @Test("install without trust fails")
    func installWithoutTrustFails() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: false)
            Issue.record("expected verifyFailed (publisherKeyNotTrusted)")
        } catch PluginInstaller.InstallError.verifyFailed {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("install with --trust-on-install succeeds + records trust")
    func installWithTrustOnInstall() async throws {
        let (src, hex) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let installed = try await installer.install(sourceDir: src, trustOnInstall: true)
        #expect(installed.pluginID == "com.test.tier-b.fixture")
        #expect(installed.publicKeyHex == hex)
        let trusted = await installer.currentTrustedKeys()
        #expect(trusted.contains(hex))
        let list = try await installer.list()
        #expect(list.count == 1)
        #expect(list[0].pluginID == "com.test.tier-b.fixture")
    }

    @Test("reinstall without --force fails")
    func reinstallRequiresForce() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: true)
            Issue.record("expected destinationAlreadyExists")
        } catch PluginInstaller.InstallError.destinationAlreadyExists {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("reinstall with --force succeeds")
    func reinstallForce() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let again = try await installer.install(sourceDir: src, trustOnInstall: true, force: true)
        #expect(again.pluginID == "com.test.tier-b.fixture")
    }

    @Test("revoke blocks re-install even with trust-on-install")
    func revokeBlocksReinstall() async throws {
        let (src, hex) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        try await installer.uninstall(pluginID: "com.test.tier-b.fixture")
        try await installer.revokeKey(hex)
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: true)
            Issue.record("expected verifyFailed (publisherKeyRevoked)")
        } catch PluginInstaller.InstallError.verifyFailed {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
        let revoked = await installer.currentRevokedKeys()
        #expect(revoked.contains(hex))
        let trusted = await installer.currentTrustedKeys()
        #expect(!trusted.contains(hex), "revoke should remove from trust list")
    }

    @Test("uninstall removes the bundle directory")
    func uninstallRemovesBundle() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let installed = try await installer.install(sourceDir: src, trustOnInstall: true)
        try await installer.uninstall(pluginID: installed.pluginID)
        let list = try await installer.list()
        #expect(list.isEmpty)
    }

    @Test("unrevokeKey lifts the revocation block")
    func unrevokeAllowsAgain() async throws {
        let (src, hex) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        try await installer.revokeKey(hex)
        try await installer.unrevokeKey(hex)
        let revoked = await installer.currentRevokedKeys()
        #expect(!revoked.contains(hex))
        let installed = try await installer.install(sourceDir: src, trustOnInstall: true)
        #expect(installed.pluginID == "com.test.tier-b.fixture")
    }

    // MARK: - Version pins (v1.19.3)

    @Test("pin round-trip: pin → pinnedVersion → currentPins → unpin")
    func pinRoundTrip() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        var v = await installer.pinnedVersion(id: "com.test.x")
        #expect(v == nil)
        try await installer.pinPlugin(id: "com.test.x", version: "1.2.3")
        v = await installer.pinnedVersion(id: "com.test.x")
        #expect(v == "1.2.3")
        let pins = await installer.currentPins()
        #expect(pins["com.test.x"] == "1.2.3")
        // Isolation: a different id is unaffected.
        let other = await installer.pinnedVersion(id: "com.test.y")
        #expect(other == nil)
        // Overwrite is idempotent.
        try await installer.pinPlugin(id: "com.test.x", version: "1.3.0")
        v = await installer.pinnedVersion(id: "com.test.x")
        #expect(v == "1.3.0")
        try await installer.unpinPlugin(id: "com.test.x")
        v = await installer.pinnedVersion(id: "com.test.x")
        #expect(v == nil)
        let empty = await installer.currentPins()
        #expect(empty.isEmpty)
    }

    @Test("pin file is not surfaced as an installed plugin")
    func pinFileNotListed() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        try await installer.pinPlugin(id: "com.test.tier-b.fixture", version: "1.0")
        let list = try await installer.list()
        #expect(list.count == 1)
        #expect(list[0].pluginID == "com.test.tier-b.fixture")
    }

    // MARK: - Atomic install (v1.19.3)

    @Test("force-reinstall replaces in place and leaves no .tmp residue")
    func forceReinstallNoTmpResidue() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        _ = try await installer.install(sourceDir: src, trustOnInstall: true, force: true)
        let list = try await installer.list()
        #expect(list.count == 1)
        // The atomic-swap temp dir must not linger in the plugins root.
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: installer.pluginsRootPath)) ?? []
        #expect(!entries.contains(where: { $0.contains(".tmp.") }))
    }

    @Test("list() ignores a stray .tmp. directory (crash-interrupted swap)")
    func listIgnoresStrayTmp() async throws {
        let (src, _) = try Self.freshSignedBundle()
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        // Simulate a crash mid-swap leaving a temp dir behind.
        let stray = URL(fileURLWithPath: installer.pluginsRootPath)
            .appendingPathComponent("com.test.tier-b.fixture.tmp.\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: stray, withIntermediateDirectories: true)
        let list = try await installer.list()
        #expect(list.count == 1)
        #expect(list[0].pluginID == "com.test.tier-b.fixture")
    }
}
