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
}
