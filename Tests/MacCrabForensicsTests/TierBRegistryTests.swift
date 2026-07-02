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

    // MARK: - Shape 2 Phase 1: first-party execution gate at the resolve chokepoint
    // We don't spawn at this layer, so any executable serves as the bundle binary.

    /// Install a validly-signed bundle and return (registry, the bundle key's
    /// publisher fingerprint as base resolve() computes it).
    static func installForExec(id: String) async throws -> (TierBRegistry, PluginInstaller, String) {
        let m = TierBManifest(id: id, displayName: "x", version: "1.0", schemaVersion: 1, description: "x")
        let (src, _) = try Self.signedBundle(manifest: m, binaryPath: "/usr/bin/true")
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)
        let base = try await registry.resolve(pluginID: id)
        registry.cleanupVerifiedBinary(base)
        return (registry, installer, base.publicKeySHA256)
    }

    @Test("first-party exec: matching publisher fingerprint + official + no override → allow (isFirstParty)")
    func firstPartyAllow() async throws {
        let (registry, installer, fp) = try await Self.installForExec(id: "com.test.fp.allow")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let v = try await registry.resolveForFirstPartyExecution(
            pluginID: "com.test.fp.allow", officialSource: true, catalogOverrideActive: false,
            expectedPublisherFingerprint: fp, anchorConfigured: true)
        #expect(v.isFirstParty)
        #expect(FileManager.default.isExecutableFile(atPath: v.binaryPath))
        registry.cleanupVerifiedBinary(v)
    }

    @Test("first-party exec: anchor not configured → refuse (fail-closed) even for a MATCHING key")
    func firstPartyDenyUnconfigured() async throws {
        let (registry, installer, fp) = try await Self.installForExec(id: "com.test.fp.unconf")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        // Registry-level "not configured → fail-closed" invariant. Uses the core
        // overload with anchorConfigured:false + the fixture's OWN matching
        // fingerprint, so the not-configured guard is proven to win over a byte
        // match — independent of the ship anchor now being configured (Fix 1).
        await #expect(throws: TierBRegistry.RegistryError.self) {
            _ = try await registry.resolveForFirstPartyExecution(
                pluginID: "com.test.fp.unconf", officialSource: true, catalogOverrideActive: false,
                expectedPublisherFingerprint: fp, anchorConfigured: false)
        }
    }

    @Test("first-party exec: a DIFFERENT (third-party) key → refuse, even with a configured anchor")
    func firstPartyDenyWrongKey() async throws {
        let (registry, installer, _) = try await Self.installForExec(id: "com.test.fp.wrong")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        await #expect(throws: TierBRegistry.RegistryError.self) {
            _ = try await registry.resolveForFirstPartyExecution(
                pluginID: "com.test.fp.wrong", officialSource: true, catalogOverrideActive: false,
                expectedPublisherFingerprint: String(repeating: "c", count: 64), anchorConfigured: true)
        }
    }

    @Test("first-party exec: matching key but non-official source → refuse (defense in depth)")
    func firstPartyDenyNonOfficial() async throws {
        let (registry, installer, fp) = try await Self.installForExec(id: "com.test.fp.unofficial")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        await #expect(throws: TierBRegistry.RegistryError.self) {
            _ = try await registry.resolveForFirstPartyExecution(
                pluginID: "com.test.fp.unofficial", officialSource: false, catalogOverrideActive: false,
                expectedPublisherFingerprint: fp, anchorConfigured: true)
        }
    }

    @Test("first-party exec: matching key but catalog override active → refuse (defense in depth)")
    func firstPartyDenyOverride() async throws {
        let (registry, installer, fp) = try await Self.installForExec(id: "com.test.fp.override")
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        await #expect(throws: TierBRegistry.RegistryError.self) {
            _ = try await registry.resolveForFirstPartyExecution(
                pluginID: "com.test.fp.override", officialSource: true, catalogOverrideActive: true,
                expectedPublisherFingerprint: fp, anchorConfigured: true)
        }
    }
}
