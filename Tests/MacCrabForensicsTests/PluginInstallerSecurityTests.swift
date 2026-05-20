// PluginInstaller — security regression tests.
//
// Asserts the install-time defenses against four classes of
// attack confirmed live during the rc.3-era audit:
//
//   audit-1: plugin-ID path traversal
//   audit-2: symlink in source bundle
//   audit-3: trust list file perms 0o600
//   audit-4: TOCTOU between verify and spawn (covered in
//            TierBRegistryTOCTOUTests)

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("PluginInstaller security — audit-1 + audit-2 + audit-3")
struct PluginInstallerSecurityTests {

    static func freshSignedBundle(
        pluginID: String,
        extraFiles: [(name: String, content: Data)] = [],
        addSymlink: (name: String, target: String)? = nil
    ) throws -> URL {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("audit-bundle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let manifestJSON = "{\"id\":\"\(pluginID)\",\"displayName\":\"x\",\"version\":\"1\",\"schemaVersion\":1,\"description\":\"x\"}"
        try Data(manifestJSON.utf8).write(to: root.appendingPathComponent("manifest.json"))
        try Data("#!/bin/sh\necho test\n".utf8).write(to: root.appendingPathComponent("binary"))
        for (name, content) in extraFiles {
            try content.write(to: root.appendingPathComponent(name))
        }
        let key = Curve25519.Signing.PrivateKey()
        try PluginSignatureVerifier.sign(
            bundle: PluginSignatureVerifier.BundleLayout(bundleRoot: root),
            privateKey: key
        )
        if let s = addSymlink {
            try FileManager.default.createSymbolicLink(
                atPath: root.appendingPathComponent(s.name).path,
                withDestinationPath: s.target
            )
        }
        return root
    }

    static func freshInstaller() -> PluginInstaller {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("audit-installer-\(UUID().uuidString)")
        return PluginInstaller(pluginsRoot: root)
    }

    // MARK: - audit-1: plugin-ID path traversal

    @Test("audit-1: rejects '..' traversal id")
    func rejectsTraversalDotDot() async throws {
        let src = try Self.freshSignedBundle(pluginID: "../escaped")
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: true)
            Issue.record("expected invalidPluginID for ../escaped")
        } catch PluginInstaller.InstallError.invalidPluginID {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("audit-1: rejects slash-injection id")
    func rejectsSlashInjection() async throws {
        let src = try Self.freshSignedBundle(pluginID: "subdir/inner")
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: true)
            Issue.record("expected invalidPluginID for subdir/inner")
        } catch PluginInstaller.InstallError.invalidPluginID {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("audit-1: rejects leading-dot id")
    func rejectsLeadingDot() async throws {
        let src = try Self.freshSignedBundle(pluginID: ".hidden")
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: true)
            Issue.record("expected invalidPluginID for .hidden")
        } catch PluginInstaller.InstallError.invalidPluginID {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("audit-1: accepts well-formed id")
    func acceptsValidID() async throws {
        let src = try Self.freshSignedBundle(pluginID: "com.test.valid-id_1.0")
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let installed = try await installer.install(sourceDir: src, trustOnInstall: true)
        #expect(installed.pluginID == "com.test.valid-id_1.0")
    }

    @Test("audit-1: validatePluginID accepts/rejects edge cases")
    func validatePluginIDEdgeCases() {
        #expect((try? PluginInstaller.validatePluginID("a")) != nil)
        #expect((try? PluginInstaller.validatePluginID("com.test.foo")) != nil)
        #expect((try? PluginInstaller.validatePluginID("Plugin-1_2.3")) != nil)

        // Reject path traversal forms.
        #expect((try? PluginInstaller.validatePluginID("..")) == nil)
        #expect((try? PluginInstaller.validatePluginID(".")) == nil)
        #expect((try? PluginInstaller.validatePluginID("a/../b")) == nil)
        #expect((try? PluginInstaller.validatePluginID("a\\b")) == nil)

        // Reject reserved / disallowed shapes.
        #expect((try? PluginInstaller.validatePluginID("")) == nil)
        #expect((try? PluginInstaller.validatePluginID(".hidden")) == nil)
        #expect((try? PluginInstaller.validatePluginID("-leadingdash")) == nil)
        #expect((try? PluginInstaller.validatePluginID("with space")) == nil)
        #expect((try? PluginInstaller.validatePluginID("with\nnewline")) == nil)
        #expect((try? PluginInstaller.validatePluginID(String(repeating: "a", count: 200))) == nil)
    }

    // MARK: - audit-2: symlinks in source bundle

    @Test("audit-2: rejects bundle with symlink")
    func rejectsSymlinkInBundle() async throws {
        let src = try Self.freshSignedBundle(
            pluginID: "com.test.symlinker",
            addSymlink: (name: "evil-link", target: "/etc/passwd")
        )
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            _ = try await installer.install(sourceDir: src, trustOnInstall: true)
            Issue.record("expected symlinkInSourceBundle error")
        } catch PluginInstaller.InstallError.symlinkInSourceBundle {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    // MARK: - audit-3: trust list file perms

    @Test("audit-3: trusted-keys.json + revoked-keys.json end up 0o600")
    func trustListPermissions0o600() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        try await installer.addTrustedKey(String(repeating: "a", count: 64))
        try await installer.revokeKey(String(repeating: "b", count: 64))
        let fm = FileManager.default
        let trustedPath = installer.pluginsRootPath + "/trusted-keys.json"
        let revokedPath = installer.pluginsRootPath + "/revoked-keys.json"
        for path in [trustedPath, revokedPath] {
            let attrs = try fm.attributesOfItem(atPath: path)
            guard let mode = attrs[.posixPermissions] as? Int else {
                Issue.record("no posixPermissions on \(path)")
                continue
            }
            // 0o600 == 384 decimal.
            #expect(mode == 0o600, "expected 0o600 (384) on \(path), got \(String(mode, radix: 8))")
        }
    }

    @Test("audit-3: pluginsRoot is 0o700 after ensureRoot")
    func pluginsRootIs0o700() async throws {
        let installer = Self.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        try await installer.addTrustedKey(String(repeating: "c", count: 64))
        let attrs = try FileManager.default.attributesOfItem(atPath: installer.pluginsRootPath)
        let mode = attrs[.posixPermissions] as? Int ?? 0
        #expect(mode == 0o700)
    }
}

@Suite("TierBRegistry security — audit-4: TOCTOU verify-to-spawn")
struct TierBRegistryTOCTOUTests {

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

    @Test("audit-4: resolve() copies binary to fresh temp")
    func resolveCopiesBinary() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.toctou.copy",
            displayName: "x",
            version: "1",
            schemaVersion: 1,
            description: "x"
        )
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)
        let p1 = try await registry.resolve(pluginID: "com.test.toctou.copy")
        let p2 = try await registry.resolve(pluginID: "com.test.toctou.copy")
        // Two distinct temp files; neither is the bundle path.
        #expect(p1.binaryPath != p2.binaryPath, "each resolve() must allocate a fresh temp")
        let bundleBinaryPath = (p1.bundleRoot as NSString).appendingPathComponent("binary")
        #expect(p1.binaryPath != bundleBinaryPath, "binaryPath must point to temp, not bundle")
        // Cleanup both temps.
        registry.cleanupVerifiedBinary(p1)
        registry.cleanupVerifiedBinary(p2)
    }

    @Test("audit-4: temp-binary has 0o500 perms")
    func tempBinaryPerms0o500() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.toctou.perms",
            displayName: "x",
            version: "1",
            schemaVersion: 1,
            description: "x"
        )
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)
        let p = try await registry.resolve(pluginID: "com.test.toctou.perms")
        defer { registry.cleanupVerifiedBinary(p) }
        let attrs = try FileManager.default.attributesOfItem(atPath: p.binaryPath)
        let mode = attrs[.posixPermissions] as? Int ?? 0
        #expect(mode == 0o500, "expected 0o500 on temp binary, got \(String(mode, radix: 8))")
    }

    @Test("audit-4: bundle-binary swap after resolve() doesn't affect spawn")
    func swapAfterResolveDoesNotAffectSpawn() async throws {
        guard let binary = Self.fixtureBinaryPath else { return }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let manifest = TierBManifest(
            id: "com.test.toctou.swap",
            displayName: "x",
            version: "1",
            schemaVersion: 1,
            description: "x"
        )
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: manifest, binaryPath: binary)
        defer { try? FileManager.default.removeItem(at: src) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)
        let registry = TierBRegistry(installer: installer)
        let p = try await registry.resolve(pluginID: "com.test.toctou.swap")
        defer { registry.cleanupVerifiedBinary(p) }
        // Attempt to swap the bundle binary with garbage. This
        // simulates a TOCTOU attacker. The temp binary should
        // still be intact and runnable.
        let bundleBinaryPath = (p.bundleRoot as NSString).appendingPathComponent("binary")
        try Data("not the verified binary".utf8).write(to: URL(fileURLWithPath: bundleBinaryPath))

        // Re-read the temp binary's bytes and assert they match
        // what was originally signed (NOT the swap).
        let tempBytes = try Data(contentsOf: URL(fileURLWithPath: p.binaryPath))
        let originalBytes = try Data(contentsOf: URL(fileURLWithPath: binary))
        #expect(tempBytes == originalBytes, "temp binary must hold verified bytes, not swap")
    }
}
