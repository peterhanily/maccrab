// SandboxedExecutionResolveTests — TierBRegistry.resolveForSandboxedExecution:
// the disjoint twin of resolveForFirstPartyExecution. Proves the resolve chain
// (verify → quarantine → TOCTOU → 0o500 temp) feeds the ThirdPartyExecutionGate,
// that the sandboxed lane sets isSandboxed (never isFirstParty), that a
// first-party-anchor bundle is refused here (lanes never cross), and that an
// unavailable sandbox runtime fail-closes. Reuses TierBRegistryTests fixtures.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("TierBRegistry.resolveForSandboxedExecution (disjoint sandboxed lane)")
struct SandboxedExecutionResolveTests {

    /// Install a signed, trusted Tier-B bundle; return the registry, its installer
    /// (for cleanup), and the bundle's publisher-key fingerprint (publicKeySHA256).
    static func setup(id: String) async throws -> (TierBRegistry, PluginInstaller, String) {
        let binPath = NSTemporaryDirectory() + "sbx-bin-\(UUID().uuidString)"
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: binPath))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binPath)
        defer { try? FileManager.default.removeItem(atPath: binPath) }

        let m = TierBManifest(id: id, displayName: "P", version: "1.0", schemaVersion: 1, description: "d")
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: m, binaryPath: binPath)
        defer { try? FileManager.default.removeItem(at: src) }

        let installer = TierBRegistryTests.freshInstaller()
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)

        let registry = TierBRegistry(installer: installer)
        let base = try await registry.resolve(pluginID: id)
        let fp = base.publicKeySHA256
        registry.cleanupVerifiedBinary(base)
        return (registry, installer, fp)
    }

    @Test("allow: operator-trusted + sandbox available → isSandboxed, NOT isFirstParty")
    func allowSetsSandboxed() async throws {
        let id = "com.x.allow"
        let (registry, installer, _) = try await Self.setup(id: id)
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        let v = try await registry.resolveForSandboxedExecution(
            pluginID: id, sandboxRuntimeAvailable: true,
            hasValidCuratedReceipt: false, catalogOverrideActive: false)
        defer { registry.cleanupVerifiedBinary(v) }
        #expect(v.isSandboxed)
        #expect(!v.isFirstParty)
    }

    @Test("fail-closed: sandbox runtime unavailable → refused (never uncontained)")
    func refusesWhenSandboxUnavailable() async throws {
        let id = "com.x.unavail"
        let (registry, installer, _) = try await Self.setup(id: id)
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            _ = try await registry.resolveForSandboxedExecution(
                pluginID: id, sandboxRuntimeAvailable: false,
                hasValidCuratedReceipt: false, catalogOverrideActive: false)
            Issue.record("expected refusal")
        } catch let e as TierBRegistry.RegistryError {
            if case .sandboxedExecutionRefused(_, let r) = e {
                #expect(r.lowercased().contains("uncontained"))
            } else { Issue.record("wrong error: \(e)") }
        }
    }

    @Test("defense in depth: a bare resolve() output (neither lane gated) is refused by the sandboxed runner")
    func bareResolveRefusedByRunner() async throws {
        let id = "com.x.bare"
        let (registry, installer, _) = try await Self.setup(id: id)
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        // The REAL ungated resolve() — isSandboxed=false, isFirstParty=false. If a
        // future change accidentally made base resolve() set isSandboxed, the
        // runner guard is the backstop. (trampoline path is valid, but the
        // notSandboxed guard fires before any availability check or spawn.)
        let base = try await registry.resolve(pluginID: id)
        defer { registry.cleanupVerifiedBinary(base) }
        let runner = SandboxedTierBRunner(trampolinePath: "/bin/sh")
        do {
            _ = try runner.run(verified: base, scratchDir: NSTemporaryDirectory())
            Issue.record("expected notSandboxed refusal")
        } catch let e as SandboxedTierBRunner.RunnerError {
            if case .notSandboxed = e {} else { Issue.record("wrong error: \(e)") }
        }
    }

    @Test("disjoint lanes: a bundle matching the first-party anchor is refused here")
    func refusesFirstPartyAnchorMatch() async throws {
        let id = "com.x.fpmatch"
        let (registry, installer, fp) = try await Self.setup(id: id)
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        do {
            // Inject the first-party anchor == this bundle's fingerprint (configured).
            _ = try await registry.resolveForSandboxedExecution(
                pluginID: id, sandboxRuntimeAvailable: true,
                hasValidCuratedReceipt: false, catalogOverrideActive: false,
                firstPartyAnchorFingerprint: fp, firstPartyAnchorConfigured: true)
            Issue.record("expected refusal")
        } catch let e as TierBRegistry.RegistryError {
            if case .sandboxedExecutionRefused(_, let r) = e {
                #expect(r.lowercased().contains("first-party"))
            } else { Issue.record("wrong error: \(e)") }
        }
    }
}
