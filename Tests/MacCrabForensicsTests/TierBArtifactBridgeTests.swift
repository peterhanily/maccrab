// TierBArtifactBridge (Shape 2 Phase 2c) — host-stamping commit bridge. Unit
// tests pin the security properties (host owns identity/size/sha; non-metadata
// rejected in a plaintext case), and an end-to-end test spawns a real script
// plugin and proves its artifacts land in the case store host-stamped.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("TierBArtifactBridge (Shape 2 Phase 2c)")
struct TierBArtifactBridgeTests {

    static let manifest = TierBManifest(
        id: "com.maccrab.forensics.posture-pro", displayName: "PP",
        version: "1.2.3", schemaVersion: 2, description: "x")

    @Test("map host-stamps identity + recomputes sha/size (the DTO carries none)")
    func mapHostStamps() {
        let dto = TierBArtifactDTO(contentType: "posture.score", summary: "Grade A",
                                   data: ["score": .integer(95)], privacyClass: "metadata")
        guard case .record(let r) = TierBArtifactBridge.map(
            dto: dto, caseID: "CASE-1", manifest: Self.manifest, caseAllowsSensitive: false) else {
            Issue.record("expected .record"); return
        }
        #expect(r.caseID == "CASE-1")
        #expect(r.pluginID == "com.maccrab.forensics.posture-pro")
        #expect(r.pluginVersion == "1.2.3")
        #expect(r.schemaVersion == 2)
        #expect(r.sha256.count == 64)
        #expect(r.sizeBytes > 0)
        #expect(r.privacyClass == .metadata)
    }

    @Test("map rejects a non-metadata artifact in a plaintext case")
    func mapRejectsSensitiveInPlaintext() {
        let dto = TierBArtifactDTO(contentType: "secret.thing", privacyClass: "secret")
        guard case .rejected = TierBArtifactBridge.map(
            dto: dto, caseID: "C", manifest: Self.manifest, caseAllowsSensitive: false) else {
            Issue.record("expected .rejected"); return
        }
    }

    @Test("map allows a non-metadata artifact when the case is encrypted")
    func mapAllowsSensitiveWhenEncrypted() {
        let dto = TierBArtifactDTO(contentType: "secret.thing", privacyClass: "secret")
        guard case .record(let r) = TierBArtifactBridge.map(
            dto: dto, caseID: "C", manifest: Self.manifest, caseAllowsSensitive: true) else {
            Issue.record("expected .record"); return
        }
        #expect(r.privacyClass == .secret)
    }

    @Test("map: confidence maps + defaults; invalid privacyClass defaults to metadata (safe)")
    func mapDefaults() {
        let d1 = TierBArtifactDTO(contentType: "x", privacyClass: "metadata", confidence: "heuristic")
        guard case .record(let r1) = TierBArtifactBridge.map(
            dto: d1, caseID: "C", manifest: Self.manifest, caseAllowsSensitive: false) else { Issue.record("r1"); return }
        #expect(r1.confidence == .heuristic)
        let d2 = TierBArtifactDTO(contentType: "x", privacyClass: "bogus", confidence: "bogus")
        guard case .record(let r2) = TierBArtifactBridge.map(
            dto: d2, caseID: "C", manifest: Self.manifest, caseAllowsSensitive: false) else { Issue.record("r2"); return }
        #expect(r2.privacyClass == .metadata)
        #expect(r2.confidence == .observed)
    }

    @Test("end-to-end: script plugin → runner → bridge → store; host stamps identity from the manifest")
    func endToEnd() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tierb-e2e-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "e2e")

        let script = """
        #!/bin/sh
        cat >/dev/null
        printf '%s\\n' '{"kind":"artifact","artifact":{"contentType":"posture.factor","summary":"SIP enabled","privacyClass":"metadata","data":{"key":"sip","status":"pass"}}}'
        printf '%s\\n' '{"kind":"artifact","artifact":{"contentType":"posture.score","summary":"Grade A","privacyClass":"metadata","data":{"score":95}}}'
        printf '%s\\n' '{"kind":"result","result":{"status":"ok","notes":["2 controls"]}}'
        """
        let scriptPath = NSTemporaryDirectory() + "e2e-\(UUID().uuidString).sh"
        try script.write(toFile: scriptPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptPath)
        defer { try? FileManager.default.removeItem(atPath: scriptPath) }

        let m = TierBManifest(id: "com.test.e2e.posture", displayName: "P",
                              version: "2.3", schemaVersion: 1, description: "p")
        let (src, _) = try TierBRegistryTests.signedBundle(manifest: m, binaryPath: scriptPath)
        defer { try? FileManager.default.removeItem(at: src) }
        let installer = TierBRegistryTests.freshInstaller()
        defer { try? FileManager.default.removeItem(atPath: installer.pluginsRootPath) }
        _ = try await installer.install(sourceDir: src, trustOnInstall: true)

        let registry = TierBRegistry(installer: installer)
        let base = try await registry.resolve(pluginID: "com.test.e2e.posture")
        let fp = base.publicKeySHA256
        registry.cleanupVerifiedBinary(base)
        let verified = try await registry.resolveForFirstPartyExecution(
            pluginID: "com.test.e2e.posture", officialSource: true, catalogOverrideActive: false,
            expectedPublisherFingerprint: fp, anchorConfigured: true)
        defer { registry.cleanupVerifiedBinary(verified) }

        let scratch = NSTemporaryDirectory() + "e2e-scratch-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: scratch) }

        let outcome = try FirstPartyTierBRunner().run(verified: verified, scratchDir: scratch, timeout: 20)
        let result = await TierBArtifactBridge.commit(
            outcome: outcome, caseID: handle.caseID, manifest: verified.manifest,
            caseAllowsSensitive: true, output: StoreCollectorOutput(store: handle.store))

        #expect(result.artifactsCommitted == 2)
        #expect(result.status == .ok)

        let rows = try await handle.store.query(ArtifactQuery(caseID: handle.caseID, limit: 10))
        #expect(rows.count == 2)
        // Host stamped identity from the VERIFIED manifest (version 2.3), not the DTO.
        #expect(rows.allSatisfy { $0.record.pluginID == "com.test.e2e.posture" })
        #expect(rows.allSatisfy { $0.record.pluginVersion == "2.3" })
        #expect(rows.allSatisfy { $0.record.privacyClass == .metadata })
        #expect(rows.contains { $0.record.contentType == "posture.score" })
    }
}
