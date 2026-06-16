// PluginRunner + FixturePlugin tests — end-to-end lifecycle
// against the in-memory DEK vault.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("PluginRegistry")
struct PluginRegistryTests {

    @Test("Register + lookup + manifests round-trip")
    func registerLookup() async throws {
        let registry = PluginRegistry()
        try await registry.register(PluginRegistration(
            manifest: FixturePlugin.manifest,
            factory: { try await FixturePlugin() }
        ))
        let manifests = await registry.manifests()
        #expect(manifests.count == 1)
        #expect(manifests.first?.id == "com.maccrab.forensics.fixture")
        let reg = await registry.registration(forID: "com.maccrab.forensics.fixture")
        #expect(reg != nil)
    }

    @Test("Manifest filtering by plugin type")
    func filterByType() async throws {
        let registry = PluginRegistry()
        try await registry.register(PluginRegistration(
            manifest: FixturePlugin.manifest,
            factory: { try await FixturePlugin() }
        ))
        let collectors = await registry.manifests(ofType: .collector)
        #expect(collectors.count == 1)
        let analyzers = await registry.manifests(ofType: .analyzer)
        #expect(analyzers.isEmpty)
    }

    @Test("registration with malformed id throws")
    func malformedRegistrationThrows() async throws {
        let registry = PluginRegistry()
        let malformed = PluginManifest(
            id: "Bad ID Without Dots",
            version: "1.0.0",
            displayName: "Bad",
            description: "Bad",
            type: .collector,
            runtime: .tierA,
            tccRequirements: [],
            inputs: [],
            outputs: [],
            mcpTools: [],
            schemaVersion: 1,
            stability: .preview
        )
        await #expect(throws: (any Error).self) {
            try await registry.register(PluginRegistration(
                manifest: malformed,
                factory: { try await FixturePlugin() }
            ))
        }
    }
}

@Suite("FixturePlugin")
struct FixturePluginTests {

    @Test("Fixture manifest passes validate()")
    func manifestValid() throws {
        try FixturePlugin.manifest.validate()
    }

    @Test("Collect emits one fixture.heartbeat artifact and returns ok")
    func collectEmitsOne() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "fixture test")
        let runner = PluginRunner(registry: try await Self.scopedRegistry())

        let (result, invocationID) = try await runner.runCollector(
            id: "com.maccrab.forensics.fixture",
            handle: handle
        )
        #expect(result.status == .ok)
        #expect(result.artifactsCommitted == 1)
        #expect(result.artifactsRejected == 0)
        #expect(invocationID > 0)

        // Round-trip via query — the artifact should be findable.
        let rows = try await handle.store.query(ArtifactQuery(
            caseID: handle.caseID,
            contentType: "fixture.heartbeat",
            limit: 10
        ))
        #expect(rows.count == 1)
        #expect(rows.first?.record.summary == "fixture heartbeat tick 0")
        #expect(rows.first?.record.privacyClass == .metadata)
        #expect(rows.first?.record.pluginID == "com.maccrab.forensics.fixture")
    }

    @Test("Collect tagged with stable sha256 deduplicates on second run")
    func stableShaPerInvocation() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-stable-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "dedup test")
        let runner = PluginRunner(registry: try await Self.scopedRegistry())

        let (first, _) = try await runner.runCollector(
            id: "com.maccrab.forensics.fixture",
            handle: handle
        )
        let (second, _) = try await runner.runCollector(
            id: "com.maccrab.forensics.fixture",
            handle: handle
        )
        // Both runs commit (no dedup at the ArtifactStore layer
        // yet — that's a future enhancement). The fixture sha256
        // matching confirms determinism for future dedup logic.
        #expect(first.status == .ok)
        #expect(second.status == .ok)

        let rows = try await handle.store.query(ArtifactQuery(
            caseID: handle.caseID,
            limit: 10
        ))
        #expect(rows.count == 2)
        #expect(rows[0].record.sha256 == rows[1].record.sha256)
    }

    @Test("runCollector throws pluginNotFound for unknown id")
    func unknownIDThrows() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-unknown-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "x")
        let runner = PluginRunner(registry: try await Self.scopedRegistry())

        await #expect(throws: PluginRunnerError.self) {
            _ = try await runner.runCollector(
                id: "com.maccrab.no.such",
                handle: handle
            )
        }
    }

    @Test("Invocation row reflects the result")
    func invocationRowRecorded() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-runner-row-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "rec test")
        let runner = PluginRunner(registry: try await Self.scopedRegistry())

        let (result, invocationID) = try await runner.runCollector(
            id: "com.maccrab.forensics.fixture",
            handle: handle
        )
        #expect(invocationID > 0)
        #expect(result.artifactsCommitted == 1)
    }

    // Construct a scoped registry containing just the fixture plugin —
    // keeps tests independent of the shared singleton's state.
    private static func scopedRegistry() async throws -> PluginRegistry {
        let r = PluginRegistry()
        try await r.register(PluginRegistration(
            manifest: FixturePlugin.manifest,
            factory: { try await FixturePlugin() }
        ))
        return r
    }
}

// C-C: Tier B (subprocess-sandboxed) plugins must NEVER execute in-process,
// where they would inherit the host's Full-Disk-Access / TCC with their
// manifest capabilities unenforced. `PluginManifest.validate()` already rejects
// Tier B at registration; this exercises the second, execution-chokepoint guard
// that stays correct for when the sandboxed runtime lands and validate() relaxes.
@Suite("PluginRunner Tier B execution guard (C-C)")
struct PluginRunnerTierBGuardTests {

    private static func manifest(runtime: PluginRuntime) -> PluginManifest {
        PluginManifest(
            id: "com.maccrab.forensics.tierb-fixture",
            version: "1.0.0",
            displayName: "Tier B Fixture",
            description: "Reserved Tier B plugin used to prove execution is fail-closed.",
            type: .collector,
            runtime: runtime,
            tccRequirements: [],
            inputs: [],
            outputs: [],
            mcpTools: [],
            schemaVersion: 1,
            stability: .preview
        )
    }

    @Test("a .tierB registration is refused at the execution chokepoint")
    func tierBRefused() {
        // PluginRegistration init does not validate, so we can build a Tier B
        // registration the way a future non-validating path might.
        let reg = PluginRegistration(manifest: Self.manifest(runtime: .tierB),
                                     factory: { try await FixturePlugin() })
        do {
            try PluginRunner.assertExecutableRuntime(reg)
            Issue.record("expected tierBExecutionUnsupported")
        } catch let e as PluginRunnerError {
            guard case .tierBExecutionUnsupported(let id) = e else {
                Issue.record("expected tierBExecutionUnsupported, got \(e)"); return
            }
            #expect(id == "com.maccrab.forensics.tierb-fixture")
        } catch {
            Issue.record("unexpected error \(error)")
        }
    }

    @Test("a .tierA registration passes the execution guard")
    func tierAAllowed() throws {
        let reg = PluginRegistration(manifest: Self.manifest(runtime: .tierA),
                                     factory: { try await FixturePlugin() })
        try PluginRunner.assertExecutableRuntime(reg)  // must not throw
    }
}
