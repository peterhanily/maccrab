// PluginInputThreadingTests.swift
//
// Pins the two substrate behaviors the MCP Wave-2 changes depend on:
//
//  1. PluginRunner.runCollector threads operator-supplied `inputs` into
//     the collector. The MCP forensics.run_collector handler + the
//     dynamic per-plugin tools (macho_analyze_path, …) rely on a path
//     input reaching the plugin instead of its dogfood default.
//  2. CaseManager.createCase(encrypted: false) round-trips create →
//     reopen without a keychain DEK — the plaintext case an agent mints
//     via forensics.create_case and reopens headlessly.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("Plugin input threading + plaintext case")
struct PluginInputThreadingTests {

    private func scopedRegistry() async throws -> PluginRegistry {
        let registry = PluginRegistry()
        try await registry.register(PluginRegistration(
            manifest: MachOAnalyzerPlugin.manifest,
            factory: { try await MachOAnalyzerPlugin() }
        ))
        return registry
    }

    @Test("runCollector threads a `path` input to the collector (1 target, not the dogfood default)")
    func inputsReachCollector() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-inputs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let handle = try await mgr.createCase(name: "input threading", encrypted: false)
        let runner = PluginRunner(registry: try await scopedRegistry())

        // With a `path` input, the analyzer targets exactly that one binary.
        let (targeted, _) = try await runner.runCollector(
            id: MachOAnalyzerPlugin.manifest.id,
            handle: handle,
            inputs: PluginInvocationInputs(values: ["path": .string("/usr/bin/codesign")])
        )
        #expect(targeted.status == .ok)
        #expect(targeted.artifactsCommitted == 1)   // one supplied path → one artifact

        // With no inputs, it falls back to its 3-target dogfood default —
        // proving the difference above is the threaded input, not a constant.
        let (dogfood, _) = try await runner.runCollector(
            id: MachOAnalyzerPlugin.manifest.id,
            handle: handle,
            inputs: .empty
        )
        #expect(dogfood.artifactsCommitted == 3)
    }

    @Test("createCase(encrypted: false) round-trips create → reopen with no DEK")
    func plaintextCaseRoundTrips() async throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-plaintext-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }

        // An empty in-memory vault: a plaintext case must NOT need a DEK,
        // so reopen must succeed against a vault that has no entry for it.
        let vault = InMemoryDEKVault()
        let mgr = CaseManager(casesRoot: root, dekVault: vault)

        let created = try await mgr.createCase(name: "agent case", encrypted: false)
        let caseID = created.caseID
        #expect(created.encryptionState == .plaintext)

        let reopened = try await mgr.openCase(id: caseID)
        #expect(reopened.caseID == caseID)
        let row = try await reopened.store.fetchCase(id: caseID)
        #expect(row?.name == "agent case")
    }
}
