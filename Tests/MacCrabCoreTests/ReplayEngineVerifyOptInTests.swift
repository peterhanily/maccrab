// ReplayEngineVerifyOptInTests.swift
// A3-01 — ReplayEngine's opt-in tamper-evidence gate (BundleVerifier, not just
// BundleValidator). The flag defaults OFF (preserving the historical replay
// contract), so these tests set it explicitly.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ReplayEngine verifyTamperEvidence (A3-01)")
struct ReplayEngineVerifyOptInTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("replay-verify-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    /// Build a signed bundle (real TrustSubstrate, filesystem-degraded mode).
    private func buildSignedBundle() async throws -> URL {
        let (store, dbPath) = try await makeStore()
        let proc = ProcessNode(
            processKey: "k", pid: 100, ppid: 1,
            executablePath: "/bin/zsh",
            isAppleSigned: true, isNotarized: true, startTime: now
        )
        let entity = try proc.toEntity(source: "test")
        try await store.upsertEntity(entity)
        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: entity.id, anchorEventId: "ev",
            title: "T", severity: "high", confidence: 0.9,
            now: now.addingTimeInterval(1)
        )
        let loaded = try await store.loadTrace(id: trace.id)
        let inputs = BundleExporter.Inputs(
            trace: trace, entities: [entity], edges: [],
            memberships: loaded?.members ?? [],
            eventsJsonl: [#"{"event_id":"a","timestamp_ns":1700000000000000000}"#],
            policySnapshotJson: "{}",
            matchedRules: MatchedRulesArtifact(rules: [])
        )
        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("replaybundle-\(UUID().uuidString)")
        let exporter = BundleExporter(
            redactor: BundleRedactor(userName: "test"),
            trustSubstrate: TrustSubstrate(
                storage: InMemoryTrustSubstrateStorage(),
                modeOverride: .filesystemDegraded
            )
        )
        try await exporter.export(inputs: inputs, to: bundleRoot)
        await store.close()
        try? FileManager.default.removeItem(at: dbPath)
        return bundleRoot
    }

    @Test("opt-in verify: a clean signed bundle still replays OK")
    func cleanSignedBundleReplays() async throws {
        let bundle = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: bundle) }
        var options = ReplayEngine.ReplayOptions()
        options.verifyTamperEvidence = true
        let result = try await ReplayEngine().replay(bundleAt: bundle, options: options)
        #expect(result.result == .ok)
    }

    @Test("opt-in verify: a tampered signed bundle fails closed (schemaInvalid)")
    func tamperedBundleFailsClosed() async throws {
        let bundle = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: bundle) }
        // Tamper an artifact that stays structurally valid — the validator
        // passes, so only the tamper-evidence (Merkle) check can catch it.
        try #"{"event_id":"a","timestamp_ns":1700000000000000000,"x":true}"#
            .write(to: bundle.appendingPathComponent("events.jsonl"),
                   atomically: true, encoding: .utf8)

        var options = ReplayEngine.ReplayOptions()
        options.verifyTamperEvidence = true
        let result = try await ReplayEngine().replay(bundleAt: bundle, options: options)
        #expect(result.result == .schemaInvalid)
    }

    @Test("default (opt-out): the same tampered bundle still replays (unchanged contract)")
    func defaultDoesNotVerify() async throws {
        let bundle = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: bundle) }
        try #"{"event_id":"a","timestamp_ns":1700000000000000000,"x":true}"#
            .write(to: bundle.appendingPathComponent("events.jsonl"),
                   atomically: true, encoding: .utf8)

        // No options → verifyTamperEvidence defaults false → structural replay
        // proceeds exactly as before this change.
        let result = try await ReplayEngine().replay(bundleAt: bundle)
        #expect(result.result == .ok)
    }
}
