// UnifiedLogAnchorSystemTests.swift
// A3-01 — SystemUnifiedLogAnchor: emit path + in-memory read-back + graceful
// degradation of the OSLogStore path.
//
// SCOPE NOTE: the cross-process / cross-run OSLogStore read (root sysext emits,
// uid-501 verifier reads back on a LATER invocation) cannot be exercised in a
// unit test and is intentionally NOT asserted here — it is reported as a
// runtime path that NEEDS ON-DEVICE VERIFICATION. What is verifiable here: the
// same-run emit → find fast path, and that a miss degrades to nil (never a
// throw / crash), which is the contract the verifier relies on for its §19.4
// "degraded, re-run without --check-unified-log" warning.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: SystemUnifiedLogAnchor (A3-01)")
struct UnifiedLogAnchorSystemTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func record(_ root: String, at: Date? = nil) -> UnifiedLogChainHeadRecord {
        UnifiedLogChainHeadRecord(
            merkleRoot: root,
            signatureBase64: "c2ln",
            signingKeyMode: "filesystem_degraded",
            signingKeyFingerprint: "fp",
            traceId: "trace-1",
            emittedAt: at ?? now
        )
    }

    @Test("emit then find (same run) returns the record via the in-memory fast path")
    func emitThenFind() async throws {
        let anchor = SystemUnifiedLogAnchor()
        try await anchor.emit(record("root-A"))
        let window = TimeWindow(start: now.addingTimeInterval(-60), end: now.addingTimeInterval(60))
        let found = try await anchor.findChainHead(merkleRoot: "root-A", within: window)
        #expect(found?.merkleRoot == "root-A")
    }

    @Test("a never-emitted root degrades to nil (OSLogStore path must not throw)")
    func missDegradesToNil() async throws {
        let anchor = SystemUnifiedLogAnchor()
        let window = TimeWindow(start: now.addingTimeInterval(-60), end: now.addingTimeInterval(60))
        // This drops through the in-memory miss into the OSLogStore read-back,
        // which must return nil (not throw) whether or not the store is
        // readable in the test host's sandbox.
        let found = try await anchor.findChainHead(merkleRoot: "never-emitted", within: window)
        #expect(found == nil)
    }

    @Test("an emitted record outside the time window is not returned")
    func outsideWindowMisses() async throws {
        let anchor = SystemUnifiedLogAnchor()
        try await anchor.emit(record("root-B", at: now))
        // Window entirely after the emit time.
        let window = TimeWindow(start: now.addingTimeInterval(3600), end: now.addingTimeInterval(7200))
        let found = try await anchor.findChainHead(merkleRoot: "root-B", within: window)
        #expect(found == nil)
    }

    @Test("wiring the anchor into the exporter makes the chain-head emit run")
    func exporterEmitsWhenAnchorWired() async throws {
        // Build a signed bundle with a SystemUnifiedLogAnchor wired in, then
        // confirm the head is findable on that same anchor (proves emit ran).
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("anchor-export-\(UUID().uuidString).db")
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)
        defer { try? FileManager.default.removeItem(at: path) }
        let proc = ProcessNode(
            processKey: "k", pid: 100, ppid: 1, executablePath: "/bin/zsh",
            isAppleSigned: true, isNotarized: true, startTime: now
        )
        let entity = try proc.toEntity(source: "test")
        try await store.upsertEntity(entity)
        let trace = try await TraceMaterializer(store: store).materialize(
            anchorEntityId: entity.id, anchorEventId: "ev",
            title: "T", severity: "low", confidence: 0.5, now: now.addingTimeInterval(1)
        )
        let loaded = try await store.loadTrace(id: trace.id)
        let inputs = BundleExporter.Inputs(
            trace: trace, entities: [entity], edges: [],
            memberships: loaded?.members ?? [], eventsJsonl: [], policySnapshotJson: "{}"
        )
        await store.close()

        let anchor = SystemUnifiedLogAnchor()
        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("anchorbundle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }
        let exporter = BundleExporter(
            redactor: BundleRedactor(userName: "test"),
            trustSubstrate: TrustSubstrate(
                storage: InMemoryTrustSubstrateStorage(), modeOverride: .filesystemDegraded
            ),
            unifiedLogAnchor: anchor
        )
        try await exporter.export(inputs: inputs, to: bundleRoot)

        // Read the signed Merkle root back out of the bundle and confirm the
        // anchor emitted a matching head.
        let sigData = try Data(contentsOf: bundleRoot.appendingPathComponent("integrity/chain_head_signature.json"))
        let sig = try canonicalJSONDecoder().decode(ChainHeadSignatureArtifact.self, from: sigData)
        let window = TimeWindow(
            start: sig.signedAt.addingTimeInterval(-300),
            end: sig.signedAt.addingTimeInterval(300)
        )
        let found = try await anchor.findChainHead(merkleRoot: sig.merkleRoot, within: window)
        #expect(found?.merkleRoot == sig.merkleRoot)
        #expect(found?.signatureBase64 == sig.signatureBase64)
    }
}
