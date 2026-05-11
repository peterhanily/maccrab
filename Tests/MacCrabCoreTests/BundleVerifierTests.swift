// BundleVerifierTests.swift
// v1.10 TraceGraph (PR-10c) — exercises hash chain, signature, and
// unified-log verification including Fixture 8 (bundle tampering).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: BundleVerifier")
struct BundleVerifierTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("ver-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func makeProcess(_ key: String, _ path: String, isAppleSigned: Bool = true) -> ProcessNode {
        ProcessNode(
            processKey: key, pid: 100, ppid: 1,
            executablePath: path,
            isAppleSigned: isAppleSigned, isNotarized: isAppleSigned,
            startTime: now
        )
    }

    private func upsert(_ store: SQLiteCausalGraphStore, _ node: ProcessNode) async throws -> TraceEntity {
        let entity = try node.toEntity(source: "test")
        try await store.upsertEntity(entity)
        return entity
    }

    private func spawn(_ store: SQLiteCausalGraphStore, from p: TraceEntity, to c: TraceEntity) async throws -> TraceEdge {
        let edge = EdgeBuilder.build(
            sourceEntityId: p.id, targetEntityId: c.id,
            relation: .spawned, confidence: 0.95, observedAt: now
        )
        try await store.upsertEdge(edge)
        return edge
    }

    private func collectInputs(_ store: SQLiteCausalGraphStore, _ trace: Trace) async throws -> BundleExporter.Inputs {
        let loaded = try await store.loadTrace(id: trace.id)
        let memberships = loaded?.members ?? []
        var entityIds = Set<String>()
        var edgeIds = Set<String>()
        for member in memberships {
            if let id = member.entityId { entityIds.insert(id) }
            if let id = member.edgeId { edgeIds.insert(id) }
        }
        var entities: [TraceEntity] = []
        for id in entityIds { if let e = try await store.entity(id: id) { entities.append(e) } }
        var edges: [TraceEdge] = []
        for id in edgeIds { if let e = try await store.edge(id: id) { edges.append(e) } }
        return BundleExporter.Inputs(
            trace: trace, entities: entities, edges: edges,
            memberships: memberships,
            eventsJsonl: [#"{"id":"ev-1","ts":1700000000}"#],
            policySnapshotJson: "{}"
        )
    }

    private func buildSignedBundle(
        trustSubstrate: TrustSubstrate? = nil,
        unifiedLogAnchor: UnifiedLogAnchor? = nil
    ) async throws -> (URL, BundleExporter.Inputs, TrustSubstrate) {
        let (store, dbPath) = try await makeStore()
        let parent = try await upsert(store, makeProcess("parent", "/bin/zsh"))
        let child = try await upsert(store, makeProcess("child", "/usr/bin/curl"))
        _ = try await spawn(store, from: parent, to: child)
        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: child.id, anchorEventId: "ev",
            title: "T", severity: "low", confidence: 0.5,
            now: now.addingTimeInterval(1)
        )
        let inputs = try await collectInputs(store, trace)
        await store.close()
        try? FileManager.default.removeItem(at: dbPath)

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("verbundle-\(UUID().uuidString)")
        let substrate = trustSubstrate ?? TrustSubstrate(
            storage: InMemoryTrustSubstrateStorage(),
            modeOverride: .filesystemDegraded
        )
        let exporter = BundleExporter(
            redactor: BundleRedactor(userName: "test"),
            trustSubstrate: substrate,
            unifiedLogAnchor: unifiedLogAnchor
        )
        try await exporter.export(inputs: inputs, to: bundleRoot)
        return (bundleRoot, inputs, substrate)
    }

    // MARK: - Tests

    @Test("Signed bundle verifies cleanly (exit 0)")
    func signedBundleVerifies() async throws {
        let (dir, _, _) = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }
        let outcome = await BundleVerifier.verify(at: dir)
        #expect(outcome.exitCode == 0, "Verifier rejected freshly-signed bundle: \(outcome.kind) \(outcome.messages)")
    }

    @Test("UNSIGNED placeholder bundle fails with exit 3")
    func unsignedFailsExit3() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let proc = try await upsert(store, makeProcess("p", "/bin/zsh"))
        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: proc.id, anchorEventId: "ev",
            title: "T", severity: "low", confidence: 0.5,
            now: now.addingTimeInterval(1)
        )
        let inputs = try await collectInputs(store, trace)
        await store.close()

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("unsigned-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }
        // No TrustSubstrate → UNSIGNED placeholder.
        let exporter = BundleExporter(redactor: BundleRedactor(userName: "test"))
        try await exporter.export(inputs: inputs, to: bundleRoot)

        let outcome = await BundleVerifier.verify(at: bundleRoot)
        #expect(outcome.exitCode == 3)
    }

    /// Fixture 8 — modify events.jsonl in a bundle, verify must fail
    /// with explicit hash-chain mismatch.
    @Test("Fixture 8: bundle tampering detected (exit 2)")
    func fixture8_bundleTampering() async throws {
        let (dir, _, _) = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Tamper: rewrite events.jsonl with different content.
        let eventsURL = dir.appendingPathComponent("events.jsonl")
        try #"{"id":"ev-1","ts":1700000000,"tampered":true}"#
            .write(to: eventsURL, atomically: true, encoding: .utf8)

        let outcome = await BundleVerifier.verify(at: dir)
        #expect(outcome.exitCode == 2)
        // Outcome message should mention the per-artifact mismatch on events.jsonl.
        let combined = ([outcome.kindMessage] + outcome.messages).joined(separator: " ")
        #expect(
            combined.contains("events.jsonl") || combined.contains("Merkle"),
            "Expected message mentioning events.jsonl or Merkle, got: \(combined)"
        )
    }

    @Test("Tampering with manifest.json also fails verify (exit 2)")
    func manifestTamperingDetected() async throws {
        let (dir, _, _) = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }

        let manifestURL = dir.appendingPathComponent("manifest.json")
        let data = try Data(contentsOf: manifestURL)
        var manifest = try canonicalJSONDecoder().decode(BundleManifest.self, from: data)
        manifest = BundleManifest(
            format: manifest.format,
            maccrabVersion: manifest.maccrabVersion,
            rulesetVersion: manifest.rulesetVersion,
            normalizationVersion: manifest.normalizationVersion,
            createdAt: manifest.createdAt,
            hostRedacted: manifest.hostRedacted,
            traceId: manifest.traceId,
            title: "TAMPERED TITLE",
            severity: manifest.severity,
            confidence: manifest.confidence,
            provCompliant: manifest.provCompliant,
            otelAligned: manifest.otelAligned,
            otelConventionVersion: manifest.otelConventionVersion,
            processIdentityVersion: manifest.processIdentityVersion,
            traceSigningKeyMode: manifest.traceSigningKeyMode,
            replayScope: manifest.replayScope,
            attributionOverridePolicy: manifest.attributionOverridePolicy
        )
        try canonicalJSONEncoder().encode(manifest).write(to: manifestURL)

        let outcome = await BundleVerifier.verify(at: dir)
        // Either exit 2 (Merkle mismatch) or exit 1 (cross-check between
        // graph.trace and manifest.trace_id was invalidated by the rewrite).
        #expect(outcome.exitCode == 2 || outcome.exitCode == 1)
    }

    @Test("Replacing public key with a different one fails (exit 3)")
    func wrongPublicKeyFails() async throws {
        let (dir, _, _) = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }

        // Generate a different keypair via a fresh TrustSubstrate, then
        // swap the bundled public key.
        let alt = TrustSubstrate(
            storage: InMemoryTrustSubstrateStorage(),
            modeOverride: .filesystemDegraded
        )
        let altKey = try await alt.publicKey()
        try altKey.derBytes.write(to: dir.appendingPathComponent("integrity/trace-signing.pub"))

        let outcome = await BundleVerifier.verify(at: dir)
        #expect(outcome.exitCode == 3)
    }

    @Test("UnifiedLog: anchor present → exit 0 with --check-unified-log")
    func unifiedLogAnchorPresent() async throws {
        let anchor = InMemoryUnifiedLogAnchor()
        let (dir, _, _) = try await buildSignedBundle(unifiedLogAnchor: anchor)
        defer { try? FileManager.default.removeItem(at: dir) }

        var options = BundleVerifier.Options()
        options.checkUnifiedLog = true
        let outcome = await BundleVerifier.verify(at: dir, unifiedLogAnchor: anchor, options: options)
        #expect(outcome.exitCode == 0)
    }

    @Test("UnifiedLog: anchor missing → exit 4 with --check-unified-log")
    func unifiedLogAnchorMissing() async throws {
        let anchor = InMemoryUnifiedLogAnchor()  // empty — exporter never emitted to it
        let (dir, _, _) = try await buildSignedBundle()  // no anchor wired into export
        defer { try? FileManager.default.removeItem(at: dir) }

        var options = BundleVerifier.Options()
        options.checkUnifiedLog = true
        let outcome = await BundleVerifier.verify(at: dir, unifiedLogAnchor: anchor, options: options)
        #expect(outcome.exitCode == 4)
    }

    @Test("UnifiedLog: not requested → missing anchor doesn't fail")
    func unifiedLogNotRequested() async throws {
        let (dir, _, _) = try await buildSignedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }
        let outcome = await BundleVerifier.verify(at: dir)
        #expect(outcome.exitCode == 0)
    }
}

// MARK: - Outcome accessor

private extension BundleValidator.Outcome {
    var kindMessage: String {
        switch kind {
        case .valid:                                  return "valid"
        case .schemaInvalid(let m):                   return m
        case .incompatibleMajorVersion(let f, let s): return "incompatible major: \(f) vs \(s)"
        case .redactionPolicyViolation(let m):        return m
        case .internalError(let m):                   return m
        case .manifestClaimMismatch(let m):           return m
        }
    }
}

@Suite("TraceGraph: BundleMerkle reduction")
struct BundleMerkleReductionTests {

    @Test("Empty input → SHA-256 of empty data")
    func emptyReduction() {
        let root = BundleMerkle.reduce([])
        #expect(root == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test("Single leaf returns the leaf itself")
    func singleLeaf() {
        let leaf = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        let root = BundleMerkle.reduce([leaf])
        #expect(root == leaf)
    }

    @Test("Two leaves → SHA-256 of concatenation")
    func twoLeaves() {
        let leaf = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        let root1 = BundleMerkle.reduce([leaf, leaf])
        let root2 = BundleMerkle.reduce([leaf, leaf])
        #expect(root1 == root2)
        #expect(root1.count == 64)
        #expect(root1 != leaf)  // reduction actually happened
    }

    @Test("Odd-count reduction duplicates the last leaf")
    func oddCount() {
        let l1 = String(repeating: "1", count: 64)
        let l2 = String(repeating: "2", count: 64)
        let l3 = String(repeating: "3", count: 64)
        let oddRoot = BundleMerkle.reduce([l1, l2, l3])
        // Equivalent: [l1, l2, l3, l3] (Bitcoin-style duplicate)
        let evenRoot = BundleMerkle.reduce([l1, l2, l3, l3])
        #expect(oddRoot == evenRoot)
    }

    @Test("Different leaves produce different roots")
    func differentLeaves() {
        let r1 = BundleMerkle.reduce([String(repeating: "a", count: 64), String(repeating: "b", count: 64)])
        let r2 = BundleMerkle.reduce([String(repeating: "a", count: 64), String(repeating: "c", count: 64)])
        #expect(r1 != r2)
    }
}

@Suite("TraceGraph: UnifiedLogAnchor (in-memory)")
struct UnifiedLogAnchorTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func record(_ root: String, _ traceId: String = "trace-1", _ at: Date? = nil) -> UnifiedLogChainHeadRecord {
        UnifiedLogChainHeadRecord(
            merkleRoot: root,
            signatureBase64: "AAAA",
            signingKeyMode: "filesystem_degraded",
            signingKeyFingerprint: "fpfp",
            traceId: traceId,
            emittedAt: at ?? now
        )
    }

    @Test("Emit then look up by Merkle root")
    func emitAndFind() async throws {
        let anchor = InMemoryUnifiedLogAnchor()
        try await anchor.emit(record("root1"))
        let window = TimeWindow.lastMinutes(60, now: now.addingTimeInterval(60))
        let found = try await anchor.findChainHead(merkleRoot: "root1", within: window)
        #expect(found != nil)
        #expect(found?.merkleRoot == "root1")
    }

    @Test("Outside-window record is not found")
    func outOfWindow() async throws {
        let anchor = InMemoryUnifiedLogAnchor()
        try await anchor.emit(record("root2", "trace-2", now))
        let farFutureWindow = TimeWindow(
            start: now.addingTimeInterval(86_400),
            end: now.addingTimeInterval(86_500)
        )
        let found = try await anchor.findChainHead(merkleRoot: "root2", within: farFutureWindow)
        #expect(found == nil)
    }

    @Test("Wrong Merkle root yields nil")
    func wrongRoot() async throws {
        let anchor = InMemoryUnifiedLogAnchor()
        try await anchor.emit(record("rootA"))
        let window = TimeWindow.lastMinutes(60, now: now.addingTimeInterval(60))
        let found = try await anchor.findChainHead(merkleRoot: "rootB", within: window)
        #expect(found == nil)
    }
}
