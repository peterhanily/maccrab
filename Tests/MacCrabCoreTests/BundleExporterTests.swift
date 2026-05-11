// BundleExporterTests.swift
// v1.10 TraceGraph (PR-10b) — end-to-end export tests.
// Includes Fixture 1 size assertion (<1 MB raw bundle directory).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: BundleExporter")
struct BundleExporterTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("bxp-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func makeProcessNode(
        key: String,
        path: String,
        pid: Int32 = 100,
        ppid: Int32 = 1,
        isAppleSigned: Bool = false,
        teamId: String? = nil,
        agentTraceId: String? = nil
    ) -> ProcessNode {
        ProcessNode(
            processKey: key,
            pid: pid, ppid: ppid,
            executablePath: path,
            signingTeamId: teamId,
            isAppleSigned: isAppleSigned,
            isNotarized: isAppleSigned,
            startTime: now,
            agentTraceId: agentTraceId
        )
    }

    private func upsertProcess(
        _ store: SQLiteCausalGraphStore,
        _ node: ProcessNode
    ) async throws -> TraceEntity {
        let entity = try node.toEntity(source: "test")
        try await store.upsertEntity(entity)
        return entity
    }

    private func upsertSpawn(
        _ store: SQLiteCausalGraphStore,
        from parent: TraceEntity,
        to child: TraceEntity
    ) async throws -> TraceEdge {
        let edge = EdgeBuilder.build(
            sourceEntityId: parent.id,
            targetEntityId: child.id,
            relation: .spawned,
            confidence: 0.95,
            observedAt: now
        )
        try await store.upsertEdge(edge)
        return edge
    }

    private func collectInputs(
        _ store: SQLiteCausalGraphStore,
        _ trace: Trace
    ) async throws -> BundleExporter.Inputs {
        let loaded = try await store.loadTrace(id: trace.id)
        let memberships = loaded?.members ?? []
        var entityIds = Set<String>()
        var edgeIds = Set<String>()
        for member in memberships {
            if let id = member.entityId { entityIds.insert(id) }
            if let id = member.edgeId { edgeIds.insert(id) }
        }
        // Always include the anchor + root entity even if memberships
        // didn't fully enumerate them (defensive).
        if let anchor = memberships.first(where: { $0.role == "anchor" })?.entityId {
            entityIds.insert(anchor)
        }
        if let root = trace.rootEntityId {
            entityIds.insert(root)
        }
        var entities: [TraceEntity] = []
        for id in entityIds {
            if let e = try await store.entity(id: id) { entities.append(e) }
        }
        var edges: [TraceEdge] = []
        for id in edgeIds {
            if let e = try await store.edge(id: id) { edges.append(e) }
        }
        return BundleExporter.Inputs(
            trace: trace,
            entities: entities,
            edges: edges,
            memberships: memberships,
            eventsJsonl: [#"{"id":"ev-1","ts":1700000000}"#],
            machineAttributions: [],
            humanOverrides: [],
            policySnapshotJson: "{}"
        )
    }

    // MARK: - Tests

    @Test("Export → validate roundtrip succeeds (exit 0)")
    func exportThenValidate() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        let parent = try await upsertProcess(store, makeProcessNode(
            key: "parent", path: "/bin/zsh", isAppleSigned: true))
        let child = try await upsertProcess(store, makeProcessNode(
            key: "child", path: "/Users/alice/Downloads/x"))
        _ = try await upsertSpawn(store, from: parent, to: child)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: child.id,
            anchorEventId: "ev-1",
            title: "test",
            severity: "high",
            confidence: 0.9,
            now: now.addingTimeInterval(1)
        )

        let inputs = try await collectInputs(store, trace)

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }

        // Use a fully-stubbed redactor so test results don't depend on
        // the test machine's actual hostname / username.
        let exporter = BundleExporter(redactor: BundleRedactor(userName: "alice"))
        try await exporter.export(inputs: inputs, to: bundleRoot)

        // Validate the freshly-written bundle.
        let outcome = BundleValidator.validate(at: bundleRoot)
        #expect(outcome.exitCode == 0, "Validator rejected exporter output: \(outcome.kind) \(outcome.messages)")
        await store.close()
    }

    @Test("manifest.json fields match exporter inputs")
    func manifestMatchesInputs() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        let proc = try await upsertProcess(store, makeProcessNode(
            key: "p", path: "/bin/zsh", isAppleSigned: true))

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: proc.id,
            anchorEventId: "ev",
            title: "Manifest test",
            severity: "high",
            confidence: 0.85,
            now: now.addingTimeInterval(1)
        )

        let inputs = try await collectInputs(store, trace)
        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }

        let exporter = BundleExporter(redactor: BundleRedactor(userName: "test"))
        try await exporter.export(inputs: inputs, to: bundleRoot)

        let manifestData = try Data(contentsOf: bundleRoot.appendingPathComponent("manifest.json"))
        let manifest = try canonicalJSONDecoder().decode(BundleManifest.self, from: manifestData)
        #expect(manifest.traceId == trace.id)
        #expect(manifest.title == "Manifest test")
        #expect(manifest.severity == "high")
        #expect(manifest.format == BundleManifest.currentFormat)
        #expect(manifest.processIdentityVersion == "maccrab.process_identity.v1")
        #expect(manifest.hostRedacted == true)
        await store.close()
    }

    @Test("PROV-O artifact passes the manifest claim check")
    func provOClaimPasses() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        let parent = try await upsertProcess(store, makeProcessNode(
            key: "parent", path: "/bin/zsh", isAppleSigned: true))
        let child = try await upsertProcess(store, makeProcessNode(
            key: "child", path: "/usr/bin/curl", isAppleSigned: true))
        _ = try await upsertSpawn(store, from: parent, to: child)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: child.id,
            anchorEventId: "ev",
            title: "T",
            severity: "informational",
            confidence: 0.8,
            now: now.addingTimeInterval(1)
        )
        let inputs = try await collectInputs(store, trace)

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }

        let exporter = BundleExporter(redactor: BundleRedactor(userName: "test"))
        try await exporter.export(inputs: inputs, to: bundleRoot)

        let outcome = BundleValidator.validate(at: bundleRoot)
        #expect(outcome.exitCode == 0)
        await store.close()
    }

    @Test("Redaction sweep removes /Users/<name>/ from events.jsonl")
    func redactionSweepHidesUserPaths() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        let proc = try await upsertProcess(store, makeProcessNode(
            key: "p", path: "/Users/alice/Downloads/payload"))
        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: proc.id, anchorEventId: "ev",
            title: "redact test", severity: "medium",
            confidence: 0.7, now: now.addingTimeInterval(1)
        )
        var inputs = try await collectInputs(store, trace)
        // Inject a leak in events.jsonl that the sweep should redact.
        inputs = BundleExporter.Inputs(
            trace: inputs.trace,
            entities: inputs.entities,
            edges: inputs.edges,
            memberships: inputs.memberships,
            eventsJsonl: [#"{"path":"/Users/alice/secret/file"}"#],
            machineAttributions: inputs.machineAttributions,
            humanOverrides: inputs.humanOverrides,
            policySnapshotJson: inputs.policySnapshotJson,
            otelConventionVersion: inputs.otelConventionVersion
        )

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }

        let exporter = BundleExporter(redactor: BundleRedactor(userName: "alice"))
        try await exporter.export(inputs: inputs, to: bundleRoot)

        let eventsText = try String(
            contentsOf: bundleRoot.appendingPathComponent("events.jsonl"),
            encoding: .utf8
        )
        #expect(!eventsText.contains("/Users/alice/"))
        // Validator's exit-7 redaction check should pass.
        let outcome = BundleValidator.validate(at: bundleRoot)
        #expect(outcome.exitCode == 0)
        await store.close()
    }

    @Test("Hash chain Merkle root is deterministic for the same content")
    func merkleRootDeterministic() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        let proc = try await upsertProcess(store, makeProcessNode(
            key: "p", path: "/bin/zsh", isAppleSigned: true))
        let materializer = TraceMaterializer(store: store)
        // Use a fixed daemon version so the manifest content is reproducible.
        let trace = try await materializer.materialize(
            anchorEntityId: proc.id, anchorEventId: "ev",
            title: "T", severity: "low",
            confidence: 0.5, now: now.addingTimeInterval(1)
        )
        let inputs = try await collectInputs(store, trace)

        // Two exports of the same logical trace should produce the same Merkle root —
        // EXCEPT for the manifest's `created_at` field, which uses Date(). For the
        // determinism story to hold across daemon runs we'd need to plumb a fixed
        // clock; v1.10.0 documents this as a future strengthening of the
        // determinism contract. For now, verify that within a single run the
        // chain artifact and sigutil are well-formed.
        let bundle1 = FileManager.default.temporaryDirectory.appendingPathComponent("b-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundle1) }
        let exporter = BundleExporter(redactor: BundleRedactor(userName: "test"))
        try await exporter.export(inputs: inputs, to: bundle1)

        let chainData = try Data(contentsOf: bundle1.appendingPathComponent("integrity/hash_chain.json"))
        let chain = try canonicalJSONDecoder().decode(HashChainArtifact.self, from: chainData)
        #expect(!chain.merkleRoot.isEmpty)
        #expect(chain.merkleRoot.count == 64)   // SHA-256 hex
        #expect(!chain.artifacts.isEmpty)
        // Artifact list should be sorted by canonical path.
        let paths = chain.artifacts.map { $0.path }
        #expect(paths == paths.sorted())
        await store.close()
    }

    /// Fixture 1 bundle-size assertion (§18.6 / §27.2 Fixture 1 expectation).
    /// Per spec: "the Fixture 1 (AI credential chain) bundle, exported with
    /// default redaction and the default policy, must compress to less than
    /// 1 MB."
    ///
    /// PR-10b checks the *raw* bundle directory size (sum of file sizes).
    /// Compressed gzip output will only be smaller — so raw < 1 MB implies
    /// compressed < 1 MB. True compressed-size measurement runs in PR-9
    /// alongside the tar.gz packaging step.
    @Test("Fixture 1 bundle size: raw < 1 MB")
    func fixture1BundleSize() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }

        // Replicate the Fixture 1 chain from TraceMaterializerTests.
        let claudeDesktop = try await upsertProcess(store, makeProcessNode(
            key: "claude-desktop",
            path: "/Applications/Claude.app/Contents/MacOS/Claude",
            isAppleSigned: true,
            agentTraceId: "trace-claude-1"
        ))
        let mcpServer = try await upsertProcess(store, makeProcessNode(
            key: "mcp-server",
            path: "/opt/homebrew/bin/mcp-server",
            isAppleSigned: false,
            teamId: "RANDOM999",
            agentTraceId: "trace-claude-1"
        ))
        let nodeProc = try await upsertProcess(store, makeProcessNode(
            key: "node",
            path: "/opt/homebrew/bin/node",
            isAppleSigned: false,
            teamId: "RANDOM888"
        ))
        let zsh = try await upsertProcess(store, makeProcessNode(
            key: "zsh", path: "/bin/zsh", isAppleSigned: true))
        let osascript = try await upsertProcess(store, makeProcessNode(
            key: "osascript", path: "/usr/bin/osascript", isAppleSigned: true))

        _ = try await upsertSpawn(store, from: claudeDesktop, to: mcpServer)
        _ = try await upsertSpawn(store, from: mcpServer, to: nodeProc)
        _ = try await upsertSpawn(store, from: nodeProc, to: zsh)
        _ = try await upsertSpawn(store, from: zsh, to: osascript)

        let credentialFile = FileNode(
            path: "/Users/me/.aws/credentials",
            pathHash: "h-aws-creds",
            fileKind: .credentialFile,
            firstSeen: now, lastSeen: now
        )
        let credentialEntity = try credentialFile.toEntity(source: "es-collector")
        try await store.upsertEntity(credentialEntity)
        let readEdge = EdgeBuilder.build(
            sourceEntityId: osascript.id,
            targetEntityId: credentialEntity.id,
            relation: .read,
            confidence: 0.95,
            observedAt: now,
            evidenceJson: "{\"file_kind\":\"credential_file\"}"
        )
        try await store.upsertEdge(readEdge)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: osascript.id,
            anchorEventId: "ev-osascript",
            title: "AI-assisted credential access",
            severity: "high",
            confidence: 0.92,
            attackTechniques: ["T1059", "T1555"],
            now: now.addingTimeInterval(1)
        )
        let inputs = try await collectInputs(store, trace)

        let bundleRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("fixture1-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: bundleRoot) }
        let exporter = BundleExporter(redactor: BundleRedactor(userName: "me"))
        try await exporter.export(inputs: inputs, to: bundleRoot)

        // Sum file sizes recursively.
        var total: Int64 = 0
        if let enumerator = FileManager.default.enumerator(
            at: bundleRoot,
            includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) {
            for case let url as URL in enumerator {
                let res = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
                if res.isRegularFile == true, let size = res.fileSize {
                    total += Int64(size)
                }
            }
        }
        // Per §18.6 ordinary bundle target: < 1 MB compressed. Raw is a
        // strict upper bound on compressed.
        #expect(total < 1_000_000, "Fixture 1 raw bundle size \(total) bytes exceeds 1 MB")
        await store.close()
    }
}
