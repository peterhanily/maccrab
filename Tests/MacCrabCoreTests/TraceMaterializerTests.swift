// TraceMaterializerTests.swift
// v1.10 TraceGraph (PR-8) — end-to-end tests for trace materialization
// including Fixture 1 (AI credential access).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: TraceMaterializer")
struct TraceMaterializerTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-mat-\(UUID().uuidString).db")
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)
        return (store, path)
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
        to child: TraceEntity,
        confidence: Double = 0.95
    ) async throws -> TraceEdge {
        let edge = EdgeBuilder.build(
            sourceEntityId: parent.id,
            targetEntityId: child.id,
            relation: .spawned,
            confidence: confidence,
            observedAt: now
        )
        try await store.upsertEdge(edge)
        return edge
    }

    // MARK: - Tests

    @Test("Materializes a single-process trace with no ancestors")
    func materializeNoAncestors() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let node = makeProcessNode(key: "k", path: "/Users/me/Downloads/x")
        let entity = try await upsertProcess(store, node)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: entity.id,
            anchorEventId: "ev-1",
            title: "Test trace",
            severity: "high",
            confidence: 0.9,
            now: now.addingTimeInterval(1)
        )
        #expect(trace.title == "Test trace")
        #expect(trace.severity == "high")
        #expect(trace.rootEntityId == entity.id)  // anchor-is-root since no ancestors
        await store.close()
    }

    @Test("Materialization persists Trace + memberships")
    func persistsTraceAndMembers() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let parent = try await upsertProcess(store, makeProcessNode(
            key: "parent", path: "/bin/zsh", isAppleSigned: true))
        let child = try await upsertProcess(store, makeProcessNode(
            key: "child", path: "/Users/me/Downloads/evil", isAppleSigned: false))
        _ = try await upsertSpawn(store, from: parent, to: child)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: child.id,
            anchorEventId: "ev-1",
            title: "Suspicious download executed",
            severity: "high",
            confidence: 0.92,
            now: now.addingTimeInterval(1)
        )

        // Reload from store; assert membership exists.
        let loaded = try await store.loadTrace(id: trace.id)
        #expect(loaded != nil)
        #expect(loaded?.members.count ?? 0 >= 2)   // anchor + at least one other
        let anchorMember = loaded?.members.first { $0.role == "anchor" }
        #expect(anchorMember?.entityId == child.id)
        await store.close()
    }

    @Test("Trusted ancestry downgrades severity by one step")
    func trustedAncestryDowngrade() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        // All Apple-signed in trusted prefixes — chain is fully trusted.
        let term = try await upsertProcess(store, makeProcessNode(
            key: "term", path: "/Applications/Terminal.app/Contents/MacOS/Terminal", isAppleSigned: true))
        let zsh = try await upsertProcess(store, makeProcessNode(
            key: "zsh", path: "/bin/zsh", isAppleSigned: true))
        let curl = try await upsertProcess(store, makeProcessNode(
            key: "curl", path: "/usr/bin/curl", isAppleSigned: true))
        _ = try await upsertSpawn(store, from: term, to: zsh)
        _ = try await upsertSpawn(store, from: zsh, to: curl)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: curl.id,
            anchorEventId: "ev-1",
            title: "Trusted chain",
            severity: "high",
            confidence: 0.9,
            now: now.addingTimeInterval(1)
        )
        #expect(trace.severity == "medium")  // downgraded from high
        await store.close()
    }

    /// Fixture 1 — the headline AI credential access scenario.
    /// Claude Desktop → MCP Server → node → zsh → osascript → ~/.aws/credentials
    /// Per §27.2 expected:
    ///   - Process chain exists.
    ///   - AIAgentNode + Credential FileNode both reachable.
    ///   - Trace confidence ≥ 0.85.
    ///   - Root cause is MCP Server or the first materially relevant
    ///     trust-transition point.
    ///
    /// The fixture wires entities + edges manually (the ingestion side
    /// is in the RollingCausalGraph PR-8 increment); what we verify
    /// here is that the materializer assembles them into a trace
    /// satisfying the §27.2 expectations.
    @Test("Fixture 1: AI credential access end-to-end")
    func fixture1_aiCredentialAccess() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        // Chain: claude_desktop → mcp_server → node → zsh → osascript
        // claude_desktop is Apple-signed, in /Applications.
        // mcp_server is in /opt/homebrew/bin (Developer-ID, NOT trusted by default policy).
        // node + zsh + osascript are Apple-signed in trusted prefixes.
        // osascript reads ~/.aws/credentials (not modeled as a process here;
        // the FileNode would be a separate entity tracked via a `read` edge —
        // but the trust transition resolution only cares about the spawned chain).
        let claudeDesktop = try await upsertProcess(store, makeProcessNode(
            key: "claude-desktop",
            path: "/Applications/Claude.app/Contents/MacOS/Claude",
            isAppleSigned: true,
            agentTraceId: "trace-claude-1"
        ))
        let mcpServer = try await upsertProcess(store, makeProcessNode(
            key: "mcp-server",
            path: "/opt/homebrew/bin/mcp-server",
            isAppleSigned: false,    // Developer-ID-signed, but team not in default allowlist
            teamId: "RANDOM999",
            agentTraceId: "trace-claude-1"
        ))
        let node = try await upsertProcess(store, makeProcessNode(
            key: "node",
            path: "/opt/homebrew/bin/node",
            isAppleSigned: false,     // Homebrew-installed; not Apple-signed
            teamId: "RANDOM888"
        ))
        let zsh = try await upsertProcess(store, makeProcessNode(
            key: "zsh",
            path: "/bin/zsh",
            isAppleSigned: true
        ))
        let osascript = try await upsertProcess(store, makeProcessNode(
            key: "osascript",
            path: "/usr/bin/osascript",
            isAppleSigned: true
        ))

        // Spawned edges
        _ = try await upsertSpawn(store, from: claudeDesktop, to: mcpServer, confidence: 0.95)
        _ = try await upsertSpawn(store, from: mcpServer, to: node, confidence: 0.95)
        _ = try await upsertSpawn(store, from: node, to: zsh, confidence: 0.95)
        _ = try await upsertSpawn(store, from: zsh, to: osascript, confidence: 0.95)

        // Credential file (modeled as separate entity for completeness)
        let credentialFile = FileNode(
            path: "/Users/me/.aws/credentials",
            pathHash: "h-aws-creds",
            fileKind: .credentialFile,
            firstSeen: now,
            lastSeen: now
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

        // Materialize on osascript
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

        // §27.2 expectations:
        // - Trace confidence ≥ 0.85
        #expect(trace.confidence >= 0.85)

        // - Process chain exists in the persisted membership
        let loaded = try await store.loadTrace(id: trace.id)
        #expect(loaded != nil)
        let memberEntityIds = Set((loaded?.members.compactMap { $0.entityId }) ?? [])
        #expect(memberEntityIds.contains(osascript.id))   // anchor present

        // - Root cause is MCP Server (first materially-relevant
        //   trust-transition point per §12: walking from oldest
        //   ancestor toward anchor, claude_desktop is trusted —
        //   Apple-signed in /Applications, so passes the default
        //   policy — and mcp-server is the first untrusted ancestor).
        #expect(trace.rootEntityId == mcpServer.id)

        // - Severity not downgraded (root cause is a real trust transition,
        //   not trustedAncestry).
        #expect(trace.severity == "high")

        // - Attack techniques recorded
        #expect(trace.attackJson != nil)
        #expect(trace.attackJson?.contains("T1555") == true)

        await store.close()
    }

    @Test("Critical path appears in the persisted membership when ancestors exist")
    func criticalPathPersisted() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let parent = try await upsertProcess(store, makeProcessNode(
            key: "parent", path: "/bin/zsh", isAppleSigned: true))
        let child = try await upsertProcess(store, makeProcessNode(
            key: "child", path: "/Users/me/Downloads/x", isAppleSigned: false))
        _ = try await upsertSpawn(store, from: parent, to: child)

        let materializer = TraceMaterializer(store: store)
        let trace = try await materializer.materialize(
            anchorEntityId: child.id,
            anchorEventId: "ev",
            title: "T",
            severity: "high",
            confidence: 0.9,
            now: now.addingTimeInterval(1)
        )
        let loaded = try await store.loadTrace(id: trace.id)
        let criticalPathMembers = loaded?.members.filter { $0.role == "critical_path" } ?? []
        #expect(criticalPathMembers.contains { $0.edgeId != nil })
        await store.close()
    }
}
