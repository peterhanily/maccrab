// RollingCausalGraphTests.swift
// v1.10 TraceGraph (PR-8 ingestion tail) — exercises ingestion +
// anchor detection + materialization for Fixtures 2/3/5/6/9.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: RollingCausalGraph ingestion + anchor detection")
struct RollingCausalGraphTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("rcg-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func makeRollingGraph(_ store: SQLiteCausalGraphStore) -> RollingCausalGraph {
        let materializer = TraceMaterializer(store: store)
        return RollingCausalGraph(store: store, materializer: materializer)
    }

    private func proc(
        _ key: String,
        _ path: String,
        pid: Int32 = 100,
        ppid: Int32? = 1,
        appleSigned: Bool = true,
        teamId: String? = nil,
        parentKey: String? = nil
    ) -> RollingCausalGraph.ProcessObservation {
        RollingCausalGraph.ProcessObservation(
            processKey: key,
            pid: pid,
            ppid: ppid,
            executablePath: path,
            isAppleSigned: appleSigned,
            isNotarized: appleSigned,
            signingTeamId: teamId,
            startTime: now,
            parentProcessKey: parentKey
        )
    }

    private func file(_ path: String, hash: String? = nil) -> RollingCausalGraph.FileObservation {
        RollingCausalGraph.FileObservation(
            path: path,
            pathHash: hash ?? "h-\(path)"
        )
    }

    private func net(host: String? = nil, ip: String? = nil, port: Int = 443, reputation: NetworkReputation = .unknown) -> RollingCausalGraph.NetworkObservation {
        RollingCausalGraph.NetworkObservation(
            host: host,
            ip: ip,
            port: port,
            protocolName: "tcp",
            reputation: reputation
        )
    }

    private func agent(name: String, traceId: String, confidence: Double = 0.95) -> RollingCausalGraph.AgentEnrichment {
        RollingCausalGraph.AgentEnrichment(
            agentName: name,
            agentTool: name.lowercased(),
            traceId: traceId,
            confidence: confidence,
            attributionMethod: .directTraceparent
        )
    }

    // MARK: - Fixture 3 — LaunchAgent persistence

    /// Fixture 3: shell writes ~/Library/LaunchAgents/foo.plist
    /// Expected: PersistenceNode + created_persistence edge + ATT&CK T1543.001 mapping reachable.
    /// PR-8 verifies the entity + edge + anchor fire; ATT&CK mapping is layered by callers.
    @Test("Fixture 3: LaunchAgent persistence creates a persistence anchor")
    func fixture3_launchAgentPersistence() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        let event = RollingCausalGraph.NormalizedEventInput(
            eventId: "ev-1",
            timestamp: now,
            category: .file,
            action: .fileCreate,
            process: proc("zsh-key", "/bin/zsh"),
            file: file("/Users/me/Library/LaunchAgents/com.fake.agent.plist", hash: "h-fake-agent")
        )
        let traces = try await graph.ingest(event)
        #expect(traces.count == 1, "expected one persistence anchor, got \(traces.count)")

        // Persistence entity reachable in the store.
        let persistEntityId = "persistence:launch_agent:/Users/me/Library/LaunchAgents/com.fake.agent.plist"
        let persistEntity = try await store.entity(id: persistEntityId)
        #expect(persistEntity != nil)
        #expect(persistEntity?.entityType == "persistence")

        // created_persistence edge reachable.
        let edgeId = EdgeBuilder.edgeId(
            sourceEntityId: "process:zsh-key",
            targetEntityId: persistEntityId,
            relation: .createdPersistence
        )
        let edge = try await store.edge(id: edgeId)
        #expect(edge != nil)
        #expect(edge?.relation == "created_persistence")
        #expect(edge?.confidenceTier == "direct")

        await store.close()
    }

    // MARK: - Fixture 5 — weak temporal-only relation

    /// Fixture 5: two unrelated processes both read the same file at
    /// nearby times. Expected: TWO direct read edges (one per process),
    /// NO inferred edge between the processes. Per §11.2, temporal
    /// proximity alone must not produce a causal edge.
    @Test("Fixture 5: temporal-only proximity does NOT create a causal edge")
    func fixture5_temporalOnlyNoCausalEdge() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        let fileObs = file("/Users/me/.aws/credentials", hash: "h-aws")

        let eventA = RollingCausalGraph.NormalizedEventInput(
            eventId: "ev-a",
            timestamp: now,
            category: .file,
            action: .fileRead,
            process: proc("proc-a", "/usr/bin/cat", pid: 100),
            file: fileObs
        )
        let eventB = RollingCausalGraph.NormalizedEventInput(
            eventId: "ev-b",
            timestamp: now.addingTimeInterval(2),
            category: .file,
            action: .fileRead,
            process: proc("proc-b", "/usr/bin/grep", pid: 200),
            file: fileObs
        )
        _ = try await graph.ingest(eventA)
        _ = try await graph.ingest(eventB)

        // Both read edges exist (direct observations).
        let readEdgeA = EdgeBuilder.edgeId(
            sourceEntityId: "process:proc-a",
            targetEntityId: "file:h-aws",
            relation: .read
        )
        let readEdgeB = EdgeBuilder.edgeId(
            sourceEntityId: "process:proc-b",
            targetEntityId: "file:h-aws",
            relation: .read
        )
        #expect(try await store.edge(id: readEdgeA) != nil)
        #expect(try await store.edge(id: readEdgeB) != nil)

        // No process-to-process edge between A and B (would be temporal-only inference).
        for relation in EdgeRelation.allCases {
            let aToB = EdgeBuilder.edgeId(
                sourceEntityId: "process:proc-a",
                targetEntityId: "process:proc-b",
                relation: relation
            )
            let bToA = EdgeBuilder.edgeId(
                sourceEntityId: "process:proc-b",
                targetEntityId: "process:proc-a",
                relation: relation
            )
            #expect(try await store.edge(id: aToB) == nil, "stray inferred edge \(relation.rawValue): A→B")
            #expect(try await store.edge(id: bToA) == nil, "stray inferred edge \(relation.rawValue): B→A")
        }

        await store.close()
    }

    // MARK: - Fixture 6 — concurrent agents

    /// Fixture 6: Claude Code + Cursor both touch ~/Projects/foo
    /// concurrently. Expected: two distinct AIAgentNodes; file
    /// modifications bucketed by process lineage, not project path.
    @Test("Fixture 6: concurrent agents produce distinct AI agent entities")
    func fixture6_concurrentAgents() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        let claudeEvent = RollingCausalGraph.NormalizedEventInput(
            eventId: "claude-write",
            timestamp: now,
            category: .file,
            action: .fileWrite,
            process: proc("proc-claude-child", "/usr/local/bin/node", pid: 300, appleSigned: false),
            file: file("/Users/me/Projects/foo/file1.swift", hash: "h-file1"),
            agent: agent(name: "Claude Code", traceId: "trace-claude-1")
        )
        let cursorEvent = RollingCausalGraph.NormalizedEventInput(
            eventId: "cursor-write",
            timestamp: now,
            category: .file,
            action: .fileWrite,
            process: proc("proc-cursor-child", "/Applications/Cursor.app/Contents/MacOS/Cursor", pid: 400, appleSigned: false),
            file: file("/Users/me/Projects/foo/file2.swift", hash: "h-file2"),
            agent: agent(name: "Cursor", traceId: "trace-cursor-1")
        )
        _ = try await graph.ingest(claudeEvent)
        _ = try await graph.ingest(cursorEvent)

        // Two distinct agent entities exist.
        let claudeAgentEntity = try await store.entity(id: "ai_agent:claude code:trace-claude-1")
        let cursorAgentEntity = try await store.entity(id: "ai_agent:cursor:trace-cursor-1")
        #expect(claudeAgentEntity != nil)
        #expect(cursorAgentEntity != nil)
        #expect(claudeAgentEntity?.id != cursorAgentEntity?.id)

        // Each file is associated with its own process, not blended.
        let claudeFileEdge = EdgeBuilder.edgeId(
            sourceEntityId: "process:proc-claude-child",
            targetEntityId: "file:h-file1",
            relation: .wrote
        )
        let cursorFileEdge = EdgeBuilder.edgeId(
            sourceEntityId: "process:proc-cursor-child",
            targetEntityId: "file:h-file2",
            relation: .wrote
        )
        #expect(try await store.edge(id: claudeFileEdge) != nil)
        #expect(try await store.edge(id: cursorFileEdge) != nil)

        // Cross-bucket edges (Claude process touching Cursor's file) must NOT exist.
        let crossEdge = EdgeBuilder.edgeId(
            sourceEntityId: "process:proc-claude-child",
            targetEntityId: "file:h-file2",
            relation: .wrote
        )
        #expect(try await store.edge(id: crossEdge) == nil)

        await store.close()
    }

    // MARK: - Fixture 9 — benign AI-assisted edit

    /// Fixture 9: Claude Desktop → MCP Server → node → writes a project
    /// file. No credential, no persistence, no external network.
    /// Expected: NO anchor fires (no high-severity trace materialized
    /// automatically). Trace may be available on-demand via the
    /// agent-name lookup, but ingest should not auto-anchor.
    @Test("Fixture 9: benign AI-assisted edit does NOT trigger an anchor")
    func fixture9_benignAIEdit() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        // Claude Desktop spawns MCP Server (writes are agent-attributed).
        let event = RollingCausalGraph.NormalizedEventInput(
            eventId: "benign-write",
            timestamp: now,
            category: .file,
            action: .fileWrite,
            process: proc("proc-node", "/opt/homebrew/bin/node", pid: 500, appleSigned: false),
            file: file("/Users/me/Projects/foo/Sources/Main.swift", hash: "h-main"),
            agent: agent(name: "Claude Desktop", traceId: "trace-claude-2")
        )
        let traces = try await graph.ingest(event)
        // No anchor — the file is a project file, not a credential / persistence / etc.
        #expect(traces.isEmpty, "benign write should not auto-anchor; got \(traces.count) trace(s)")

        // Agent attribution still recorded (provenance, not suspicion).
        let agentEntity = try await store.entity(id: "ai_agent:claude desktop:trace-claude-2")
        #expect(agentEntity != nil)

        // The process and the file both got upserted (we still record the activity).
        #expect(try await store.entity(id: "process:proc-node") != nil)
        #expect(try await store.entity(id: "file:h-main") != nil)

        await store.close()
    }

    // MARK: - Fixture 2 — package postinstall network (partial coverage)

    /// Fixture 2: zsh → npm → postinstall script → curl → external host.
    /// PR-8 baseline: exercises the spawn chain + network anchor. Full
    /// PackageScriptNode detection (which would mark the postinstall as
    /// the root cause) is layered when ESCollector emits a richer
    /// "package script" event type — this test verifies the spawn
    /// chain + network connection are recorded.
    @Test("Fixture 2: postinstall → external network records spawn chain + network anchor")
    func fixture2_postinstallNetwork() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        let zsh = proc("k-zsh", "/bin/zsh", pid: 100, ppid: 1)
        let npm = proc("k-npm", "/opt/homebrew/bin/npm", pid: 200, ppid: 100, appleSigned: false, parentKey: "k-zsh")
        let postinstall = proc("k-postinstall", "/bin/sh", pid: 300, ppid: 200, parentKey: "k-npm")
        let curl = proc("k-curl", "/usr/bin/curl", pid: 400, ppid: 300, parentKey: "k-postinstall")

        let agentForCurl = agent(name: "Claude Desktop", traceId: "trace-claude-3")
        // Spawn chain
        _ = try await graph.ingest(.init(
            eventId: "exec-npm", timestamp: now,
            category: .process, action: .exec,
            process: npm,
            parentProcess: zsh
        ))
        _ = try await graph.ingest(.init(
            eventId: "exec-postinstall", timestamp: now.addingTimeInterval(0.1),
            category: .process, action: .exec,
            process: postinstall,
            parentProcess: npm
        ))
        _ = try await graph.ingest(.init(
            eventId: "exec-curl", timestamp: now.addingTimeInterval(0.2),
            category: .process, action: .exec,
            process: curl,
            parentProcess: postinstall
        ))
        // Network event — agent context attached so external-network anchor fires.
        let netTraces = try await graph.ingest(.init(
            eventId: "net-curl",
            timestamp: now.addingTimeInterval(0.3),
            category: .network, action: .netConnect,
            process: curl,
            network: net(ip: "203.0.113.10", port: 443, reputation: .suspicious),
            agent: agentForCurl
        ))
        #expect(netTraces.count >= 1, "expected an external-network-from-agent anchor")

        // Spawn chain reachable.
        let spawnEdges = [
            ("process:k-zsh", "process:k-npm"),
            ("process:k-npm", "process:k-postinstall"),
            ("process:k-postinstall", "process:k-curl"),
        ]
        for (src, dst) in spawnEdges {
            let id = EdgeBuilder.edgeId(sourceEntityId: src, targetEntityId: dst, relation: .spawned)
            #expect(try await store.edge(id: id) != nil, "missing spawn edge \(src)→\(dst)")
        }
        await store.close()
    }

    // MARK: - Generic invariants

    @Test("Repeat ingest of the same event is idempotent at the entity level")
    func repeatIngestIdempotent() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        let event = RollingCausalGraph.NormalizedEventInput(
            eventId: "ev-x",
            timestamp: now,
            category: .process, action: .exec,
            process: proc("k-a", "/bin/zsh")
        )
        _ = try await graph.ingest(event)
        _ = try await graph.ingest(event)
        _ = try await graph.ingest(event)

        let entity = try await store.entity(id: "process:k-a")
        #expect(entity?.observationCount == 3)
        await store.close()
    }

    @Test("recordExternalAnchor materializes a trace even when no event-side anchor fires")
    func externalAnchor() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = makeRollingGraph(store)

        // Seed an entity in the store so the materializer has an anchor to load.
        let event = RollingCausalGraph.NormalizedEventInput(
            eventId: "seed",
            timestamp: now,
            category: .process, action: .exec,
            process: proc("k-anchor", "/bin/zsh")
        )
        _ = try await graph.ingest(event)

        let trace = try await graph.recordExternalAnchor(
            anchorEntityId: "process:k-anchor",
            anchorEventId: "rule-hit",
            reason: "MaccrabRule: suspicious-shell-spawn",
            severity: "high",
            confidence: 0.9,
            observedAt: now.addingTimeInterval(1)
        )
        #expect(trace.title.contains("suspicious-shell-spawn"))
        #expect(trace.severity == "high")
        await store.close()
    }
}
