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
    /// concurrently. Expected: two distinct AIAgentNodes and agent→process
    /// edges; ordinary project files are relevance-suppressed.
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

        // Ordinary project-file nodes are relevance-suppressed even for agent
        // activity; retaining every AI build/source path was precisely the
        // unbounded rc.5 churn. Agent→process attribution remains distinct.
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
        #expect(try await store.edge(id: claudeFileEdge) == nil)
        #expect(try await store.edge(id: cursorFileEdge) == nil)
        #expect(try await store.edge(id: EdgeBuilder.edgeId(
            sourceEntityId: "ai_agent:claude code:trace-claude-1",
            targetEntityId: "process:proc-claude-child",
            relation: .associatedWithAgent
        )) != nil)
        #expect(try await store.edge(id: EdgeBuilder.edgeId(
            sourceEntityId: "ai_agent:cursor:trace-cursor-1",
            targetEntityId: "process:proc-cursor-child",
            relation: .associatedWithAgent
        )) != nil)

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

        // Process + AI attribution remain causal provenance. The ordinary
        // project-file node is intentionally relevance-suppressed: no shipped
        // file graph rule consumes it, and persisting every unique build/source
        // path was the rc.5 write-amplification source.
        #expect(try await store.entity(id: "process:proc-node") != nil)
        #expect(try await store.entity(id: "file:h-main") == nil)

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

    @Test("Coalescer bounds 1,000 repeated observations while preserving exact state")
    func coalescerBoundsRepeatedObservationWrites() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 60,
                maximumPendingEvents: 250,
                maximumPendingRows: 4_000
            )
        )

        // `untrustedContent` makes this file rule-relevant without itself
        // producing an anchor, so all three rows (process, file, read edge)
        // exercise cross-event coalescing rather than the relevance gate.
        for i in 0..<1_000 {
            _ = try await graph.ingest(.init(
                eventId: "repeat-\(i)",
                timestamp: now.addingTimeInterval(Double(i) / 1_000),
                category: .file,
                action: .fileRead,
                process: proc("repeat-proc", "/usr/bin/cat"),
                file: .init(
                    path: "/tmp/rule-relevant.txt",
                    pathHash: "repeat-file",
                    untrustedContent: true
                )
            ))
        }

        let telemetry = await graph.writeTelemetry()
        #expect(telemetry.inputEventsTotal == 1_000)
        #expect(telemetry.eventsCommittedTotal == 1_000)
        #expect(telemetry.eventsFailedTotal == 0)
        #expect(telemetry.eventsInFlight == 0)
        #expect(telemetry.eventsPending == 0)
        #expect(telemetry.writeAttemptsTotal == 4)
        #expect(telemetry.writeBatchesCommittedTotal == 4)
        #expect(telemetry.writeRowsAttemptedTotal == 12)
        #expect(telemetry.writeRowsCommittedTotal == 12)
        #expect(telemetry.coalescedNoopRowsTotal == 2_988)
        #expect(telemetry.entityObservationsTotal + telemetry.edgeObservationsTotal == 3_000)
        #expect(
            telemetry.entityObservationsTotal + telemetry.edgeObservationsTotal
                == telemetry.writeRowsAttemptedTotal
                    + telemetry.coalescedNoopRowsTotal
                    + UInt64(telemetry.pendingEntityRows + telemetry.pendingEdgeRows)
        )

        // Aggregation is physically smaller but semantically identical to
        // 1,000 sequential UPSERTs.
        #expect(try await store.entity(id: "process:repeat-proc")?.observationCount == 1_000)
        #expect(try await store.entity(id: "file:repeat-file")?.observationCount == 1_000)
        let edgeId = EdgeBuilder.edgeId(
            sourceEntityId: "process:repeat-proc",
            targetEntityId: "file:repeat-file",
            relation: .read
        )
        let storedEdge = try await store.edge(id: edgeId)
        #expect(storedEdge?.eventIdsJson == "[\"repeat-999\"]")
        #expect(abs((storedEdge?.lastSeen.timeIntervalSince1970 ?? 0)
            - now.addingTimeInterval(0.999).timeIntervalSince1970) < 0.000_001)
        await store.close()
    }

    @Test("Ordinary unique file churn is suppressed before SQL while process provenance remains")
    func fileRelevanceAdmissionSuppressesUniqueChurn() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 60,
                maximumPendingEvents: 1_000,
                maximumPendingRows: 4_000
            )
        )

        for i in 0..<1_000 {
            _ = try await graph.ingest(.init(
                eventId: "scratch-\(i)",
                timestamp: now,
                category: .file,
                action: .fileRead,
                process: proc("compiler", "/usr/bin/swiftc"),
                file: file("/private/tmp/build-\(i).o", hash: "scratch-\(i)")
            ))
        }
        try await graph.flushPending()

        let telemetry = await graph.writeTelemetry()
        #expect(telemetry.relevanceSuppressedFileEventsTotal == 1_000)
        #expect(telemetry.relevanceSuppressedRowsTotal == 2_000)
        #expect(telemetry.writeAttemptsTotal == 1)
        #expect(telemetry.writeRowsAttemptedTotal == 1)
        #expect(telemetry.coalescedNoopRowsTotal == 999)
        #expect(try await store.entity(id: "process:compiler")?.observationCount == 1_000)
        #expect(try await store.entity(id: "file:scratch-999") == nil)
        await store.close()
    }

    @Test("Novel anchor forces pending substrate to disk before materialization")
    func novelAnchorForcesPendingFlush() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 60,
                maximumPendingEvents: 256,
                maximumPendingRows: 1_024
            )
        )

        _ = try await graph.ingest(.init(
            eventId: "pending",
            timestamp: now,
            category: .process,
            action: .exec,
            process: proc("pending-proc", "/usr/bin/true")
        ))
        #expect((await graph.writeTelemetry()).eventsPending == 1)

        let traces = try await graph.ingest(.init(
            eventId: "persistence-anchor",
            timestamp: now.addingTimeInterval(0.1),
            category: .file,
            action: .fileCreate,
            process: proc("pending-proc", "/usr/bin/true"),
            file: file("/Users/me/Library/LaunchAgents/evil.plist", hash: "launch-agent")
        ))
        #expect(traces.count == 1)
        let telemetry = await graph.writeTelemetry()
        #expect(telemetry.eventsPending == 0)
        #expect(telemetry.eventsCommittedTotal == 2)
        #expect(telemetry.writeBatchesCommittedTotal == 1)
        #expect(try await store.entity(id: "process:pending-proc")?.observationCount == 2)
        await store.close()
    }

    @Test("Concurrent ingest snapshots preserve both conservation equations")
    func concurrentIngestConservation() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 60,
                maximumPendingEvents: 8,
                maximumPendingRows: 32
            )
        )

        await withTaskGroup(of: Void.self) { group in
            for i in 0..<200 {
                group.addTask {
                    _ = try? await graph.ingest(.init(
                        eventId: "concurrent-\(i)",
                        timestamp: self.now,
                        category: .process,
                        action: .exec,
                        process: self.proc("concurrent-\(i)", "/usr/bin/true", pid: Int32(i + 1))
                    ))
                }
            }
        }
        try await graph.flushPending()

        let t = await graph.writeTelemetry()
        #expect(t.inputEventsTotal == 200)
        #expect(t.inputEventsTotal == t.eventsCommittedTotal + t.eventsFailedTotal + UInt64(t.eventsInFlight + t.eventsPending))
        #expect(t.writeAttemptsTotal == t.writeBatchesCommittedTotal + t.writeBatchesFailedTotal + UInt64(t.writeBatchesInFlight))
        #expect(t.writeRowsAttemptedTotal == t.writeRowsCommittedTotal + t.writeRowsFailedTotal + UInt64(t.writeRowsInFlight))
        #expect(t.eventsCommittedTotal == 200)
        #expect(t.writeRowsCommittedTotal == 200)
        await store.close()
    }

    @Test("Failed coalesced batch is dropped once and conserved exactly")
    func failedBatchConservation() async throws {
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        _ = await store.updateStorageAdmission(
            maxFootprintBytes: 4_096,
            freeSpaceFloorBytes: nil,
            transactionReserveBytes: 4_096
        )
        let graph = RollingCausalGraph(
            store: store,
            materializer: TraceMaterializer(store: store),
            ingestionWritePolicy: CausalGraphIngestionWritePolicy(
                maximumDelaySeconds: 60,
                maximumPendingEvents: 2,
                maximumPendingRows: 32
            )
        )

        _ = try await graph.ingest(.init(
            eventId: "blocked-1", timestamp: now,
            category: .process, action: .exec,
            process: proc("blocked", "/usr/bin/true")
        ))
        await #expect(throws: CausalGraphStorageAdmissionError.self) {
            _ = try await graph.ingest(.init(
                eventId: "blocked-2", timestamp: now,
                category: .process, action: .exec,
                process: proc("blocked", "/usr/bin/true")
            ))
        }

        let t = await graph.writeTelemetry()
        #expect(t.inputEventsTotal == 2)
        #expect(t.eventsCommittedTotal == 0)
        #expect(t.eventsFailedTotal == 2)
        #expect(t.eventsPending == 0)
        #expect(t.writeAttemptsTotal == 1)
        #expect(t.writeBatchesFailedTotal == 1)
        #expect(t.writeRowsAttemptedTotal == 1)
        #expect(t.writeRowsFailedTotal == 1)
        #expect(t.coalescedNoopRowsTotal == 1)
        await store.close()
    }

    @Test("File relevance policy covers every shipped file-node graph rule")
    func fileRelevancePolicyMatchesRuleCorpus() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let projectRoot = testFile
            .deletingLastPathComponent() // MacCrabCoreTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // repository root
        let graphRules = GraphRuleLoader.loadRules(
            from: projectRoot.appendingPathComponent("Rules/graph"),
            enabledStatuses: ["stable", "test", "experimental", "deprecated"]
        )
        #expect(!graphRules.isEmpty)

        var fileNodeCount = 0
        for rule in graphRules {
            for (_, node) in rule.nodes where node.type == FileNode.entityType {
                fileNodeCount += 1
                let clauses = node.where ?? [:]
                let credentialOnly = clauses["file_kind"]?.equals == FileKind.credentialFile.rawValue
                    || clauses["file_kind"]?.in == [FileKind.credentialFile.rawValue]
                let requiresUntrusted = clauses["untrusted_content"]?.equalsBool == true
                #expect(
                    credentialOnly || requiresUntrusted,
                    "Rule \(rule.id) adds a file-node need outside the pre-SQL relevance contract"
                )
            }
        }
        #expect(fileNodeCount > 0)

        #expect(RollingCausalGraph.fileObservationIsRelevant(kind: .credentialFile, untrustedContent: false))
        #expect(RollingCausalGraph.fileObservationIsRelevant(kind: .launchAgent, untrustedContent: false))
        #expect(RollingCausalGraph.fileObservationIsRelevant(kind: .launchDaemon, untrustedContent: false))
        #expect(RollingCausalGraph.fileObservationIsRelevant(kind: .loginItem, untrustedContent: false))
        #expect(RollingCausalGraph.fileObservationIsRelevant(kind: .shellProfile, untrustedContent: false))
        #expect(RollingCausalGraph.fileObservationIsRelevant(kind: .unknown, untrustedContent: true))
        #expect(!RollingCausalGraph.fileObservationIsRelevant(kind: .unknown, untrustedContent: false))
        #expect(!RollingCausalGraph.fileObservationIsRelevant(kind: .packageFile, untrustedContent: false))
    }

    @Test("Every built-in CredentialFence pattern remains graph-relevant")
    func credentialFenceCorpusCannotDriftFromGraphClassification() {
        for sensitive in CredentialFence.defaultPaths {
            let probe: String
            switch sensitive.kind {
            case .exactFilename:
                probe = "/Users/graph-parity/\(sensitive.pattern)"
            case .filenamePrefix:
                probe = "/Users/graph-parity/\(sensitive.pattern)production"
            case .pathFragment:
                probe = "/Users/graph-parity\(sensitive.pattern)"
                    + (sensitive.pattern.hasSuffix("/") ? "probe" : "")
            }
            #expect(
                CredentialFence.defaultCredentialType(filePath: probe) != nil,
                "CredentialFence default fixture did not match its own probe: \(sensitive.pattern)"
            )
            #expect(
                RollingCausalGraph.inferFileKind(path: probe) == .credentialFile,
                "CredentialFence path would be relevance-suppressed by the graph: \(probe)"
            )
        }
    }

    @Test("Daemon lifecycle flushes and heartbeat write telemetry cannot drift")
    func daemonIntegrationPreservesGraphWriteContract() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let projectRoot = testFile
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let signals = try String(
            contentsOf: projectRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/SignalHandlers.swift"
            ),
            encoding: .utf8
        )
        let bootstrap = try String(
            contentsOf: projectRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonBootstrap.swift"
            ),
            encoding: .utf8
        )
        let lifecycle = try String(
            contentsOf: projectRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonLifecycle.swift"
            ),
            encoding: .utf8
        )
        let bridge = try String(
            contentsOf: projectRoot.appendingPathComponent(
                "Sources/MacCrabCore/TraceGraph/EventToRollingCausalGraphBridge.swift"
            ),
            encoding: .utf8
        )
        let timers = try String(
            contentsOf: projectRoot.appendingPathComponent(
                "Sources/MacCrabAgentKit/DaemonTimers.swift"
            ),
            encoding: .utf8
        )
        let signalFlushes = signals.components(
            separatedBy: "try await bridge.flushPending()"
        ).count - 1
        #expect(signalFlushes >= 1, "SIGHUP reload must flush before swapping graph rules")
        #expect(lifecycle.contains("try await bridge.flushPending()"),
                "the central shutdown coordinator must flush the graph")
        #expect(signals.contains("DaemonShutdownCoordinator.finalize("),
                "SIGTERM/SIGINT must enter the central shutdown coordinator")
        #expect(bootstrap.contains("DaemonShutdownCoordinator.finalize("),
                "event-stream termination must enter the same shutdown coordinator")
        #expect(bridge.contains("await rollingGraph.writeTelemetry()"))
        #expect(bridge.contains("try await rollingGraph.flushPending()"))

        let rolling = try String(
            contentsOf: projectRoot.appendingPathComponent(
                "Sources/MacCrabCore/TraceGraph/RollingCausalGraph.swift"
            ),
            encoding: .utf8
        )
        #expect(rolling.contains("private var inFlightStoreWrite: Task<Void, Error>?"))
        #expect(rolling.contains("while let existing = inFlightStoreWrite"))
        #expect(rolling.contains("try await existing.value"),
                "lifecycle flush must join an already-detached store write")

        let heartbeatKeys = [
            "ingest_events_total",
            "ingest_events_committed_total",
            "ingest_events_failed_total",
            "ingest_events_in_flight",
            "ingest_events_pending",
            "entity_observations_total",
            "edge_observations_total",
            "relevance_suppressed_file_events_total",
            "relevance_suppressed_rows_total",
            "write_attempts_total",
            "write_batches_committed_total",
            "write_batches_failed_total",
            "write_batches_in_flight",
            "write_rows_attempted_total",
            "write_rows_committed_total",
            "write_rows_failed_total",
            "write_rows_in_flight",
            "coalesced_noop_rows_total",
            "pending_entity_rows",
            "pending_edge_rows",
        ]
        #expect(timers.contains("let w = await bridge.writeTelemetry()"))
        for key in heartbeatKeys {
            #expect(
                timers.contains("d[\"\(key)\"]"),
                "Missing rolling-graph heartbeat field: \(key)"
            )
        }
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
