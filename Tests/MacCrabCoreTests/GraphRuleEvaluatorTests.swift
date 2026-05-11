// GraphRuleEvaluatorTests.swift
// v1.10 TraceGraph (PR-13) — exercises GraphRule + GraphRuleEvaluator
// against synthetic traces, plus loads the 5 starter rules from
// Rules/graph/ and verifies they decode + match expected fixtures.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: GraphRuleEvaluator")
struct GraphRuleEvaluatorTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    // MARK: - Helpers

    private func processEntity(
        key: String,
        path: String,
        isAppleSigned: Bool = true
    ) throws -> TraceEntity {
        let node = ProcessNode(
            processKey: key, pid: 100, ppid: 1,
            executablePath: path,
            isAppleSigned: isAppleSigned,
            isNotarized: isAppleSigned,
            startTime: now
        )
        return try node.toEntity(source: "test")
    }

    private func fileEntity(_ path: String, kind: FileKind) throws -> TraceEntity {
        let node = FileNode(
            path: path, pathHash: "h-\(path)",
            fileKind: kind,
            firstSeen: now, lastSeen: now
        )
        return try node.toEntity(source: "test")
    }

    private func networkEntity(_ host: String, reputation: NetworkReputation = .suspicious) throws -> TraceEntity {
        let node = NetworkNode(
            destinationHost: host, port: 443,
            protocolName: "tcp", reputation: reputation,
            firstSeen: now
        )
        return try node.toEntity(source: "test")
    }

    private func agentEntity(_ name: String, traceId: String) throws -> TraceEntity {
        let node = AIAgentNode(
            agentId: "\(name.lowercased()):\(traceId)",
            agentName: name,
            traceId: traceId,
            confidence: 0.95,
            attributionMethod: .directTraceparent,
            firstSeen: now
        )
        return try node.toEntity(source: "test", confidence: 0.95)
    }

    private func persistenceEntity(_ path: String, type: PersistenceType = .launchAgent) throws -> TraceEntity {
        let node = PersistenceNode(
            persistenceType: type,
            path: path,
            firstSeen: now
        )
        return try node.toEntity(source: "test")
    }

    private func mcpEntity(_ name: String) throws -> TraceEntity {
        let node = MCPServerNode(
            serverName: name, transport: "stdio",
            firstSeen: now
        )
        return try node.toEntity(source: "test")
    }

    private func edge(
        from: TraceEntity, to: TraceEntity,
        relation: EdgeRelation,
        confidence: Double = 0.9
    ) -> TraceEdge {
        EdgeBuilder.build(
            sourceEntityId: from.id, targetEntityId: to.id,
            relation: relation, confidence: confidence,
            observedAt: now
        )
    }

    // MARK: - Starter rule loading

    @Test("All 5 starter rules in Rules/graph/ decode cleanly")
    func starterRulesDecode() {
        let projectRoot = projectRootURL()
        let rules = GraphRuleLoader.loadFromProjectSource(projectRoot: projectRoot)
        let ids = Set(rules.map { $0.id })
        #expect(ids.contains("maccrab_ai_agent_credential_network_persistence"))
        #expect(ids.contains("maccrab_unsigned_download_executes_then_persists"))
        #expect(ids.contains("maccrab_mcp_server_spawns_shell_then_credential"))
        #expect(ids.contains("maccrab_launchagent_after_credential_access"))
        #expect(ids.contains("maccrab_agent_associated_shell_writes_to_login_item"))
        #expect(rules.count >= 5, "expected at least 5 starter rules, got \(rules.count)")
    }

    // MARK: - Headline rule fires on Fixture 1 shape

    @Test("AI-agent credential+network+persistence rule fires on the headline fixture")
    func aiAgentCredentialNetworkPersistenceRule() async throws {
        let agent = try agentEntity("Claude Desktop", traceId: "trace-1")
        let proc = try processEntity(key: "p", path: "/usr/bin/osascript")
        let cred = try fileEntity("/Users/me/.aws/credentials", kind: .credentialFile)
        let net = try networkEntity("evil.example.com")
        let persist = try persistenceEntity("/Users/me/Library/LaunchAgents/com.fake.agent.plist")

        let entities = [agent, proc, cred, net, persist]
        let edges = [
            edge(from: agent,   to: proc,    relation: .associatedWithAgent, confidence: 0.95),
            edge(from: proc,    to: cred,    relation: .read,                confidence: 0.92),
            edge(from: proc,    to: net,     relation: .connectedTo,         confidence: 0.92),
            edge(from: proc,    to: persist, relation: .createdPersistence,  confidence: 0.95),
        ]

        let rules = GraphRuleLoader.loadFromProjectSource(projectRoot: projectRootURL())
        let evaluator = GraphRuleEvaluator(rules: rules)
        let matches = await evaluator.evaluate(entities: entities, edges: edges)

        let headlineMatch = matches.first { $0.ruleId == "maccrab_ai_agent_credential_network_persistence" }
        #expect(headlineMatch != nil)
        #expect(headlineMatch?.attack.contains("T1555") == true)
        #expect(headlineMatch?.bindings["agent"] == agent.id)
        #expect(headlineMatch?.bindings["proc"] == proc.id)
        #expect(headlineMatch?.matchedEdgeIds.count == 4)
    }

    // MARK: - Negative case

    @Test("Headline rule does NOT fire when network reputation is private_range")
    func headlineDoesNotFireOnPrivateNetwork() async throws {
        let agent = try agentEntity("Claude Desktop", traceId: "trace-1")
        let proc = try processEntity(key: "p", path: "/usr/bin/osascript")
        let cred = try fileEntity("/Users/me/.aws/credentials", kind: .credentialFile)
        let net = try networkEntity("internal.example.com", reputation: .privateRange)
        let persist = try persistenceEntity("/Users/me/Library/LaunchAgents/com.fake.agent.plist")

        let entities = [agent, proc, cred, net, persist]
        let edges = [
            edge(from: agent,   to: proc,    relation: .associatedWithAgent, confidence: 0.95),
            edge(from: proc,    to: cred,    relation: .read),
            edge(from: proc,    to: net,     relation: .connectedTo),
            edge(from: proc,    to: persist, relation: .createdPersistence,  confidence: 0.95),
        ]

        let rules = GraphRuleLoader.loadFromProjectSource(projectRoot: projectRootURL())
        let evaluator = GraphRuleEvaluator(rules: rules)
        let matches = await evaluator.evaluate(entities: entities, edges: edges)
        #expect(matches.first(where: { $0.ruleId == "maccrab_ai_agent_credential_network_persistence" }) == nil)
    }

    // MARK: - Confidence-tier enforcement

    @Test("Edge with weak_inferred tier does NOT satisfy strong_inferred requirement")
    func tierEnforcement() async throws {
        let agent = try agentEntity("X", traceId: "tx")
        let shell = try processEntity(key: "shell", path: "/bin/zsh")
        let login = try persistenceEntity("/Users/me/Library/LoginItems/foo.plist", type: .loginItem)
        let entities = [agent, shell, login]
        // associated_with_agent edge at WEAK confidence — fails the
        // strong_inferred default for the relation.
        let edges = [
            edge(from: agent, to: shell, relation: .associatedWithAgent, confidence: 0.4),
            edge(from: shell, to: login, relation: .createdPersistence,  confidence: 0.95),
        ]
        let rules = GraphRuleLoader.loadFromProjectSource(projectRoot: projectRootURL())
        let evaluator = GraphRuleEvaluator(rules: rules)
        let matches = await evaluator.evaluate(entities: entities, edges: edges)
        #expect(matches.first(where: { $0.ruleId == "maccrab_agent_associated_shell_writes_to_login_item" }) == nil)
    }

    // MARK: - Temporal-only never matches

    @Test("temporal_only edge tier never satisfies a graph rule even at min_confidence below threshold")
    func temporalOnlyNeverMatches() async throws {
        let proc = try processEntity(key: "p", path: "/Users/me/Downloads/x", isAppleSigned: false)
        let persist = try persistenceEntity("/Users/me/Library/LaunchAgents/foo.plist")
        let entities = [proc, persist]
        // Force temporal_only by giving a confidence under 0.30.
        let edges = [
            edge(from: proc, to: persist, relation: .createdPersistence, confidence: 0.1),
        ]
        let rules = GraphRuleLoader.loadFromProjectSource(projectRoot: projectRootURL())
        let evaluator = GraphRuleEvaluator(rules: rules)
        let matches = await evaluator.evaluate(entities: entities, edges: edges)
        #expect(matches.first(where: { $0.ruleId == "maccrab_unsigned_download_executes_then_persists" }) == nil)
    }

    // MARK: - Constraints

    @Test("Constraint min_confidence excludes edges below threshold")
    func minConfidenceConstraint() async throws {
        // Build a synthetic rule with min_confidence: 0.95
        let rule = GraphRule(
            id: "test_rule",
            title: "Test",
            severity: "high",
            nodes: [
                "p":  GraphRule.NodeSpec(type: "process"),
                "f":  GraphRule.NodeSpec(type: "file", where: ["file_kind": .init(equals: "credential_file")]),
            ],
            edges: [
                GraphRule.EdgeSpec(from: "p", to: "f", relation: "read", minTier: "weak_inferred"),
            ],
            constraints: GraphRule.Constraints(minConfidence: 0.95)
        )
        let proc = try processEntity(key: "p", path: "/usr/bin/cat")
        let cred = try fileEntity("/Users/me/.aws/credentials", kind: .credentialFile)

        // Confidence below threshold
        let lowConfEdges = [edge(from: proc, to: cred, relation: .read, confidence: 0.5)]
        let evaluator1 = GraphRuleEvaluator(rules: [rule])
        let lowMatches = await evaluator1.evaluate(entities: [proc, cred], edges: lowConfEdges)
        #expect(lowMatches.isEmpty)

        // Confidence above threshold
        let highConfEdges = [edge(from: proc, to: cred, relation: .read, confidence: 0.99)]
        let evaluator2 = GraphRuleEvaluator(rules: [rule])
        let highMatches = await evaluator2.evaluate(entities: [proc, cred], edges: highConfEdges)
        #expect(highMatches.count == 1)
    }

    @Test("Constraint within_seconds excludes edges spread across a long window")
    func withinSecondsConstraint() async throws {
        let rule = GraphRule(
            id: "test_within",
            title: "T",
            severity: "high",
            nodes: [
                "p":  GraphRule.NodeSpec(type: "process"),
                "f":  GraphRule.NodeSpec(type: "file"),
                "n":  GraphRule.NodeSpec(type: "network"),
            ],
            edges: [
                GraphRule.EdgeSpec(from: "p", to: "f", relation: "read"),
                GraphRule.EdgeSpec(from: "p", to: "n", relation: "connected_to"),
            ],
            constraints: GraphRule.Constraints(withinSeconds: 60)
        )
        let proc = try processEntity(key: "p", path: "/usr/bin/cat")
        let f = try fileEntity("/Users/me/.aws/credentials", kind: .credentialFile)
        let n = try networkEntity("evil.com")

        // Edges 5 seconds apart — within 60s window.
        let closeEdges = [
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: f.id,
                              relation: .read, confidence: 0.9, observedAt: now),
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: n.id,
                              relation: .connectedTo, confidence: 0.9, observedAt: now.addingTimeInterval(5)),
        ]
        let evaluator1 = GraphRuleEvaluator(rules: [rule])
        let close = await evaluator1.evaluate(entities: [proc, f, n], edges: closeEdges)
        #expect(close.count == 1)

        // Edges 1 hour apart — outside the window.
        let farEdges = [
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: f.id,
                              relation: .read, confidence: 0.9, observedAt: now),
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: n.id,
                              relation: .connectedTo, confidence: 0.9, observedAt: now.addingTimeInterval(3600)),
        ]
        let evaluator2 = GraphRuleEvaluator(rules: [rule])
        let far = await evaluator2.evaluate(entities: [proc, f, n], edges: farEdges)
        #expect(far.isEmpty)
    }

    // MARK: - WhereClause

    @Test("WhereClause `in` filters by string value")
    func whereInFilter() async throws {
        let rule = GraphRule(
            id: "shell_only",
            title: "T",
            severity: "low",
            nodes: [
                "p": GraphRule.NodeSpec(
                    type: "process",
                    where: ["executable_name": .init(in: ["zsh", "bash"])]
                ),
            ],
            edges: []
        )
        let zsh = try processEntity(key: "z", path: "/bin/zsh")
        let cat = try processEntity(key: "c", path: "/usr/bin/cat")
        let evaluator = GraphRuleEvaluator(rules: [rule])
        let onlyZsh = await evaluator.evaluate(entities: [zsh, cat], edges: [])
        #expect(onlyZsh.count == 1)
        #expect(onlyZsh.first?.bindings["p"] == zsh.id)
    }

    @Test("WhereClause `not_in` excludes by string value")
    func whereNotInFilter() async throws {
        let rule = GraphRule(
            id: "non_apple_only",
            title: "T",
            severity: "low",
            nodes: [
                "p": GraphRule.NodeSpec(
                    type: "process",
                    where: ["executable_name": .init(notIn: ["zsh", "bash"])]
                ),
            ],
            edges: []
        )
        let zsh = try processEntity(key: "z", path: "/bin/zsh")
        let cat = try processEntity(key: "c", path: "/usr/bin/cat")
        let evaluator = GraphRuleEvaluator(rules: [rule])
        let onlyCat = await evaluator.evaluate(entities: [zsh, cat], edges: [])
        #expect(onlyCat.count == 1)
        #expect(onlyCat.first?.bindings["p"] == cat.id)
    }

    @Test("WhereClause `equals_bool` filters processes by signing state")
    func whereEqualsBoolFilter() async throws {
        let rule = GraphRule(
            id: "unsigned_only",
            title: "T",
            severity: "low",
            nodes: [
                "p": GraphRule.NodeSpec(
                    type: "process",
                    where: ["is_apple_signed": .init(equalsBool: false)]
                ),
            ],
            edges: []
        )
        let signed = try processEntity(key: "s", path: "/bin/zsh", isAppleSigned: true)
        let unsigned = try processEntity(key: "u", path: "/Users/me/Downloads/x", isAppleSigned: false)
        let evaluator = GraphRuleEvaluator(rules: [rule])
        let matches = await evaluator.evaluate(entities: [signed, unsigned], edges: [])
        #expect(matches.count == 1)
        #expect(matches.first?.bindings["p"] == unsigned.id)
    }

    // MARK: - Helpers

    /// Walk up from this test file's location to find the project root
    /// (the directory containing Package.swift).
    private func projectRootURL() -> URL {
        var url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) {
                return url
            }
            url = url.deletingLastPathComponent()
        }
        return URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    }
}
