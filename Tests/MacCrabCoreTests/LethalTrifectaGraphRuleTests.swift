// LethalTrifectaGraphRuleTests.swift
// v1.21.4 (Phase-6 6B) — exercises the trace-id-anchored lethal-trifecta
// GRAPH rule (Rules/graph/maccrab_ai_agent_lethal_trifecta.json) and the
// leg-2 "untrusted content" substrate weld.
//
// The rule fires only when ONE agent session (a single shared `proc` bound to
// an `ai_agent` via an `associated_with_agent` edge at the DIRECT tier — i.e.
// W3C-traceparent trace-id binding, not ppid lineage) performs all three
// lethal-trifecta legs inside 600s: reads credential material (leg 1), reads a
// file flagged with untrusted (prompt-injection) content (leg 2), and connects
// out to a non-good / non-private destination (leg 3).
//
// Rule-firing tests feed synthetic [TraceEntity]/[TraceEdge] to the pure
// GraphRuleEvaluator (deterministic, no store). The final weld round-trip
// drives the bridge → rolling graph → store to prove the enrichment threads
// through to the persisted FileNode attribute.

import Testing
import Foundation
import CryptoKit
@testable import MacCrabCore

@Suite("TraceGraph: Lethal-trifecta graph rule (Phase-6 6B)")
struct LethalTrifectaGraphRuleTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)
    private let ruleId = "maccrab_ai_agent_lethal_trifecta"

    // MARK: - Synthetic-entity helpers (GraphRuleEvaluatorTests style)

    private func processEntity(key: String, path: String) throws -> TraceEntity {
        let node = ProcessNode(
            processKey: key, pid: 501, ppid: 1,
            executablePath: path,
            isAppleSigned: false, isNotarized: false,
            startTime: now
        )
        return try node.toEntity(source: "test")
    }

    /// Credential file: file_kind == credential_file, untrusted_content == false
    /// (default) so it can only bind the `cred` node, never `untrusted`.
    private func credFileEntity(_ path: String) throws -> TraceEntity {
        let node = FileNode(
            path: path, pathHash: "cred-\(path)",
            fileKind: .credentialFile,
            firstSeen: now, lastSeen: now
        )
        return try node.toEntity(source: "test")
    }

    /// Untrusted-content file: untrusted_content == true and a non-credential
    /// kind so it can only bind the `untrusted` node, never `cred`.
    private func untrustedFileEntity(_ path: String) throws -> TraceEntity {
        let node = FileNode(
            path: path, pathHash: "poison-\(path)",
            fileKind: .script,
            untrustedContent: true,
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

    private func edge(
        from: TraceEntity, to: TraceEntity,
        relation: EdgeRelation,
        confidence: Double = 0.9,
        at: Date? = nil
    ) -> TraceEdge {
        EdgeBuilder.build(
            sourceEntityId: from.id, targetEntityId: to.id,
            relation: relation, confidence: confidence,
            observedAt: at ?? now
        )
    }

    private func loadRules() -> [GraphRule] {
        GraphRuleLoader.loadFromProjectSource(projectRoot: projectRootURL())
    }

    /// Full 5-entity / 4-edge lethal-trifecta fixture. Callers can override the
    /// agent-edge confidence (to test tier anchoring), the egress reputation, or
    /// the egress-edge timestamp (to test the window), or drop the untrusted leg.
    private func fixture(
        agentConfidence: Double = 0.95,
        netReputation: NetworkReputation = .suspicious,
        netEdgeAt: Date? = nil,
        includeUntrusted: Bool = true
    ) throws -> ([TraceEntity], [TraceEdge]) {
        let agent = try agentEntity("Claude Code", traceId: "trace-lethal-1")
        let proc = try processEntity(key: "p1", path: "/usr/bin/osascript")
        let cred = try credFileEntity("/Users/me/.aws/credentials")
        let net = try networkEntity("evil.example.com", reputation: netReputation)

        var entities: [TraceEntity] = [agent, proc, cred, net]
        var edges: [TraceEdge] = [
            edge(from: agent, to: proc, relation: .associatedWithAgent, confidence: agentConfidence),
            edge(from: proc,  to: cred, relation: .read,                confidence: 0.9),
            edge(from: proc,  to: net,  relation: .connectedTo,         confidence: 0.9, at: netEdgeAt),
        ]
        if includeUntrusted {
            let untrusted = try untrustedFileEntity("/Users/me/.claude/skills/poison/SKILL.md")
            entities.append(untrusted)
            edges.append(edge(from: proc, to: untrusted, relation: .read, confidence: 0.9))
        }
        return (entities, edges)
    }

    // MARK: - Fires

    @Test("Fires on all 3 legs + a DIRECT-tier agent edge within 600s (exactly one critical match)")
    func firesOnFullTrifecta() async throws {
        let (entities, edges) = try fixture()
        let evaluator = GraphRuleEvaluator(rules: loadRules())
        let matches = await evaluator.evaluate(entities: entities, edges: edges)

        let lethal = matches.filter { $0.ruleId == ruleId }
        #expect(lethal.count == 1)
        #expect(lethal.first?.severity == "critical")
        #expect(lethal.first?.attack.contains("T1555") == true)
        #expect(lethal.first?.matchedEdgeIds.count == 4)
        #expect(lethal.first?.bindings["proc"] != nil)
        #expect(lethal.first?.bindings["agent"] != nil)
        #expect(lethal.first?.bindings["untrusted"] != lethal.first?.bindings["cred"])
    }

    // MARK: - Leg 2 is load-bearing

    @Test("Does NOT fire when the untrusted-content read leg is dropped (cred + egress alone stays silent)")
    func noFireWithoutUntrustedLeg() async throws {
        let (entities, edges) = try fixture(includeUntrusted: false)
        let evaluator = GraphRuleEvaluator(rules: loadRules())
        let matches = await evaluator.evaluate(entities: entities, edges: edges)
        #expect(matches.first(where: { $0.ruleId == ruleId }) == nil)
    }

    // MARK: - Trace-id anchoring (DIRECT tier only)

    @Test("Does NOT fire when the agent edge is strong_inferred or weak_inferred (proves trace-id, not ppid)")
    func noFireOnNonDirectAgentEdge() async throws {
        let rules = loadRules()

        // strong_inferred (0.8): passes min_confidence 0.75 but FAILS min_tier
        // 'direct' — isolates the tier as the sole reason for no-fire.
        let (se, sedges) = try fixture(agentConfidence: 0.8)
        let strongMatches = await GraphRuleEvaluator(rules: rules).evaluate(entities: se, edges: sedges)
        #expect(strongMatches.first(where: { $0.ruleId == ruleId }) == nil)

        // weak_inferred (0.4): a ppid-lineage-grade edge — also no-fire.
        let (we, wedges) = try fixture(agentConfidence: 0.4)
        let weakMatches = await GraphRuleEvaluator(rules: rules).evaluate(entities: we, edges: wedges)
        #expect(weakMatches.first(where: { $0.ruleId == ruleId }) == nil)
    }

    // MARK: - Egress reputation gate

    @Test("Does NOT fire when the egress destination is in private_range")
    func noFireOnPrivateEgress() async throws {
        let (entities, edges) = try fixture(netReputation: .privateRange)
        let evaluator = GraphRuleEvaluator(rules: loadRules())
        let matches = await evaluator.evaluate(entities: entities, edges: edges)
        #expect(matches.first(where: { $0.ruleId == ruleId }) == nil)
    }

    // MARK: - Temporal window

    @Test("Does NOT fire when the legs are spread beyond the 600s window")
    func noFireOutsideWindow() async throws {
        // Push the egress edge to +601s — outside the 600s within_seconds bound.
        let (entities, edges) = try fixture(netEdgeAt: now.addingTimeInterval(601))
        let evaluator = GraphRuleEvaluator(rules: loadRules())
        let matches = await evaluator.evaluate(entities: entities, edges: edges)
        #expect(matches.first(where: { $0.ruleId == ruleId }) == nil)
    }

    // MARK: - Substrate weld round-trip

    @Test("Weld round-trip: FileNode.toEntity carries untrusted_content; bridge maps the enrichment through")
    func weldRoundTrip() async throws {
        // (a) FileNode.toEntity directly encodes untrustedContent into attributes.
        let node = FileNode(
            path: "/Users/me/.claude/skills/x/SKILL.md", pathHash: "h1",
            fileKind: .script, untrustedContent: true, firstSeen: now, lastSeen: now
        )
        let entity = try node.toEntity(source: "test")
        let attrs = try JSONSerialization.jsonObject(with: Data(entity.attributesJson.utf8)) as? [String: Any]
        #expect(attrs?["untrustedContent"] as? Bool == true)

        // (b) end-to-end: bridge reads enrichments["untrusted_content"]="true" →
        // FileObservation → FileNode → persisted entity attribute.
        let (store, dbPath) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbPath) }
        let rollingGraph = RollingCausalGraph(store: store, materializer: TraceMaterializer(store: store))
        let bridge = EventToRollingCausalGraphBridge(rollingGraph: rollingGraph)

        let path = "/Users/me/.claude/skills/poison/SKILL.md"
        let poisoned = Event(
            timestamp: now, eventCategory: .file, eventType: .info, eventAction: "open",
            process: processInfo(pid: 501, executable: "/usr/bin/osascript"),
            file: FileInfo(path: path, action: .open),
            enrichments: ["untrusted_content": "true"]
        )
        _ = await bridge.process(poisoned)
        let fileEntity = try await store.entity(id: "file:\(pathHashHex(path))")
        #expect(fileEntity != nil)
        let fattrs = try JSONSerialization.jsonObject(
            with: Data((fileEntity?.attributesJson ?? "{}").utf8)) as? [String: Any]
        #expect(fattrs?["untrustedContent"] as? Bool == true)

        // Control: no enrichment → untrustedContent defaults false.
        let cleanPath = "/Users/me/.claude/skills/clean/SKILL.md"
        let clean = Event(
            timestamp: now, eventCategory: .file, eventType: .info, eventAction: "open",
            process: processInfo(pid: 502, executable: "/usr/bin/osascript"),
            file: FileInfo(path: cleanPath, action: .open)
        )
        _ = await bridge.process(clean)
        let cleanEntity = try await store.entity(id: "file:\(pathHashHex(cleanPath))")
        let cattrs = try JSONSerialization.jsonObject(
            with: Data((cleanEntity?.attributesJson ?? "{}").utf8)) as? [String: Any]
        #expect(cattrs?["untrustedContent"] as? Bool == false)
        await store.close()
    }

    // MARK: - Round-trip helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("lethal-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }

    private func processInfo(pid: Int32, executable: String) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [], workingDirectory: "/",
            userId: 501, userName: "test", groupId: 20,
            startTime: now,
            codeSignature: CodeSignatureInfo(signerType: .apple, isNotarized: true),
            isPlatformBinary: true
        )
    }

    /// Same lowercase-hex SHA-256 the bridge uses to key file entities.
    private func pathHashHex(_ path: String) -> String {
        SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined()
    }

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
