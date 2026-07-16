// DeterministicExplainerTests.swift
// v1.10 TraceGraph (DeterministicExplainer) — verifies the structured
// explanation reflects the spec §16.1 shape and is deterministic.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: DeterministicExplainer")
struct DeterministicExplainerTests {

    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func processEntity(
        key: String, path: String,
        appleSigned: Bool = true
    ) throws -> TraceEntity {
        let node = ProcessNode(
            processKey: key, pid: 100, ppid: 1,
            executablePath: path,
            isAppleSigned: appleSigned, isNotarized: appleSigned,
            startTime: now
        )
        return try node.toEntity(source: "test")
    }

    private func fileEntity(_ path: String, kind: FileKind) throws -> TraceEntity {
        let node = FileNode(
            path: path, pathHash: "h-\(path)",
            fileKind: kind, firstSeen: now, lastSeen: now
        )
        return try node.toEntity(source: "test")
    }

    private func networkEntity(host: String, reputation: NetworkReputation) throws -> TraceEntity {
        let node = NetworkNode(
            destinationHost: host, port: 443, protocolName: "tcp",
            reputation: reputation, firstSeen: now
        )
        return try node.toEntity(source: "test")
    }

    private func agentEntity(name: String, method: AttributionMethod = .directTraceparent) throws -> TraceEntity {
        let node = AIAgentNode(
            agentId: "\(name.lowercased()):trace-1",
            agentName: name, traceId: "trace-1",
            confidence: 0.95, attributionMethod: method,
            firstSeen: now
        )
        return try node.toEntity(source: "test", confidence: 0.95)
    }

    private func persistEntity(_ path: String, type: PersistenceType = .launchAgent) throws -> TraceEntity {
        let node = PersistenceNode(persistenceType: type, path: path, firstSeen: now)
        return try node.toEntity(source: "test")
    }

    private func makeTrace(severity: String = "high") -> Trace {
        Trace(
            id: "trace-1", title: "Test trace", anchorEventId: "ev-1",
            rootEntityId: "process:p", severity: severity, confidence: 0.9,
            createdAt: now, updatedAt: now,
            daemonVersion: "1.10.0", rulesetVersion: "1.10.0",
            policyId: "default", policyVersion: "1",
            policySha256: "x", policySnapshotJson: "{}",
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
    }

    @Test("Determinism: same inputs produce byte-identical canonical JSON")
    func determinism() throws {
        let proc = try processEntity(key: "p", path: "/usr/bin/osascript")
        let cred = try fileEntity("/Users/me/.aws/credentials", kind: .credentialFile)
        let edge = EdgeBuilder.build(
            sourceEntityId: proc.id, targetEntityId: cred.id,
            relation: .read, confidence: 0.9, observedAt: now
        )
        let exp1 = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [proc, cred],
            edges: [edge],
            rootCauseEntityId: proc.id,
            rootCauseTrustTransition: "first non-Apple-signed ancestor",
            criticalPathEdgeIds: [edge.id],
            attackTechniques: ["T1555"]
        )
        let exp2 = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [proc, cred],
            edges: [edge],
            rootCauseEntityId: proc.id,
            rootCauseTrustTransition: "first non-Apple-signed ancestor",
            criticalPathEdgeIds: [edge.id],
            attackTechniques: ["T1555"]
        )
        #expect(exp1 == exp2)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data1 = try encoder.encode(exp1)
        let data2 = try encoder.encode(exp2)
        #expect(data1 == data2)
    }

    @Test("Severity reasons surface AI-agent + credential + persistence + network on Fixture 1")
    func fixture1SeverityReasons() throws {
        let agent = try agentEntity(name: "Claude Desktop")
        let proc = try processEntity(key: "p", path: "/usr/bin/osascript")
        let cred = try fileEntity("/Users/me/.aws/credentials", kind: .credentialFile)
        let net = try networkEntity(host: "evil.com", reputation: .suspicious)
        let persist = try persistEntity("/Users/me/Library/LaunchAgents/foo.plist")

        let edges = [
            EdgeBuilder.build(sourceEntityId: agent.id, targetEntityId: proc.id, relation: .associatedWithAgent, confidence: 0.95, observedAt: now),
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: cred.id, relation: .read, confidence: 0.9, observedAt: now),
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: net.id, relation: .connectedTo, confidence: 0.9, observedAt: now),
            EdgeBuilder.build(sourceEntityId: proc.id, targetEntityId: persist.id, relation: .createdPersistence, confidence: 0.95, observedAt: now),
        ]
        // Make osascript "spawn" itself for the shell-spawn detection
        // (the rule looks at any spawn relation whose target is shell-like).
        let shellSpawn = EdgeBuilder.build(
            sourceEntityId: agent.id, targetEntityId: proc.id,
            relation: .spawned, confidence: 0.9, observedAt: now
        )

        let exp = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [agent, proc, cred, net, persist],
            edges: edges + [shellSpawn],
            rootCauseEntityId: proc.id,
            rootCauseTrustTransition: "MCP Server",
            criticalPathEdgeIds: edges.map { $0.id },
            attackTechniques: ["T1059", "T1555", "T1543.001", "T1105"]
        )
        // §16 expectations
        #expect(exp.severityReasons.contains("AI-agent associated shell execution"))
        #expect(exp.severityReasons.contains("credential file access"))
        #expect(exp.severityReasons.contains("external network connection"))
        #expect(exp.severityReasons.contains("launch agent persistence"))
        #expect(exp.attackMapping == ["T1059", "T1105", "T1543.001", "T1555"])  // sorted
    }

    @Test("Confidence reasons name the attribution method when an agent is present")
    func confidenceReasonsNameAttributionMethod() throws {
        let agent = try agentEntity(name: "Cursor", method: .processLineageMatch)
        let proc = try processEntity(key: "p", path: "/usr/bin/osascript")
        let edge = EdgeBuilder.build(
            sourceEntityId: agent.id, targetEntityId: proc.id,
            relation: .associatedWithAgent, confidence: 0.7, observedAt: now
        )
        let exp = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [agent, proc],
            edges: [edge],
            rootCauseEntityId: proc.id,
            rootCauseTrustTransition: "x",
            criticalPathEdgeIds: [edge.id]
        )
        #expect(exp.confidenceReasons.contains("process lineage attribution"))
    }

    @Test("Critical path entries carry display names + tier + edge id")
    func pathEdgeShape() throws {
        let parent = try processEntity(key: "parent", path: "/bin/zsh")
        let child = try processEntity(key: "child", path: "/usr/bin/curl")
        let edge = EdgeBuilder.build(
            sourceEntityId: parent.id, targetEntityId: child.id,
            relation: .spawned, confidence: 0.95, observedAt: now
        )
        let exp = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [parent, child],
            edges: [edge],
            rootCauseEntityId: parent.id,
            rootCauseTrustTransition: "x",
            criticalPathEdgeIds: [edge.id]
        )
        #expect(exp.criticalPath.count == 1)
        #expect(exp.criticalPath.first?.from == "zsh")
        #expect(exp.criticalPath.first?.to == "curl")
        #expect(exp.criticalPath.first?.relation == "spawned")
        #expect(exp.criticalPath.first?.tier == "direct")
        #expect(exp.criticalPath.first?.edgeId == edge.id)
    }

    @Test("Drift guard: AI-agent severity reason still carries the §11.3 gate marker")
    func agentReasonCarriesGateMarker() throws {
        // The TraceMaterializer §11.3 honesty gate locates the AI-agent severity
        // reason via AIAttributionRenderer.assertedAgentReasonMarker (a substring
        // match) before softening it. If this prose drifts, fail LOUDLY here
        // rather than silently un-gating below-threshold attribution downstream.
        let agent = try agentEntity(name: "Claude Desktop")
        let shell = try processEntity(key: "p", path: "/bin/zsh")
        let spawn = EdgeBuilder.build(
            sourceEntityId: agent.id, targetEntityId: shell.id,
            relation: .spawned, confidence: 0.9, observedAt: now
        )
        let exp = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [agent, shell], edges: [spawn],
            rootCauseEntityId: shell.id, rootCauseTrustTransition: "x",
            criticalPathEdgeIds: [spawn.id]
        )
        #expect(exp.severityReasons.contains {
            $0.contains(AIAttributionRenderer.assertedAgentReasonMarker)
        })
    }

    @Test("Empty critical path produces empty array (not crash)")
    func emptyCriticalPath() throws {
        let proc = try processEntity(key: "p", path: "/bin/zsh")
        let exp = DeterministicExplainer.explain(
            trace: makeTrace(),
            entities: [proc], edges: [],
            rootCauseEntityId: proc.id,
            rootCauseTrustTransition: "x",
            criticalPathEdgeIds: []
        )
        #expect(exp.criticalPath.isEmpty)
        #expect(exp.severityReasons.isEmpty)
    }
}
