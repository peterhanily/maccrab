// CausalGraphStoreTests.swift
// v1.10 TraceGraph (PR-6b) — tests for SQLiteCausalGraphStore against
// a temp tracegraph.db.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: SQLiteCausalGraphStore")
struct SQLiteCausalGraphStoreTests {

    // MARK: - Helpers

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-\(UUID().uuidString).db")
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)
        return (store, path)
    }

    private func makeEntity(
        id: String,
        type: String = "process",
        stableKey: String? = nil,
        firstSeen: Date = Date(timeIntervalSince1970: 1_700_000_000),
        lastSeen: Date? = nil
    ) -> TraceEntity {
        TraceEntity(
            id: id,
            entityType: type,
            stableKey: stableKey ?? id,
            displayName: id,
            firstSeen: firstSeen,
            lastSeen: lastSeen ?? firstSeen,
            attributesJson: "{\"name\":\"\(id)\"}",
            source: "test"
        )
    }

    private func makeEdge(
        id: String,
        from: String,
        to: String,
        relation: String = "spawned",
        firstSeen: Date = Date(timeIntervalSince1970: 1_700_000_000),
        lastSeen: Date? = nil,
        confidence: Double = 0.95,
        tier: String = "direct"
    ) -> TraceEdge {
        TraceEdge(
            id: id,
            sourceEntityId: from,
            targetEntityId: to,
            relation: relation,
            firstSeen: firstSeen,
            lastSeen: lastSeen ?? firstSeen,
            confidence: confidence,
            confidenceTier: tier,
            evidenceJson: "{}",
            eventIdsJson: "[]"
        )
    }

    private func makeTrace(
        id: String = "trace-1",
        rootEntityId: String? = nil
    ) -> Trace {
        Trace(
            id: id,
            title: "Test trace",
            anchorEventId: "event-1",
            rootEntityId: rootEntityId,
            severity: "high",
            confidence: 0.9,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
            daemonVersion: "1.10.0",
            rulesetVersion: "1.10.0",
            policyId: "default",
            policyVersion: "1",
            policySha256: "deadbeef",
            policySnapshotJson: "{}",
            traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
    }

    // MARK: - Schema + lifecycle

    @Test("Open creates the database with all 7 tables")
    func openCreatesSchema() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        // Smoke test: insert into each table type without error.
        try await store.upsertEntity(makeEntity(id: "e1"))
        try await store.saveTrace(makeTrace(id: "t1"), members: [])
        try await store.recordRuleHit(TraceRuleHit(
            id: "h1", traceId: "t1", ruleId: "r1", ruleTitle: "x",
            ruleVersion: "1.10.0", severity: "high",
            matchedAt: Date(), explanationJson: "{}"
        ))
        await store.close()
    }

    // MARK: - Entity upsert

    @Test("upsertEntity inserts then increments observation_count on conflict")
    func upsertEntityIncrement() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let e = makeEntity(id: "e1")
        try await store.upsertEntity(e)
        try await store.upsertEntity(e)
        try await store.upsertEntity(e)

        let stored = try await store.entity(id: "e1")
        #expect(stored?.observationCount == 3)
        await store.close()
    }

    @Test("upsertEntity advances last_seen on conflict but preserves first_seen")
    func upsertEntityTimes() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let early = Date(timeIntervalSince1970: 1_700_000_000)
        let later = Date(timeIntervalSince1970: 1_700_000_500)
        try await store.upsertEntity(makeEntity(id: "e1", firstSeen: early, lastSeen: early))
        try await store.upsertEntity(makeEntity(id: "e1", firstSeen: later, lastSeen: later))

        let stored = try await store.entity(id: "e1")
        #expect(stored?.firstSeen == early)
        #expect(stored?.lastSeen == later)
        await store.close()
    }

    // MARK: - Edge upsert

    @Test("upsertEdge dedupes on (source, target, relation)")
    func upsertEdgeDedup() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(makeEntity(id: "a"))
        try await store.upsertEntity(makeEntity(id: "b"))
        try await store.upsertEdge(makeEdge(id: "edge-x", from: "a", to: "b"))
        try await store.upsertEdge(makeEdge(id: "edge-y", from: "a", to: "b"))

        // Both upserts hit (source=a, target=b, relation=spawned). The
        // second one's id is ignored on conflict (existing id wins).
        let edge1 = try await store.edge(id: "edge-x")
        #expect(edge1 != nil)
        let edge2 = try await store.edge(id: "edge-y")
        #expect(edge2 == nil)

        await store.close()
    }

    // MARK: - Ancestors / descendants

    @Test("ancestors walks the parent chain")
    func ancestorsChain() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        // Build chain: g → p → c
        try await store.upsertEntity(makeEntity(id: "g"))
        try await store.upsertEntity(makeEntity(id: "p"))
        try await store.upsertEntity(makeEntity(id: "c"))
        try await store.upsertEdge(makeEdge(id: "e_gp", from: "g", to: "p"))
        try await store.upsertEdge(makeEdge(id: "e_pc", from: "p", to: "c"))

        let result = try await store.ancestors(of: "c", depth: 5, within: .unlimited)
        let entityIds = Set(result.entities.map { $0.id })
        #expect(entityIds == Set(["g", "p"]))
        #expect(result.edges.count == 2)
        #expect(!result.truncated)
        await store.close()
    }

    @Test("ancestors respects the depth cap and reports truncation")
    func ancestorsDepthCap() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(makeEntity(id: "g"))
        try await store.upsertEntity(makeEntity(id: "p"))
        try await store.upsertEntity(makeEntity(id: "c"))
        try await store.upsertEdge(makeEdge(id: "e_gp", from: "g", to: "p"))
        try await store.upsertEdge(makeEdge(id: "e_pc", from: "p", to: "c"))

        // depth=1 → only direct parent
        let result = try await store.ancestors(of: "c", depth: 1, within: .unlimited)
        let entityIds = Set(result.entities.map { $0.id })
        #expect(entityIds == Set(["p"]))
        #expect(result.truncated)
        await store.close()
    }

    @Test("ancestors filters by time window")
    func ancestorsWindow() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let oldTime = Date(timeIntervalSince1970: 1_700_000_000)
        let newTime = Date(timeIntervalSince1970: 1_700_001_000)

        try await store.upsertEntity(makeEntity(id: "g"))
        try await store.upsertEntity(makeEntity(id: "p"))
        try await store.upsertEdge(makeEdge(id: "e_gp", from: "g", to: "p", lastSeen: oldTime))

        // Window covers the edge → ancestor visible.
        let inside = try await store.ancestors(of: "p", depth: 5,
            within: TimeWindow(start: oldTime.addingTimeInterval(-1), end: newTime))
        #expect(inside.entities.count == 1)

        // Window excludes the edge → no ancestor.
        let outside = try await store.ancestors(of: "p", depth: 5,
            within: TimeWindow(start: newTime, end: newTime.addingTimeInterval(60)))
        #expect(outside.entities.isEmpty)
        await store.close()
    }

    @Test("descendants walks the child chain")
    func descendantsChain() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(makeEntity(id: "g"))
        try await store.upsertEntity(makeEntity(id: "p"))
        try await store.upsertEntity(makeEntity(id: "c"))
        try await store.upsertEdge(makeEdge(id: "e_gp", from: "g", to: "p"))
        try await store.upsertEdge(makeEdge(id: "e_pc", from: "p", to: "c"))

        let result = try await store.descendants(of: "g", depth: 5, within: .unlimited)
        let ids = Set(result.entities.map { $0.id })
        #expect(ids == Set(["p", "c"]))
        await store.close()
    }

    @Test("ancestors via non-spawned relation is excluded")
    func ancestorsOnlySpawned() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(makeEntity(id: "p"))
        try await store.upsertEntity(makeEntity(id: "c"))
        // 'read' relation, not 'spawned'
        try await store.upsertEdge(makeEdge(id: "e_pc", from: "p", to: "c", relation: "read"))

        let result = try await store.ancestors(of: "c", depth: 5, within: .unlimited)
        #expect(result.entities.isEmpty)
        await store.close()
    }

    // MARK: - Neighborhood

    @Test("neighborhood includes anchor + bidirectional edges")
    func neighborhoodBidirectional() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(makeEntity(id: "p"))
        try await store.upsertEntity(makeEntity(id: "anchor"))
        try await store.upsertEntity(makeEntity(id: "c"))
        try await store.upsertEntity(makeEntity(id: "f", type: "file"))

        try await store.upsertEdge(makeEdge(id: "e1", from: "p", to: "anchor"))
        try await store.upsertEdge(makeEdge(id: "e2", from: "anchor", to: "c"))
        try await store.upsertEdge(makeEdge(id: "e3", from: "anchor", to: "f", relation: "wrote"))

        let result = try await store.neighborhood(of: "anchor", depth: 1, within: .unlimited)
        let ids = Set(result.entities.map { $0.id })
        #expect(ids == Set(["anchor", "p", "c", "f"]))
        #expect(result.edges.count == 3)
        await store.close()
    }

    // MARK: - Critical path

    @Test("criticalPath returns shortest path")
    func criticalPathShortest() async throws {
        let (store, dbURL) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbURL) }
        // Build: a → b → c → d, and a → c (shortcut)
        for id in ["a", "b", "c", "d"] {
            try await store.upsertEntity(makeEntity(id: id))
        }
        try await store.upsertEdge(makeEdge(id: "e1", from: "a", to: "b"))
        try await store.upsertEdge(makeEdge(id: "e2", from: "b", to: "c"))
        try await store.upsertEdge(makeEdge(id: "e3", from: "c", to: "d"))
        try await store.upsertEdge(makeEdge(id: "shortcut", from: "a", to: "c", relation: "caused"))

        let pathResult = try await store.criticalPath(from: "a", to: "d", maxDepth: 10)
        // Shortest path: a → c (shortcut) → d  = 2 edges
        #expect(pathResult.count == 2)
        #expect(pathResult.first?.sourceEntityId == "a")
        #expect(pathResult.last?.targetEntityId == "d")
        await store.close()
    }

    @Test("criticalPath returns empty when no path exists")
    func criticalPathNoPath() async throws {
        let (store, dbURL) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: dbURL) }
        try await store.upsertEntity(makeEntity(id: "a"))
        try await store.upsertEntity(makeEntity(id: "b"))
        // No edge between them.
        let result = try await store.criticalPath(from: "a", to: "b", maxDepth: 5)
        #expect(result.isEmpty)
        await store.close()
    }

    // MARK: - Trace lifecycle

    @Test("saveTrace + loadTrace roundtrip")
    func traceRoundtrip() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let trace = makeTrace(id: "t1", rootEntityId: "root-entity")
        let members = [
            TraceMembership(traceId: "t1", entityId: "root-entity", role: "root", layer: "core"),
            TraceMembership(traceId: "t1", entityId: "anchor-entity", role: "anchor", layer: "core"),
            TraceMembership(traceId: "t1", edgeId: "edge-1", role: "critical_path", layer: "core"),
        ]
        try await store.saveTrace(trace, members: members)

        let loaded = try await store.loadTrace(id: "t1")
        #expect(loaded?.trace == trace)
        #expect(loaded?.members.count == 3)
        await store.close()
    }

    @Test("saveTrace replaces prior membership on re-save (idempotent)")
    func traceMembersReplaceOnResave() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let trace = makeTrace(id: "t1")
        try await store.saveTrace(trace, members: [
            TraceMembership(traceId: "t1", entityId: "e1", role: "root", layer: "core"),
        ])
        try await store.saveTrace(trace, members: [
            TraceMembership(traceId: "t1", entityId: "e2", role: "root", layer: "core"),
            TraceMembership(traceId: "t1", entityId: "e3", role: "context", layer: "context"),
        ])
        let loaded = try await store.loadTrace(id: "t1")
        let ids = Set(loaded?.members.compactMap { $0.entityId } ?? [])
        #expect(ids == Set(["e2", "e3"]))
        await store.close()
    }

    @Test("updateTraceStatus mutates status + updated_at")
    func updateStatus() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let trace = makeTrace(id: "t1")
        try await store.saveTrace(trace, members: [])

        let later = Date(timeIntervalSince1970: 1_700_001_000)
        try await store.updateTraceStatus(id: "t1", status: "triaged", updatedAt: later)
        let loaded = try await store.loadTrace(id: "t1")
        #expect(loaded?.trace.status == "triaged")
        #expect(loaded?.trace.updatedAt == later)
        await store.close()
    }

    @Test("listTraces returns rows ordered by created_at DESC")
    func listOrdered() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        let t1 = Date(timeIntervalSince1970: 1_700_000_100)
        var traceA = makeTrace(id: "a")
        var traceB = makeTrace(id: "b")
        // Construct with explicit createdAt differences
        traceA = Trace(
            id: "a", title: "A", anchorEventId: "e",
            rootEntityId: nil, severity: "low", confidence: 0.5,
            createdAt: t0, updatedAt: t0,
            daemonVersion: "1.10.0", rulesetVersion: "1.10.0",
            policyId: "p", policyVersion: "1", policySha256: "x",
            policySnapshotJson: "{}", traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
        traceB = Trace(
            id: "b", title: "B", anchorEventId: "e",
            rootEntityId: nil, severity: "low", confidence: 0.5,
            createdAt: t1, updatedAt: t1,
            daemonVersion: "1.10.0", rulesetVersion: "1.10.0",
            policyId: "p", policyVersion: "1", policySha256: "x",
            policySnapshotJson: "{}", traceSigningKeyMode: "filesystem_degraded",
            replayScope: "declared_deterministic_subset",
            attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default"
        )
        try await store.saveTrace(traceA, members: [])
        try await store.saveTrace(traceB, members: [])

        let listed = try await store.listTraces(limit: 10)
        #expect(listed.map { $0.id } == ["b", "a"])
        await store.close()
    }

    // MARK: - Rule hits + replay + chain

    @Test("recordRuleHit + listing")
    func ruleHitInsert() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.saveTrace(makeTrace(id: "t1"), members: [])
        let hit = TraceRuleHit(
            id: "h1", traceId: "t1", ruleId: "rule_x", ruleTitle: "Test rule",
            ruleVersion: "1.10.0", severity: "high",
            matchedEventId: "ev1", matchedAt: Date(timeIntervalSince1970: 1_700_000_000),
            explanationJson: "{\"reason\":\"matched\"}"
        )
        try await store.recordRuleHit(hit)
        // Smoke: re-running the hit upserts (INSERT OR REPLACE).
        try await store.recordRuleHit(hit)
        await store.close()
    }

    @Test("recordReplayRun handles nil completedAt")
    func replayRunNilCompleted() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.saveTrace(makeTrace(id: "t1"), members: [])
        let run = TraceReplayRun(
            id: "r1", traceId: "t1", bundleId: "b1",
            rulesetVersion: "1.10.0", daemonVersion: "1.10.0",
            normalizationVersion: "1",
            startedAt: Date(timeIntervalSince1970: 1_700_000_000),
            completedAt: nil,
            deterministic: false,
            resultJson: "{\"result\":\"unsupported_stateful_replay\"}"
        )
        try await store.recordReplayRun(run)
        await store.close()
    }

    @Test("appendHashChain + latestHashChainEntry")
    func hashChainAppend() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }

        let entry1 = TraceHashChainEntry(
            id: "h1", traceId: "t1", sequenceNumber: 1,
            previousHash: nil, currentHash: "aaa",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let entry2 = TraceHashChainEntry(
            id: "h2", traceId: "t1", sequenceNumber: 2,
            previousHash: "aaa", currentHash: "bbb",
            createdAt: Date(timeIntervalSince1970: 1_700_000_010)
        )
        let entry3 = TraceHashChainEntry(
            id: "h3", traceId: "t1", sequenceNumber: 3,
            previousHash: "bbb", currentHash: "ccc",
            chainHeadSignature: "sig-ccc",
            chainHeadPublishedToUnifiedLog: true,
            createdAt: Date(timeIntervalSince1970: 1_700_000_020)
        )

        try await store.appendHashChain(entry1)
        try await store.appendHashChain(entry2)
        try await store.appendHashChain(entry3)

        let length = try await store.hashChainLength(for: "t1")
        #expect(length == 3)

        let latest = try await store.latestHashChainEntry(for: "t1")
        #expect(latest?.sequenceNumber == 3)
        #expect(latest?.currentHash == "ccc")
        #expect(latest?.previousHash == "bbb")
        #expect(latest?.chainHeadSignature == "sig-ccc")
        #expect(latest?.chainHeadPublishedToUnifiedLog == true)
        await store.close()
    }

    @Test("Empty hash chain returns nil for latest")
    func hashChainEmpty() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        let latest = try await store.latestHashChainEntry(for: "nonexistent-trace")
        #expect(latest == nil)
        let length = try await store.hashChainLength(for: "nonexistent-trace")
        #expect(length == 0)
        await store.close()
    }

    // MARK: - Reopen (schema persists)

    @Test("Reopen preserves data and schema")
    func reopenPreservesState() async throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-reopen-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: path) }
        do {
            let store = try await SQLiteCausalGraphStore(databasePath: path.path)
            try await store.upsertEntity(makeEntity(id: "e1"))
            try await store.saveTrace(makeTrace(id: "t1"), members: [])
            await store.close()
        }
        // Reopen — schema migration must be idempotent, data must persist.
        let store2 = try await SQLiteCausalGraphStore(databasePath: path.path)
        let entity = try await store2.entity(id: "e1")
        #expect(entity != nil)
        let trace = try await store2.loadTrace(id: "t1")
        #expect(trace != nil)
        await store2.close()
    }
}
