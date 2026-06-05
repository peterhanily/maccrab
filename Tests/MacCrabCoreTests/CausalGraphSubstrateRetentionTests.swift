// CausalGraphSubstrateRetentionTests.swift
// v1.18 — tests for the orphan-aware substrate retention added to
// SQLiteCausalGraphStore (pruneOrphanedGraph / pruneOldestGraph).
//
// trace_entities + trace_edges are the GLOBAL causal-graph substrate.
// Pre-v1.18 nothing ever deleted them (cascadeDeleteTraces only removed
// the `traces` table + its children), so tracegraph.db grew to 17 GB on
// a busy host. These methods bound the substrate WITHOUT corrupting any
// surviving trace: a row is deletable only when it is older than the
// retention window AND unreferenced by any surviving trace (membership /
// hash_chain) and, for entities, not an endpoint of a surviving edge.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: substrate retention (v1.18)")
struct CausalGraphSubstrateRetentionTests {

    // ~2020 (older than cutoff) / ~2025 (newer than cutoff) / cutoff between.
    private let old = Date(timeIntervalSince1970: 1_600_000_000)
    private let recent = Date(timeIntervalSince1970: 1_750_000_000)
    private let cutoff = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("tracegraph-gc-\(UUID().uuidString).db")
        let store = try await SQLiteCausalGraphStore(databasePath: path.path)
        return (store, path)
    }

    private func ent(_ id: String, lastSeen: Date) -> TraceEntity {
        TraceEntity(id: id, entityType: "process", stableKey: id, displayName: id,
                    firstSeen: lastSeen, lastSeen: lastSeen,
                    attributesJson: "{}", source: "test")
    }
    private func edg(_ id: String, from: String, to: String, lastSeen: Date) -> TraceEdge {
        TraceEdge(id: id, sourceEntityId: from, targetEntityId: to, relation: "spawned",
                  firstSeen: lastSeen, lastSeen: lastSeen, confidence: 0.9,
                  confidenceTier: "direct", evidenceJson: "{}", eventIdsJson: "[]")
    }
    private func trc(_ id: String) -> Trace {
        Trace(id: id, title: "t", anchorEventId: "ev", rootEntityId: nil,
              severity: "high", confidence: 0.9,
              createdAt: cutoff, updatedAt: cutoff,
              daemonVersion: "1.18.0", rulesetVersion: "1.18.0",
              policyId: "default", policyVersion: "1", policySha256: "x",
              policySnapshotJson: "{}", traceSigningKeyMode: "filesystem_degraded",
              replayScope: "declared_deterministic_subset",
              attributionOverridePolicy: "include_as_human_annotation_do_not_apply_by_default")
    }

    @Test("Deletes OLD, unreferenced substrate (the 17 GB bug)")
    func deletesOldOrphans() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(ent("a", lastSeen: old))
        try await store.upsertEntity(ent("b", lastSeen: old))
        try await store.upsertEdge(edg("e", from: "a", to: "b", lastSeen: old))

        let res = try await store.pruneOrphanedGraph(olderThan: cutoff)

        #expect(res.edges == 1)
        #expect(res.entities == 2)
        #expect(try await store.edge(id: "e") == nil)
        #expect(try await store.entity(id: "a") == nil)
        #expect(try await store.entity(id: "b") == nil)
        await store.close()
    }

    @Test("Preserves RECENT substrate (the rolling correlation working set)")
    func preservesRecent() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(ent("a", lastSeen: recent))
        try await store.upsertEntity(ent("b", lastSeen: recent))
        try await store.upsertEdge(edg("e", from: "a", to: "b", lastSeen: recent))

        let res = try await store.pruneOrphanedGraph(olderThan: cutoff)

        #expect(res.edges == 0)
        #expect(res.entities == 0)
        #expect(try await store.entity(id: "a") != nil)
        await store.close()
    }

    @Test("Preserves old substrate referenced by a surviving trace (membership + edge endpoint)")
    func preservesMembers() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(ent("a", lastSeen: old))
        try await store.upsertEntity(ent("b", lastSeen: old))
        try await store.upsertEdge(edg("e", from: "a", to: "b", lastSeen: old))
        try await store.saveTrace(trc("t1"), members: [
            TraceMembership(traceId: "t1", entityId: "a", role: "root", layer: "core"),
            TraceMembership(traceId: "t1", edgeId: "e", role: "critical_path", layer: "core"),
        ])

        let res = try await store.pruneOrphanedGraph(olderThan: cutoff)

        // a + e are members; b survives as an endpoint of the surviving edge e.
        #expect(res.edges == 0)
        #expect(res.entities == 0)
        #expect(try await store.entity(id: "a") != nil)
        #expect(try await store.entity(id: "b") != nil)
        #expect(try await store.edge(id: "e") != nil)
        await store.close()
    }

    @Test("Preserves an old edge referenced only by the hash chain")
    func preservesHashChainEdge() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(ent("a", lastSeen: old))
        try await store.upsertEntity(ent("b", lastSeen: old))
        try await store.upsertEdge(edg("e", from: "a", to: "b", lastSeen: old))
        try await store.saveTrace(trc("t1"), members: [])
        try await store.appendHashChain(TraceHashChainEntry(
            id: "h1", traceId: "t1", sequenceNumber: 1,
            previousHash: nil, currentHash: "aaa", edgeId: "e", createdAt: old))

        let res = try await store.pruneOrphanedGraph(olderThan: cutoff)

        #expect(res.edges == 0)                          // edge protected by hash chain
        #expect(try await store.edge(id: "e") != nil)
        await store.close()
    }

    @Test("Mixed graph: deletes only the old orphans")
    func mixed() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(ent("orphan", lastSeen: old))     // delete
        try await store.upsertEntity(ent("member", lastSeen: old))     // keep (member)
        try await store.upsertEntity(ent("fresh", lastSeen: recent))   // keep (recent)
        try await store.saveTrace(trc("t1"), members: [
            TraceMembership(traceId: "t1", entityId: "member", role: "root", layer: "core"),
        ])

        let res = try await store.pruneOrphanedGraph(olderThan: cutoff)

        #expect(res.entities == 1)
        #expect(try await store.entity(id: "orphan") == nil)
        #expect(try await store.entity(id: "member") != nil)
        #expect(try await store.entity(id: "fresh") != nil)
        await store.close()
    }

    @Test("pruneOldestGraph evicts the oldest orphans up to count, never a member")
    func oldestEviction() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertEntity(ent("o1", lastSeen: Date(timeIntervalSince1970: 1_600_000_000)))
        try await store.upsertEntity(ent("o2", lastSeen: Date(timeIntervalSince1970: 1_600_000_100)))
        try await store.upsertEntity(ent("o3", lastSeen: Date(timeIntervalSince1970: 1_600_000_200)))
        // member is the OLDEST overall — must survive despite oldest-first eviction.
        try await store.upsertEntity(ent("m", lastSeen: Date(timeIntervalSince1970: 1_500_000_000)))
        try await store.saveTrace(trc("t1"), members: [
            TraceMembership(traceId: "t1", entityId: "m", role: "root", layer: "core"),
        ])

        let res = try await store.pruneOldestGraph(count: 2)

        #expect(res.entities == 2)
        #expect(try await store.entity(id: "o1") == nil)   // oldest orphan
        #expect(try await store.entity(id: "o2") == nil)
        #expect(try await store.entity(id: "o3") != nil)   // survives the count=2 cap
        #expect(try await store.entity(id: "m") != nil)    // guard beats oldest-first
        await store.close()
    }

    @Test("liveDataSizeBytes tracks prunes so the size-cap loop self-terminates (over-prune guard)")
    func liveSizeTracksPrunes() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        for i in 0..<5000 { try await store.upsertEntity(ent("e\(i)", lastSeen: old)) }

        let liveBefore = await store.liveDataSizeBytes()
        #expect(liveBefore > 0)

        // Evict ~90% of the substrate (all orphans, oldest-first).
        var dropped = 0
        for _ in 0..<5 {
            let r = try await store.pruneOldestGraph(count: 1000)
            dropped += r.entities
            if r.entities == 0 { break }
            if dropped >= 4500 { break }
        }
        #expect(dropped >= 4000)

        // With ~90% of the substrate gone, liveDataSizeBytes — (page_count −
        // freelist) × page_size — MUST read substantially smaller, even though
        // the file is NOT vacuumed yet (freed pages sit on the freelist, so
        // databaseSizeBytes / the file footprint is unchanged). The size-cap
        // loop breaks on liveDataSizeBytes; before this fix it broke on the
        // file footprint, which never moved pre-vacuum, so the loop ran all 5
        // iterations and over-pruned the substrate to near-empty.
        let liveAfter = await store.liveDataSizeBytes()
        #expect(liveAfter < liveBefore * 7 / 10, "live size must track the prune (got \(liveAfter) vs \(liveBefore))")

        // The freed pages are reclaimable: auto_vacuum=INCREMENTAL is set in
        // openDatabase, so incremental_vacuum shrinks the live/page accounting
        // without a full VACUUM (validates the corrected Wave-9B.1 comment).
        _ = try await store.incrementalVacuum(maxPages: 200_000)
        #expect(await store.liveDataSizeBytes() <= liveAfter)

        await store.close()
    }
}
