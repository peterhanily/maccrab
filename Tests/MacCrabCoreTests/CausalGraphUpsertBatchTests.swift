// CausalGraphUpsertBatchTests.swift
// v1.17.4 — tests for SQLiteCausalGraphStore.upsertBatch, the single-
// transaction per-event persist that replaces ~7 autocommit upserts.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: upsertBatch (v1.17.4 perf)")
struct CausalGraphUpsertBatchTests {
    private let now = Date(timeIntervalSince1970: 1_700_000_000)

    private func makeStore() async throws -> (SQLiteCausalGraphStore, URL) {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("batch-\(UUID().uuidString).db")
        return (try await SQLiteCausalGraphStore(databasePath: path.path), path)
    }
    private func ent(_ id: String, observationCount: Int = 1) -> TraceEntity {
        TraceEntity(id: id, entityType: "process", stableKey: id, displayName: id,
                    firstSeen: now, lastSeen: now, attributesJson: "{}", source: "test",
                    observationCount: observationCount)
    }
    private func edg(_ id: String, from: String, to: String) -> TraceEdge {
        TraceEdge(id: id, sourceEntityId: from, targetEntityId: to, relation: "spawned",
                  firstSeen: now, lastSeen: now, confidence: 0.9, confidenceTier: "direct",
                  evidenceJson: "{}", eventIdsJson: "[]")
    }

    @Test("Persists all entities then all edges in one transaction")
    func batchPersists() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertBatch(
            entities: [ent("a"), ent("b")],
            edges: [edg("e", from: "a", to: "b")])
        #expect(try await store.entity(id: "a") != nil)
        #expect(try await store.entity(id: "b") != nil)
        #expect(try await store.edge(id: "e") != nil)
        await store.close()
    }

    @Test("Aggregated observation weights equal sequential entity upserts")
    func batchObservationWeightsAreExact() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertBatch(entities: [ent("weighted", observationCount: 257)], edges: [])
        try await store.upsertBatch(entities: [ent("weighted", observationCount: 743)], edges: [])
        #expect(try await store.entity(id: "weighted")?.observationCount == 1_000)
        await store.close()
    }

    @Test("A failed row rolls back the whole batch instead of committing partial growth")
    func batchFailureIsAtomic() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        await #expect(throws: CausalGraphStoreError.self) {
            try await store.upsertBatch(
                entities: [ent("a"), ent("b")],
                edges: [edg("good", from: "a", to: "b"),
                        edg("bad", from: "a", to: "missing")])
        }
        #expect(try await store.entity(id: "a") == nil)
        #expect(try await store.entity(id: "b") == nil)
        #expect(try await store.edge(id: "good") == nil)
        #expect(try await store.edge(id: "bad") == nil)
        await store.close()
    }

    @Test("Empty batch is a no-op")
    func batchEmpty() async throws {
        let (store, path) = try await makeStore()
        defer { try? FileManager.default.removeItem(at: path) }
        try await store.upsertBatch(entities: [], edges: [])
        await store.close()
    }
}
