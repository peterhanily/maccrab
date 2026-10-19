import Testing
import Foundation
import CSQLCipher
@testable import MacCrabCore

/// Only synthetic rows in test-owned temporary SQLite families. No installed
/// store, collectors, processes, network, or security-response fixtures.
@Suite("TraceGraph: bounded checkpoint work and telemetry")
struct CausalGraphCheckpointTelemetryTests {
    private let old = Date(timeIntervalSince1970: 1_600_000_000)
    private let cutoff = Date(timeIntervalSince1970: 1_700_000_000)
    private let recent = Date(timeIntervalSince1970: 1_750_000_000)

    private final class FreeSpaceProbe: @unchecked Sendable {
        private let lock = NSLock()
        private var allowedReads: Int?

        func refuseAfter(_ reads: Int) {
            lock.lock()
            allowedReads = reads
            lock.unlock()
        }

        func read() -> Int64? {
            lock.lock()
            defer { lock.unlock() }
            guard let remaining = allowedReads else { return .max }
            guard remaining > 0 else { return 0 }
            allowedReads = remaining - 1
            return .max
        }
    }

    private func withStore(
        freeSpaceProbe: CausalGraphStorageProbe? = nil,
        _ body: (SQLiteCausalGraphStore, String) async throws -> Void
    ) async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("graph-checkpoint-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("graph.db").path
        let store = try await SQLiteCausalGraphStore(
            databasePath: path,
            freeSpaceFloorBytes: freeSpaceProbe == nil ? nil : 1,
            freeSpaceProbe: freeSpaceProbe
        )
        do {
            try await body(store, path)
            await store.close()
        } catch {
            await store.close()
            throw error
        }
    }

    private func entity(_ id: String, at date: Date) -> TraceEntity {
        TraceEntity(
            id: id, entityType: "process", stableKey: id, displayName: id,
            firstSeen: date, lastSeen: date, attributesJson: "{}",
            source: "checkpoint-test")
    }

    private func seedOrphanEdge(in store: SQLiteCausalGraphStore) async throws {
        try await store.upsertBatch(
            entities: [entity("older-a", at: old), entity("older-b", at: old)],
            edges: [TraceEdge(
                id: "older-edge", sourceEntityId: "older-a",
                targetEntityId: "older-b", relation: "spawned",
                firstSeen: old, lastSeen: old, confidence: 1,
                confidenceTier: "direct", evidenceJson: "{}", eventIdsJson: "[]")]
        )
    }

    private func expectConserved(_ value: CausalGraphCheckpointModeTelemetry) {
        #expect(value.requestsTotal == value.attemptsTotal
            + value.admissionDeferralsTotal + value.unavailableTotal)
        #expect(value.attemptsTotal == value.completedTotal
            + value.pinnedDeferralsTotal + value.failuresTotal)
        #expect(value.requestNanosecondsTotal >= value.sqliteNanosecondsTotal)
        #expect(value.requestMaxNanoseconds >= value.sqliteMaxNanoseconds)
        #expect(value.requestNanosecondsTotal >= value.requestMaxNanoseconds)
        #expect(value.sqliteNanosecondsTotal >= value.sqliteMaxNanoseconds)
    }

    @Test("Empty substrate selections retain entry admission but issue no per-batch checkpoints")
    func emptySelectionsAvoidPerBatchCheckpoints() async throws {
        try await withStore { store, _ in
            let before = await store.checkpointTelemetry()
            let result = try await store.pruneOrphanedGraph(olderThan: cutoff)
            let after = await store.checkpointTelemetry()
            #expect(result.edges == 0 && result.entities == 0)
            #expect(after.truncate.requestsTotal - before.truncate.requestsTotal == 1)
            #expect(after.truncate.completedTotal - before.truncate.completedTotal == 1)
            expectConserved(after.truncate)
        }
    }

    @Test("Empty bounded recovery retains one common boundary, not the adjacent duplicate")
    func emptyRecoveryRetainsCommonBoundary() async throws {
        try await withStore { store, _ in
            let before = await store.checkpointTelemetry()
            let result = try await store.recoverStorageBudget(
                retentionCutoff: cutoff, orphanCutoff: cutoff,
                maxTraceDeletes: 0, maxGraphDeletesPerTable: 10,
                maxVacuumPages: 0)
            let after = await store.checkpointTelemetry()
            #expect(result.edgesDeleted == 0 && result.entitiesDeleted == 0)
            // Entry, edge-phase boundary, common entity/end boundary.
            #expect(after.truncate.requestsTotal - before.truncate.requestsTotal == 3)
            #expect(after.truncate.completedTotal - before.truncate.completedTotal == 3)
            expectConserved(after.truncate)
        }
    }

    @Test("Real substrate deletes retain fresh pre/post checkpoints and protected cutoffs")
    func realDeletesRetainBothBoundaries() async throws {
        try await withStore { store, _ in
            try await seedOrphanEdge(in: store)
            try await store.upsertEntity(entity("recent", at: recent))
            let before = await store.checkpointTelemetry()
            let result = try await store.recoverStorageBudget(
                retentionCutoff: cutoff, orphanCutoff: cutoff,
                maxTraceDeletes: 0, maxGraphDeletesPerTable: 10,
                maxVacuumPages: 0)
            let after = await store.checkpointTelemetry()
            #expect(result.edgesDeleted == 1 && result.entitiesDeleted == 2)
            #expect(try await store.entity(id: "older-a") == nil)
            #expect(try await store.entity(id: "recent") != nil)
            // Three shared boundaries plus pre/post for each nonempty table.
            #expect(after.truncate.requestsTotal - before.truncate.requestsTotal == 7)
            #expect(after.truncate.completedTotal - before.truncate.completedTotal == 7)
            #expect(!result.pinnedReader,
                    "the candidate SELECT must release its reader before checkpointing")
            expectConserved(after.truncate)
        }
    }

    @Test("Headroom is freshly rechecked after selection and before any DELETE")
    func lowHeadroomAfterEntryPreservesCandidates() async throws {
        let free = FreeSpaceProbe()
        try await withStore(freeSpaceProbe: { _ in free.read() }) { store, _ in
            try await seedOrphanEdge(in: store)
            let before = await store.checkpointTelemetry()
            // Entry succeeds. The very next checkpoint (after selection) is
            // refused; these entities remain referenced by the preserved edge.
            free.refuseAfter(1)
            let result = try await store.pruneOrphanedGraph(olderThan: cutoff)
            let after = await store.checkpointTelemetry()
            #expect(result.edges == 0 && result.entities == 0)
            #expect(try await store.edge(id: "older-edge") != nil)
            #expect(try await store.entity(id: "older-a") != nil)
            #expect(after.truncate.requestsTotal - before.truncate.requestsTotal == 2)
            #expect(after.truncate.attemptsTotal - before.truncate.attemptsTotal == 1)
            #expect(after.truncate.admissionDeferralsTotal
                - before.truncate.admissionDeferralsTotal == 1)
            #expect((await store.storageAdmissionStatus()).shedMutationsTotal == 0)
            expectConserved(after.truncate)
        }
    }

    @Test("All explicit checkpoint modes defer before SQLite when below the free-space floor")
    func allModesRefuseBelowFloorWithoutSQLiteAttempts() async throws {
        let free = FreeSpaceProbe()
        try await withStore(freeSpaceProbe: { _ in free.read() }) { store, _ in
            try await seedOrphanEdge(in: store)
            let before = await store.checkpointTelemetry()
            // The configured floor is one byte. Deny immediately so neither
            // PASSIVE nor its RESTART fallback may enter SQLite; TRUNCATE must
            // independently apply the same fresh admission gate.
            free.refuseAfter(0)
            #expect(!(await store.walCheckpoint()))
            #expect(!(await store.walCheckpointTruncate()))
            let after = await store.checkpointTelemetry()
            for (start, end) in [(before.passive, after.passive),
                                 (before.restart, after.restart),
                                 (before.truncate, after.truncate)] {
                #expect(end.requestsTotal - start.requestsTotal == 1)
                #expect(end.admissionDeferralsTotal - start.admissionDeferralsTotal == 1)
                #expect(end.attemptsTotal == start.attemptsTotal)
                #expect(end.sqliteNanosecondsTotal == start.sqliteNanosecondsTotal)
                #expect(end.completedTotal == start.completedTotal)
                #expect(end.unavailableTotal == start.unavailableTotal)
                expectConserved(end)
            }
            #expect((await store.storageAdmissionStatus()).reason == .lowFreeSpace)
            #expect(try await store.edge(id: "older-edge") != nil)

            // Refusal must remain recoverable when a fresh probe admits it.
            free.refuseAfter(Int.max)
            #expect(await store.walCheckpointTruncate())
            let recovered = await store.checkpointTelemetry()
            #expect(recovered.truncate.attemptsTotal - after.truncate.attemptsTotal == 1)
            #expect(recovered.truncate.completedTotal - after.truncate.completedTotal == 1)
            #expect(recovered.truncate.admissionDeferralsTotal == after.truncate.admissionDeferralsTotal)
            expectConserved(recovered.truncate)
        }
    }

    @Test("A pinned reader is counted as deferral and prevents substrate deletion")
    func pinnedReaderPreservesCandidatesUntilRelease() async throws {
        try await withStore { store, path in
            try await seedOrphanEdge(in: store)
            var reader: OpaquePointer?
            let rc = sqlite3_open_v2(
                path, &reader, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, nil)
            defer { if let reader { sqlite3_close(reader) } }
            #expect(rc == SQLITE_OK)
            let handle = try #require(reader)
            #expect(sqlite3_exec(handle, "BEGIN", nil, nil, nil) == SQLITE_OK)
            var statement: OpaquePointer?
            #expect(sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM trace_edges",
                                      -1, &statement, nil) == SQLITE_OK)
            let prepared = try #require(statement)
            let step = sqlite3_step(prepared)
            sqlite3_finalize(prepared)
            #expect(step == SQLITE_ROW)
            try await store.upsertEntity(entity("newer-frame", at: recent))
            let before = await store.checkpointTelemetry()
            let held = try await store.pruneOrphanedGraph(olderThan: cutoff)
            let after = await store.checkpointTelemetry()
            #expect(held.edges == 0 && held.entities == 0)
            #expect(after.truncate.pinnedDeferralsTotal
                - before.truncate.pinnedDeferralsTotal == 1)
            #expect(after.truncate.failuresTotal == before.truncate.failuresTotal)
            #expect(try await store.edge(id: "older-edge") != nil)
            #expect(sqlite3_exec(handle, "COMMIT", nil, nil, nil) == SQLITE_OK)
            #expect(sqlite3_close(handle) == SQLITE_OK)
            reader = nil
            let released = try await store.pruneOrphanedGraph(olderThan: cutoff)
            #expect(released.edges == 1 && released.entities == 2)
            expectConserved((await store.checkpointTelemetry()).truncate)
        }
    }

    @Test("Closed handles remain unavailable, never successful zero-work checkpoints")
    func unavailableHandlesAreSeparateFromAttempts() async throws {
        try await withStore { store, _ in
            #expect(await store.controlledCheckpointSnapshot() != nil)
            await store.close()
            let before = await store.checkpointTelemetry()
            #expect(!(await store.walCheckpoint()))
            #expect(!(await store.walCheckpointTruncate()))
            let after = await store.checkpointTelemetry()
            for (start, end) in [(before.passive, after.passive),
                                 (before.restart, after.restart),
                                 (before.truncate, after.truncate)] {
                #expect(end.unavailableTotal - start.unavailableTotal == 1)
                #expect(end.attemptsTotal == start.attemptsTotal)
                expectConserved(end)
            }
            #expect(await store.controlledCheckpointSnapshot() == nil)
            let encoded = try JSONEncoder().encode(after)
            let object = try #require(
                JSONSerialization.jsonObject(with: encoded) as? [String: Any])
            #expect(Set(object.keys) == Set(["passive", "restart", "truncate"]))
            #expect(try JSONDecoder().decode(CausalGraphCheckpointTelemetry.self,
                                            from: encoded) == after)
        }
    }
}
